// rtm.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <errno.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/stat.h>
#include <signal.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN    (1024 * (EVENT_SIZE + NAME_MAX + 1))
#define MAX_EXCLUSIONS 256

// ================== global control ==================
static volatile sig_atomic_t running = 1;

// ================== exclusions ==================
static char* exclusionList[MAX_EXCLUSIONS];
static int exclusionCount = 0;

static void trim_newline(char* s){
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = '\0';
}

static void LoadExclusions(const char* exeDir) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/exclusions.txt", exeDir);

    FILE* f = fopen(path, "r");
    if (!f) {
        printf("[-] No exclusions.txt found at %s – continuing without exclusions.\n", path);
        return;
    }
    char line[PATH_MAX];
    while (fgets(line, sizeof(line), f) && exclusionCount < MAX_EXCLUSIONS) {
        trim_newline(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        exclusionList[exclusionCount++] = strdup(line);
        printf("[+] Loaded exclusion: %s\n", line);
    }
    fclose(f);
}

static int IsExcluded(const char* path) {
    for (int i = 0; i < exclusionCount; i++) {
        const char* ex = exclusionList[i];
        size_t elen = strlen(ex);
        if (strncmp(path, ex, elen) == 0 &&
            (path[elen] == '/' || path[elen] == '\0')) {
            return 1;
        }
    }
    return 0;
}

// ================== watch map: (fd, wd) -> path ==================
typedef struct WatchNode {
    int fd;
    int wd;
    char *path;                 // heap-allocated for safety
    struct WatchNode* next;
} WatchNode;

static WatchNode* watchList = NULL;
static pthread_mutex_t watchListMutex = PTHREAD_MUTEX_INITIALIZER;

static void AddWatchNode(int fd, int wd, const char* path) {
    WatchNode* node = (WatchNode*)malloc(sizeof(WatchNode));
    if (!node) return;
    node->fd = fd;
    node->wd = wd;
    node->path = strdup(path);
    node->next = NULL;

    pthread_mutex_lock(&watchListMutex);
    node->next = watchList;
    watchList = node;
    pthread_mutex_unlock(&watchListMutex);
}

static int RemoveWatchNode(int fd, int wd, char* outPath /* optional */, size_t outSize) {
    int removed = 0;
    pthread_mutex_lock(&watchListMutex);
    WatchNode **pp = &watchList, *cur;
    while ((cur = *pp) != NULL) {
        if (cur->fd == fd && cur->wd == wd) {
            if (outPath && outSize) {
                snprintf(outPath, outSize, "%s", cur->path);
            }
            *pp = cur->next;
            free(cur->path);
            free(cur);
            removed = 1;
            break;
        }
        pp = &cur->next;
    }
    pthread_mutex_unlock(&watchListMutex);
    return removed;
}

static int GetPathFromWd(int fd, int wd, char* out, size_t outsz) {
    int found = 0;
    pthread_mutex_lock(&watchListMutex);
    for (WatchNode* n = watchList; n; n = n->next) {
        if (n->fd == fd && n->wd == wd) {
            snprintf(out, outsz, "%s", n->path);
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&watchListMutex);
    return found;
}

// remove all nodes for a given fd (thread shutdown)
static void RemoveAllForFd(int fd) {
    pthread_mutex_lock(&watchListMutex);
    WatchNode **pp = &watchList, *cur;
    while ((cur = *pp) != NULL) {
        if (cur->fd == fd) {
            *pp = cur->next;
            free(cur->path);
            free(cur);
            continue;
        }
        pp = &cur->next;
    }
    pthread_mutex_unlock(&watchListMutex);
}

// ================== scan worker ==================
typedef struct {
    char *path;
} ScanTask;

static void* ScanWorker(void* arg) {
    ScanTask* t = (ScanTask*)arg;
    if (!t) return NULL;
    if (!running) { free(t->path); free(t); return NULL; }

    const char* filePath = t->path;

    if (IsExcluded(filePath)) {
        printf("[-] Skipping excluded path: %s\n", filePath);
        free(t->path);
        free(t);
        return NULL;
    }

    printf("[+] Called detection for: %s\n", filePath);
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0) {
        // child
        execl("/home/moon/YouTube/How to create YOUR own Antivirus software/engine_compile",
              "./engine_compile", filePath, (char *)NULL);
        perror("execl failed");
        _exit(1);
    } else if (pid < 0) {
        perror("fork failed");
    } else {
        // wait but don't block shutdown forever
        int status = 0;
        (void)waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code != 0) {
                fprintf(stderr, "[-] engine exit code %d for %s\n", code, filePath);
            }
        }
    }

    free(t->path);
    free(t);
    return NULL;
}

static void dispatch_scan(const char* fullPath) {
    if (!running) return;
    if (IsExcluded(fullPath)) {
        printf("[-] Ignored excluded: %s\n", fullPath);
        return;
    }
    ScanTask* task = (ScanTask*)malloc(sizeof(ScanTask));
    if (!task) return;
    task->path = strdup(fullPath);
    if (!task->path) { free(task); return; }

    pthread_t th;
    if (pthread_create(&th, NULL, ScanWorker, task) == 0) {
        // Workers can be detached; we accept that scans in-flight may finish after 'q'.
        pthread_detach(th);
    } else {
        perror("pthread_create ScanWorker");
        free(task->path);
        free(task);
    }
}

// ================== recursive add ==================
static void AddWatchesRecursively(int fd, const char* basePath) {
    if (IsExcluded(basePath)) {
        printf("[-] Excluding directory: %s\n", basePath);
        return;
    }

    int wd = inotify_add_watch(fd, basePath,
        IN_CREATE | IN_MODIFY | IN_MOVED_TO | IN_CLOSE_WRITE |
        IN_DELETE_SELF | IN_MOVE_SELF);
    if (wd < 0) {
        fprintf(stderr, "[-] Failed to add watch on %s: %s\n", basePath, strerror(errno));
        return;
    }
    AddWatchNode(fd, wd, basePath);
    printf("[+] Monitoring directory: %s\n", basePath);

    DIR* dir = opendir(basePath);
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char fullPath[PATH_MAX];
        snprintf(fullPath, sizeof(fullPath), "%s/%s", basePath, entry->d_name);

        struct stat st;
        if (stat(fullPath, &st) == 0 && S_ISDIR(st.st_mode)) {
            AddWatchesRecursively(fd, fullPath);
        }
    }
    closedir(dir);
}

// ================== monitor thread ==================
typedef struct {
    char* rootPath;
    pthread_t tid;
} MonitorCtx;

static void* MonitorDirectoryThread(void* arg) {
    char* rootPath = (char*)arg;

    int fd = inotify_init1(IN_NONBLOCK); // nonblocking read; still OK to use blocking pattern
    if (fd < 0) {
        perror("inotify_init1");
        free(rootPath);
        return NULL;
    }

    AddWatchesRecursively(fd, rootPath);

    // We'll do a simple blocking read loop; if nonblocking returns EAGAIN, just sleep briefly
    char buffer[BUF_LEN];
    while (running) {
        ssize_t length = read(fd, buffer, sizeof(buffer));
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(50 * 1000);
                continue;
            }
            perror("read");
            break;
        }
        if (length == 0) { // nothing read; yield
            usleep(10 * 1000);
            continue;
        }

        ssize_t i = 0;
        while (i < length) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];

            char basePath[PATH_MAX] = {0};
            if (!GetPathFromWd(fd, event->wd, basePath, sizeof(basePath))) {
                // Unknown wd (might have been removed); skip
                i += EVENT_SIZE + event->len;
                continue;
            }

            // Handle directory self-deletion/move first: remove mapping to avoid wd reuse bugs
            if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                char removedPath[PATH_MAX] = {0};
                inotify_rm_watch(fd, event->wd);
                RemoveWatchNode(fd, event->wd, removedPath, sizeof(removedPath));
                printf("[-] Watch removed (self %s): %s\n",
                       (event->mask & IN_DELETE_SELF) ? "delete" : "move",
                       removedPath[0] ? removedPath : basePath);
                i += EVENT_SIZE + event->len;
                continue;
            }

            if (event->len) {
                char fullPath[PATH_MAX];
                snprintf(fullPath, sizeof(fullPath), "%s/%s", basePath, event->name);

                if (event->mask & IN_ISDIR) {
                    // new directory created or moved into
                    if ((event->mask & IN_CREATE) || (event->mask & IN_MOVED_TO)) {
                        printf("[+] New directory detected: %s\n", fullPath);
                        AddWatchesRecursively(fd, fullPath);
                    }
                } else {
                    // file events we care about
                    if ((event->mask & IN_CLOSE_WRITE) ||
                        (event->mask & IN_MODIFY) ||
                        (event->mask & IN_MOVED_TO) ||
                        (event->mask & IN_CREATE)) {
                        printf("[+] Change detected in file: %s\n", fullPath);
                        dispatch_scan(fullPath);
                    }
                }
            }

            i += EVENT_SIZE + event->len;
        }
    }

    // cleanup for this thread's fd
    // Remove all watches for this fd (if any remain)
    RemoveAllForFd(fd);
    close(fd);
    free(rootPath);
    return NULL;
}

// ================== signal handler ==================
static void on_sigint(int sig) {
    (void)sig;
    running = 0;
}

// ================== main ==================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <directory1> [directory2] [...]\n", argv[0]);
        return 1;
    }

    // Resolve executable directory for exclusions.txt
    char exePath[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exePath, sizeof(exePath)-1);
    if (n >= 0) {
        exePath[n] = '\0';
        char* slash = strrchr(exePath, '/');
        if (slash) *slash = '\0';
        LoadExclusions(exePath);
    } else {
        printf("[-] Could not resolve /proc/self/exe; exclusions file may not be found.\n");
    }

    // Handle Ctrl+C nicely
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Create monitor threads (joinable)
    int nroots = argc - 1;
    MonitorCtx* ctx = (MonitorCtx*)calloc(nroots, sizeof(MonitorCtx));
    if (!ctx) {
        perror("calloc");
        return 1;
    }

    for (int i = 0; i < nroots; i++) {
        ctx[i].rootPath = strdup(argv[i+1]);
        if (!ctx[i].rootPath) {
            perror("strdup");
            running = 0;
            nroots = i;
            break;
        }
        if (pthread_create(&ctx[i].tid, NULL, MonitorDirectoryThread, ctx[i].rootPath) != 0) {
            fprintf(stderr, "[-] Failed to create thread for: %s\n", argv[i+1]);
            free(ctx[i].rootPath);
            ctx[i].rootPath = NULL;
        }
    }

    printf("Press 'q' followed by Enter to exit...\n");
    int c;
    while ((c = getchar()) != EOF) {
        if (c == 'q' || c == 'Q') break;
    }

    // start shutdown
    running = 0;

    // join threads
    for (int i = 0; i < nroots; i++) {
        if (ctx[i].rootPath) {
            pthread_join(ctx[i].tid, NULL);
            // rootPath freed by thread
        }
    }
    free(ctx);

    // free exclusions
    for (int i = 0; i < exclusionCount; i++) {
        free(exclusionList[i]);
    }

    // final sweep (should already be empty)
    RemoveAllForFd(-1); // -1 means "remove none"; kept for symmetry

    printf("[+] Clean shutdown.\n");
    return 0;
}
