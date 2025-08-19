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

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + NAME_MAX + 1))
#define MAX_EXCLUSIONS 256

// ====== Exclusion List (loaded at runtime) ======
static char* exclusionList[MAX_EXCLUSIONS];
static int exclusionCount = 0;

void LoadExclusions(const char* exePath) {
    char exclusionFile[PATH_MAX];
    snprintf(exclusionFile, sizeof(exclusionFile), "%s/exclusions.txt", exePath);

    FILE* file = fopen(exclusionFile, "r");
    if (!file) {
        printf("[-] No exclusions.txt found. Continuing without exclusions.\n");
        return;
    }

    char line[PATH_MAX];
    while (fgets(line, sizeof(line), file) && exclusionCount < MAX_EXCLUSIONS) {
        line[strcspn(line, "\r\n")] = 0; // remove newline
        if (strlen(line) > 0) {
            exclusionList[exclusionCount++] = strdup(line);
            printf("[+] Loaded exclusion: %s\n", line);
        }
    }
    fclose(file);
}

int IsExcluded(const char* path) {
    for (int i = 0; i < exclusionCount; i++) {
        if (strncmp(path, exclusionList[i], strlen(exclusionList[i])) == 0) {
            return 1; // path starts with excluded folder
        }
    }
    return 0;
}

// ====== Watch List (map wd -> path) ======
typedef struct WatchNode {
    int wd;
    char path[PATH_MAX];
    struct WatchNode* next;
} WatchNode;

static WatchNode* watchList = NULL;
pthread_mutex_t watchListMutex = PTHREAD_MUTEX_INITIALIZER;

void AddWatchNode(int wd, const char* path) {
    WatchNode* node = malloc(sizeof(WatchNode));
    node->wd = wd;
    strncpy(node->path, path, PATH_MAX);
    node->next = NULL;

    pthread_mutex_lock(&watchListMutex);
    node->next = watchList;
    watchList = node;
    pthread_mutex_unlock(&watchListMutex);
}

char* GetPathFromWd(int wd) {
    pthread_mutex_lock(&watchListMutex);
    WatchNode* node = watchList;
    while (node) {
        if (node->wd == wd) {
            pthread_mutex_unlock(&watchListMutex);
            return node->path;
        }
        node = node->next;
    }
    pthread_mutex_unlock(&watchListMutex);
    return NULL;
}

// ====== Detection Engine ======
void CallDetectionEngine(const char* filePath) {
    if (IsExcluded(filePath)) {
        printf("[-] Skipping excluded path: %s\n", filePath);
        return;
    }

    printf("[+] Called detection for: %s\n", filePath);
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0) {  // child process
        execl("/home/moon/YouTube/How to create YOUR own Antivirus software/engine_compile",
              "./engine_compile", filePath, (char *)NULL);
        perror("execl failed");
        exit(1);
    } else if (pid < 0) {
        perror("fork failed");
    } else {
        wait(NULL);  // parent waits for child
    }
}

// ====== Recursive Watch ======
void AddWatchesRecursively(int fd, const char* basePath) {
    if (IsExcluded(basePath)) {
        printf("[-] Excluding directory: %s\n", basePath);
        return;
    }

    int wd = inotify_add_watch(fd, basePath, IN_CREATE | IN_MODIFY | IN_ISDIR);
    if (wd < 0) {
        fprintf(stderr, "[-] Failed to add watch on %s: %s\n", basePath, strerror(errno));
        return;
    }
    AddWatchNode(wd, basePath);
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
            AddWatchesRecursively(fd, fullPath); // recursive call
        }
    }
    closedir(dir);
}

// ====== Monitoring Thread ======
void* MonitorDirectoryThread(void* arg) {
    char* rootPath = (char*)arg;

    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        free(rootPath);
        return NULL;
    }

    // Add root + all subdirectories recursively
    AddWatchesRecursively(fd, rootPath);

    char buffer[BUF_LEN];
    while (1) {
        ssize_t length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }

        ssize_t i = 0;
        while (i < length) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];
            char* basePath = GetPathFromWd(event->wd);
            if (basePath && event->len) {
                char fullPath[PATH_MAX];
                snprintf(fullPath, sizeof(fullPath), "%s/%s", basePath, event->name);

                if (IsExcluded(fullPath)) {
                    printf("[-] Ignored excluded: %s\n", fullPath);
                } else if (event->mask & IN_ISDIR) {
                    if (event->mask & IN_CREATE) {
                        printf("[+] New directory created: %s\n", fullPath);
                        AddWatchesRecursively(fd, fullPath);
                    }
                } else {
                    printf("[+] Change detected in file: %s\n", fullPath);
                    CallDetectionEngine(fullPath);
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    close(fd);
    free(rootPath);
    return NULL;
}

// ====== Main ======
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <directory1> [directory2] [...]\n", argv[0]);
        return 1;
    }

    // Get path to executable's folder
    char exeDir[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exeDir, sizeof(exeDir)-1);
    if (len != -1) {
        exeDir[len] = '\0';
        char* lastSlash = strrchr(exeDir, '/');
        if (lastSlash) *lastSlash = '\0'; // keep only directory
        LoadExclusions(exeDir);
    }

    for (int i = 1; i < argc; i++) {
        pthread_t thread_id;
        char* dir = strdup(argv[i]);
        if (pthread_create(&thread_id, NULL, MonitorDirectoryThread, dir) != 0) {
            fprintf(stderr, "[-] Failed to create thread for: %s\n", argv[i]);
            free(dir);
        }
        pthread_detach(thread_id);
    }

    printf("Press 'q' followed by Enter to exit...\n");
    char userInput;
    do {
        userInput = getchar();
    } while (userInput != 'q');

    return 0;
}
