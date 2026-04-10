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
#include <stdbool.h>
#include <semaphore.h>

#define MAX_THREADS 5
#define MAX_WATCHES 2048
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + NAME_MAX + 1))

char exceptions[50][PATH_MAX];
int exCount = 0;
sem_t thread_sem;
pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int wd;
    char path[PATH_MAX];
} WatchMap;

WatchMap watch_list[MAX_WATCHES];
int watch_count = 0;

// --- Safe path printer (avoids non-UTF-8 bytes crashing Python GUI) ---

void print_safe_path(const char* path) {
    for (const char* p = path; *p; p++) {
        if ((unsigned char)*p >= 0x20 && (unsigned char)*p < 0x7F)
            putchar(*p);
        else
            printf("\\x%02x", (unsigned char)*p);
    }
    putchar('\n');
    fflush(stdout);
}

// --- Helper Functions ---

void LoadExceptions() {
    FILE* f = fopen("exceptions.txt", "r");
    if (!f) return;
    while (exCount < 50 && fgets(exceptions[exCount], PATH_MAX, f)) {
        exceptions[exCount][strcspn(exceptions[exCount], "\n")] = 0;
        exCount++;
    }
    fclose(f);
}

void add_to_map(int wd, const char* path) {
    pthread_mutex_lock(&map_mutex);
    if (watch_count < MAX_WATCHES) {
        watch_list[watch_count].wd = wd;
        strncpy(watch_list[watch_count].path, path, PATH_MAX - 1);
        watch_list[watch_count].path[PATH_MAX - 1] = '\0';
        watch_count++;
    }
    pthread_mutex_unlock(&map_mutex);
}

const char* get_path_from_wd(int wd) {
    pthread_mutex_lock(&map_mutex);
    for (int i = 0; i < watch_count; i++) {
        if (watch_list[i].wd == wd) {
            pthread_mutex_unlock(&map_mutex);
            return watch_list[i].path;
        }
    }
    pthread_mutex_unlock(&map_mutex);
    return NULL;
}

bool IsExcluded(const char* path) {
    char absPath[PATH_MAX];
    if (!realpath(path, absPath)) strncpy(absPath, path, PATH_MAX - 1);

    for (int i = 0; i < exCount; i++) {
        if (strstr(absPath, exceptions[i]) != NULL) return true;
    }
    return false;
}

// --- Engine Execution ---

typedef struct {
    char filePath[PATH_MAX];
} ScanArgs;

void* ScanThread(void* arg) {
    ScanArgs* data = (ScanArgs*)arg;

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe failed");
        free(data);
        sem_post(&thread_sem);
        return NULL;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child: redirect engine stdout+stderr into pipe
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl("/home/surja/Downloads/Black-Swan-main/engine", "engine", data->filePath, (char*)NULL);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        // Parent: read engine output line by line and forward to RTM stdout
        close(pipefd[1]);
        char line[4096];
        FILE* engine_out = fdopen(pipefd[0], "r");
        if (engine_out) {
            while (fgets(line, sizeof(line), engine_out)) {
                // Sanitize non-UTF-8 bytes before forwarding to GUI
                for (char* p = line; *p; p++) {
                    if ((unsigned char)*p < 0x20 && *p != '\n' && *p != '\t')
                        *p = '?';
                }
                printf("%s", line);
                fflush(stdout);
            }
            fclose(engine_out);
        } else {
            close(pipefd[0]);
        }
        waitpid(pid, NULL, 0);
    } else {
        perror("fork failed");
        close(pipefd[0]);
        close(pipefd[1]);
    }

    free(data);
    sem_post(&thread_sem);
    return NULL;
}

void CallDetectionEngine(const char* filePath) {
    if (IsExcluded(filePath)) return;

    ScanArgs* args = malloc(sizeof(ScanArgs));
    if (!args) {
        fprintf(stderr, "[-] malloc failed for ScanArgs\n");
        fflush(stderr);
        return;
    }
    strncpy(args->filePath, filePath, PATH_MAX - 1);
    args->filePath[PATH_MAX - 1] = '\0';

    sem_wait(&thread_sem);
    pthread_t scanThread;
    if (pthread_create(&scanThread, NULL, ScanThread, args) == 0) {
        pthread_detach(scanThread);
    } else {
        perror("pthread_create failed");
        free(args);
        sem_post(&thread_sem);
    }
}

// --- Monitoring Logic ---

void AddWatchRecursively(int fd, const char* basePath) {
    if (IsExcluded(basePath)) return;

    int wd = inotify_add_watch(fd, basePath, IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO);
    if (wd < 0) return;

    add_to_map(wd, basePath);

    DIR* dir = opendir(basePath);
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", basePath, entry->d_name);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            AddWatchRecursively(fd, path);
        }
    }
    closedir(dir);
}

void* MonitorDirectoryThread(void* arg) {
    char* directoryPath = (char*)arg;

    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        free(directoryPath);
        return NULL;
    }

    AddWatchRecursively(fd, directoryPath);

    printf("[+] Monitoring: %s\n", directoryPath);
    fflush(stdout);

    char buffer[BUF_LEN];
    while (1) {
        ssize_t length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            if (errno == EINTR) continue;
            perror("read inotify");
            break;
        }

        ssize_t i = 0;
        while (i < length) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];

            if (event->len > 0) {
                const char* parent = get_path_from_wd(event->wd);
                if (!parent) {
                    i += EVENT_SIZE + event->len;
                    continue;
                }

                char fullPath[PATH_MAX];
                snprintf(fullPath, sizeof(fullPath), "%s/%s", parent, event->name);

                if (!IsExcluded(fullPath)) {
                    struct stat st;
                    if (stat(fullPath, &st) == 0) {
                        if (S_ISDIR(st.st_mode)) {
                            if (event->mask & (IN_CREATE | IN_MOVED_TO))
                                AddWatchRecursively(fd, fullPath);
                        } else if (S_ISREG(st.st_mode)) {
                            printf("[+] Event detected: ");
                            print_safe_path(fullPath);
                            CallDetectionEngine(fullPath);
                        }
                    }
                }
            }

            i += EVENT_SIZE + event->len;
        }
    }

    close(fd);
    free(directoryPath);
    return NULL;
}

// --- Main ---

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory1> [directory2] ...\n", argv[0]);
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    sem_init(&thread_sem, 0, MAX_THREADS);
    LoadExceptions();

    for (int i = 1; i < argc; i++) {
        pthread_t tid;
        char* path_copy = strdup(argv[i]);
        if (!path_copy) {
            fprintf(stderr, "[-] strdup failed\n");
            continue;
        }
        if (pthread_create(&tid, NULL, MonitorDirectoryThread, path_copy) != 0) {
            perror("pthread_create for monitor thread");
            free(path_copy);
        } else {
            pthread_detach(tid);
        }
    }

    printf("RTM Running. Press 'q' to quit.\n");
    fflush(stdout);

    int c;
    while ((c = getchar()) != EOF && c != 'q');

    sem_destroy(&thread_sem);
    return 0;
}
