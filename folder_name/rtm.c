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

struct ScanArgs {
    char filePath[PATH_MAX];
};

void* ScanThread(void* arg) {
    struct ScanArgs* data = (struct ScanArgs*)arg;
    pid_t pid = fork();
    if (pid == 0) {
        execl("/home/surja/Downloads/Black-Swan-main/engine", "engine", data->filePath, (char *)NULL);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
    }
    free(data);
    sem_post(&thread_sem);
    return NULL;
}

void CallDetectionEngine(const char* filePath) {
    if (IsExcluded(filePath)) return;
    
    struct ScanArgs* args = malloc(sizeof(struct ScanArgs));
    strncpy(args->filePath, filePath, PATH_MAX - 1);

    sem_wait(&thread_sem);
    pthread_t scanThread;
    if (pthread_create(&scanThread, NULL, ScanThread, args) == 0) {
        pthread_detach(scanThread);
    } else {
        free(args);
        sem_post(&thread_sem);
    }
}

// --- Monitoring Logic ---

void AddWatchRecursively(int fd, const char* basePath) {
    if (IsExcluded(basePath)) return;

    // IN_CLOSE_WRITE is the gold standard for finished file writes
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
    if (fd < 0) { perror("inotify_init"); return NULL; }

    AddWatchRecursively(fd, directoryPath);
    printf("[+] Monitoring: %s\n", directoryPath);

    char buffer[BUF_LEN];
    while (1) {
        ssize_t length = read(fd, buffer, BUF_LEN);
        if (length < 0) break;

        ssize_t i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len > 0) {
                const char* parent = get_path_from_wd(event->wd);
                char fullPath[PATH_MAX];
                snprintf(fullPath, sizeof(fullPath), "%s/%s", parent ? parent : directoryPath, event->name);

                if (!IsExcluded(fullPath)) {
                    struct stat st;
                    if (stat(fullPath, &st) == 0) {
                        if (S_ISDIR(st.st_mode)) {
                            if (event->mask & (IN_CREATE | IN_MOVED_TO))
                                AddWatchRecursively(fd, fullPath);
                        } else {
                            printf("[+] Event detected: %s\n", fullPath);
                            CallDetectionEngine(fullPath);
                        }
                    }
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    sem_init(&thread_sem, 0, MAX_THREADS);
    LoadExceptions();

    for (int i = 1; i < argc; i++) {
        pthread_t tid;
        pthread_create(&tid, NULL, MonitorDirectoryThread, strdup(argv[i]));
        pthread_detach(tid);
    }

    printf("RTM Running. Press 'q' to quit.\n");
    while (getchar() != 'q');
    return 0;
}
