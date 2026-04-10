// Engine code
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <yara.h>
#include <sys/stat.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>

int quarantine_file(const char* file_path, const char* matched_rules);

#define PATH_SEPARATOR '/'
#define BUFFER_SIZE 1024
#define MAX_MATCHES 100
#define MAX_RULES 64

#define QUEUE_MAX 10000

typedef struct {
    char* matches[MAX_MATCHES];
    int count;
} MatchList;

void CallQuarantine(const char* filePath, MatchList* matchList);

// ---------------- GLOBALS ----------------
static char g_rules_realpath[PATH_MAX] = {0};

YR_RULES** g_rules_list;
int g_rules_count;

typedef struct {
    char* items[QUEUE_MAX];
    int front;
    int rear;
    int count;

    pthread_mutex_t lock;
    pthread_cond_t cond;
} FileQueue;

FileQueue queue;

// ---------------- CALLBACK ----------------
int scanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
    MatchList* matchList = (MatchList*)user_data;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;

        if (matchList->count < MAX_MATCHES) {
            matchList->matches[matchList->count] = strdup(rule->identifier);
            matchList->count++;
        }
    }

    return CALLBACK_CONTINUE;
}

// ---------------- SCAN FILE ----------------
void scanFile(const char* filePath, YR_RULES** rules_list, int rules_count, MatchList* matchList)
{
    for (int i = 0; i < rules_count; i++) {
        yr_rules_scan_file(
            rules_list[i],
            filePath,
            SCAN_FLAGS_REPORT_RULES_MATCHING,
            scanCallback,
            matchList,
            NULL
        );
    }
}

// ---------------- QUEUE ----------------
void pushQueue(const char* path)
{
    pthread_mutex_lock(&queue.lock);

    if (queue.count < QUEUE_MAX) {
        queue.items[queue.rear] = strdup(path);
        queue.rear = (queue.rear + 1) % QUEUE_MAX;
        queue.count++;
        pthread_cond_signal(&queue.cond);
    }

    pthread_mutex_unlock(&queue.lock);
}

char* popQueue()
{
    pthread_mutex_lock(&queue.lock);

    while (queue.count == 0)
        pthread_cond_wait(&queue.cond, &queue.lock);

    char* item = queue.items[queue.front];
    queue.front = (queue.front + 1) % QUEUE_MAX;
    queue.count--;

    pthread_mutex_unlock(&queue.lock);

    return item;
}

// ---------------- WORKER THREAD ----------------
void* workerThread(void* arg)
{
    while (1)
    {
        char* filePath = popQueue();
        if (!filePath) continue;

        struct stat st;
        if (stat(filePath, &st) == 0 && S_ISREG(st.st_mode))
        {
            MatchList localMatch = {.count = 0};

            scanFile(filePath, g_rules_list, g_rules_count, &localMatch);

            if (localMatch.count > 0) {
                printf("❌ Infected: %s\n", filePath);
                CallQuarantine(filePath, &localMatch);
            }

            for (int i = 0; i < localMatch.count; i++)
                free(localMatch.matches[i]);
        }

        free(filePath);
    }

    return NULL;
}

// ---------------- DIRECTORY SCAN (NOW QUEUE ONLY) ----------------
void scanDirectoryFlat(const char* rootPath,
                       YR_RULES** rules_list,
                       int rules_count,
                       MatchList* matchList)
{
    DIR* dir = opendir(rootPath);
    if (!dir) {
        perror("[-] Failed to open directory");
        return;
    }

    struct dirent* entry;
    char fullPath[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullPath, sizeof(fullPath), "%s/%s",
                 rootPath, entry->d_name);

        struct stat st;

        if (lstat(fullPath, &st) != 0)
            continue;

        if (S_ISLNK(st.st_mode))
            continue;

        if (S_ISREG(st.st_mode)) {
            pushQueue(fullPath);
        }
    }

    closedir(dir);
}

// ---------------- QUARANTINE ----------------
void CallQuarantine(const char* filePath, MatchList* matchList)
{
    char rules_str[1024] = "";

    for (int i = 0; i < matchList->count; i++) {
        strncat(rules_str, matchList->matches[i],
                 sizeof(rules_str) - strlen(rules_str) - 2);

        if (i < matchList->count - 1)
            strncat(rules_str, ",",
                     sizeof(rules_str) - strlen(rules_str) - 1);
    }

    printf("[!] Sending to quarantine: %s | Rules: %s\n",
           filePath, rules_str);

    quarantine_file(filePath, rules_str);
}

// ---------------- MAIN ----------------
int main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("Usage: %s <file-or-directory-to-scan>\n", argv[0]);
        return 1;
    }

    const char* rules_dir = "/home/surja/Downloads/Black-Swan-main/myrule/compiled/";
    const char* target_path = argv[1];

    if (realpath(rules_dir, g_rules_realpath) == NULL) {
        perror("[-] Failed to resolve rules directory path");
        return 1;
    }

    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "[-] Failed to initialize YARA\n");
        return 1;
    }

    YR_RULES* rules_list[MAX_RULES];
    int rules_count = 0;

    DIR* dir = opendir(rules_dir);
    if (!dir) {
        perror("[-] Failed to open compiled rules directory");
        yr_finalize();
        return 1;
    }

    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL && rules_count < MAX_RULES) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".yarac")) {

            char rule_file[BUFFER_SIZE];
            snprintf(rule_file, sizeof(rule_file),
                     "%s/%s", rules_dir, entry->d_name);

            if (yr_rules_load(rule_file, &rules_list[rules_count]) == ERROR_SUCCESS) {
                rules_count++;
            }
        }
    }

    closedir(dir);

    if (rules_count == 0) {
        fprintf(stderr, "[-] No valid rule files found\n");
        yr_finalize();
        return 1;
    }

    printf("[+] Loaded %d rule file(s). Scanning: %s\n",
           rules_count, target_path);

    // -------- INIT QUEUE --------
    queue.front = 0;
    queue.rear = 0;
    queue.count = 0;
    pthread_mutex_init(&queue.lock, NULL);
    pthread_cond_init(&queue.cond, NULL);

    g_rules_list = rules_list;
    g_rules_count = rules_count;

    // -------- START WORKER --------
    pthread_t worker;
    pthread_create(&worker, NULL, workerThread, NULL);

    // -------- SCAN ENTRY --------
    struct stat path_stat;

    if (stat(target_path, &path_stat) != 0) {
        perror("[-] Failed to stat target path");

    } else if (S_ISREG(path_stat.st_mode)) {
        pushQueue(target_path);

    } else if (S_ISDIR(path_stat.st_mode)) {
        scanDirectoryFlat(target_path, rules_list, rules_count, NULL);

    } else {
        printf("[-] Unknown target type.\n");
    }

    // -------- WAIT (IMPORTANT) --------
    pthread_join(worker, NULL);

    // -------- CLEANUP --------
    for (int i = 0; i < rules_count; i++)
        yr_rules_destroy(rules_list[i]);

    yr_finalize();

    return 0;
}
