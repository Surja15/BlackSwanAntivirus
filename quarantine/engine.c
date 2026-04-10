#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <yara.h>
#include <sys/stat.h>
#include <limits.h>

int quarantine_file(const char* file_path, const char* matched_rules);

#define PATH_SEPARATOR '/'
#define BUFFER_SIZE 1024
#define MAX_MATCHES 100
#define MAX_RULES 64
#define MAX_STACK_DEPTH 10000

typedef struct {
    char* matches[MAX_MATCHES];
    int count;
} MatchList;

typedef struct {
    char path[PATH_MAX];
} PathNode;

void CallQuarantine(const char* filePath, MatchList* matchList);

static char g_rules_realpath[PATH_MAX] = {0};

int scanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
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

void scanFile(const char* filePath, YR_RULES** rules_list, int rules_count, MatchList* matchList) {
    for (int i = 0; i < rules_count; i++) {
        yr_rules_scan_file(rules_list[i], filePath, SCAN_FLAGS_REPORT_RULES_MATCHING, scanCallback, matchList, 0);
    }
}

void scanDirectoryRecursively(const char* rootPath,
                              YR_RULES** rules_list,
                              int rules_count)
{
    // Heap-allocated stack — avoids ~40MB stack overflow from PathNode stack[10000] on call stack
    PathNode* stack = malloc(MAX_STACK_DEPTH * sizeof(PathNode));
    if (!stack) {
        fprintf(stderr, "[-] Out of memory allocating directory scan stack\n");
        return;
    }

    int top = 0;
    strncpy(stack[top].path, rootPath, PATH_MAX - 1);
    stack[top].path[PATH_MAX - 1] = '\0';
    top++;

    while (top > 0) {
        PathNode current = stack[--top];

        DIR* dir = opendir(current.path);
        if (!dir) continue;

        struct dirent* entry;
        char fullPath[PATH_MAX];

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            snprintf(fullPath, sizeof(fullPath), "%s/%s",
                     current.path, entry->d_name);

            struct stat st;

            // lstat prevents following symlinks
            if (lstat(fullPath, &st) != 0)
                continue;

            // Block symlinks completely
            if (S_ISLNK(st.st_mode))
                continue;

            if (S_ISDIR(st.st_mode)) {
                if (top < MAX_STACK_DEPTH - 1) {
                    strncpy(stack[top].path, fullPath, PATH_MAX - 1);
                    stack[top].path[PATH_MAX - 1] = '\0';
                    top++;
                } else {
                    fprintf(stderr, "[-] Directory stack full, skipping: %s\n", fullPath);
                }
            } else if (S_ISREG(st.st_mode)) {
                MatchList localMatch = {.count = 0};

                scanFile(fullPath, rules_list, rules_count, &localMatch);

                if (localMatch.count > 0) {
                    printf("❌ Infected: %s\n", fullPath);
                    CallQuarantine(fullPath, &localMatch);

                    for (int i = 0; i < localMatch.count; i++)
                        free(localMatch.matches[i]);
                }
            }
        }

        closedir(dir);
    }

    free(stack);
}

void CallQuarantine(const char* filePath, MatchList* matchList) {
    char rules_str[1024] = "";
    for (int i = 0; i < matchList->count; i++) {
        strncat(rules_str, matchList->matches[i], sizeof(rules_str) - strlen(rules_str) - 2);
        if (i < matchList->count - 1)
            strncat(rules_str, ",", sizeof(rules_str) - strlen(rules_str) - 1);
    }
    printf("[!] Sending to quarantine: %s | Rules: %s\n", filePath, rules_str);
    quarantine_file(filePath, rules_str);
}

int main(int argc, char* argv[]) {
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
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".yarac") != NULL) {
            char rule_file[BUFFER_SIZE];
            snprintf(rule_file, sizeof(rule_file), "%s/%s", rules_dir, entry->d_name);

            if (yr_rules_load(rule_file, &rules_list[rules_count]) == ERROR_SUCCESS) {
                rules_count++;
            } else {
                fprintf(stderr, "[-] Failed to load compiled rules: %s\n", rule_file);
            }
        }
    }
    closedir(dir);

    if (rules_count == 0) {
        fprintf(stderr, "[-] No valid rule files found in: %s\n", rules_dir);
        yr_finalize();
        return 1;
    }

    printf("[+] Loaded %d rule file(s). Scanning: %s\n", rules_count, target_path);

    struct stat path_stat;
    if (stat(target_path, &path_stat) != 0) {
        perror("[-] Failed to stat target path");
    } else if (S_ISREG(path_stat.st_mode)) {
        // Single file scan
        MatchList matchList = {.count = 0};
        scanFile(target_path, rules_list, rules_count, &matchList);

        if (matchList.count > 0) {
            printf("❌ Infected: %s\n", target_path);
            CallQuarantine(target_path, &matchList);
            for (int i = 0; i < matchList.count; i++)
                free(matchList.matches[i]);
        } else {
            printf("[+] No threats found in: %s\n", target_path);
        }
    } else if (S_ISDIR(path_stat.st_mode)) {
        // Directory scan — each infected file is quarantined individually inside the function
        scanDirectoryRecursively(target_path, rules_list, rules_count);
        printf("[+] Directory scan complete: %s\n", target_path);
    } else {
        printf("[-] Unknown target type.\n");
    }

    // Cleanup all loaded rules
    for (int i = 0; i < rules_count; i++)
        yr_rules_destroy(rules_list[i]);

    yr_finalize();
    return 0;
}
