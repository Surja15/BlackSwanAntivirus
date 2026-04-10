//Engine code// FINAL S15
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

typedef struct {
    char* matches[MAX_MATCHES];
    int count;
} MatchList;

void CallQuarantine(const char* filePath, MatchList* matchList);

static char g_rules_realpath[PATH_MAX] = {0};
static char g_target_realpath[PATH_MAX] = {0};  // NEW: target boundary guard

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

void scanDirectoryRecursively(const char* dirPath,
                              YR_RULES** rules_list,
                              int rules_count,
                              MatchList* matchList)
{
    DIR* dir = opendir(dirPath);
    if (!dir) return;

    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char fullPath[PATH_MAX];
        snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry->d_name);

        struct stat st;
        if (lstat(fullPath, &st) != 0)
            continue;

        if (S_ISLNK(st.st_mode))
            continue;

        if (S_ISDIR(st.st_mode)) {
            char resolvedPath[PATH_MAX];
            if (realpath(fullPath, resolvedPath) == NULL) continue;
if(strstr(resolvedPath, "/myrule") != NULL) continue; // so it doesnt eat up the RULES folder. DO NOT REMOVE THIS, or the whole project will be like titanic
            // Only descend if still inside the original target directory
            if (strncmp(resolvedPath, g_target_realpath, strlen(g_target_realpath)) != 0)
                continue;

            scanDirectoryRecursively(fullPath, rules_list, rules_count, matchList);
        }
        else if (S_ISREG(st.st_mode)) {
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

    // Resolve rules dir real path
    if (realpath(rules_dir, g_rules_realpath) == NULL) {
        perror("[-] Failed to resolve rules directory path");
        return 1;
    }

    // Resolve target real path — scanner will never leave this boundary
    if (realpath(target_path, g_target_realpath) == NULL) {
        perror("[-] Failed to resolve target path");
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

    MatchList matchList = {.count = 0};

    struct stat path_stat;
    if (stat(target_path, &path_stat) != 0) {
        perror("[-] Failed to stat target path");
    } else if (S_ISREG(path_stat.st_mode)) {
        scanFile(target_path, rules_list, rules_count, &matchList);
    } else if (S_ISDIR(path_stat.st_mode)) {
        scanDirectoryRecursively(target_path, rules_list, rules_count, &matchList);
    } else {
        printf("[-] Unknown target type.\n");
    }

    for (int i = 0; i < rules_count; i++)
        yr_rules_destroy(rules_list[i]);

    if (matchList.count > 0) {
        for (int i = 0; i < matchList.count; ++i)
            printf("Matched rule: %s\n", matchList.matches[i]);

        CallQuarantine(target_path, &matchList);

        for (int i = 0; i < matchList.count; ++i)
            free(matchList.matches[i]);
    } else {
        printf("[+] No threats found in: %s\n", target_path);
    }

    yr_finalize();
    return 0;
}
