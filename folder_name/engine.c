//Engine code//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <yara.h>
#include <sys/stat.h>

int quarantine_file(const char* file_path, const char* matched_rules);

#define BUFFER_SIZE 1024
#define RULES_STR_MAX 1024

typedef struct {
    char rules_str[RULES_STR_MAX];
    int  matched;
} ScanResult;

int scanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    ScanResult* result = (ScanResult*)user_data;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        if (result->matched)
            strncat(result->rules_str, ",", RULES_STR_MAX - strlen(result->rules_str) - 1);
        strncat(result->rules_str, rule->identifier, RULES_STR_MAX - strlen(result->rules_str) - 1);
        result->matched = 1;
    }

    return CALLBACK_CONTINUE;
}

void scanAndQuarantineFile(const char* filePath, YR_RULES** rule_set, int rule_count) {
    ScanResult result = {.rules_str = "", .matched = 0};

    for (int i = 0; i < rule_count; i++)
        yr_rules_scan_file(rule_set[i], filePath, SCAN_FLAGS_REPORT_RULES_MATCHING,
                           scanCallback, &result, 0);

    if (result.matched) {
        printf("[!] Threat found: %s | Rules: %s\n", filePath, result.rules_str);
        quarantine_file(filePath, result.rules_str);
    } else {
        printf("[+] Clean: %s\n", filePath);
    }
}

void scanDirectoryRecursively(const char* dirPath, YR_RULES** rule_set, int rule_count) {
    // Skip quarantine directory entirely
    if (strstr(dirPath, "/quarantine") != NULL) return;

    DIR* dir = opendir(dirPath);
    if (!dir) {
        perror("[-] Failed to open directory");
        return;
    }

    struct dirent* entry;
    char path[BUFFER_SIZE];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", dirPath, entry->d_name);

        struct stat st;
        lstat(path, &st);  // lstat: does NOT follow symlinks — prevents infinite loop

        if (S_ISDIR(st.st_mode))
            scanDirectoryRecursively(path, rule_set, rule_count);
        else if (S_ISREG(st.st_mode))
            scanAndQuarantineFile(path, rule_set, rule_count);
        // symlinks (S_ISLNK) are simply skipped — not followed
    }

    closedir(dir);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file-or-directory-to-scan>\n", argv[0]);
        return 1;
    }

    const char* rules_dir  = "/home/surja/Downloads/Black-Swan-main/myrule/compiled/";
    const char* target_path = argv[1];

    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "[-] Failed to initialize YARA\n");
        return 1;
    }

    DIR* dir = opendir(rules_dir);
    if (!dir) {
        perror("[-] Failed to open compiled rules directory");
        yr_finalize();
        return 1;
    }

    YR_RULES* rule_set[128];
    int rule_count = 0;
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL && rule_count < 128) {
        if (entry->d_type != DT_REG) continue;
        if (!strstr(entry->d_name, ".yarac")) continue;

        char rule_file[BUFFER_SIZE];
        snprintf(rule_file, sizeof(rule_file), "%s/%s", rules_dir, entry->d_name);

        YR_RULES* rules = NULL;
        if (yr_rules_load(rule_file, &rules) == ERROR_SUCCESS)
            rule_set[rule_count++] = rules;
        else
            fprintf(stderr, "[-] Failed to load: %s\n", rule_file);
    }
    closedir(dir);

    printf("[+] Loaded %d rule file(s). Scanning: %s\n", rule_count, target_path);

    struct stat path_stat;
    lstat(target_path, &path_stat);  // lstat here too

    if (S_ISREG(path_stat.st_mode))
        scanAndQuarantineFile(target_path, rule_set, rule_count);
    else if (S_ISDIR(path_stat.st_mode))
        scanDirectoryRecursively(target_path, rule_set, rule_count);
    else
        printf("[-] Unknown target type.\n");

    for (int i = 0; i < rule_count; i++)
        yr_rules_destroy(rule_set[i]);

    yr_finalize();
    return 0;
}
