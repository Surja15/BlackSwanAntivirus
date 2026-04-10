#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <yara.h>
#include <sys/stat.h>
#include <limits.h>

int quarantine_file(const char* file_path, const char* matched_rules);

#define BUFFER_SIZE  1024
#define MAX_MATCHES  100
#define MAX_RULES     64
#define MAX_SUBDIRS  512   /* max subdirectories we'll descend into */

typedef struct {
    char* matches[MAX_MATCHES];
    int   count;
} MatchList;

void CallQuarantine(const char* filePath, MatchList* matchList);

/* ── YARA callback ───────────────────────────────────────────────────────── */
int scanCallback(YR_SCAN_CONTEXT* context, int message,
                 void* message_data, void* user_data)
{
    MatchList* ml = (MatchList*)user_data;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        if (ml->count < MAX_MATCHES)
            ml->matches[ml->count++] = strdup(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

/* ── scan one file against all loaded rules ──────────────────────────────── */
void scanFile(const char* filePath,
              YR_RULES** rules_list, int rules_count,
              MatchList* matchList)
{
    for (int i = 0; i < rules_count; i++)
        yr_rules_scan_file(rules_list[i], filePath,
                           SCAN_FLAGS_REPORT_RULES_MATCHING,
                           scanCallback, matchList, 0);
}

/* ── scan every regular file directly inside one directory ──────────────── */
/*    fills subdir_paths[] with any subdirectories found, returns count      */
int scanOneDirectory(const char* dirPath,
                     YR_RULES** rules_list, int rules_count,
                     char subdir_paths[][PATH_MAX], int max_subdirs)
{
    DIR* dir = opendir(dirPath);
    if (!dir) {
        fprintf(stderr, "[-] Cannot open directory: %s\n", dirPath);
        return 0;
    }

    int subdir_count = 0;
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char fullPath[PATH_MAX];
        snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry->d_name);

        struct stat st;
        if (lstat(fullPath, &st) != 0) continue;  /* skip unreadable */
        if (S_ISLNK(st.st_mode))       continue;  /* skip symlinks   */

        if (S_ISREG(st.st_mode)) {
            /* ── it's a file: scan it now ── */
            MatchList localMatch = {.count = 0};
            scanFile(fullPath, rules_list, rules_count, &localMatch);

            if (localMatch.count > 0) {
                printf("❌ Infected: %s\n", fullPath);
                CallQuarantine(fullPath, &localMatch);
                for (int i = 0; i < localMatch.count; i++)
                    free(localMatch.matches[i]);
            }

        } else if (S_ISDIR(st.st_mode)) {
            /* ── it's a directory: remember it for later ── */
            if (subdir_count < max_subdirs) {
                strncpy(subdir_paths[subdir_count], fullPath, PATH_MAX - 1);
                subdir_paths[subdir_count][PATH_MAX - 1] = '\0';
                subdir_count++;
            } else {
                fprintf(stderr, "[-] Subdir limit reached, skipping: %s\n", fullPath);
            }
        }
    }

    closedir(dir);
    return subdir_count;
}

/* ── quarantine helper ───────────────────────────────────────────────────── */
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
    printf("[!] Sending to quarantine: %s | Rules: %s\n", filePath, rules_str);
    quarantine_file(filePath, rules_str);
}

/* ── main ────────────────────────────────────────────────────────────────── */
int main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("Usage: %s <file-or-directory-to-scan>\n", argv[0]);
        return 1;
    }

    const char* rules_dir   = "/home/surja/Downloads/Black-Swan-main/myrule/compiled/";
    const char* target_path = argv[1];

    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "[-] Failed to initialize YARA\n");
        return 1;
    }

    /* ── load all .yarac rule files ── */
    YR_RULES* rules_list[MAX_RULES];
    int rules_count = 0;

    DIR* rdir = opendir(rules_dir);
    if (!rdir) {
        perror("[-] Failed to open compiled rules directory");
        yr_finalize();
        return 1;
    }

    struct dirent* entry;
    while ((entry = readdir(rdir)) != NULL && rules_count < MAX_RULES) {
        if (entry->d_type == DT_REG &&
            strstr(entry->d_name, ".yarac") != NULL)
        {
            char rule_file[BUFFER_SIZE];
            snprintf(rule_file, sizeof(rule_file),
                     "%s/%s", rules_dir, entry->d_name);

            if (yr_rules_load(rule_file, &rules_list[rules_count]) == ERROR_SUCCESS)
                rules_count++;
            else
                fprintf(stderr, "[-] Failed to load: %s\n", rule_file);
        }
    }
    closedir(rdir);

    if (rules_count == 0) {
        fprintf(stderr, "[-] No valid rule files found in: %s\n", rules_dir);
        yr_finalize();
        return 1;
    }

    printf("[+] Loaded %d rule file(s). Scanning: %s\n", rules_count, target_path);

    /* ── dispatch ── */
    struct stat path_stat;
    if (stat(target_path, &path_stat) != 0) {
        perror("[-] Failed to stat target path");

    } else if (S_ISREG(path_stat.st_mode)) {
        /* ── single file ── */
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
        /*
         * Two-level flat scan:
         *   Pass 1 — scan files in the target directory,
         *            collect any subdirectories found.
         *   Pass 2 — for each subdirectory, scan its files.
         *            No further descent. RTM handles deeper ongoing coverage.
         */

        /* heap-alloc the subdir table — PATH_MAX*512 is too big for the stack */
        char (*subdirs)[PATH_MAX] = malloc(MAX_SUBDIRS * sizeof(*subdirs));
        if (!subdirs) {
            fprintf(stderr, "[-] Out of memory\n");
            goto cleanup;
        }

        printf("[+] Pass 1: scanning files in %s\n", target_path);
        int subdir_count = scanOneDirectory(target_path,
                                            rules_list, rules_count,
                                            subdirs, MAX_SUBDIRS);

        printf("[+] Found %d subdirectory/ies. Pass 2: scanning each.\n",
               subdir_count);

        for (int i = 0; i < subdir_count; i++) {
            printf("[+] Scanning subdir: %s\n", subdirs[i]);
            /* pass NULL / 0 for subdir collection — we don't go deeper */
            scanOneDirectory(subdirs[i],
                             rules_list, rules_count,
                             NULL, 0);
        }

        free(subdirs);
        printf("[+] Scan complete: %s\n", target_path);

    } else {
        printf("[-] Unknown target type.\n");
    }

cleanup:
    for (int i = 0; i < rules_count; i++)
        yr_rules_destroy(rules_list[i]);

    yr_finalize();
    return 0;
}
