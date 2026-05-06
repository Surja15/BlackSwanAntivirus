/*
 * ============================================================
 *  BLACK SWAN AV — ENGINE.C
 *  Core scanning engine. Compiled as a standalone binary.
 * ============================================================
 *
 *  WHAT THIS FILE DOES:
 *  --------------------
 *  This is the detection brain of Black Swan AV. It takes a
 *  file or directory path as input, loads compiled YARA rules,
 *  and checks every file against those rules. If a match is
 *  found, it hands the file off to quarantine.c via
 *  quarantine_file().
 *
 *  WHAT IS YARA?
 *  -------------
 *  YARA is an open-source pattern-matching tool used by
 *  security researchers and AV engines to identify and
 *  classify malware. You write "rules" that describe what a
 *  malicious file looks like — byte sequences, strings,
 *  conditions, etc.
 *
 *  A YARA rule looks like this:
 *
 *      rule DetectEicar {
 *          meta:
 *              description = "Detects EICAR test virus string"
 *          strings:
 *              $magic = "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
 *          condition:
 *              $magic
 *      }
 *
 *  Rules are compiled from .yar text files into .yarac binary
 *  files for faster loading. This engine loads the .yarac files
 *  from /myrule/compiled/ at startup.
 *
 *  HOW SCANNING WORKS (flow):
 *  --------------------------
 *  1. Load all .yarac files from the rules directory into an
 *     array of YR_RULES* pointers.
 *  2. Accept a target path (file or directory) as argv[1].
 *  3. For each file encountered, call scanFile() which runs
 *     yr_rules_scan_file() for every loaded rule set.
 *  4. yr_rules_scan_file() fires scanCallback() for each
 *     rule that matches.
 *  5. Matched rule names are collected in a MatchList struct.
 *  6. If any matches exist, CallQuarantine() is invoked, which
 *     builds a comma-separated string of rule names and calls
 *     quarantine_file() from quarantine.c.
 *
 *  DIRECTORY TRAVERSAL SAFETY:
 *  ----------------------------
 *  The engine uses realpath() to resolve the true absolute path
 *  of the scan target before starting. All subdirectory paths
 *  encountered during recursion are checked against this
 *  resolved path to prevent symlink-based directory traversal
 *  attacks (e.g., a malware sample linking back to /).
 *  Symlinks are skipped entirely via lstat() + S_ISLNK check.
 *  The /myrule folder is also explicitly excluded so the engine
 *  never scans and quarantines its own rule files.
 *
 *  CONNECTION TO OTHER FILES:
 *  --------------------------
 *  - quarantine.c  : provides quarantine_file(), called here
 *                    when a match is detected.
 *  - rtm.c         : spawns this engine binary as a child
 *                    process via execl() for real-time scanning.
 *  - restore.c     : independent; does not interact with engine.
 *
 *  COMPILE:
 *      gcc engine.c quarantine.c -o engine -lyara
 * ============================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>        /* opendir, readdir, closedir — directory traversal */
#include <yara.h>          /* YARA API: yr_initialize, yr_rules_scan_file, etc. */
#include <sys/stat.h>      /* stat(), lstat(), S_ISREG, S_ISDIR, S_ISLNK */
#include <limits.h>        /* PATH_MAX — maximum length of a filesystem path */

/* Forward declaration: defined in quarantine.c, linked at compile time */
int quarantine_file(const char* file_path, const char* matched_rules);

#define PATH_SEPARATOR '/'    /* Character used to separate path components on Linux */
#define BUFFER_SIZE 1024      /* General-purpose buffer size (used in CallQuarantine) */
#define MAX_MATCHES 100       /* Max number of YARA rule matches stored per file scan */
#define MAX_RULES 64          /* Max number of .yarac rule files that can be loaded */

/*
 * MatchList — holds the names of all YARA rules that matched a file.
 * 'matches' is an array of heap-allocated strings (rule identifiers).
 * 'count' tracks how many entries are currently filled.
 */
typedef struct {
    char* matches[MAX_MATCHES]; /* Array of pointers to matched rule name strings */
    int count;                  /* Number of matches collected so far */
} MatchList;

/* Forward declaration for CallQuarantine (defined later in this file) */
void CallQuarantine(const char* filePath, MatchList* matchList);

/*
 * g_rules_realpath — resolved absolute path of the YARA rules directory.
 * Used to ensure the engine never accidentally scans its own rules.
 * 'static' means it's file-scoped (not visible outside engine.c).
 * PATH_MAX is typically 4096 on Linux.
 */
static char g_rules_realpath[PATH_MAX] = {0};

/*
 * g_target_realpath — resolved absolute path of the scan target supplied
 * by the user. Acts as a boundary: recursive scanning will never leave
 * this directory tree, preventing symlink escape attacks.
 */
static char g_target_realpath[PATH_MAX] = {0};


/* ================================================================
 *  scanCallback
 *  Called by the YARA library for every rule evaluated during a scan.
 *  YARA calls this once per rule, with different 'message' values:
 *    CALLBACK_MSG_RULE_MATCHING  — rule matched the file
 *    CALLBACK_MSG_RULE_NOT_MATCHING — rule did not match
 *  We only act on matches.
 * ================================================================ */
int scanCallback(YR_SCAN_CONTEXT* context,   /* Internal YARA scan state (not used directly here) */
                 int message,                 /* Type of callback event (matching / not matching) */
                 void* message_data,          /* For RULE_MATCHING: points to the YR_RULE that matched */
                 void* user_data)             /* Our MatchList pointer, passed in via yr_rules_scan_file */
{
    /* Cast the generic void* back to our MatchList so we can write into it */
    MatchList* matchList = (MatchList*)user_data;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        /* Cast message_data to a YR_RULE pointer to access rule metadata */
        YR_RULE* rule = (YR_RULE*)message_data;

        if (matchList->count < MAX_MATCHES) {
            /*
             * strdup() allocates a new heap string and copies rule->identifier
             * into it. rule->identifier is the rule name from the .yar source,
             * e.g. "DetectEicar". We own this memory and must free() it later.
             */
            matchList->matches[matchList->count] = strdup(rule->identifier);
            matchList->count++;
        }
    }

    /*
     * CALLBACK_CONTINUE tells YARA to keep evaluating remaining rules.
     * Returning CALLBACK_ABORT would stop the scan early.
     */
    return CALLBACK_CONTINUE;
}


/* ================================================================
 *  scanFile
 *  Runs a single file through ALL loaded YARA rule sets.
 *  Each .yarac file is a separate YR_RULES object, so we loop
 *  through the array and scan against each one.
 * ================================================================ */
void scanFile(const char* filePath,        /* Absolute path of the file to scan */
              YR_RULES** rules_list,        /* Array of pointers to loaded rule sets */
              int rules_count,             /* Number of entries in rules_list */
              MatchList* matchList)        /* Output: populated with matched rule names */
{
    for (int i = 0; i < rules_count; i++) {
        /*
         * yr_rules_scan_file() is the core YARA API call.
         * Args:
         *   rules_list[i]                  — the rule set to apply
         *   filePath                       — file to scan
         *   SCAN_FLAGS_REPORT_RULES_MATCHING — only fire callback for matches
         *   scanCallback                   — our callback function
         *   matchList                      — passed as user_data into callback
         *   0                              — timeout in seconds (0 = no timeout)
         */
        yr_rules_scan_file(rules_list[i], filePath,
                           SCAN_FLAGS_REPORT_RULES_MATCHING,
                           scanCallback, matchList, 0);
    }
}


/* ================================================================
 *  scanDirectoryRecursively
 *  Walks a directory tree depth-first, scanning every regular file.
 *  Safety measures:
 *    1. Skips "." and ".." to avoid infinite loops
 *    2. Skips symlinks (lstat + S_ISLNK) to prevent traversal attacks
 *    3. Resolves realpath of subdirs and checks they're still inside
 *       g_target_realpath (boundary guard)
 *    4. Skips any path containing "/myrule" (protects rule files)
 * ================================================================ */
void scanDirectoryRecursively(const char* dirPath,
                              YR_RULES** rules_list,
                              int rules_count,
                              MatchList* matchList)
{ // Jai Shree Ram
    DIR* dir = opendir(dirPath);  /* Open directory stream for iteration */
    if (!dir) return;             /* Silently skip if we can't open (permissions, etc.) */

    struct dirent* entry;         /* Pointer to each directory entry as we iterate */

    while ((entry = readdir(dir)) != NULL) {

        /* Skip the "." (current dir) entry — would cause infinite recursion */
        if (strcmp(entry->d_name, ".") == 0 ||
            /* Skip ".." (parent dir) — could escape the target boundary */
            strcmp(entry->d_name, "..") == 0)
            continue;

        /* Build the full path by joining dirPath + "/" + entry->d_name */
        char fullPath[PATH_MAX];
        snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry->d_name);

        /*
         * lstat() fills 'st' with file metadata WITHOUT following symlinks.
         * This is critical — stat() would follow a symlink and we'd lose
         * the ability to detect it's a symlink in the first place.
         */
        struct stat st;
        if (lstat(fullPath, &st) != 0)
            continue;   /* Can't stat? Skip silently (deleted during scan, no perms, etc.) */

        /*
         * S_ISLNK checks the file type bits in st.st_mode.
         * Symlinks are skipped entirely — a malicious file could link to /etc
         * or back to the rules folder; skipping is the safest approach.
         */
        if (S_ISLNK(st.st_mode))
            continue;

        if (S_ISDIR(st.st_mode)) {
            /*
             * Resolve the true canonical path of this subdirectory.
             * realpath() expands all "..", ".", and symlinks to get the
             * real absolute path on disk.
             */
            char resolvedPath[PATH_MAX];
            if (realpath(fullPath, resolvedPath) == NULL) continue;

            /*
             * SAFETY: Skip the rules directory if somehow encountered.
             * strstr() checks if "/myrule" appears anywhere in resolvedPath.
             * Without this, the engine could quarantine its own rule files
             * and permanently break itself — "titanic mode".
             */
            if (strstr(resolvedPath, "/myrule") != NULL) continue;

            /*
             * BOUNDARY GUARD: strncmp compares the first N characters of
             * resolvedPath against g_target_realpath (the original scan root).
             * If the resolved subdir path doesn't START with the target root,
             * it means we've somehow escaped the target tree — skip it.
             * This is the main defence against symlink escape attacks.
             */
            if (strncmp(resolvedPath, g_target_realpath, strlen(g_target_realpath)) != 0)
                continue;

            /* Safe to recurse into this subdirectory */
            scanDirectoryRecursively(fullPath, rules_list, rules_count, matchList);
        }
        else if (S_ISREG(st.st_mode)) {  /* S_ISREG: is this a regular file (not device, socket, etc.)? */
            /*
             * Use a local MatchList for this individual file.
             * This way each file's matches are isolated; we don't
             * mix matches from different files together.
             */
            MatchList localMatch = {.count = 0};  /* Designated initialiser: count starts at 0 */
            scanFile(fullPath, rules_list, rules_count, &localMatch);

            if (localMatch.count > 0) {
                printf(" Infected: %s\n", fullPath);
                CallQuarantine(fullPath, &localMatch);

                /* Free every strdup'd rule name string to avoid memory leaks */
                for (int i = 0; i < localMatch.count; i++)
                    free(localMatch.matches[i]);
            }
        }
    }

    closedir(dir);   /* Release the directory stream handle */
}


/* ================================================================
 *  CallQuarantine
 *  Bridges the engine and quarantine.c.
 *  Builds a single comma-separated string from all matched rule
 *  names (e.g. "DetectEicar,SuspiciousPE,MimikatzSig") and passes
 *  it to quarantine_file() alongside the file path.
 * ================================================================ */
void CallQuarantine(const char* filePath, MatchList* matchList) {
    char rules_str[1024] = "";   /* Output buffer for comma-joined rule names */

    for (int i = 0; i < matchList->count; i++) {
        /*
         * strncat safely appends a string up to N bytes.
         * We compute remaining space as: sizeof(buf) - current_len - 2
         * The -2 reserves room for a possible "," and null terminator.
         */
        strncat(rules_str, matchList->matches[i],
                sizeof(rules_str) - strlen(rules_str) - 2);

        /* Append comma separator between entries (not after the last one) */
        if (i < matchList->count - 1)
            strncat(rules_str, ",", sizeof(rules_str) - strlen(rules_str) - 1);
    }

    printf("[!] Sending to quarantine: %s | Rules: %s\n", filePath, rules_str);

    /*
     * quarantine_file() is defined in quarantine.c.
     * It encrypts the file, splits it into parts, moves it to
     * ~/quarantine/, and logs the event.
     */
    quarantine_file(filePath, rules_str);
}


/* ================================================================
 *  main
 *  Entry point. Loads rules, resolves paths, dispatches scanning.
 * ================================================================ */
int main(int argc, char* argv[]) {

    /* argc is the argument count. argv[0] is the binary name, argv[1] is the target. */
    if (argc != 2) {
        printf("Usage: %s <file-or-directory-to-scan>\n", argv[0]);
        return 1;  /* Non-zero exit = error */
    }

    /* Hardcoded path to the directory containing compiled .yarac rule files */
    const char* rules_dir = "/home/surja/Downloads/Black-Swan-main/myrule/compiled/";
    const char* target_path = argv[1];   /* The file or directory the user wants scanned */

    /*
     * realpath() resolves a path to its canonical absolute form,
     * expanding symlinks and ".." components.
     * We store the rules dir real path so we can detect if the scanner
     * accidentally wanders into it during directory traversal.
     */
    if (realpath(rules_dir, g_rules_realpath) == NULL) {
        perror("[-] Failed to resolve rules directory path");
        return 1;
    }

    /*
     * Resolve and store the scan target's real path.
     * This becomes the boundary: no scanning will leave this tree.
     * g_target_realpath is a global used by scanDirectoryRecursively().
     */
    if (realpath(target_path, g_target_realpath) == NULL) {
        perror("[-] Failed to resolve target path");
        return 1;
    }

    /*
     * yr_initialize() sets up YARA's internal state and memory.
     * Must be called before any other YARA function.
     * Returns ERROR_SUCCESS (0) on success.
     */
    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "[-] Failed to initialize YARA\n");
        return 1;
    }

    YR_RULES* rules_list[MAX_RULES];  /* Array of pointers, one per loaded .yarac file */
    int rules_count = 0;              /* How many rule sets have been successfully loaded */

    /* Open the compiled rules directory to iterate over .yarac files */
    DIR* dir = opendir(rules_dir);
    if (!dir) {
        perror("[-] Failed to open compiled rules directory");
        yr_finalize();   /* Clean up YARA before exiting */
        return 1;
    }

    struct dirent* entry;

    /*
     * Iterate over every entry in the rules directory.
     * entry->d_type == DT_REG means it's a regular file (not a directory).
     * strstr checks for ".yarac" in the filename to filter out non-rule files.
     */
    while ((entry = readdir(dir)) != NULL && rules_count < MAX_RULES) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".yarac") != NULL) {

            /* Build full path to this rule file */
            char rule_file[BUFFER_SIZE];
            snprintf(rule_file, sizeof(rule_file), "%s/%s", rules_dir, entry->d_name);

            /*
             * yr_rules_load() reads a compiled .yarac file from disk and
             * returns a YR_RULES* object ready for scanning.
             * On success, we store it in rules_list and increment the counter.
             */
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

    /*
     * matchList is used when the TARGET ITSELF is a single file.
     * For directory scans, each file uses its own local MatchList inside
     * scanDirectoryRecursively(). This outer one handles the single-file case.
     */
    MatchList matchList = {.count = 0};

    /*
     * stat() (not lstat) is fine here because argv[1] is user-supplied
     * and we want to follow symlinks at the top level if the user
     * explicitly pointed at one.
     * path_stat.st_mode contains the file type and permission bits.
     */
    struct stat path_stat;
    if (stat(target_path, &path_stat) != 0) {
        perror("[-] Failed to stat target path");
    } else if (S_ISREG(path_stat.st_mode)) {
        /* Target is a single file — scan it directly */
        scanFile(target_path, rules_list, rules_count, &matchList);
    } else if (S_ISDIR(path_stat.st_mode)) {
        /* Target is a directory — recursively scan everything inside */
        scanDirectoryRecursively(target_path, rules_list, rules_count, &matchList);
    } else {
        printf("[-] Unknown target type.\n");
    }

    /* Clean up all loaded YARA rule sets to free their memory */
    for (int i = 0; i < rules_count; i++)
        yr_rules_destroy(rules_list[i]);

    /*
     * If the target was a single file and had matches, matchList will be
     * populated here. (Directory scan matches are handled inside
     * scanDirectoryRecursively and never make it back to this matchList.)
     */
    if (matchList.count > 0) {
        for (int i = 0; i < matchList.count; ++i)
            printf("Matched rule: %s\n", matchList.matches[i]);

        CallQuarantine(target_path, &matchList);

        for (int i = 0; i < matchList.count; ++i)
            free(matchList.matches[i]);
    } else {
        printf("[+] No threats found in: %s\n", target_path);
    }

    /*
     * yr_finalize() releases all global YARA resources.
     * Counterpart to yr_initialize(). Always call this before exit.
     */
    yr_finalize();
    return 0;
}
