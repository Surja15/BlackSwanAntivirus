// quarantine.c
// Standalone quarantine module for Black Swan AV
// Compile: gcc quarantine.c -o quarantine
// Usage:   ./quarantine quarantine <filepath>
//          ./quarantine restore <filename>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

// ─── Config ────────────────────────────────────────────────────────────────
#define QUARANTINE_DIR  "/home/surja/quarantine"
#define LOG_FILE        QUARANTINE_DIR "/quarantine_log.txt"
#define KEY             "Ganesh"
#define KEY_LEN         6
#define PARTS           2
// ───────────────────────────────────────────────────────────────────────────

// XOR encrypt/decrypt (same function, XOR is symmetric)
static void xor_crypt(unsigned char* data, size_t len) {
    const char* key = KEY;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= (unsigned char)key[i % KEY_LEN];
    }
}

// Ensure quarantine directory exists
static int ensure_quarantine_dir() {
    struct stat st;
    if (stat(QUARANTINE_DIR, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;
    if (mkdir(QUARANTINE_DIR, 0700) != 0) {
        fprintf(stderr, "[-] Failed to create quarantine dir: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

// ─── Quarantine ────────────────────────────────────────────────────────────
// Called by engine via CallQuarantine(filepath, matched_rules)
// Can also be called standalone from CLI
int quarantine_file(const char* file_path, const char* matched_rules) {
    if (ensure_quarantine_dir() != 0) return -1;

    // Read file
    FILE* f = fopen(file_path, "rb");
    if (!f) {
        fprintf(stderr, "[-] Cannot open file: %s\n", strerror(errno));
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    unsigned char* data = malloc(file_size);
    if (!data) { fclose(f); fprintf(stderr, "[-] malloc failed\n"); return -1; }
    fread(data, 1, file_size, f);
    fclose(f);

    // XOR encrypt in-place
    xor_crypt(data, file_size);

    // Timestamp for part names: HHMMSS-DDMMYY
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H%M%S-%d%m%y", t);

    // Split into PARTS and write each part
    long chunk = file_size / PARTS;
    char part_names[PARTS][256];

    for (int i = 0; i < PARTS; i++) {
        snprintf(part_names[i], sizeof(part_names[i]),
                 "%s/%s_%c", QUARANTINE_DIR, timestamp, 'a' + i);

        long offset = i * chunk;
        long size   = (i == PARTS - 1) ? (file_size - offset) : chunk;

        FILE* pf = fopen(part_names[i], "wb");
        if (!pf) {
            fprintf(stderr, "[-] Cannot write part %d: %s\n", i, strerror(errno));
            free(data);
            return -1;
        }
        fwrite(data + offset, 1, size, pf);
        fclose(pf);
    }
    free(data);

    // Extract just the filename (basename) from path
    const char* basename = strrchr(file_path, '/');
    basename = basename ? basename + 1 : file_path;

    // Log: filename|timestamp|part_a,part_b|rules_matched
    FILE* log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "%s|%s|", basename, timestamp);
        // write part basenames only (no full path in log)
        for (int i = 0; i < PARTS; i++) {
            const char* pbn = strrchr(part_names[i], '/');
            pbn = pbn ? pbn + 1 : part_names[i];
            fprintf(log, "%s%s", pbn, (i < PARTS - 1) ? "," : "");
        }
        fprintf(log, "|%s\n", matched_rules ? matched_rules : "N/A");
        fclose(log);
    }

    printf("[+] Quarantined: %s -> %s\n", file_path, QUARANTINE_DIR);

    // Remove original
    if (remove(file_path) != 0)
        fprintf(stderr, "[!] Warning: could not remove original: %s\n", strerror(errno));

    return 0;
}

// ─── Restore ───────────────────────────────────────────────────────────────
int restore_file(const char* filename) {
    // Password check
    char password[64];
    printf("Enter password to restore: ");
    fflush(stdout);
    if (!fgets(password, sizeof(password), stdin)) return -1;
    password[strcspn(password, "\n")] = 0;

    if (strcmp(password, KEY) != 0) {
        printf("[-] Incorrect password. Aborting.\n");
        return -1;
    }

    // Read log to find parts
    FILE* log = fopen(LOG_FILE, "r");
    if (!log) {
        printf("[-] No log found. Cannot restore.\n");
        return -1;
    }

    char line[1024];
    char found_parts[PARTS][256];
    int  found = 0;

    while (fgets(line, sizeof(line), log)) {
        line[strcspn(line, "\n")] = 0;

        // Parse: orig|timestamp|part_a,part_b|rules
        char orig[256], timestamp[64], parts_str[512], rules[512];
        if (sscanf(line, "%255[^|]|%63[^|]|%511[^|]|%511[^\n]",
                   orig, timestamp, parts_str, rules) < 3)
            continue;

        if (strcmp(orig, filename) == 0) {
            // Split parts_str by comma
            char* token = strtok(parts_str, ",");
            int idx = 0;
            while (token && idx < PARTS) {
                snprintf(found_parts[idx], sizeof(found_parts[idx]),
                         "%s/%s", QUARANTINE_DIR, token);
                idx++;
                token = strtok(NULL, ",");
            }
            found = idx;
            break;
        }
    }
    fclose(log);

    if (!found) {
        printf("[-] No record of '%s' in quarantine log.\n", filename);
        return -1;
    }

    // Read and combine all parts
    size_t total_size = 0;
    unsigned char* combined = NULL;

    for (int i = 0; i < found; i++) {
        FILE* pf = fopen(found_parts[i], "rb");
        if (!pf) {
            fprintf(stderr, "[-] Cannot open part: %s\n", found_parts[i]);
            free(combined);
            return -1;
        }
        fseek(pf, 0, SEEK_END);
        long part_size = ftell(pf);
        rewind(pf);

        combined = realloc(combined, total_size + part_size);
        if (!combined) { fclose(pf); fprintf(stderr, "[-] realloc failed\n"); return -1; }
        fread(combined + total_size, 1, part_size, pf);
        fclose(pf);
        total_size += part_size;
    }

    // XOR decrypt
    xor_crypt(combined, total_size);

    // Write restored file to current directory
    FILE* out = fopen(filename, "wb");
    if (!out) {
        fprintf(stderr, "[-] Cannot write restored file: %s\n", strerror(errno));
        free(combined);
        return -1;
    }
    fwrite(combined, 1, total_size, out);
    fclose(out);
    free(combined);

    printf("[+] File restored successfully: %s\n", filename);
    return 0;
}

// ─── CLI entry point ────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <quarantine|restore> <file>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "quarantine") == 0) {
        return quarantine_file(argv[2], NULL);
    } else if (strcmp(argv[1], "restore") == 0) {
        return restore_file(argv[2]);
    } else {
        printf("[-] Unknown action: %s\n", argv[1]);
        return 1;
    }
}
