// quarantine.c
// Standalone quarantine module for Black Swan AV by S15
// Compile with engine: gcc engine.c quarantine.c -o engine -lyara
// After first run, lock log: sudo chattr +a ~/quarantine/quarantine_log.txt

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

// XOR encrypt/decrypt (symmetric)
static void xor_crypt(unsigned char* data, size_t len) {
    const char* key = KEY;
    for (size_t i = 0; i < len; i++)
        data[i] ^= (unsigned char)key[i % KEY_LEN];
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

// ─── Log Protection ────────────────────────────────────────────────────────
// Sets log to read-only after every write.
// For full append-only immutability, run ONCE as root after first use:
//   sudo chattr +a /home/surja/quarantine/quarantine_log.txt
static void lock_log_file() {
    chmod(LOG_FILE, 0444);  // read-only for all users
}

// ─── Timestamps ────────────────────────────────────────────────────────────
// Human-readable for log:       2026-03-17 14:30:22
static void get_timestamp(char* buf, size_t len) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", t);
}

// Compact for filenames:        20260317_143022
static void get_file_timestamp(char* buf, size_t len) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    strftime(buf, len, "%Y%m%d_%H%M%S", t);
}

// ─── Quarantine ────────────────────────────────────────────────────────────
int quarantine_file(const char* file_path, const char* matched_rules) {
    if (ensure_quarantine_dir() != 0) return -1;

    // Read file
    FILE* f = fopen(file_path, "rb");
    if (!f) { fprintf(stderr, "[-] Cannot open file: %s\n", strerror(errno)); return -1; }
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    unsigned char* data = malloc(file_size);
    if (!data) { fclose(f); fprintf(stderr, "[-] malloc failed\n"); return -1; }
    fread(data, 1, file_size, f);
    fclose(f);

    // XOR encrypt in-place
    xor_crypt(data, file_size);

    // Two timestamp formats
    char ts_readable[32];
    char ts_filename[32];
    get_timestamp(ts_readable, sizeof(ts_readable));
    get_file_timestamp(ts_filename, sizeof(ts_filename));

    // Split into PARTS and write
    long chunk = file_size / PARTS;
    char part_names[PARTS][256];

    for (int i = 0; i < PARTS; i++) {
        snprintf(part_names[i], sizeof(part_names[i]),
                 "%s/%s_%c", QUARANTINE_DIR, ts_filename, 'a' + i);

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

    // Basename
    const char* basename = strrchr(file_path, '/');
    basename = basename ? basename + 1 : file_path;

    // Log: [2026-03-17 14:30:22] filename|20260317_143022|part_a,part_b|rules
    FILE* log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "[%s] %s|%s|", ts_readable, basename, ts_filename);
        for (int i = 0; i < PARTS; i++) {
            const char* pbn = strrchr(part_names[i], '/');
            pbn = pbn ? pbn + 1 : part_names[i];
            fprintf(log, "%s%s", pbn, (i < PARTS - 1) ? "," : "");
        }
        fprintf(log, "|%s\n", matched_rules ? matched_rules : "N/A");
        fclose(log);
        lock_log_file();  // protect after every write
    }

    printf("[+] Quarantined: %s -> %s\n", file_path, QUARANTINE_DIR);

    if (remove(file_path) != 0)
        fprintf(stderr, "[!] Warning: could not remove original: %s\n", strerror(errno));

    return 0;
}

// ─── Restore ───────────────────────────────────────────────────────────────
int restore_file(const char* filename) {
    char password[64];
    printf("Enter password to restore: ");
    fflush(stdout);
    if (!fgets(password, sizeof(password), stdin)) return -1;
    password[strcspn(password, "\n")] = 0;

    if (strcmp(password, KEY) != 0) {
        printf("[-] Incorrect password. Aborting.\n");
        return -1;
    }

    FILE* log = fopen(LOG_FILE, "r");
    if (!log) { printf("[-] No log found. Cannot restore.\n"); return -1; }

    char line[1024];
    char found_parts[PARTS][256];
    int  found = 0;

    while (fgets(line, sizeof(line), log)) {
        line[strcspn(line, "\n")] = 0;

        // Strip "[2026-03-17 14:30:22] " prefix
        char* entry = line;
        if (line[0] == '[') {
            entry = strchr(line, ']');
            if (entry) entry += 2;  // skip "] "
            else entry = line;
        }

        char orig[256], ts_filename[64], parts_str[512], rules[512];
        if (sscanf(entry, "%255[^|]|%63[^|]|%511[^|]|%511[^\n]",
                   orig, ts_filename, parts_str, rules) < 3)
            continue;

        if (strcmp(orig, filename) == 0) {
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

    if (!found) { printf("[-] No record of '%s' in log.\n", filename); return -1; }

    // Combine parts
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
    if (strcmp(argv[1], "quarantine") == 0)
        return quarantine_file(argv[2], NULL);
    else if (strcmp(argv[1], "restore") == 0)
        return restore_file(argv[2]);
    else {
        printf("[-] Unknown action: %s\n", argv[1]);
        return 1;
    }
}

/*and if for some reason you want to delete log file, need to do it manually
sudo chattr -a ~/quarantine/quarantine_log.txt
sudo rm ~/quarantine/quarantine_log.txt*/
