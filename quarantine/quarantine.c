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
#define MASTER_KEY      "Surja"
#define KEY_LEN         5
#define PARTS           2
#define NONCE_DIGITS    7       // 7-digit nonce: 1000000 to 9999999
// ───────────────────────────────────────────────────────────────────────────


// ─── Keystream Generator ───────────────────────────────────────────────────
// PRNG-style keystream seeded from master key + nonce + counter.
// This is a simplified ChaCha20-style construction:
//   state = mix(master_key, nonce, counter)
//   keystream byte = state & 0xFF
//
// Each byte position gets a unique seed so:
//   - same key + different nonce = completely different keystream
//   - same key + same nonce + different counter = different keystream byte
// Never reuse the same nonce with the same key. Don't delete log file either or file gone forever. 

static unsigned int keystream_prng(const char* key, unsigned int nonce, unsigned long counter) {
    unsigned int state = nonce;

    // Mix in master key bytes
    for (int i = 0; i < KEY_LEN; i++)
        state ^= ((unsigned int)(unsigned char)key[i]) << ((i % 4) * 8);

    // Mix in counter (position in file)
    state ^= (unsigned int)(counter & 0xFFFFFFFF);
    state ^= (unsigned int)((counter >> 32) & 0xFFFFFFFF);

    // Avalanche: a few rounds of cheap bit mixing (xorshift style)
    state ^= (state << 13);
    state ^= (state >> 17);
    state ^= (state << 5);
    state *= 0x9e3779b9;   // golden ratio constant, improves distribution
    state ^= (state >> 16);

    return state & 0xFF;
}

// Generate a random 7-digit nonce (1000000 - 9999999)
static unsigned int generate_nonce() {
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
    return 1000000 + (rand() % 9000000);
}

// XOR file data against keystream derived from key+nonce
// Encryption and decryption are the same operation (XOR symmetric)
static void xor_keystream_crypt(unsigned char* data, size_t len,
                                 const char* key, unsigned int nonce) {
    for (size_t i = 0; i < len; i++)
        data[i] ^= (unsigned char)keystream_prng(key, nonce, (unsigned long)i);
}

// ─── Quarantine Dir ────────────────────────────────────────────────────────
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

static void lock_log_file() {
    (void)0;  // use: sudo chattr +a ~/quarantine/quarantine_log.txt
}

// ─── Timestamps ────────────────────────────────────────────────────────────
static void get_timestamp(char* buf, size_t len) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", t);
}

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

    // Generate nonce and encrypt with keystream
    unsigned int nonce = generate_nonce();
    xor_keystream_crypt(data, file_size, MASTER_KEY, nonce);

    // Timestamps
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

    // Log format:
    // [2026-03-17 14:30:22] filename|20260317_143022|part_a,part_b|rules|nonce
    FILE* log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "[%s] %s|%s|", ts_readable, basename, ts_filename);
        for (int i = 0; i < PARTS; i++) {
            const char* pbn = strrchr(part_names[i], '/');
            pbn = pbn ? pbn + 1 : part_names[i];
            fprintf(log, "%s%s", pbn, (i < PARTS - 1) ? "," : "");
        }
        fprintf(log, "|%s|%07u\n", matched_rules ? matched_rules : "N/A", nonce);
        fclose(log);
        lock_log_file();
    }

    printf("[+] Quarantined: %s -> %s (nonce: %07u)\n", file_path, QUARANTINE_DIR, nonce);

    if (remove(file_path) != 0)
        fprintf(stderr, "[!] Warning: could not remove original: %s\n", strerror(errno));

    return 0;
}

// ─── Restore ───────────────────────────────────────────────────────────────
int restore_file(const char* filename) {
    char password[64];
    printf("Enter master key to restore: ");
    fflush(stdout);
    if (!fgets(password, sizeof(password), stdin)) return -1;
    password[strcspn(password, "\n")] = 0;

    if (strcmp(password, MASTER_KEY) != 0) {
        printf("[-] Incorrect master key. Aborting.\n");
        return -1;
    }

    FILE* log = fopen(LOG_FILE, "r");
    if (!log) { printf("[-] No log found. Cannot restore.\n"); return -1; }

    char line[1024];
    char found_parts[PARTS][256];
    unsigned int found_nonce = 0;
    int found = 0;

    while (fgets(line, sizeof(line), log)) {
        line[strcspn(line, "\n")] = 0;

        // Strip "[2026-03-17 14:30:22] " prefix
        char* entry = line;
        if (line[0] == '[') {
            entry = strchr(line, ']');
            if (entry) entry += 2;
            else entry = line;
        }

        char orig[256], ts_filename[64], parts_str[512], rules[512];
        unsigned int nonce = 0;

        if (sscanf(entry, "%255[^|]|%63[^|]|%511[^|]|%511[^|]|%07u",
                   orig, ts_filename, parts_str, rules, &nonce) < 5)
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
            found_nonce = nonce;
            break;
        }
    }
    fclose(log);

    if (!found) { printf("[-] No record of '%s' in log.\n", filename); return -1; }
    if (found_nonce == 0) { printf("[-] Nonce missing from log entry.\n"); return -1; }

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

    // Decrypt using keystream with same key+nonce
    xor_keystream_crypt(combined, total_size, MASTER_KEY, found_nonce);

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
