// restore.c
// Standalone restore tool for Black Swan AV quarantine
// Compile: gcc restore.c -o restore
// Usage:   ./restore <original_filename> <7-digit-nonce>
// Example: ./restore malware.exe 1234567

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUARANTINE_DIR  "/home/surja/quarantine"
#define LOG_FILE        QUARANTINE_DIR "/quarantine_log.txt"
#define MASTER_KEY      "Surja"
#define KEY_LEN         5
#define PARTS           2

// Must match quarantine.c exactly
static unsigned int keystream_prng(const char* key, unsigned int nonce, unsigned long counter) {
    unsigned int state = nonce;
    for (int i = 0; i < KEY_LEN; i++)
        state ^= ((unsigned int)(unsigned char)key[i]) << ((i % 4) * 8);
    state ^= (unsigned int)(counter & 0xFFFFFFFF);
    state ^= (unsigned int)((counter >> 32) & 0xFFFFFFFF);
    state ^= (state << 13);
    state ^= (state >> 17);
    state ^= (state << 5);
    state *= 0x9e3779b9;
    state ^= (state >> 16);
    return state & 0xFF;
}

static void xor_keystream_crypt(unsigned char* data, size_t len,
                                 const char* key, unsigned int nonce) {
    for (size_t i = 0; i < len; i++)
        data[i] ^= (unsigned char)keystream_prng(key, nonce, (unsigned long)i);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <original_filename> <7-digit-nonce>\n", argv[0]);
        printf("Example: %s malware.exe 1234567\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    unsigned int nonce = (unsigned int)atoi(argv[2]);

    if (nonce < 1000000 || nonce > 9999999) {
        printf("[-] Nonce must be a 7-digit number (1000000-9999999)\n");
        return 1;
    }

    // Prompt for master key
    char password[64];
    printf("Enter master key: ");
    fflush(stdout);
    if (!fgets(password, sizeof(password), stdin)) return 1;
    password[strcspn(password, "\n")] = 0;

    if (strcmp(password, MASTER_KEY) != 0) {
        printf("[-] Incorrect master key. Aborting.\n");
        return 1;
    }

    // Find log entry matching filename
    FILE* log = fopen(LOG_FILE, "r");
    if (!log) {
        printf("[-] Cannot open log file: %s\n", LOG_FILE);
        return 1;
    }

    char line[1024];
    char found_parts[PARTS][256];
    int found = 0;

    while (fgets(line, sizeof(line), log)) {
        line[strcspn(line, "\n")] = 0;

        char* entry = line;
        if (line[0] == '[') {
            entry = strchr(line, ']');
            if (entry) entry += 2;
            else entry = line;
        }

        char orig[256], ts_filename[64], parts_str[512], rules[512];
        unsigned int log_nonce = 0;

        if (sscanf(entry, "%255[^|]|%63[^|]|%511[^|]|%511[^|]|%07u",
                   orig, ts_filename, parts_str, rules, &log_nonce) < 5)
            continue;

        // Match by filename AND nonce so duplicates don't conflict
        if (strcmp(orig, filename) == 0 && log_nonce == nonce) {
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
        printf("[-] No log entry found for '%s' with nonce %07u\n", filename, nonce);
        return 1;
    }

    // Combine parts
    size_t total_size = 0;
    unsigned char* combined = NULL;

    for (int i = 0; i < found; i++) {
        FILE* pf = fopen(found_parts[i], "rb");
        if (!pf) {
            fprintf(stderr, "[-] Cannot open part: %s\n", found_parts[i]);
            free(combined);
            return 1;
        }
        fseek(pf, 0, SEEK_END);
        long part_size = ftell(pf);
        rewind(pf);

        combined = realloc(combined, total_size + part_size);
        if (!combined) {
            fclose(pf);
            fprintf(stderr, "[-] realloc failed\n");
            return 1;
        }
        fread(combined + total_size, 1, part_size, pf);
        fclose(pf);
        total_size += part_size;
    }

    // Decrypt
    xor_keystream_crypt(combined, total_size, MASTER_KEY, nonce);

    // Write restored file to current directory
    FILE* out = fopen(filename, "wb");
    if (!out) {
        fprintf(stderr, "[-] Cannot write restored file: %s\n", filename);
        free(combined);
        return 1;
    }
    fwrite(combined, 1, total_size, out);
    fclose(out);
    free(combined);

    printf("[+] File restored successfully: %s\n", filename);
    printf("[!] Warning: this file was quarantined as malware. Handle with care.\n");
    return 0;
}
