// restore.c
// Standalone restore tool for Black Swan AV quarantine

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUARANTINE_DIR "/home/surja/quarantine"
#define LOG_FILE       QUARANTINE_DIR "/quarantine_log.txt"
#define MASTER_KEY     "Surja"
#define KEY_LEN        5
#define PARTS          2

// PRNG (must match quarantine exactly)
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
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // Ask for master key
    char password[64];
    printf("Enter master key: ");
    fflush(stdout);

    if (!fgets(password, sizeof(password), stdin)) {
        printf("[-] Input error\n");
        return 1;
    }

    password[strcspn(password, "\n")] = 0;

    if (strcmp(password, MASTER_KEY) != 0) {
        printf("[-] Incorrect master key\n");
        return 1;
    }

    const char* filename = argv[1];

    FILE* log = fopen(LOG_FILE, "r");
    if (!log) {
        printf("[-] Cannot open log file\n");
        return 1;
    }

    char line[1024];
    char parts[PARTS][256];
    unsigned int nonce = 0;
    int found = 0;

    // Find file entry in log
    while (fgets(line, sizeof(line), log)) {
        char* entry = strchr(line, ']');
        if (entry) entry += 2;
        else entry = line;

        char orig[256], ts[64], parts_str[512], rules[512];

        if (sscanf(entry, "%255[^|]|%63[^|]|%511[^|]|%511[^|]|%u",
                   orig, ts, parts_str, rules, &nonce) < 5)
            continue;

        if (strcmp(orig, filename) == 0) {
            char* token = strtok(parts_str, ",");
            int i = 0;
            while (token && i < PARTS) {
                snprintf(parts[i], sizeof(parts[i]), "%s/%s", QUARANTINE_DIR, token);
                token = strtok(NULL, ",");
                i++;
            }
            found = i;
            break;
        }
    }

    fclose(log);

    if (!found) {
        printf("[-] File not found in log\n");
        return 1;
    }

    if (nonce == 0) {
        printf("[-] Invalid nonce\n");
        return 1;
    }

    // Combine parts
    unsigned char* combined = NULL;
    size_t total = 0;

    for (int i = 0; i < found; i++) {
        FILE* f = fopen(parts[i], "rb");
        if (!f) {
            printf("[-] Cannot open part: %s\n", parts[i]);
            free(combined);
            return 1;
        }

        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        rewind(f);

        if (size <= 0) {
            fclose(f);
            continue;
        }

        unsigned char* temp = realloc(combined, total + size);
        if (!temp) {
            printf("[-] Memory allocation failed\n");
            fclose(f);
            free(combined);
            return 1;
        }

        combined = temp;

        if (fread(combined + total, 1, size, f) != (size_t)size) {
            printf("[-] Read error\n");
            fclose(f);
            free(combined);
            return 1;
        }

        fclose(f);
        total += size;
    }

    if (total == 0) {
        printf("[-] No data to restore\n");
        free(combined);
        return 1;
    }

    // Decrypt using MASTER_KEY to match quarantine.c exactly
    xor_keystream_crypt(combined, total, MASTER_KEY, nonce);

    FILE* out = fopen(filename, "wb");
    if (!out) {
        printf("[-] Cannot write output file\n");
        free(combined);
        return 1;
    }

    fwrite(combined, 1, total, out);
    fclose(out);

    free(combined);

    printf("[+] File restored successfully: %s\n", filename);
    return 0;
}
