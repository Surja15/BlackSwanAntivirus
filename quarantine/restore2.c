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

// Run a zenity command and capture its output (strips trailing newline)
// Returns 1 on success, 0 on cancel/error
static int zenity_prompt(const char* cmd, char* out, size_t outlen) {
    FILE* p = popen(cmd, "r");
    if (!p) return 0;
    if (!fgets(out, (int)outlen, p)) {
        pclose(p);
        return 0;
    }
    int ret = (pclose(p) == 0);
    out[strcspn(out, "\n")] = 0;  // strip newline
    return ret;
}

// Check if zenity is available
static int zenity_available(void) {
    return system("which zenity > /dev/null 2>&1") == 0;
}

int main(int argc, char* argv[]) {
    char filename[512] = {0};
    char password[64]  = {0};

    if (zenity_available()) {
        // --- GUI mode ---

        // Filename dialog (pre-fill from argv[1] if provided)
        char cmd[1024];
        if (argc >= 2) {
            snprintf(cmd, sizeof(cmd),
                "zenity --entry "
                "--title='Black Swan AV — Restore' "
                "--text='Enter filename to restore:' "
                "--entry-text='%s'", argv[1]);
        } else {
            snprintf(cmd, sizeof(cmd),
                "zenity --entry "
                "--title='Black Swan AV — Restore' "
                "--text='Enter filename to restore:'");
        }

        if (!zenity_prompt(cmd, filename, sizeof(filename))) {
            printf("[-] Cancelled\n");
            return 1;
        }

        if (strlen(filename) == 0) {
            printf("[-] No filename entered\n");
            return 1;
        }

        // Password dialog
        snprintf(cmd, sizeof(cmd),
            "zenity --password "
            "--title='Black Swan AV — Restore'");

        if (!zenity_prompt(cmd, password, sizeof(password))) {
            printf("[-] Cancelled\n");
            return 1;
        }

    } else {
        // --- Console fallback ---
        if (argc < 2) {
            printf("Usage: %s <filename>\n", argv[0]);
            return 1;
        }
        strncpy(filename, argv[1], sizeof(filename) - 1);

        printf("Enter master key: ");
        fflush(stdout);
        if (!fgets(password, sizeof(password), stdin)) {
            printf("[-] Input error\n");
            return 1;
        }
        password[strcspn(password, "\n")] = 0;
    }

    // Authenticate
    if (strcmp(password, MASTER_KEY) != 0) {
        if (zenity_available()) {
            system("zenity --error --title='Black Swan AV' --text='Incorrect master key'");
        } else {
            printf("[-] Incorrect master key\n");
        }
        return 1;
    }

    // --- Log lookup ---
    FILE* log = fopen(LOG_FILE, "r");
    if (!log) {
        printf("[-] Cannot open log file\n");
        return 1;
    }

    char line[1024];
    char parts[PARTS][256];
    unsigned int nonce = 0;
    int found = 0;

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
        if (zenity_available()) {
            system("zenity --error --title='Black Swan AV' --text='File not found in quarantine log'");
        } else {
            printf("[-] File not found in log\n");
        }
        return 1;
    }

    if (nonce == 0) {
        printf("[-] Invalid nonce\n");
        return 1;
    }

    // --- Combine parts ---
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

    // --- Decrypt ---
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

    if (zenity_available()) {
        char msg[600];
        snprintf(msg, sizeof(msg),
            "zenity --info --title='Black Swan AV' --text='File restored successfully:\n%s'",
            filename);
        system(msg);
    }

    printf("[+] File restored successfully: %s\n", filename);
    return 0;
}
