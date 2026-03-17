// restore.c
// Usage: ./restore <original_filename> <xor_key>
// Example: ./restore eicar.txt Ganesh
/*gcc restore.c -o restore
./restore eicar.txt Ganesh
Wrong key = garbage output. No log = fails immediately. That's the only two requirements to make it work.*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUARANTINE_DIR "/home/surja/quarantine"
#define LOG_FILE       QUARANTINE_DIR "/quarantine_log.txt"
#define MAX_PARTS      10

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <original_filename> <xor_key>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    const char* key      = argv[2];
    int key_len          = strlen(key);

    // Search log for the file
    FILE* log = fopen(LOG_FILE, "r");
    if (!log) { fprintf(stderr, "[-] Cannot open log: %s\n", LOG_FILE); return 1; }

    char line[1024];
    char parts_str[512] = "";
    int found = 0;

    while (fgets(line, sizeof(line), log)) {
        line[strcspn(line, "\n")] = 0;
        char orig[256], timestamp[64], pstr[512], rules[512];
        if (sscanf(line, "%255[^|]|%63[^|]|%511[^|]|%511[^\n]", orig, timestamp, pstr, rules) < 3)
            continue;
        if (strcmp(orig, filename) == 0) {
            strncpy(parts_str, pstr, sizeof(parts_str) - 1);
            found = 1;
            break;
        }
    }
    fclose(log);

    if (!found) { fprintf(stderr, "[-] '%s' not found in log.\n", filename); return 1; }

    // Read and combine all parts
    unsigned char* combined = NULL;
    size_t total = 0;

    char* token = strtok(parts_str, ",");
    while (token) {
        char part_path[512];
        snprintf(part_path, sizeof(part_path), "%s/%s", QUARANTINE_DIR, token);

        FILE* pf = fopen(part_path, "rb");
        if (!pf) { fprintf(stderr, "[-] Cannot open part: %s\n", part_path); free(combined); return 1; }

        fseek(pf, 0, SEEK_END);
        long sz = ftell(pf);
        rewind(pf);

        combined = realloc(combined, total + sz);
        fread(combined + total, 1, sz, pf);
        fclose(pf);
        total += sz;//S15

        token = strtok(NULL, ",");
    }

    // XOR decrypt
    for (size_t i = 0; i < total; i++)
        combined[i] ^= (unsigned char)key[i % key_len];

    // Write restored file
    FILE* out = fopen(filename, "wb");
    if (!out) { fprintf(stderr, "[-] Cannot write output file.\n"); free(combined); return 1; }
    fwrite(combined, 1, total, out);
    fclose(out);
    free(combined);

    printf("[+] Restored: %s\n", filename);
    return 0;
}
