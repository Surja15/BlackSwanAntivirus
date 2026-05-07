/*
 * ============================================================
 *  BLACK SWAN AV — RESTORE.C
 *  Decrypts and reassembles quarantined files back to disk.
 * ============================================================
 *
 *  WHAT THIS FILE DOES:
 *  --------------------
 *  This is the recovery tool for Black Swan AV. When quarantine.c
 *  isolates an infected file, it:
 *    1. Encrypts the file with XOR + a keystream
 *    2. Splits it into 2 parts (part_a, part_b)
 *    3. Logs everything (original name, part filenames, nonce)
 *
 *  restore.c reverses all of that:
 *    1. Reads the quarantine log to find the file's parts + nonce
 *    2. Reassembles the parts back into one buffer
 *    3. Decrypts using the same XOR keystream (XOR is its own inverse)
 *    4. Writes the original file back to disk
 *    5. Updates the log to mark the entry as RESTORED
 *
 *  HOW XOR DECRYPTION WORKS (why it's the same as encryption):
 *  ------------------------------------------------------------
 *  XOR is symmetric: A ^ B ^ B = A.
 *  If you encrypt with:   ciphertext = plaintext ^ keystream
 *  Then decrypt with:     plaintext  = ciphertext ^ keystream
 *  It's the exact same operation. That's why xor_keystream_crypt()
 *  is used for both encrypting (in quarantine.c) and decrypting here.
 *  The only requirement is that you use the SAME key and SAME nonce.
 *  The nonce is stored in the quarantine log for exactly this reason.
 *
 *  THE KEYSTREAM (how it's generated):
 *  ------------------------------------
 *  keystream_prng() produces one pseudo-random byte per file position.
 *  It takes:
 *    - The master key ("Surja") — seeded into state as character bytes
 *    - The nonce — a random 7-digit number generated at quarantine time
 *    - A counter — the byte position (0, 1, 2, ...) within the file
 *  These three inputs are mixed together using XOR and bit shifts
 *  (xorshift pattern) to produce a byte unique to that exact position.
 *  Same key + same nonce + same position = same keystream byte, always.
 *  Different nonce = completely different keystream = different encryption.
 *
 *  THE LOG FORMAT:
 *  ---------------
 *  Each line in quarantine_log.txt looks like:
 *
 *  [2026-05-01 14:30:22] malware.exe|20260501_143022|20260501_143022_a,20260501_143022_b|DetectEicar|0042381
 *
 *  Fields (pipe-separated after the timestamp):
 *    1. Original filename       (malware.exe)
 *    2. Timestamp string        (20260501_143022)
 *    3. Part filenames          (20260501_143022_a,20260501_143022_b)
 *    4. Matched YARA rules      (DetectEicar)
 *    5. Nonce (7 digits)        (0042381)
 *
 *  After restore, a |RESTORED|2026-05-01 14:35:10 suffix is appended
 *  to the matching log line to create an audit trail.
 *
 *  GUI vs CONSOLE MODE:
 *  ---------------------
 *  restore.c detects whether zenity (a GTK dialog tool) is installed.
 *  If yes → it shows graphical prompts for filename and password.
 *  If no  → it falls back to plain terminal input.
 *  This means it works both as a GUI tool (launched from the Python
 *  front-end) and as a standalone command-line utility.
 *
 *  AUTHENTICATION:
 *  ---------------
 *  The master key ("Surja") serves double duty: it's both the
 *  encryption key AND the password required to authorise a restore.
 *  Without knowing the key, you can't decrypt the file anyway, so
 *  the password check is a UX guard rather than a separate secret.
 *
 *  CONNECTION TO OTHER FILES:
 *  --------------------------
 *  - quarantine.c  : wrote the files this tool reads. Must use the
 *                    exact same MASTER_KEY, KEY_LEN, PARTS, and PRNG
 *                    logic or decryption will produce garbage.
 *  - engine.c      : not involved in restore at all.
 *  - rtm.c         : not involved in restore at all.
 *
 *  COMPILE:
 *      gcc restore.c -o restore
 * ============================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>      /* time(), localtime(), strftime() — for restore timestamp */

/* ----------------------------------------------------------------
 *  CONFIGURATION — must match quarantine.c exactly.
 *  If any of these differ, decryption produces garbage output.
 * ---------------------------------------------------------------- */
#define QUARANTINE_DIR "/home/surja/quarantine"   /* Directory holding encrypted parts */
#define LOG_FILE        QUARANTINE_DIR "/quarantine_log.txt"  /* Audit log file */
#define MASTER_KEY      "Surja"   /* Encryption key AND restore password */
#define KEY_LEN         5         /* strlen(MASTER_KEY) — used in PRNG mixing loop */
#define PARTS           2         /* Number of parts each quarantined file is split into */


/* ================================================================
 *  keystream_prng
 *  Generates one pseudo-random byte for position 'counter' in the
 *  file, given the master key and nonce.
 *
 *  This is a simplified xorshift-style PRNG:
 *    state = nonce                          (seed from nonce)
 *    state ^= key bytes (shifted in)        (mix in key)
 *    state ^= counter (low 32 + high 32)    (mix in file position)
 *    state = xorshift avalanche             (diffuse bits)
 *    state *= golden ratio constant         (improve distribution)
 *    return state & 0xFF                    (take lowest byte)
 *
 *  The golden ratio constant 0x9e3779b9 is used in many hash
 *  functions (e.g. Knuth's multiplicative hash). It spreads bit
 *  patterns more evenly across the output range.
 *
 *  MUST be byte-for-byte identical to the version in quarantine.c
 *  or decryption will produce wrong output.
 * ================================================================ */
static unsigned int keystream_prng(const char* key,
                                    unsigned int nonce,
                                    unsigned long counter)
{
    unsigned int state = nonce;   /* Start state seeded with the file's unique nonce */

    /* Mix each byte of the master key into state at different bit positions */
    for (int i = 0; i < KEY_LEN; i++)
        /*
         * Cast key[i] to unsigned char before widening to unsigned int.
         * Without this, a char value > 127 would sign-extend to a large
         * negative integer, corrupting the XOR. Shift by (i%4)*8 places
         * each key byte into a different byte lane of the 32-bit state.
         */
        state ^= ((unsigned int)(unsigned char)key[i]) << ((i % 4) * 8);

    /* Mix the 64-bit file position (counter) into state in two 32-bit halves */
    state ^= (unsigned int)(counter & 0xFFFFFFFF);           /* Lower 32 bits */
    state ^= (unsigned int)((counter >> 32) & 0xFFFFFFFF);   /* Upper 32 bits */

    /* Xorshift avalanche: rapidly diffuses any input bit change across all bits */
    state ^= (state << 13);   /* Left shift 13 and XOR back — spreads high bits down */
    state ^= (state >> 17);   /* Right shift 17 and XOR — spreads low bits up */
    state ^= (state << 5);    /* Left shift 5 — final mixing pass */

    state *= 0x9e3779b9;      /* Multiply by golden ratio — improves bit distribution */
    state ^= (state >> 16);   /* One more fold — ensures high bits affect low bits */

    return state & 0xFF;   /* Return only the lowest 8 bits as a single keystream byte */
}


/* ================================================================
 *  xor_keystream_crypt
 *  Applies the keystream to a data buffer in-place.
 *  Because XOR is its own inverse (A^B^B = A), this single function
 *  handles BOTH encryption and decryption.
 *  Just call it with the same key+nonce you used to encrypt, and
 *  you get the original plaintext back.
 * ================================================================ */
static void xor_keystream_crypt(unsigned char* data,   /* Buffer to encrypt/decrypt in-place */
                                 size_t len,             /* Number of bytes in buffer */
                                 const char* key,        /* Master key string */
                                 unsigned int nonce)     /* The nonce stored in the log */
{
    for (size_t i = 0; i < len; i++)
        /*
         * XOR each byte with the keystream byte for position i.
         * keystream_prng(key, nonce, i) always returns the same byte
         * for the same (key, nonce, i) triple — deterministic decryption.
         */
        data[i] ^= (unsigned char)keystream_prng(key, nonce, (unsigned long)i);
}


/* ================================================================
 *  zenity_prompt
 *  Runs a zenity dialog command and captures the user's input.
 *  zenity is a command-line tool that shows GTK dialog boxes.
 *
 *  popen() runs the command in a shell and returns a FILE* to read
 *  its stdout (what the user typed into the dialog).
 *  pclose() waits for the command to finish and returns its exit code.
 *  Returns 1 if the user clicked OK, 0 if they cancelled or an error.
 * ================================================================ */
static int zenity_prompt(const char* cmd,   /* Full zenity shell command to run */
                          char* out,          /* Buffer to store user's input */
                          size_t outlen)      /* Size of output buffer */
{
    FILE* p = popen(cmd, "r");   /* Run cmd, open its stdout for reading */
    if (!p) return 0;

    /* Read one line of output (what the user typed) */
    if (!fgets(out, (int)outlen, p)) {
        pclose(p);
        return 0;   /* No input = user cancelled or dialog failed */
    }

    int ret = (pclose(p) == 0);            /* pclose returns exit code: 0 = OK button clicked */
    out[strcspn(out, "\n")] = 0;           /* Strip trailing newline from captured text */
    return ret;
}


/* ================================================================
 *  zenity_available
 *  Checks if the zenity binary exists on the system.
 *  system("which zenity > /dev/null 2>&1") runs a shell command.
 *  'which' prints the path of a binary if found; we discard output.
 *  Returns 0 if found (system() returns the command's exit code).
 * ================================================================ */
static int zenity_available(void) {
    return system("which zenity > /dev/null 2>&1") == 0;
}


/* ================================================================
 *  update_log_restored
 *  Finds the first unrestored log entry for 'filename' and appends
 *  a |RESTORED|<timestamp> suffix to create an audit trail.
 *
 *  Strategy:
 *    1. Read entire log file into a heap buffer.
 *    2. Walk line by line. For the first matching, unrestored line,
 *       copy the line without its newline, append "|RESTORED|<ts>\n".
 *    3. Copy all other lines unchanged.
 *    4. Write the modified buffer back to the log file.
 *
 *  Why read the whole file? The log uses chattr +a (append-only) in
 *  production, but restore temporarily needs write access. Reading
 *  fully and rewriting is simpler than in-place editing for variable-
 *  length lines.
 * ================================================================ */
static int update_log_restored(const char* filename) {
    FILE* log = fopen(LOG_FILE, "r");
    if (!log) return 0;

    /* Get file size to allocate an exact-fit buffer */
    fseek(log, 0, SEEK_END);
    long fsize = ftell(log);   /* ftell returns current position = file size after SEEK_END */
    rewind(log);               /* Reset position to start for reading */

    if (fsize <= 0) { fclose(log); return 0; }

    char* buf = malloc(fsize + 1);   /* +1 for null terminator we add after reading */
    if (!buf) { fclose(log); return 0; }

    size_t read_len = fread(buf, 1, fsize, log);  /* Read entire file into buf */
    fclose(log);
    buf[read_len] = '\0';   /* Null-terminate so string functions work correctly */

    /* Build timestamp string for the RESTORED annotation */
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char restore_ts[64];
    strftime(restore_ts, sizeof(restore_ts), "%Y-%m-%d %H:%M:%S", tm_info);

    /*
     * Allocate output buffer. Most lines pass through unchanged,
     * but one line will grow by strlen("|RESTORED|") + len(timestamp) + ~2.
     * Adding 'extra' to read_len guarantees we have enough space.
     */
    size_t extra = strlen("|RESTORED|") + strlen(restore_ts) + 2;
    char* newbuf = malloc(read_len + extra + 1);
    if (!newbuf) { free(buf); return 0; }

    char* out_ptr = newbuf;   /* Write cursor into newbuf */
    char* line    = buf;      /* Read cursor into buf — points to start of current line */
    int updated   = 0;        /* Flag: have we already updated one line? (only update first match) */

    while (*line) {
        /* Find end of this line — eol points to '\n', or NULL if last line has no newline */
        char* eol = strchr(line, '\n');
        size_t line_len = eol ? (size_t)(eol - line + 1) : strlen(line);

        /*
         * Log lines look like: "[2026-05-01 14:30:22] filename|..."
         * strchr finds the ']' to skip past "[timestamp] ".
         * entry then points to the start of the pipe-separated data fields.
         */
        char* entry = strchr(line, ']');
        if (entry && (entry - line) < (long)line_len)
            entry += 2;   /* Skip "] " (bracket + space) to get to "filename|..." */
        else
            entry = line;

        /* Parse just the first field (original filename) from this line */
        char orig[256];
        if (sscanf(entry, "%255[^|]", orig) == 1 &&   /* Read up to first '|' into orig */
            strcmp(orig, filename) == 0 &&              /* Does it match what we want? */
            !updated &&                                 /* Haven't already updated a line? */
            strstr(line, "|RESTORED|") == NULL)         /* Not already marked as restored? */
        {
            /* Copy line content WITHOUT its trailing newline */
            size_t body_len = line_len - (eol ? 1 : 0);
            memcpy(out_ptr, line, body_len);
            out_ptr += body_len;

            /* Append restore annotation and newline */
            int written = snprintf(out_ptr, extra + 1,
                                   "|RESTORED|%s\n", restore_ts);
            out_ptr += written;
            updated = 1;   /* Mark done — only annotate the first matching entry */
        } else {
            /* Unchanged line — copy as-is */
            memcpy(out_ptr, line, line_len);
            out_ptr += line_len;
        }

        line += line_len;   /* Advance read cursor past this line */
    }

    *out_ptr = '\0';   /* Null-terminate the output buffer */

    if (!updated) { free(buf); free(newbuf); return 0; }

    /* Write the modified buffer back to the log file */
    FILE* logw = fopen(LOG_FILE, "w");
    if (!logw) { free(buf); free(newbuf); return 0; }

    fwrite(newbuf, 1, out_ptr - newbuf, logw);
    fclose(logw);

    free(buf);
    free(newbuf);
    return 1;   /* Success */
}


/* ================================================================
 *  main
 *  Orchestrates the entire restore flow:
 *    1. Collect filename + password (GUI or console)
 *    2. Authenticate against MASTER_KEY
 *    3. Look up the file in the quarantine log
 *    4. Read and combine the encrypted parts
 *    5. Decrypt with XOR keystream
 *    6. Write restored file to disk
 *    7. Update the log
 * ================================================================ */
int main(int argc, char* argv[]) {
    char filename[512] = {0};  /* Name of the file to restore (from log, not full path) */
    char password[64]  = {0};  /* Password entered by user to authorise restore */

    if (zenity_available()) {
        /* ── GUI MODE: show graphical dialog boxes via zenity ── */

        char cmd[1024];

        /*
         * Build the zenity --entry command for the filename dialog.
         * If argv[1] was supplied (e.g. GUI passed the filename in),
         * pre-fill the text box with --entry-text so user doesn't retype it.
         */
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

        /* Show the dialog; if user cancels, zenity_prompt returns 0 */
        if (!zenity_prompt(cmd, filename, sizeof(filename))) {
            printf("[-] Cancelled\n"); return 1;
        }
        if (strlen(filename) == 0) {
            printf("[-] No filename entered\n"); return 1;
        }

        /*
         * zenity --password shows a dialog with a hidden text field.
         * Output is the typed password on stdout, which popen captures.
         */
        snprintf(cmd, sizeof(cmd),
            "zenity --password "
            "--title='Black Swan AV — Restore'");

        if (!zenity_prompt(cmd, password, sizeof(password))) {
            printf("[-] Cancelled\n"); return 1;
        }

    } else {
        /* ── CONSOLE FALLBACK: plain stdin/stdout ── */

        if (argc < 2) {
            printf("Usage: %s <filename>\n", argv[0]);
            return 1;
        }
        strncpy(filename, argv[1], sizeof(filename) - 1);

        printf("Enter master key: ");
        fflush(stdout);

        if (!fgets(password, sizeof(password), stdin)) {
            printf("[-] Input error\n"); return 1;
        }
        password[strcspn(password, "\n")] = 0;   /* Strip trailing newline from fgets */
    }

    /* ── AUTHENTICATION ── */
    if (strcmp(password, MASTER_KEY) != 0) {
        /*
         * strcmp returns 0 only if strings are identical.
         * Non-zero means wrong password — deny the restore.
         */
        if (zenity_available())
            system("zenity --error --title='Black Swan AV' --text='Incorrect master key'");
        else
            printf("[-] Incorrect master key\n");
        return 1;
    }

    /* ── LOG LOOKUP ── */
    FILE* log = fopen(LOG_FILE, "r");
    if (!log) { printf("[-] Cannot open log file\n"); return 1; }

    char line[1024];
    char parts[PARTS][256];   /* Will hold the full path to each encrypted part file */
    unsigned int nonce = 0;   /* The nonce stored at quarantine time — needed for decryption */
    int found = 0;            /* How many valid part paths were parsed */

    while (fgets(line, sizeof(line), log)) {
        /* Skip past the "[timestamp] " prefix to get to the pipe-separated fields */
        char* entry = strchr(line, ']');
        if (entry) entry += 2;
        else entry = line;

        char orig[256], ts[64], parts_str[512], rules[512];

        /*
         * sscanf with format "%255[^|]|%63[^|]|%511[^|]|%511[^|]|%u"
         * parses pipe-separated fields:
         *   %255[^|]  — read up to 255 chars stopping at '|'  → orig (filename)
         *   |         — literal pipe separator
         *   %63[^|]   — timestamp string                       → ts
         *   |%511[^|] — part filenames (comma-separated)       → parts_str
         *   |%511[^|] — matched YARA rules                     → rules
         *   |%u       — nonce as unsigned int                  → nonce
         * If fewer than 5 fields parse, skip this line (malformed/incomplete).
         */
        if (sscanf(entry, "%255[^|]|%63[^|]|%511[^|]|%511[^|]|%u",
                   orig, ts, parts_str, rules, &nonce) < 5)
            continue;

        if (strcmp(orig, filename) == 0) {
            /*
             * strtok splits parts_str on "," to get individual part filenames.
             * e.g. "20260501_143022_a,20260501_143022_b" → two tokens.
             * We prepend QUARANTINE_DIR to get full paths.
             * NOTE: strtok modifies parts_str in-place (replaces ',' with '\0').
             */
            char* token = strtok(parts_str, ",");
            int i = 0;
            while (token && i < PARTS) {
                snprintf(parts[i], sizeof(parts[i]),
                         "%s/%s", QUARANTINE_DIR, token);
                token = strtok(NULL, ",");   /* NULL = continue tokenising same string */
                i++;
            }
            found = i;   /* Number of parts successfully parsed */
            break;       /* Stop at first matching log entry */
        }
    }
    fclose(log);

    if (!found) {
        if (zenity_available())
            system("zenity --error --title='Black Swan AV' --text='File not found in quarantine log'");
        else
            printf("[-] File not found in log\n");
        return 1;
    }

    if (nonce == 0) {
        /* nonce == 0 would mean the sscanf didn't parse it, or a corrupted log */
        printf("[-] Invalid nonce\n");
        return 1;
    }

    /* ── COMBINE PARTS ── */

    /*
     * combined grows via realloc() as we read each part.
     * Starting as NULL is valid: realloc(NULL, size) == malloc(size).
     * total tracks the cumulative byte count across all parts.
     */
    unsigned char* combined = NULL;
    size_t total = 0;

    for (int i = 0; i < found; i++) {
        FILE* f = fopen(parts[i], "rb");   /* Open in binary read mode */
        if (!f) {
            printf("[-] Cannot open part: %s\n", parts[i]);
            free(combined);
            return 1;
        }

        fseek(f, 0, SEEK_END);
        long size = ftell(f);   /* Size of this part in bytes */
        rewind(f);

        if (size <= 0) { fclose(f); continue; }  /* Empty part — skip */

        /*
         * realloc() resizes the combined buffer to fit this part's data.
         * If realloc fails, it returns NULL WITHOUT freeing the old pointer —
         * so we store the return in 'temp' first, check it, then assign.
         * If we wrote 'combined = realloc(combined, ...)' and it returned NULL,
         * we'd leak the old combined buffer.
         */
        unsigned char* temp = realloc(combined, total + size);
        if (!temp) {
            printf("[-] Memory allocation failed\n");
            fclose(f);
            free(combined);   /* Free old buffer before exit */
            return 1;
        }
        combined = temp;

        /* Read this part's bytes directly into the end of combined */
        if (fread(combined + total, 1, size, f) != (size_t)size) {
            printf("[-] Read error\n");
            fclose(f);
            free(combined);
            return 1;
        }

        fclose(f);
        total += size;   /* Advance total by how many bytes we just added */
    }

    if (total == 0) {
        printf("[-] No data to restore\n");
        free(combined);
        return 1;
    }

    /* ── DECRYPT ── */
    /*
     * xor_keystream_crypt with the same MASTER_KEY and nonce used at
     * quarantine time reverses the encryption. XOR is its own inverse:
     *   decrypt(encrypt(data, key, nonce), key, nonce) == data
     * The nonce was read from the log log — this is why logging it is critical.
     * If the log is lost, decryption is impossible.
     */
    xor_keystream_crypt(combined, total, MASTER_KEY, nonce);

    /* ── WRITE RESTORED FILE ── */
    /*
     * Writes to the current working directory with the original filename.
     * The caller (or GUI) is responsible for placing the restore tool
     * in the right directory, or moving the file afterward.
     */
    FILE* out = fopen(filename, "wb");   /* wb = write binary — no newline translation */
    if (!out) {
        printf("[-] Cannot write output file\n");
        free(combined);
        return 1;
    }

    fwrite(combined, 1, total, out);   /* Write all decrypted bytes at once */
    fclose(out);
    free(combined);   /* Release the decrypt buffer — always free after use */

    /* ── UPDATE LOG ── */
    /*
     * Annotates the matching log line with |RESTORED|<timestamp>.
     * Provides an audit trail: you can see which files were restored and when.
     * Failure here is non-fatal (file is already restored) — just a warning.
     */
    if (update_log_restored(filename))
        printf("[+] Quarantine log updated\n");
    else
        printf("[!] Warning: file restored but log could not be updated\n");

    /* Show success dialog if running in GUI mode */
    if (zenity_available()) {
        char msg[600];
        snprintf(msg, sizeof(msg),
            "zenity --info --title='Black Swan AV' "
            "--text='File restored successfully:\n%s'",
            filename);
        system(msg);
    }

    printf("[+] File restored successfully: %s\n", filename);
    return 0;
}
