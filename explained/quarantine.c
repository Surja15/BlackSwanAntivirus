// quarantine.c
// Standalone quarantine module for Black Swan AV by S15
// Compile with engine: gcc engine.c quarantine.c -o engine -lyara
// After first run, lock log: sudo chattr +a ~/quarantine/quarantine_log.txt

/*
 * ═══════════════════════════════════════════════════════════════════════
 * HOW THIS MODULE WORKS — READ FIRST
 * ═══════════════════════════════════════════════════════════════════════
 *
 * PURPOSE:
 *   When engine.c detects a threat via YARA, it calls quarantine_file().
 *   This module isolates the threat so it cannot execute, but preserves
 *   it for later analysis or restoration.
 *
 * ENCRYPTION SCHEME — XOR KEYSTREAM:
 *   The file is NOT encrypted with AES or similar. Instead, a PRNG
 *   generates a keystream byte-by-byte, and each file byte is XOR'd
 *   against it. XOR is its own inverse: encrypt(encrypt(x)) = x.
 *   So the exact same function both encrypts and decrypts.
 *   This breaks the file so the OS cannot execute or parse it,
 *   while keeping restore trivially simple.
 *
 * KEYSTREAM CONSTRUCTION (simplified ChaCha20-style):
 *   real ChaCha20 uses a 512-bit block state with 20 mixing rounds.
 *   This uses a single 32-bit state with 3 xorshift rounds + multiply.
 *   Input:  master_key (string) + nonce (random 7-digit int) + counter (byte position)
 *   Output: one pseudo-random byte per call
 *   Security property: same key + different nonce = completely different stream.
 *   The nonce is the "salt" — without it, two files encrypted with the
 *   same key would produce identical ciphertexts for identical plaintexts.
 *
 * NONCE:
 *   A random 7-digit number generated at quarantine time.
 *   Stored in the log file. Required for decryption.
 *   If the log is lost, the quarantined files are unrecoverable.
 *
 * FILE SPLITTING:
 *   The encrypted file is split into PARTS (2) chunks.
 *   Rationale: some malware specifically targets AV quarantine folders
 *   and tries to self-restore. Splitting means neither chunk alone is
 *   a complete file, so a naive self-restore attempt fails.
 *
 * LOG FILE FORMAT (one line per quarantined file):
 *   [YYYY-MM-DD HH:MM:SS] filename|timestamp|part_a,part_b|rules|nonce
 *   Example:
 *   [2026-05-06 10:22:11] trojan.elf|20260506_102211|20260506_102211_a,20260506_102211_b|rule_shellcode|1837492
 *
 * LOG IMMUTABILITY:
 *   After first run, lock with: sudo chattr +a quarantine_log.txt
 *   chattr +a = append-only. Even root cannot delete/overwrite lines.
 *   This prevents malware from erasing its own quarantine record.
 *   Restore module reads this log to find chunks + nonce for decryption.
 *
 * CONNECTED TO:
 *   - engine.c  → calls quarantine_file(path, matched_rules) on detection
 *   - restore.c → reads the log and calls the inverse of this process
 * ═══════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>    // fopen, fread, fwrite, fprintf, printf, fseek, ftell, rewind
#include <stdlib.h>   // malloc, free, rand, srand, exit
#include <string.h>   // strrchr, strerror, snprintf
#include <time.h>     // time(), localtime(), strftime() — for timestamps and PRNG seed
#include <sys/stat.h> // stat(), mkdir(), S_ISDIR() — for checking/creating quarantine dir
#include <unistd.h>   // getpid() — used to add entropy to the PRNG seed
#include <errno.h>    // errno — set by system calls on failure, used for error messages


// ─── Config ────────────────────────────────────────────────────────────────

#define QUARANTINE_DIR  "/home/surja/quarantine"   // Absolute path to quarantine folder
#define LOG_FILE        QUARANTINE_DIR "/quarantine_log.txt"  // Appended to on every quarantine
#define MASTER_KEY      "Surja"                    // The encryption key — shared secret
#define KEY_LEN         5                          // strlen("Surja") — used in keystream mixing loop
#define PARTS           2                          // Number of chunks to split encrypted file into
#define NONCE_DIGITS    7                          // Nonce range: 1000000 to 9999999 (7 digits)

// ───────────────────────────────────────────────────────────────────────────


/*
 * ┌─────────────────────────────────────────────────────────┐
 * │  KEYSTREAM GENERATOR                                    │
 * │                                                         │
 * │  Produces one pseudo-random byte for a given:          │
 * │    - key     : the master key string ("Surja")         │
 * │    - nonce   : random value chosen at quarantine time  │
 * │    - counter : position of this byte in the file       │
 * │                                                         │
 * │  Think of it like: keystream[i] = f(key, nonce, i)    │
 * │  Every byte position gets a unique, deterministic byte. │
 * │                                                         │
 * │  XORSHIFT: a fast, simple bit-mixing technique.        │
 * │  Three shifts + XORs create avalanche effect where     │
 * │  flipping 1 input bit changes ~half the output bits.   │
 * │  Not cryptographically secure, but sufficient to       │
 * │  destroy file structure and prevent execution.         │
 * └─────────────────────────────────────────────────────────┘
 */
static unsigned int keystream_prng(const char* key, unsigned int nonce, unsigned long counter) {
    unsigned int state = nonce;   // Start state with the nonce — unique per quarantine event

    // Mix in each byte of the master key into the state.
    // i % 4 cycles through 0,1,2,3 — shifts key bytes to different bit positions
    // (i%4)*8 gives shifts of 0, 8, 16, 24 bits — spreading key across all 32 bits of state
    for (int i = 0; i < KEY_LEN; i++)
        state ^= ((unsigned int)(unsigned char)key[i]) << ((i % 4) * 8);

    // Mix in the counter (file byte position) — this makes each byte unique.
    // counter is unsigned long (64-bit), so we XOR the low 32 bits and high 32 bits separately
    // because state is only 32-bit.
    state ^= (unsigned int)(counter & 0xFFFFFFFF);           // Low  32 bits of position
    state ^= (unsigned int)((counter >> 32) & 0xFFFFFFFF);  // High 32 bits of position

    /*
     * XORSHIFT BIT MIXING — 3 rounds:
     * Each ^= (state << N) or ^= (state >> N) avalanches bits.
     * The specific shifts (13, 17, 5) are a known good xorshift triplet
     * that passes basic randomness tests (Marsaglia 2003).
     */
    state ^= (state << 13);   // Shift left 13, XOR back — high bits influence low bits
    state ^= (state >> 17);   // Shift right 17, XOR back — low bits influence high bits
    state ^= (state << 5);    // Final left shift for extra mixing

    // Multiply by the golden ratio constant (2^32 / phi ≈ 0x9e3779b9).
    // Multiplication spreads bit patterns better than XOR alone —
    // causes carries to propagate across all 32 bits.
    state *= 0x9e3779b9;

    state ^= (state >> 16);   // Final fold: top half XOR'd into bottom half

    return state & 0xFF;      // Return only the lowest 8 bits — one keystream byte
}


/*
 * Nonce Generator
 * Nonce = "number used once" — a random value that makes each encryption unique.
 * Even if the same file is quarantined twice, different nonces = different ciphertext.
 * Range: 1,000,000 – 9,999,999 (always 7 digits, matches NONCE_DIGITS above).
 */
static unsigned int generate_nonce() {
    // Seed with time XOR pid: time() alone repeats if called within same second;
    // XOR with getpid() adds process-level uniqueness to avoid collisions.
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    // rand() % 9000000 gives 0–8999999; +1000000 shifts range to 1000000–9999999
    return 1000000 + (rand() % 9000000);
}


/*
 * XOR Keystream Cipher — Encryption AND Decryption (same function)
 * XOR truth table: 0^0=0, 1^1=0, 0^1=1, 1^0=1
 * Therefore: plaintext ^ keystream = ciphertext
 *            ciphertext ^ keystream = plaintext  (identical operation)
 * This means quarantine_file and restore_file can both call this function
 * with the same key+nonce to encrypt or decrypt respectively.
 *
 * data    : pointer to file bytes in memory (modified in-place)
 * len     : number of bytes in the file
 * key     : master key string
 * nonce   : the nonce stored in the log — must match what was used to encrypt
 */
static void xor_keystream_crypt(unsigned char* data, size_t len,
                                 const char* key, unsigned int nonce) {
    for (size_t i = 0; i < len; i++)
        // Each byte is XOR'd against its unique keystream byte at position i
        data[i] ^= (unsigned char)keystream_prng(key, nonce, (unsigned long)i);
}


/*
 * Quarantine Directory Setup
 * stat() checks if the path exists and what type it is (file, dir, symlink, etc.)
 * S_ISDIR() macro checks the st_mode field for directory type.
 * mkdir() with 0700 = owner rwx, no permissions for group or others —
 * so only the AV process owner can read/write the quarantine folder.
 */
static int ensure_quarantine_dir() {
    struct stat st;                          // struct to hold file/dir metadata
    if (stat(QUARANTINE_DIR, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;                            // Dir already exists — nothing to do
    if (mkdir(QUARANTINE_DIR, 0700) != 0) { // 0700 = rwx------ (owner only)
        fprintf(stderr, "[-] Failed to create quarantine dir: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}


/*
 * Log file locking placeholder.
 * Actual locking is done manually post-run via:
 *   sudo chattr +a ~/quarantine/quarantine_log.txt
 * chattr +a = set append-only attribute on Linux ext4/xfs filesystems.
 * After this, even root (uid 0) cannot truncate or overwrite the file —
 * only new lines can be appended. This is a kernel-level protection,
 * not just a file permission — it must be removed with chattr -a first.
 */
static void lock_log_file() {
    (void)0;  // No-op — reminder to run chattr manually after first quarantine
}


/*
 * Timestamp Helpers
 * Two formats because:
 *   ts_readable → goes into log for human reading: "2026-05-06 10:22:11"
 *   ts_filename → goes into filenames (no spaces/colons): "20260506_102211"
 *                 colons are illegal in many filesystems and break shell commands
 *
 * strftime() formats a struct tm (broken-down time) into a string.
 * localtime() converts a Unix timestamp (seconds since epoch) to local time struct.
 */
static void get_timestamp(char* buf, size_t len) {
    time_t now = time(NULL);             // Current Unix timestamp
    struct tm* t = localtime(&now);      // Convert to local wall-clock time
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", t);  // "2026-05-06 10:22:11"
}

static void get_file_timestamp(char* buf, size_t len) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    strftime(buf, len, "%Y%m%d_%H%M%S", t);      // "20260506_102211"
}


/*
 * ═══════════════════════════════════════════════════════
 * MAIN QUARANTINE FUNCTION
 * Called by engine.c when YARA flags a file as malicious.
 *
 * Steps:
 *   1. Ensure quarantine dir exists
 *   2. Read entire file into memory
 *   3. Generate nonce, encrypt in-place with XOR keystream
 *   4. Split encrypted bytes into PARTS chunk files
 *   5. Append one log line with all metadata + nonce
 *   6. Delete the original file from its original location
 *
 * file_path     : absolute path to the detected malicious file
 * matched_rules : comma-separated YARA rule names that triggered, e.g. "rule_shellcode,rule_rat"
 * returns       : 0 on success, -1 on any failure
 * ═══════════════════════════════════════════════════════
 */
int quarantine_file(const char* file_path, const char* matched_rules) {
    if (ensure_quarantine_dir() != 0) return -1;  // Abort if we can't create/find quarantine dir

    // ── Step 1: Read entire file into heap memory ──────────────────────────
    FILE* f = fopen(file_path, "rb");  // "rb" = read binary — no newline translation
    if (!f) {
        fprintf(stderr, "[-] Cannot open file: %s\n", strerror(errno));
        return -1;
    }

    fseek(f, 0, SEEK_END);     // Move file cursor to end
    long file_size = ftell(f); // ftell() returns current cursor position = file size in bytes
    rewind(f);                 // Reset cursor back to start before reading

    unsigned char* data = malloc(file_size);  // Allocate exact number of bytes needed
    if (!data) {
        fclose(f);
        fprintf(stderr, "[-] malloc failed\n");
        return -1;
    }
    fread(data, 1, file_size, f);  // Read file_size bytes, 1 byte at a time, into data buffer
    fclose(f);

    // ── Step 2: Encrypt in memory ──────────────────────────────────────────
    unsigned int nonce = generate_nonce();                        // Fresh random nonce
    xor_keystream_crypt(data, file_size, MASTER_KEY, nonce);     // XOR entire buffer in-place

    // ── Step 3: Build timestamps ───────────────────────────────────────────
    char ts_readable[32];   // "2026-05-06 10:22:11" — for log display
    char ts_filename[32];   // "20260506_102211"      — for chunk filenames
    get_timestamp(ts_readable, sizeof(ts_readable));
    get_file_timestamp(ts_filename, sizeof(ts_filename));

    // ── Step 4: Split encrypted buffer into PARTS chunk files ─────────────
    /*
     * With PARTS=2 and a 1000-byte file:
     *   chunk = 500
     *   part 0: bytes   0–499  → written to "20260506_102211_a"
     *   part 1: bytes 500–999  → written to "20260506_102211_b"
     *   (last part always gets the remainder to handle odd-sized files)
     */
    long chunk = file_size / PARTS;       // Base size of each part (integer division)
    char part_names[PARTS][256];          // Array to hold full paths of each chunk file

    for (int i = 0; i < PARTS; i++) {
        // Build chunk filename: "<quarantine_dir>/<timestamp>_a", "_b", etc.
        // 'a' + i gives 'a' for i=0, 'b' for i=1, 'c' for i=2, etc.
        snprintf(part_names[i], sizeof(part_names[i]),
                 "%s/%s_%c", QUARANTINE_DIR, ts_filename, 'a' + i);

        long offset = i * chunk;  // Byte offset into data[] where this chunk starts
        // Last part gets everything remaining (handles files not evenly divisible by PARTS)
        long size   = (i == PARTS - 1) ? (file_size - offset) : chunk;

        FILE* pf = fopen(part_names[i], "wb");  // "wb" = write binary
        if (!pf) {
            fprintf(stderr, "[-] Cannot write part %d: %s\n", i, strerror(errno));
            free(data);
            return -1;
        }
        fwrite(data + offset, 1, size, pf);  // Write this chunk's slice from data buffer
        fclose(pf);
    }
    free(data);  // All chunks written — release the heap buffer

    // ── Step 5: Append to log ─────────────────────────────────────────────
    /*
     * strrchr(path, '/') finds the LAST '/' in the path string.
     * +1 skips past the '/' to get just the filename (basename).
     * If no '/' found (relative path), use the whole string.
     * Example: "/home/surja/evil.sh" → basename = "evil.sh"
     */
    const char* basename = strrchr(file_path, '/');
    basename = basename ? basename + 1 : file_path;

    /*
     * Log line format:
     * [2026-05-06 10:22:11] evil.sh|20260506_102211|20260506_102211_a,20260506_102211_b|rule_shellcode|1837492
     *  ^timestamp            ^orig   ^file-timestamp ^chunk names (comma-sep)           ^YARA rules    ^nonce
     *
     * "a" flag to fopen = append mode — never overwrites, always adds to end.
     * This is the same behavior enforced at kernel level by chattr +a.
     */
    FILE* log = fopen(LOG_FILE, "a");    // Open log in append mode
    if (log) {
        fprintf(log, "[%s] %s|%s|", ts_readable, basename, ts_filename);

        // Write chunk basenames separated by commas: "20260506_102211_a,20260506_102211_b"
        for (int i = 0; i < PARTS; i++) {
            const char* pbn = strrchr(part_names[i], '/');   // Find last '/' in chunk path
            pbn = pbn ? pbn + 1 : part_names[i];             // Step past it to get filename
            fprintf(log, "%s%s", pbn, (i < PARTS - 1) ? "," : "");  // Comma between, not after last
        }

        // %07u formats nonce as 7-digit zero-padded integer, e.g. 0083742
        fprintf(log, "|%s|%07u\n", matched_rules ? matched_rules : "N/A", nonce);
        fclose(log);
        lock_log_file();  // No-op here — reminder that chattr should already be set
    }

    printf("[+] Quarantined: %s -> %s (nonce: %07u)\n", file_path, QUARANTINE_DIR, nonce);

    // ── Step 6: Delete original ────────────────────────────────────────────
    // remove() calls unlink() for files — removes directory entry.
    // Failure here is non-fatal (file may be on read-only fs, etc.) — warn but continue.
    if (remove(file_path) != 0)
        fprintf(stderr, "[!] Warning: could not remove original: %s\n", strerror(errno));

    return 0;  // Success
}

// ─── Restore is handled in restore.c ──────────────────────────────────────

/*
 * To manually unlock and delete the log file if ever needed:
 *   sudo chattr -a ~/quarantine/quarantine_log.txt   ← remove append-only attribute
 *   sudo rm ~/quarantine/quarantine_log.txt           ← now deletion is allowed
 *
 * WARNING: Deleting the log means all quarantined file nonces are gone.
 * Without the nonce, XOR decryption produces garbage — files are unrecoverable.
 */
