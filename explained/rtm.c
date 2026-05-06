/*
 * ═══════════════════════════════════════════════════════════════════════
 * rtm.c — Real-Time Monitor for Black Swan AV
 * ═══════════════════════════════════════════════════════════════════════
 *
 * PURPOSE:
 *   This is the "always-on" layer of the AV. It watches directories for
 *   filesystem events and automatically triggers engine.c whenever a
 *   file is created, written, or moved into a watched folder.
 *
 * ARCHITECTURE — HOW THE PIECES CONNECT:
 *
 *   Python GUI
 *       │  spawns RTM as a subprocess, reads its stdout line by line
 *       ▼
 *   rtm.c  (this file)
 *       │  watches directories via inotify (kernel filesystem events)
 *       │  on file event: fork() + execl() → engine
 *       ▼
 *   engine.c
 *       │  runs YARA rules on the file
 *       │  on match: calls quarantine_file()
 *       ▼
 *   quarantine.c
 *       │  encrypts + splits + logs the threat
 *
 * KEY TECHNOLOGIES USED:
 *
 *   INOTIFY (Linux kernel subsystem):
 *     A kernel mechanism that delivers filesystem events to userspace.
 *     You register a "watch" on a path; the kernel sends events (IN_CREATE,
 *     IN_CLOSE_WRITE, etc.) into a file descriptor you read() like a pipe.
 *     Much more efficient than polling — zero CPU when nothing happens.
 *
 *   PTHREADS (POSIX threads):
 *     Each monitored directory gets its own thread (MonitorDirectoryThread).
 *     Each file scan runs in its own thread (ScanThread) so multiple files
 *     can be scanned in parallel without blocking the monitor.
 *
 *   SEMAPHORE (thread_sem):
 *     A semaphore is a counter that controls access to a shared resource.
 *     sem_wait() decrements it (blocks if 0); sem_post() increments it.
 *     Here it acts as a thread pool cap: MAX_THREADS scans can run at once.
 *     If 5 scans are already running, the 6th blocks at sem_wait() until
 *     one finishes and calls sem_post().
 *
 *   FORK + EXECL (process-level isolation):
 *     Each scan spawns a child process running engine. If engine crashes
 *     or hangs on a malformed file, the parent RTM process is unaffected.
 *     Output is captured via a pipe and forwarded to the Python GUI.
 *
 *   PIPE:
 *     A unidirectional byte channel: write end → kernel buffer → read end.
 *     Used here to capture engine's stdout/stderr and relay it to RTM's
 *     own stdout (which the Python GUI is reading).
 *
 * THREAD SAFETY:
 *   watch_list (the wd→path map) is shared across threads.
 *   map_mutex protects all reads and writes to it.
 *   The semaphore controls how many ScanThreads run concurrently.
 *
 * RECURSIVE WATCHING:
 *   inotify does NOT automatically watch subdirectories. AddWatchRecursively()
 *   walks the entire directory tree at startup and adds a watch for each
 *   subdirectory. When a new subdirectory is created at runtime, it's
 *   immediately added to the watch list too.
 * ═══════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>         // printf, fprintf, fopen, fgets, fflush, perror
#include <stdlib.h>        // malloc, free, strdup, exit
#include <string.h>        // strncpy, strcspn, strstr
#include <pthread.h>       // pthread_create, pthread_detach, pthread_mutex_t
#include <unistd.h>        // read, close, fork, execl, dup2, pipe, getchar
#include <sys/inotify.h>   // inotify_init, inotify_add_watch, inotify_event, IN_* flags
#include <limits.h>        // PATH_MAX — max length of a filesystem path (typically 4096)
#include <errno.h>         // errno — error code set by failed syscalls
#include <sys/wait.h>      // waitpid — reap child process after engine finishes
#include <dirent.h>        // opendir, readdir, closedir — directory traversal
#include <sys/stat.h>      // stat(), S_ISDIR(), S_ISREG() — check file type
#include <stdbool.h>       // bool, true, false
#include <semaphore.h>     // sem_t, sem_init, sem_wait, sem_post, sem_destroy


// ── Constants ──────────────────────────────────────────────────────────────

#define MAX_THREADS 5    // Max concurrent engine scans (semaphore ceiling)
#define MAX_WATCHES 2048 // Max number of directories we can watch simultaneously

// inotify delivers variable-length events. Each event is:
//   sizeof(inotify_event) = fixed header (16 bytes)
//   + event->len bytes    = filename (0 if not applicable)
// NAME_MAX = max filename length (255 on Linux)
#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + NAME_MAX + 1))  // Buffer for ~1024 events at once


// ── Global State ───────────────────────────────────────────────────────────

char exceptions[50][PATH_MAX];         // List of paths to never scan (user exclusions)
int  exCount = 0;                      // How many exceptions are loaded

/*
 * SEMAPHORE — thread_sem
 * Controls how many ScanThreads can run at once.
 * Initialized to MAX_THREADS (5). Think of it as 5 "slots":
 *   - sem_wait(): take a slot (blocks if all 5 are taken)
 *   - sem_post(): release a slot when scan is done
 */
sem_t thread_sem;

/*
 * MUTEX — map_mutex
 * A mutex (mutual exclusion lock) ensures only one thread at a time
 * can read or modify watch_list. Without this, two threads writing
 * simultaneously could corrupt the array (data race).
 * PTHREAD_MUTEX_INITIALIZER sets it up statically without calling mutex_init().
 */
pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;


// ── Watch Descriptor → Path Map ────────────────────────────────────────────

/*
 * inotify_add_watch() returns an integer watch descriptor (wd).
 * When an event fires, we only get the wd + filename — NOT the full path.
 * This map lets us look up "wd 7 → /home/surja/Documents" so we can
 * reconstruct the full path of the file that changed.
 */
typedef struct {
    int  wd;              // Watch descriptor returned by inotify_add_watch()
    char path[PATH_MAX];  // Absolute path of the directory being watched
} WatchMap;

WatchMap watch_list[MAX_WATCHES];  // Static array — no heap alloc needed
int      watch_count = 0;          // Current number of active watches


// ── Safe Path Printer ──────────────────────────────────────────────────────

/*
 * Linux filenames can contain arbitrary bytes (non-UTF-8, control chars, etc.)
 * Printing them raw to the Python GUI can cause the GUI to crash or
 * misparse its input stream.
 * This function prints printable ASCII (0x20–0x7E) as-is,
 * and escapes anything else as \xNN hex — safe for any receiver.
 */
void print_safe_path(const char* path) {
    for (const char* p = path; *p; p++) {
        if ((unsigned char)*p >= 0x20 && (unsigned char)*p < 0x7F)
            putchar(*p);                           // Safe printable ASCII
        else
            printf("\\x%02x", (unsigned char)*p); // Escape as \xNN
    }
    putchar('\n');
    fflush(stdout);  // Force output to reach Python GUI immediately (no buffering delay)
}


// ── Exception / Exclusion List ─────────────────────────────────────────────

/*
 * Reads exceptions.txt line by line.
 * Each line is a path prefix/substring — any path containing it is skipped.
 * strcspn(str, "\n") returns the index of the first '\n', used to strip it.
 * Example exceptions.txt:
 *   /proc
 *   /sys
 *   /home/surja/quarantine    ← critical: prevents RTM from scanning quarantined files
 */
void LoadExceptions() {
    FILE* f = fopen("exceptions.txt", "r");
    if (!f) {
        printf("[!] exceptions.txt not found, no exclusions loaded.\n");
        fflush(stdout);
        return;
    }
    while (exCount < 50 && fgets(exceptions[exCount], PATH_MAX, f)) {
        exceptions[exCount][strcspn(exceptions[exCount], "\n")] = 0;  // Strip trailing newline
        exCount++;
    }
    fclose(f);
    if (exCount > 0)
        printf("[+] Loaded %d exception(s) from exceptions.txt\n", exCount);
    else
        printf("[+] exceptions.txt is empty, no exclusions loaded.\n");
    fflush(stdout);
}


// ── Watch Map Operations (mutex-protected) ─────────────────────────────────

/*
 * Add a new wd→path mapping to the global watch_list.
 * Mutex-locked because multiple MonitorDirectoryThreads (one per directory
 * argument) may call this concurrently during their recursive setup.
 */
void add_to_map(int wd, const char* path) {
    pthread_mutex_lock(&map_mutex);      // Acquire lock — only one thread enters at a time
    if (watch_count < MAX_WATCHES) {
        watch_list[watch_count].wd = wd;
        strncpy(watch_list[watch_count].path, path, PATH_MAX - 1);
        watch_list[watch_count].path[PATH_MAX - 1] = '\0';  // Guarantee null termination
        watch_count++;
    }
    pthread_mutex_unlock(&map_mutex);    // Release lock
}

/*
 * Look up the directory path for a given watch descriptor.
 * Called during event processing to reconstruct the full file path.
 * Returns NULL if wd is not in the map (stale/removed watch).
 * Note: unlocks before returning — caller must not hold the lock already.
 */
const char* get_path_from_wd(int wd) {
    pthread_mutex_lock(&map_mutex);
    for (int i = 0; i < watch_count; i++) {
        if (watch_list[i].wd == wd) {
            pthread_mutex_unlock(&map_mutex);
            return watch_list[i].path;   // Return pointer into the static array
        }
    }
    pthread_mutex_unlock(&map_mutex);
    return NULL;                         // Not found
}


// ── Path Exclusion Check ───────────────────────────────────────────────────

/*
 * Returns true if the given path should be skipped (not scanned).
 * realpath() resolves symlinks and ".." components to get the canonical path.
 * If realpath() fails (file doesn't exist yet), falls back to the raw path.
 * strstr() checks if any exception string appears anywhere in the path.
 * Example: exception="/proc" matches "/proc/1234/maps" via strstr.
 */
bool IsExcluded(const char* path) {
    char absPath[PATH_MAX];
    if (!realpath(path, absPath))                  // Resolve to absolute canonical path
        strncpy(absPath, path, PATH_MAX - 1);      // Fallback: use as-is if realpath fails

    for (int i = 0; i < exCount; i++) {
        if (strstr(absPath, exceptions[i]) != NULL) return true;  // Substring match
    }
    return false;
}


// ── Engine Execution ───────────────────────────────────────────────────────

/*
 * Struct passed to each ScanThread via void* arg.
 * Contains the full path of the file to scan.
 * Heap-allocated so it survives past the calling function's stack frame.
 */
typedef struct {
    char filePath[PATH_MAX];
} ScanArgs;


/*
 * ┌─────────────────────────────────────────────────────────────┐
 * │  ScanThread — runs in its own thread, one per file event   │
 * │                                                             │
 * │  Flow:                                                      │
 * │    1. Create a pipe (pipefd[0]=read, pipefd[1]=write)      │
 * │    2. fork() — split into parent (RTM) and child (engine)  │
 * │    3. Child: redirect stdout/stderr → pipe write end        │
 * │              execl() replaces child with engine binary      │
 * │    4. Parent: read pipe line by line, sanitize, forward     │
 * │               waitpid() reaps child when done              │
 * │    5. sem_post() releases the thread slot                  │
 * └─────────────────────────────────────────────────────────────┘
 *
 * PIPE:
 *   pipefd[1] (write end) → kernel buffer → pipefd[0] (read end)
 *   Child writes to pipefd[1] (its stdout). Parent reads from pipefd[0].
 *   Each side must close the end it doesn't use — otherwise EOF never arrives.
 *
 * FORK:
 *   fork() duplicates the entire process. Both parent and child continue
 *   from the same point. Return value distinguishes them:
 *     pid == 0  → we are the child
 *     pid > 0   → we are the parent, pid = child's PID
 *     pid < 0   → fork failed
 *
 * EXECL:
 *   Replaces the child's memory image with engine binary.
 *   Arguments: path, argv[0] (name), argv[1] (file to scan), NULL sentinel.
 *   If execl succeeds, nothing after it runs — the child IS engine now.
 *   If execl fails (binary not found), perror + exit(1) prevents zombie.
 *
 * DUP2:
 *   dup2(pipefd[1], STDOUT_FILENO) makes file descriptor 1 (stdout)
 *   point to the pipe's write end. So engine's printf() goes into the pipe.
 *   Same for STDERR_FILENO — captures error messages too.
 */
void* ScanThread(void* arg) {
    ScanArgs* data = (ScanArgs*)arg;

    int pipefd[2];                         // pipefd[0]=read end, pipefd[1]=write end
    if (pipe(pipefd) < 0) {
        perror("pipe failed");
        free(data);
        sem_post(&thread_sem);             // Always release slot even on error
        return NULL;
    }

    pid_t pid = fork();                    // Create child process

    if (pid == 0) {
        // ── CHILD PROCESS ──────────────────────────────────────────────────
        close(pipefd[0]);                  // Child doesn't read — close read end
        dup2(pipefd[1], STDOUT_FILENO);    // Redirect child's stdout → pipe write end
        dup2(pipefd[1], STDERR_FILENO);    // Redirect child's stderr → pipe write end
        close(pipefd[1]);                  // Original write end fd no longer needed

        // Replace this process with engine, passing filePath as its argument
        execl("/home/surja/Downloads/Black-Swan-main/engine",
              "engine",          // argv[0]: process name (conventional)
              data->filePath,    // argv[1]: file to scan
              (char*)NULL);      // NULL sentinel: marks end of argument list

        // If execl returns, it failed — engine binary not found or not executable
        perror("execl failed");
        exit(1);  // Exit child — do NOT continue into parent code

    } else if (pid > 0) {
        // ── PARENT PROCESS ─────────────────────────────────────────────────
        close(pipefd[1]);                  // Parent doesn't write — close write end

        char line[4096];
        FILE* engine_out = fdopen(pipefd[0], "r");  // Wrap read fd in a FILE* for fgets
        if (engine_out) {
            while (fgets(line, sizeof(line), engine_out)) {
                // Sanitize control characters (below 0x20) except newline/tab
                // These would corrupt the Python GUI's line-by-line parsing
                for (char* p = line; *p; p++) {
                    if ((unsigned char)*p < 0x20 && *p != '\n' && *p != '\t')
                        *p = '?';          // Replace bad bytes with '?'
                }
                printf("%s", line);        // Forward engine output to Python GUI
                fflush(stdout);
            }
            fclose(engine_out);            // Also closes pipefd[0]
        } else {
            close(pipefd[0]);              // fdopen failed — close manually
        }

        waitpid(pid, NULL, 0);            // Block until child exits — prevents zombie process

    } else {
        // ── FORK FAILED ────────────────────────────────────────────────────
        perror("fork failed");
        close(pipefd[0]);
        close(pipefd[1]);
    }

    free(data);           // Free the heap-allocated ScanArgs
    sem_post(&thread_sem); // Release one semaphore slot — allows next scan to start
    return NULL;
}


/*
 * CallDetectionEngine — entry point for triggering a file scan.
 * Called from the inotify event loop whenever a regular file event fires.
 *
 * Steps:
 *   1. Skip if path is in exceptions list
 *   2. Heap-allocate ScanArgs (so it survives thread creation)
 *   3. sem_wait() — block if MAX_THREADS scans are already running
 *   4. Create a detached thread running ScanThread
 *      "detached" = thread cleans up its own resources when done,
 *      no need for pthread_join() from the parent thread
 */
void CallDetectionEngine(const char* filePath) {
    if (IsExcluded(filePath)) return;

    ScanArgs* args = malloc(sizeof(ScanArgs));
    if (!args) {
        fprintf(stderr, "[-] malloc failed for ScanArgs\n");
        fflush(stderr);
        return;
    }
    strncpy(args->filePath, filePath, PATH_MAX - 1);
    args->filePath[PATH_MAX - 1] = '\0';

    sem_wait(&thread_sem);  // Block here if 5 scans are already running

    pthread_t scanThread;
    if (pthread_create(&scanThread, NULL, ScanThread, args) == 0) {
        pthread_detach(scanThread);    // Don't need to join — let it clean itself up
    } else {
        perror("pthread_create failed");
        free(args);
        sem_post(&thread_sem);         // Creation failed — release slot immediately
    }
}


// ── Recursive Directory Watching ───────────────────────────────────────────

/*
 * Registers inotify watches for basePath and ALL subdirectories recursively.
 * Called once at startup for each command-line directory argument.
 * Also called at runtime when IN_CREATE/IN_MOVED_TO fires for a new directory.
 *
 * inotify_add_watch() flags used:
 *   IN_CREATE      — a file/dir was created inside the watched directory
 *   IN_CLOSE_WRITE — a file that was open for writing has been closed
 *                    (safer than IN_MODIFY which fires on every write syscall)
 *   IN_MOVED_TO    — a file/dir was moved INTO this directory (mv command)
 *
 * We do NOT watch IN_MODIFY to avoid thrashing on large file writes.
 * IN_CLOSE_WRITE ensures the file is fully written before scanning.
 */
void AddWatchRecursively(int fd, const char* basePath) {
    if (IsExcluded(basePath)) return;   // Skip excluded paths entirely

    // Register inotify watch — returns watch descriptor (positive int) or -1
    int wd = inotify_add_watch(fd, basePath, IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO);
    if (wd < 0) return;                 // Permission denied, broken path, etc. — skip silently

    add_to_map(wd, basePath);           // Record wd→path so events can be resolved later

    // Walk subdirectories
    DIR* dir = opendir(basePath);
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;  // Skip "." ".." and hidden dirs

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", basePath, entry->d_name);

        struct stat st;
        // stat() follows symlinks (lstat would not). S_ISDIR checks directory bit.
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
            AddWatchRecursively(fd, path);   // Recurse into subdirectory
    }
    closedir(dir);
}


// ── Directory Monitor Thread ───────────────────────────────────────────────

/*
 * One of these threads runs per command-line directory argument.
 * It owns a private inotify file descriptor and event loop.
 * Multiple directories are monitored in true parallel — separate threads,
 * separate inotify fds, no sharing except the watch_list map (mutex-protected).
 *
 * EVENT LOOP:
 *   read() on an inotify fd BLOCKS until at least one event is available.
 *   When events arrive, they're packed back-to-back in the buffer.
 *   We walk the buffer by jumping EVENT_SIZE + event->len bytes each iteration.
 *   event->len is the length of the filename field (0 if no filename).
 *
 * EINTR handling:
 *   read() can be interrupted by signals (EINTR error). We simply retry — 
 *   this is the standard pattern for interruptible blocking syscalls.
 */
void* MonitorDirectoryThread(void* arg) {
    char* directoryPath = (char*)arg;   // Heap-allocated by main(), we free it at end

    int fd = inotify_init();            // Create a new inotify instance — returns a file descriptor
    if (fd < 0) {
        perror("inotify_init");
        free(directoryPath);
        return NULL;
    }

    AddWatchRecursively(fd, directoryPath);   // Register watches for entire subtree

    printf("[+] Monitoring: %s\n", directoryPath);
    fflush(stdout);

    char buffer[BUF_LEN];   // Raw event buffer — holds multiple inotify_event structs

    while (1) {   // Infinite event loop — runs until RTM exits or fd is closed
        // read() blocks here until kernel has filesystem events to deliver
        ssize_t length = read(fd, buffer, BUF_LEN);

        if (length < 0) {
            if (errno == EINTR) continue;   // Interrupted by signal — retry
            perror("read inotify");
            break;                          // Real error — exit loop
        }

        // Walk packed events in buffer
        ssize_t i = 0;
        while (i < length) {
            // Cast current buffer position to inotify_event pointer (no copy needed)
            struct inotify_event* event = (struct inotify_event*)&buffer[i];

            if (event->len > 0) {           // event->len > 0 means a filename is present
                const char* parent = get_path_from_wd(event->wd);  // Resolve wd → directory path
                if (!parent) {
                    i += EVENT_SIZE + event->len;
                    continue;               // Stale watch descriptor — skip
                }

                // Reconstruct full path: parent directory + "/" + event filename
                char fullPath[PATH_MAX];
                snprintf(fullPath, sizeof(fullPath), "%s/%s", parent, event->name);

                if (!IsExcluded(fullPath)) {
                    struct stat st;
                    if (stat(fullPath, &st) == 0) {

                        if (S_ISDIR(st.st_mode)) {
                            // New directory created or moved in — watch it recursively
                            if (event->mask & (IN_CREATE | IN_MOVED_TO))
                                AddWatchRecursively(fd, fullPath);

                        } else if (S_ISREG(st.st_mode)) {
                            // Regular file — log it and trigger a scan
                            printf("[+] Event detected: ");
                            print_safe_path(fullPath);       // Safe UTF-8 output to GUI
                            CallDetectionEngine(fullPath);   // Spawn engine on this file
                        }
                        // Symlinks, devices, sockets etc. are intentionally ignored
                    }
                }
            }

            i += EVENT_SIZE + event->len;   // Advance to next event in buffer
        }
    }

    close(fd);            // Close inotify fd — removes all watches associated with it
    free(directoryPath);  // Free the strdup'd path from main()
    return NULL;
}


// ── Main ───────────────────────────────────────────────────────────────────

/*
 * Entry point.
 * Accepts one or more directory paths as arguments.
 * Spawns one MonitorDirectoryThread per directory.
 * Runs until user presses 'q' + Enter.
 *
 * setvbuf(stdout, NULL, _IONBF, 0):
 *   Disables stdout buffering entirely (_IONBF = unbuffered).
 *   Without this, printf output sits in a libc buffer and the Python GUI
 *   would not see it until the buffer fills or fflush is called.
 *   Critical for real-time output to the GUI.
 *
 * strdup():
 *   Allocates a heap copy of the string. Needed because argv[i] is
 *   stack memory in main — passing it to a thread that outlives main's
 *   stack frame would be a use-after-free bug. The thread frees it when done.
 *
 * pthread_detach():
 *   Tells the system this thread won't be joined. Resources are freed
 *   automatically when it exits. Without detach or join, the thread's
 *   resources (stack, etc.) leak until the process exits.
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory1> [directory2] ...\n", argv[0]);
        return 1;
    }

    // Disable stdout buffering — Python GUI reads RTM's stdout line-by-line
    setvbuf(stdout, NULL, _IONBF, 0);

    // Initialize semaphore: 0 = not shared between processes, MAX_THREADS = initial count
    sem_init(&thread_sem, 0, MAX_THREADS);

    LoadExceptions();   // Load exclusion list before any threads start

    // Spawn one monitor thread per directory argument
    for (int i = 1; i < argc; i++) {
        pthread_t tid;
        char* path_copy = strdup(argv[i]);   // Heap copy — thread will free it
        if (!path_copy) {
            fprintf(stderr, "[-] strdup failed\n");
            continue;
        }
        if (pthread_create(&tid, NULL, MonitorDirectoryThread, path_copy) != 0) {
            perror("pthread_create for monitor thread");
            free(path_copy);      // Thread never started — free here instead
        } else {
            pthread_detach(tid);  // We won't join this thread — let it self-clean
        }
    }

    printf("RTM Running. Press 'q' to quit.\n");
    fflush(stdout);

    // Block main thread waiting for 'q' or EOF (Ctrl+D)
    // All real work happens in the monitor threads above
    int c;
    while ((c = getchar()) != EOF && c != 'q');

    sem_destroy(&thread_sem);   // Clean up semaphore resources
    return 0;
    // Note: monitor threads are not explicitly stopped — they're killed when
    // the process exits. A production AV would signal threads to stop cleanly.
  /*Why inotify instead of polling? Polling (checking every file every N seconds) wastes CPU and introduces a detection delay. inotify is event-driven — the kernel tells RTM the instant something changes, with zero CPU cost while nothing is happening.
Why fork+execl instead of calling engine directly? If engine crashes on a malformed/malicious file, the RTM process stays alive. Process isolation is a fundamental AV design principle — the scanner dying shouldn't kill the monitor.
Why IN_CLOSE_WRITE instead of IN_MODIFY? IN_MODIFY fires on every write() syscall — a 100MB file copy would trigger hundreds of scans of incomplete data. IN_CLOSE_WRITE fires exactly once when the file is fully written and closed. Much more efficient and correct.
The semaphore is the throttle. Without it, 500 files appearing at once (e.g. extracting a zip) would spawn 500 threads simultaneously, crashing the system. The semaphore ensures at most 5 engine processes run at any moment.*/
}
