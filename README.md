#  BLACK SWAN Antivirus
## Real-Time Malware Detection, Quarantine, and Recovery System for Linux

Black Swan AV is a fully custom-built antivirus system for Linux written entirely in C with a Python GUI.  
The project combines:

- Signature-based malware detection using YARA
- Real-time filesystem monitoring using `inotify`
- Recursive directory scanning using DFS traversal
- Encrypted quarantine isolation
- Secure file restoration and recovery

The antivirus is designed to simulate core architectural components of modern endpoint protection systems while remaining lightweight, modular, and transparent.

---

# 📌 Core Features

- 🔍 YARA-based malware signature detection
- ⚡ Real-Time Monitoring (RTM)
- 🧠 Multi-threaded scan execution
- 🔐 Encrypted quarantine vault
- ♻️ Secure restoration mechanism
- 🧾 Quarantine logging system
- 🐧 Linux-native implementation
- 🧱 Modular architecture in pure C
- 🚫 Symbolic-link traversal protection
- 🛡️ Directory boundary enforcement
- 📂 Recursive DFS scanning
- 🚨 Automatic threat isolation

---

# 🏗️ System Architecture

```text id="2u7gl6"
                    ┌────────────────────┐
                    │    RTM (rtm.c)    │
                    │  inotify monitor  │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │  ENGINE (engine.c) │
                    │   YARA Scanner     │
                    └─────────┬──────────┘
                              │
                    Malware Match Found
                              │
                              ▼
                    ┌────────────────────┐
                    │ QUARANTINE SYSTEM  │
                    │  quarantine.c      │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │ RESTORE MODULE     │
                    │   restore.c        │
                    └────────────────────┘
```

---

# 📂 Project Structure

```text id="t4tv9f"
BLACK-SWAN-AV/
│
├── engine.c
├── quarantine.c
├── restore.c
├── rtm.c
│
├── myrule/
│   └── compiled/
│       ├── trojan.yarac
│       ├── ransomware.yarac
│       └── ...
│
├── quarantine/
│   ├── quarantine_log.txt
│   ├── 20260509_001212_a
│   └── 20260509_001212_b
│
├── exceptions.txt
└── README.md
```

---

# 🔍 Detection Engine (`engine.c`)

The engine is the malware scanning core of Black Swan AV.

It:
- Loads compiled `.yarac` rules dynamically
- Scans files and directories recursively
- Uses YARA callback-based rule matching
- Triggers quarantine automatically on detection

---

## ✅ YARA Rule Loading

The engine loads all compiled rules from:

```text id="oqjsg7"
/myrule/compiled/
```

Each rule file is loaded using:

```c id="cc4jgf"
yr_rules_load(rule_file, &rules_list[rules_count])
```

This allows modular signature expansion without modifying engine logic.

---

## ✅ Recursive DFS Directory Traversal

The scanner performs recursive traversal using a Depth-First Search (DFS) strategy.

### Example

```text id="1ggm4n"
/downloads
├── folder1
│   ├── file.exe
│   └── nested/
│       └── malware.bin
└── folder2
```

DFS ensures:
- deep directory coverage
- systematic traversal
- low memory overhead

---

## ✅ Symbolic Link Protection

The engine explicitly ignores symbolic links:

```c id="0jefrd"
if (S_ISLNK(st.st_mode))
    continue;
```

This prevents:
- recursive loop attacks
- path escape attempts
- traversal outside scan boundaries

---

## ✅ Boundary Enforcement

The scanner resolves absolute paths using:

```c id="9g8wmp"
realpath()
```

and prevents traversal outside the original target directory.

This protects against:
- symlink redirection
- filesystem escape attacks
- unintended recursive scans

---

## ✅ YARA Callback Matching

The engine uses:

```c id="bq3mh4"
CALLBACK_MSG_RULE_MATCHING
```

to capture malware rule matches dynamically.

Matched rule identifiers are stored in:

```c id="d1y77o"
MatchList
```

and forwarded to quarantine.

---

# ⚡ Real-Time Monitor (`rtm.c`)

The RTM module provides continuous filesystem protection using Linux `inotify`.

It monitors:
- file creation
- file movement
- file write completion

---

# 🔄 RTM Workflow

```text id="jqb6x0"
Filesystem Event
       ↓
inotify captures event
       ↓
RTM reconstructs full path
       ↓
Thread created
       ↓
engine.c executed
       ↓
Threat detected
       ↓
Automatic quarantine
```

---

## ✅ Multi-Threaded Scan Execution

RTM uses:
- POSIX threads (`pthread`)
- semaphores (`sem_t`)
- detached worker threads

to allow concurrent scans.

Maximum simultaneous scan threads:

```c id="9jlwmj"
#define MAX_THREADS 5
```

---

## ✅ Engine Invocation

RTM launches the detection engine using:

```c id="w6r8jz"
execl("/home/surja/Downloads/Black-Swan-main/engine", ...)
```

Each suspicious file is scanned independently.

---

## ✅ Watch Descriptor Mapping

The RTM maintains an internal mapping:

```c id="55lk4g"
WatchMap watch_list[MAX_WATCHES]
```

This reconstructs filesystem paths from raw inotify watch descriptors.

---

## ✅ Recursive Watch Addition

New directories created during runtime are automatically added to monitoring.

This enables:
- dynamic directory coverage
- persistent recursive monitoring

---

## ✅ Exception Handling

RTM supports exclusion rules using:

```text id="92xgpf"
exceptions.txt
```

Excluded paths are skipped automatically.

---

# 🔐 Quarantine System (`quarantine.c`)

The quarantine module isolates infected files securely instead of deleting them immediately.

---

# 🔒 Encryption Design

The quarantine system uses a custom XOR-keystream encryption model inspired by ChaCha20-style stream cipher concepts.

The design combines:
- master key
- nonce
- counter
- keystream generation

---

## ✅ Keystream Generator

The keystream is generated using:

```c id="nxbmav"
keystream_prng()
```

Internal state is mixed using:
- master key bytes
- nonce values
- byte position counters
- xorshift-style avalanche mixing

---

## ✅ Encryption Formula

Each file byte is transformed independently:

```text id="b7fgpc"
encrypted_byte =
original_byte XOR keystream_byte
```

Since XOR is symmetric:

```text id="d7tq1v"
cipher XOR keystream = original
```

the same operation decrypts the file during restoration.

---

## ✅ Nonce-Based Isolation

A random 7-digit nonce is generated for every quarantined file:

```c id="bqf2lc"
1000000 → 9999999
```

This ensures:
- unique keystreams
- prevention of keystream reuse
- different encryption output even for identical files

---

## ✅ Counter-Based Byte Transformation

Each byte position acts as a counter input:

```text id="e7i5fy"
counter = file byte offset
```

Meaning:
- byte 0 uses counter 0
- byte 700 uses counter 700
- every byte gets a unique keystream byte

---

# 🧩 File Splitting Mechanism

After encryption, the quarantined file is divided into multiple parts:

```c id="s4t8u0"
#define PARTS 2
```

Example:

```text id="7ahxlo"
20260509_101010_a
20260509_101010_b
```

This is designed to:
- reduce single-file exposure
- complicate malware targeting
- isolate encrypted fragments

---

# 🧾 Quarantine Logging

All quarantine operations are logged in:

```text id="5twf6w"
quarantine_log.txt
```

Example entry:

```text id="kqvbqe"
[2026-05-09 14:30:22]
test.exe|20260509_143022|
20260509_143022_a,20260509_143022_b|
TrojanRule|4821934
```

The log stores:
- original filename
- quarantine timestamp
- quarantine fragments
- matched malware rules
- nonce value

---

# ♻️ Restore System (`restore.c`)

The restore module reconstructs quarantined files securely.

---

# 🔄 Restoration Workflow

```text id="5w8x4y"
User Authentication
        ↓
Log Lookup
        ↓
Locate File Fragments
        ↓
Recombine Parts
        ↓
Regenerate Keystream
        ↓
Decrypt File
        ↓
Restore Original File
```

---

## ✅ Authentication

The restore tool requires:
- master key verification

before restoration is allowed.

---

## ✅ Keystream Regeneration

The restore process regenerates the identical keystream using:
- master key
- nonce
- byte counter sequence

Without identical regeneration, decryption fails.

---

## ✅ GUI + Console Support

Restore supports:
- Zenity GUI dialogs
- console fallback mode

depending on Linux environment availability.

---

## ✅ Restoration Audit Logging

Successful restores append:

```text id="6n2a7o"
|RESTORED|timestamp
```

to quarantine log entries.

This creates a restoration audit trail.

---

# 🧪 Compilation

## Install Dependencies

### Ubuntu / Debian

```bash id="g3v6q2"
sudo apt update
sudo apt install yara libyara-dev build-essential zenity
```

---

## Compile Engine

```bash id="7m4krd"
gcc engine.c quarantine.c -o engine -lyara
```

---

## Compile RTM

```bash id="1slw1v"
gcc rtm.c -o rtm -lpthread
```

---

## Compile Restore Tool

```bash id="xfj0ht"
gcc restore.c -o restore
```

---

# 🚀 Usage

## Scan Single File

```bash id="aqw1ob"
./engine suspicious.exe
```

---

## Scan Directory

```bash id="r0m5f7"
./engine /home/user/downloads
```

---

## Start Real-Time Monitoring

```bash id="h3xwjj"
./rtm /home/user/downloads
```

---

## Restore Quarantined File

```bash id="o5g2p9"
./restore test.exe
```

---

# 🧠 Technologies Used

| Technology | Purpose |
|---|---|
| C | Core implementation |
| YARA | Malware signature detection |
| inotify | Real-time monitoring |
| POSIX Threads | Concurrent scanning |
| XOR Stream Encryption | Quarantine isolation |
| DFS Traversal | Recursive scanning |
| Zenity | GUI restore interface |

---

# 🔒 Security Design Notes

- Recursive scan boundary enforcement prevents escape traversal
- Symbolic links are ignored for safety
- Real-time monitoring reacts instantly to filesystem changes
- Quarantined files are encrypted before storage
- File splitting reduces direct exposure risk
- Restore operations require authentication
- Restoration activity is logged

---

# 📈 Future Improvements

- Heuristic malware detection
- Behavioral analysis engine
- Full ChaCha20 implementation
- Hash reputation system
- Signature auto-updates
- Multi-engine scanning
- Sandbox execution
- Kernel-level hooks
- Centralized dashboard

---

# 📚 Educational Purpose

Black Swan AV was developed as an educational and research-oriented cybersecurity project focused on understanding:

- antivirus engine design
- malware signature analysis
- filesystem event monitoring
- stream cipher concepts
- secure quarantine systems
- restoration pipelines
- Linux security architecture

---

# 👨‍💻 Author

**Surja Sekhar Sengupta**  
Linux Malware Detection & Response Project

---

# 📜 License

This project is intended strictly for:
- academic
- educational
- cybersecurity research

purposes only.

Use responsibly.
