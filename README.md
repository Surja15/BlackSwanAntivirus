# 🦢 BLACK SWAN AV
### Real-Time Malware Detection, Quarantine, and Recovery System for Linux

Black Swan AV is a custom-built antivirus engine written entirely in C for Linux systems.  
It combines static malware detection using YARA signatures with real-time filesystem monitoring, encrypted quarantine isolation, and secure restoration mechanisms.

The project is designed to demonstrate how modern antivirus components work internally — from detection pipelines to encrypted containment and recovery.

---

# 📌 Features

- 🔍 Signature-based malware detection using YARA
- ⚡ Real-Time Monitoring (RTM) using Linux `inotify`
- 🧪 Recursive directory scanning with DFS traversal
- 🔐 Secure encrypted quarantine system
- ♻️ File restoration and recovery engine
- 🧾 Quarantine logging and metadata tracking
- 🐧 Lightweight Linux-native architecture
- 🧱 Modular C-based design

---

# 🏗️ Architecture

```text
                +-------------------+
                |   RTM (rtm.c)     |
                | inotify watcher   |
                +---------+---------+
                          |
                          v
                +-------------------+
                |   ENGINE (engine.c)|
                | YARA Scan Engine  |
                +---------+---------+
                          |
            Malware Found |
                          v
                +-------------------+
                | QUARANTINE        |
                | quarantine.c      |
                +---------+---------+
                          |
                          v
                +-------------------+
                | RESTORE           |
                | restore.c         |
                +-------------------+
📂 Project Structure
BLACK-SWAN-AV/
│
├── engine.c           # Core scanning engine
├── rtm.c              # Real-time monitor
├── quarantine.c       # Encrypted quarantine module
├── restore.c          # File restoration module
│
├── rules/
│   ├── malware.yar    # YARA rules
│   └── ...
│
├── quarantine/
│   ├── vault/         # Encrypted isolated files
│   └── quarantine.log
│
├── samples/           # Test malware samples
│
├── Makefile
└── README.md
🔍 Detection Engine (engine.c)

The engine is the detection brain of Black Swan AV.

It:

Loads compiled YARA rules
Recursively scans files/directories
Matches malware signatures
Triggers quarantine when a threat is detected
Key Concepts
✅ YARA Rule Matching

YARA acts like a malware fingerprinting engine.

Example:

rule Trojan_Test
{
    strings:
        $a = "malicious_code"

    condition:
        $a
}

If a scanned file contains the matching signature, the engine flags it as malicious.

✅ DFS-Based Recursive Scanning

The engine uses Depth-First Search (DFS) traversal to recursively scan nested directories.

Example:

/home/user/
├── folder1/
│   └── infected.exe
└── folder2/

DFS ensures every subdirectory is explored before returning.

⚡ Real-Time Monitor (rtm.c)

The RTM module continuously watches directories using Linux inotify.

Whenever a file is:

created
modified
moved

the RTM automatically triggers the scanning engine.

Flow
Filesystem Event
       ↓
RTM receives event
       ↓
Path reconstructed
       ↓
engine.c executed
       ↓
Threat scanned instantly

This creates real-time protection behavior similar to modern antivirus software.

🔐 Quarantine System (quarantine.c)

The quarantine module securely isolates infected files instead of deleting them immediately.

Process
Original file is read
File data is encrypted
Encrypted file moved to quarantine vault
Metadata logged
Original file removed
Encryption Design

The quarantine system uses:

XOR byte transformation
nonce values
counters
keystream generation

Each byte is transformed uniquely using:

encrypted_byte =
original_byte XOR keystream_byte

This prevents direct recovery without restoration logic.

Quarantine Metadata

Example log entry:

[2026-05-09]
Original: /home/user/test.exe
Stored: quarantine/vault/ab12.qnt
Nonce: 92831
Status: QUARANTINED
♻️ Restore System (restore.c)

The restore module decrypts quarantined files and reconstructs them safely.

Restore Steps
Read quarantine metadata
Regenerate keystream
Reverse XOR transformation
Restore original file bytes
Recreate original file path
Why Keystream Regeneration Matters

Restoration requires the same:

master key
nonce
counter sequence

Without identical keystream regeneration, original bytes cannot be reconstructed correctly.

🧪 Compilation
Install Dependencies
Ubuntu / Debian
sudo apt update
sudo apt install yara libyara-dev build-essential
Compile Engine
gcc engine.c quarantine.c -o engine -lyara
Compile RTM
gcc rtm.c -o rtm
Compile Restore
gcc restore.c -o restore
