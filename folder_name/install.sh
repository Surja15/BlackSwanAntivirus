#!/bin/bash
# Black Swan AV — Installer - just an experiment for one click install of project
# Run with: bash install.sh

set -e  # stop on any error

# ─── Colors ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}[*] Black Swan AV Installer${NC}"
echo "------------------------------------"

# ─── 1. Detect user and set install path ───────────────────────────────────
INSTALL_DIR="$HOME/blackswan"
RULES_DIR="$INSTALL_DIR/myrule"
COMPILED_DIR="$RULES_DIR/compiled"
QUARANTINE_DIR="$HOME/quarantine"
RULES_REPO="https://github.com/YOUR_USERNAME/YOUR_RULES_REPO/archive/refs/heads/main.zip"
# ^^^ will replace with my compiled rules file once i make public git

echo -e "${CYAN}[*] Installing to: $INSTALL_DIR${NC}"
echo -e "${CYAN}[*] Detected user: $USER${NC}"

# ─── 2. Install system dependencies ───────────────────────────────────────
echo -e "\n${CYAN}[*] Installing dependencies...${NC}"
sudo apt update -qq
sudo apt install -y gcc make python3 python3-pip libyara-dev yara git unzip wget

# ─── 3. Install Python dependencies ───────────────────────────────────────
echo -e "\n${CYAN}[*] Installing Python packages...${NC}"
pip install pillow --quiet

# ─── 4. Create folder structure ───────────────────────────────────────────
echo -e "\n${CYAN}[*] Creating folder structure...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$COMPILED_DIR"
mkdir -p "$QUARANTINE_DIR"

# ─── 5. Copy project files ────────────────────────────────────────────────
echo -e "\n${CYAN}[*] Copying project files...${NC}"
# Assumes install.sh is run from the project folder
cp engine.c "$INSTALL_DIR/"
cp quarantine.c "$INSTALL_DIR/"
cp rtm.c "$INSTALL_DIR/"
cp restore.c "$INSTALL_DIR/"
cp gui.py "$INSTALL_DIR/"
cp exceptions.txt "$INSTALL_DIR/" 2>/dev/null || touch "$INSTALL_DIR/exceptions.txt"
cp -r images "$INSTALL_DIR/" 2>/dev/null || echo "[!] No images folder found, skipping"

# ─── 6. Patch hardcoded paths in source files ─────────────────────────────
echo -e "\n${CYAN}[*] Patching paths for user: $USER${NC}"

# engine.c — rules dir
sed -i "s|/home/surja/Downloads/Black-Swan-main/myrule/compiled/|$COMPILED_DIR/|g" "$INSTALL_DIR/engine.c"

# quarantine.c — quarantine dir
sed -i "s|/home/surja/quarantine|$QUARANTINE_DIR|g" "$INSTALL_DIR/quarantine.c"

# restore.c — quarantine dir
sed -i "s|/home/surja/quarantine|$QUARANTINE_DIR|g" "$INSTALL_DIR/restore.c"

# rtm.c — engine path
sed -i "s|/home/surja/Downloads/Black-Swan-main/engine|$INSTALL_DIR/engine|g" "$INSTALL_DIR/rtm.c"

# gui.py — engine and rtm paths
sed -i "s|ENGINE_PATH.*=.*|ENGINE_PATH = \"$INSTALL_DIR/engine\"|g" "$INSTALL_DIR/gui.py"
sed -i "s|ENGINE_RTM_PATH.*=.*|ENGINE_RTM_PATH = \"$INSTALL_DIR/rtm\"|g" "$INSTALL_DIR/gui.py"

# ─── 7. Download and compile YARA rules ───────────────────────────────────
echo -e "\n${CYAN}[*] Downloading YARA rules...${NC}"
wget -q "$RULES_REPO" -O /tmp/rules.zip
unzip -q /tmp/rules.zip -d /tmp/rules_extracted
# Move all .yar files into myrule/
find /tmp/rules_extracted -name "*.yar" -exec cp {} "$RULES_DIR/" \;
rm -rf /tmp/rules.zip /tmp/rules_extracted

echo -e "\n${CYAN}[*] Compiling YARA rules...${NC}"
cd "$RULES_DIR"
for f in *.yar; do
    [ -f "$f" ] || continue
    yarac "$f" "$COMPILED_DIR/${f%.yar}.yarac" 2>/dev/null && \
        echo -e "  ${GREEN}[+] Compiled: $f${NC}" || \
        echo -e "  ${RED}[-] Failed: $f${NC}"
done
cd "$INSTALL_DIR"

# ─── 8. Compile C binaries ────────────────────────────────────────────────
echo -e "\n${CYAN}[*] Compiling engine...${NC}"
gcc "$INSTALL_DIR/engine.c" "$INSTALL_DIR/quarantine.c" -o "$INSTALL_DIR/engine" -lyara
echo -e "${GREEN}[+] Engine compiled${NC}"

echo -e "\n${CYAN}[*] Compiling RTM...${NC}"
gcc "$INSTALL_DIR/rtm.c" -o "$INSTALL_DIR/rtm" -lpthread
echo -e "${GREEN}[+] RTM compiled${NC}"

echo -e "\n${CYAN}[*] Compiling restore utility...${NC}"
gcc "$INSTALL_DIR/restore.c" -o "$INSTALL_DIR/restore"
echo -e "${GREEN}[+] Restore compiled${NC}"

# ─── 9. Set permissions ───────────────────────────────────────────────────
chmod +x "$INSTALL_DIR/engine"
chmod +x "$INSTALL_DIR/rtm"
chmod +x "$INSTALL_DIR/restore"

# ─── 10. Lock quarantine log (append-only) ────────────────────────────────
touch "$QUARANTINE_DIR/quarantine_log.txt"
sudo chattr +a "$QUARANTINE_DIR/quarantine_log.txt"
echo -e "${GREEN}[+] Quarantine log protected${NC}"

# ─── 11. Create desktop launcher ──────────────────────────────────────────
echo -e "\n${CYAN}[*] Creating desktop launcher...${NC}"
DESKTOP_FILE="$HOME/Desktop/BlackSwanAV.desktop"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Version=1.0
Name=Black Swan AV
Comment=Black Swan Antivirus
Exec=python3 $INSTALL_DIR/gui.py
Icon=$INSTALL_DIR/images/icon.png
Terminal=false
Type=Application
Categories=Utility;Security;
EOF
chmod +x "$DESKTOP_FILE"

# ─── Done ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}======================================"
echo -e "  Black Swan AV installed successfully"
echo -e "  Location : $INSTALL_DIR"
echo -e "  Launch   : python3 $INSTALL_DIR/gui.py"
echo -e "  Desktop  : BlackSwanAV shortcut created"
echo -e "======================================${NC}"
