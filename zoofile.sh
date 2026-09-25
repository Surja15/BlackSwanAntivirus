#!/usr/bin/env bash
# flatten_corpus.sh
# Recursively finds password-protected zip samples under a source directory
# (e.g. a clone of theZoo), extracts them, and copies every resulting file
# into one flat output folder for easier batch scanning.
#
# SAFETY: run this only inside a disposable/snapshot VM or container with
# no shared folders and no network beyond what you need. Do not run on
# your host machine. Wipe/revert the VM afterward.
#
# Usage: ./flatten_corpus.sh <source_dir> <output_dir> [zip_password]

set -euo pipefail

SRC_DIR="${1:?Usage: $0 <source_dir> <output_dir> [zip_password]}"
OUT_DIR="${2:?Usage: $0 <source_dir> <output_dir> [zip_password]}"
ZIP_PASS="${3:-infected}"   # theZoo's documented standard archive password

mkdir -p "$OUT_DIR"
TMP_EXTRACT=$(mktemp -d)
MANIFEST="$OUT_DIR/manifest.csv"
echo "flattened_name,original_path" > "$MANIFEST"

trap 'rm -rf "$TMP_EXTRACT"' EXIT

count=0
skipped=0

find "$SRC_DIR" -type f -iname "*.zip" | while IFS= read -r zipfile; do
    work="$TMP_EXTRACT/$(basename "${zipfile%.zip}")_$$_$RANDOM"
    mkdir -p "$work"

    # Try the standard password first; fall back to no password.
    if ! unzip -qq -P "$ZIP_PASS" -o "$zipfile" -d "$work" 2>/dev/null; then
        if ! unzip -qq -o "$zipfile" -d "$work" 2>/dev/null; then
            echo "  [skip] could not extract: $zipfile" >&2
            skipped=$((skipped + 1))
            rm -rf "$work"
            continue
        fi
    fi

    # Flatten every extracted file into OUT_DIR with a collision-safe name.
    find "$work" -type f | while IFS= read -r f; do
        base=$(basename "$f")
        # Prefix with a short hash of the full path so identical filenames
        # from different samples don't overwrite each other.
        prefix=$(echo "$f" | sha1sum | cut -c1-8)
        target="$OUT_DIR/${prefix}_${base}"
        cp -n "$f" "$target"
        echo "${prefix}_${base},${f#$work/}" >> "$MANIFEST"
        count=$((count + 1))
    done

    rm -rf "$work"
done

echo ""
echo "Done. Flattened files are in: $OUT_DIR"
echo "Manifest (flattened name -> original relative path): $MANIFEST"
echo "Skipped archives (bad password / corrupt): $skipped"
