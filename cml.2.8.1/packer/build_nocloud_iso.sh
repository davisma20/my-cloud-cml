#!/bin/bash
# Script to generate a NoCloud seed ISO for CML 2.8.1 cloud-init automation
set -e

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_DATA="$SCRIPT_DIR/user-data"
META_DATA="$SCRIPT_DIR/meta-data"
SEED_ISO="$SCRIPT_DIR/seed.iso"

# Prefer genisoimage, fallback to mkisofs (macOS/Homebrew)
if command -v genisoimage >/dev/null 2>&1; then
    ISO_CMD=genisoimage
elif command -v mkisofs >/dev/null 2>&1; then
    ISO_CMD=mkisofs
else
    echo "Neither genisoimage nor mkisofs found. Please install one (brew install cdrtools or apt-get install genisoimage)."
    exit 1
fi

if [ ! -f "$USER_DATA" ] || [ ! -f "$META_DATA" ]; then
    echo "user-data or meta-data file missing in $SCRIPT_DIR."
    exit 2
fi

echo "Generating NoCloud ISO: $SEED_ISO using $ISO_CMD"
$ISO_CMD -output "$SEED_ISO" -volid cidata -joliet -rock "$USER_DATA" "$META_DATA"
echo "Done. Attach $SEED_ISO as a secondary CD-ROM for cloud-init."
