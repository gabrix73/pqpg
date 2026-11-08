#!/bin/bash
# pqpg-encrypt-folder.sh - Encrypt folder(s) into .tar.pqpg with PQPG
# Usage: pqpg-encrypt-folder.sh <folder1> [folder2] ...

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/pqpg-common.sh"

if [ $# -eq 0 ]; then
    zenity --error --title="PQPG Tools" --text="Nessuna cartella selezionata."
    exit 1
fi

check_selection_type "$@"

for TARGET in "$@"; do
    if [ ! -d "$TARGET" ]; then
        zenity --error --title="PQPG Tools" \
            --text="La selezione contiene file normali:\n$(basename "$TARGET")\n\nQuesta azione è riservata esclusivamente alle cartelle."
        exit 1
    fi
done

RECIPIENT_KEY="$(select_recipient)"
if [ -z "$RECIPIENT_KEY" ]; then
    exit 0
fi

ENCRYPTED_COUNT=0
for TARGET in "$@"; do
    if [ ! -d "$TARGET" ]; then
        continue
    fi

    DIR_NAME="$(dirname "$TARGET")"
    BASE_NAME="$(basename "$TARGET")"
    OUTPUT="${TARGET}.tar.pqpg"

    tar czf - -C "$DIR_NAME" "$BASE_NAME" | "$PQPG_BIN" encrypt -r "$RECIPIENT_KEY" -o "$OUTPUT"
    ENCRYPTED_COUNT=$((ENCRYPTED_COUNT + 1))
done

thunar --reload 2>/dev/null || true

RECIPIENT_NAME="$(basename "$RECIPIENT_KEY" .pub)"
zenity --info --title="PQPG Tools" \
    --text="✓ Cifrate con successo $ENCRYPTED_COUNT cartelle.\n\nDestinatario: $RECIPIENT_NAME\nArchivio creato: .tar.pqpg"
