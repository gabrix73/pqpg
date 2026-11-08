#!/bin/bash
# pqpg-decrypt.sh - Decrypt .pqpg and .tar.pqpg with PQPG
# Usage: pqpg-decrypt.sh <file1.pqpg> [file2.pqpg] ...

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/pqpg-common.sh"

if [ $# -eq 0 ]; then
    zenity --error --title="PQPG Tools" --text="Nessun file selezionato."
    exit 1
fi

check_selection_type "$@"
ensure_keypair

DECRYPTED_COUNT=0
FAILED_COUNT=0

for TARGET in "$@"; do
    if [ ! -f "$TARGET" ]; then
        continue
    fi

    if [[ "$TARGET" != *.pqpg ]]; then
        FAILED_COUNT=$((FAILED_COUNT + 1))
        continue
    fi

    if [[ "$TARGET" == *.tar.pqpg ]]; then
        DEST_DIR="$(dirname "$TARGET")"
        if "$PQPG_BIN" decrypt -s "$PQPG_KEY" "$TARGET" | tar xzf - -C "$DEST_DIR"; then
            DECRYPTED_COUNT=$((DECRYPTED_COUNT + 1))
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    else
        OUTPUT="${TARGET%.pqpg}"
        if [ -e "$OUTPUT" ]; then
            if ! zenity --question --title="PQPG Tools - Sovrascrittura" \
                --text="Il file di destinazione esiste già:\n$(basename "$OUTPUT")\n\nVuoi sovrascriverlo?" \
                --ok-label="Sovrascrivi" --cancel-label="Salta"; then
                continue
            fi
        fi

        if "$PQPG_BIN" decrypt -s "$PQPG_KEY" -o "$OUTPUT" "$TARGET"; then
            DECRYPTED_COUNT=$((DECRYPTED_COUNT + 1))
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    fi
done

thunar --reload 2>/dev/null || true

if [ $FAILED_COUNT -eq 0 ]; then
    zenity --info --title="PQPG Tools" \
        --text="✓ Decifrati con successo $DECRYPTED_COUNT elementi con la tua chiave privata."
else
    zenity --warning --title="PQPG Tools" \
        --text="Decifrazione completata con errori.\n\nElementi decifrati: $DECRYPTED_COUNT\nElementi falliti: $FAILED_COUNT"
fi
