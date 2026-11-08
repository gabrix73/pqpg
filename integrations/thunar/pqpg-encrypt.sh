#!/bin/bash
# pqpg-encrypt.sh - Encrypt file(s) with PQPG (ML-KEM-768 + X25519)
# Usage: pqpg-encrypt.sh <file1> [file2] ...

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/pqpg-common.sh"

if [ $# -eq 0 ]; then
    zenity --error --title="PQPG Tools" --text="Nessun file selezionato."
    exit 1
fi

check_selection_type "$@"

# Check for directories or already encrypted files
for TARGET in "$@"; do
    if [ -d "$TARGET" ]; then
        zenity --error --title="PQPG Tools" \
            --text="La selezione contiene una cartella:\n$(basename "$TARGET")\n\nPer cifrare intere cartelle usa la voce dedicata 'Cifra Cartella (.tar.pqpg)'."
        exit 1
    fi
    if [[ "$TARGET" == *.pqpg ]]; then
        zenity --warning --title="PQPG Tools" \
            --text="Il file risulta già cifrato:\n$(basename "$TARGET")\n\nNon è possibile cifrarlo nuovamente. Puoi decifrarlo o firmarlo."
        exit 0
    fi
done

RECIPIENT_KEY="$(select_recipient)"
if [ -z "$RECIPIENT_KEY" ]; then
    exit 0
fi

ENCRYPTED_COUNT=0
for TARGET in "$@"; do
    if [ ! -f "$TARGET" ]; then
        continue
    fi

    OUTPUT="${TARGET}.pqpg"
    "$PQPG_BIN" encrypt -r "$RECIPIENT_KEY" -o "$OUTPUT" "$TARGET"
    ENCRYPTED_COUNT=$((ENCRYPTED_COUNT + 1))
done

thunar --reload 2>/dev/null || true

RECIPIENT_NAME="$(basename "$RECIPIENT_KEY" .pub)"
zenity --info --title="PQPG Tools" \
    --text="✓ Cifrati con successo $ENCRYPTED_COUNT file.\n\nDestinatario: $RECIPIENT_NAME\nAlgoritmo: ML-KEM-768 + X25519 + ChaCha20-Poly1305\nEstensione generata: .pqpg"
