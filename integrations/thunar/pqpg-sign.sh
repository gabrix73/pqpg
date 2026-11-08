#!/bin/bash
# pqpg-sign.sh - Sign file with PQPG (Ed25519 digital signature)
# Usage: pqpg-sign.sh <file1> [file2] ...

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/pqpg-common.sh"

if [ $# -eq 0 ]; then
    zenity --error --title="PQPG Tools" --text="Nessun file selezionato."
    exit 1
fi

check_selection_type "$@"
ensure_keypair

# Check if target is a directory or already signed
for TARGET in "$@"; do
    if [ -d "$TARGET" ]; then
        zenity --error --title="PQPG Tools" \
            --text="La selezione contiene una cartella:\n$(basename "$TARGET")\n\nPer firmare una cartella comprimila prima oppure usa l'archivio .tar.pqpg."
        exit 1
    fi

    if [[ "$TARGET" == *.sig ]] || [[ "$TARGET" == *.pqpg.sig ]]; then
        zenity --warning --title="PQPG Tools" \
            --text="Il file selezionato è già una firma digitale:\n$(basename "$TARGET")\n\nPer convalidarlo usa la voce 'Verifica Firma'."
        exit 0
    fi

    if [ -f "${TARGET}.pqpg.sig" ]; then
        zenity --warning --title="PQPG Tools" \
            --text="Il file risulta già firmato:\n$(basename "$TARGET")\n(File di firma presente: $(basename "${TARGET}.pqpg.sig"))\n\nNon è necessario firmarlo nuovamente. Puoi cifrarlo o verificare la firma esistente."
        exit 0
    fi
done

SIGNED_COUNT=0
for TARGET in "$@"; do
    if [ ! -f "$TARGET" ]; then
        continue
    fi

    OUTPUT="${TARGET}.pqpg.sig"
    "$PQPG_BIN" sign -s "$PQPG_KEY" -o "$OUTPUT" "$TARGET"
    SIGNED_COUNT=$((SIGNED_COUNT + 1))
done

thunar --reload 2>/dev/null || true

zenity --info --title="PQPG Tools" \
    --text="✓ Firmati con successo $SIGNED_COUNT file con firma Ed25519.\n\nFile di firma generato: .pqpg.sig"
