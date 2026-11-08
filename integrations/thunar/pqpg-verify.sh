#!/bin/bash
# pqpg-verify.sh - Verify PQPG Ed25519 digital signature
# Usage: pqpg-verify.sh <file1> [file2] ...

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/pqpg-common.sh"

if [ $# -eq 0 ]; then
    zenity --error --title="PQPG Tools" --text="Nessun file selezionato."
    exit 1
fi

check_selection_type "$@"
ensure_keypair

VERIFIED_COUNT=0
FAILED_COUNT=0
REPORT=""

for TARGET in "$@"; do
    if [ ! -f "$TARGET" ]; then
        continue
    fi

    DATA_FILE=""
    SIG_FILE=""

    if [[ "$TARGET" == *.pqpg.sig ]]; then
        SIG_FILE="$TARGET"
        DATA_FILE="${TARGET%.pqpg.sig}"
    elif [[ "$TARGET" == *.sig ]]; then
        SIG_FILE="$TARGET"
        DATA_FILE="${TARGET%.sig}"
    elif [ -f "${TARGET}.pqpg.sig" ]; then
        DATA_FILE="$TARGET"
        SIG_FILE="${TARGET}.pqpg.sig"
    fi

    if [ -z "$DATA_FILE" ] || [ ! -f "$DATA_FILE" ]; then
        DATA_FILE=$(zenity --file-selection --title="Seleziona il file originale per: $(basename "$TARGET")") || true
        if [ -z "$DATA_FILE" ] || [ ! -f "$DATA_FILE" ]; then
            REPORT="${REPORT}• $(basename "$TARGET"): File dati non trovato o selezione annullata.\n"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            continue
        fi
        SIG_FILE="$TARGET"
    fi

    # Try matching against known public keys
    VERIFIED_SIGNER=""

    # 1. Check self
    if "$PQPG_BIN" verify -k "$PQPG_PUBKEY" -s "$SIG_FILE" "$DATA_FILE" >/dev/null 2>&1; then
        VERIFIED_SIGNER="Personale (identity.pub)"
    fi

    # 2. Check contacts in recipients
    if [ -z "$VERIFIED_SIGNER" ]; then
        shopt -s nullglob
        recipient_files=("$PQPG_RECIPIENTS"/*.pub)
        shopt -u nullglob

        for rpub in "${recipient_files[@]}"; do
            if "$PQPG_BIN" verify -k "$rpub" -s "$SIG_FILE" "$DATA_FILE" >/dev/null 2>&1; then
                VERIFIED_SIGNER="$(basename "$rpub" .pub)"
                break
            fi
        done
    fi

    # 3. If still unverified, prompt for manual public key
    if [ -z "$VERIFIED_SIGNER" ]; then
        if zenity --question --title="PQPG Tools - Verifica Firma" \
            --text="La firma per $(basename "$DATA_FILE") non corrisponde alla tua chiave né ai contatti salvati in ~/.config/pqpg/recipients/.\n\nVuoi selezionare un file di chiave pubblica (.pub) da verificare?" \
            --ok-label="Sfoglia..." --cancel-label="Segnala come non valida"; then
            
            MANUAL_PUB=$(zenity --file-selection --title="Seleziona la chiave pubblica (.pub) del firmatario") || true
            if [ -n "$MANUAL_PUB" ] && [ -f "$MANUAL_PUB" ]; then
                if "$PQPG_BIN" verify -k "$MANUAL_PUB" -s "$SIG_FILE" "$DATA_FILE" >/dev/null 2>&1; then
                    VERIFIED_SIGNER="Manuale ($(basename "$MANUAL_PUB"))"
                fi
            fi
        fi
    fi

    if [ -n "$VERIFIED_SIGNER" ]; then
        VERIFIED_COUNT=$((VERIFIED_COUNT + 1))
        REPORT="${REPORT}✓ $(basename "$DATA_FILE"): VALIDA (Firmatario: $VERIFIED_SIGNER)\n"
    else
        FAILED_COUNT=$((FAILED_COUNT + 1))
        REPORT="${REPORT}✗ $(basename "$DATA_FILE"): NON VALIDA o firmatario sconosciuto\n"
    fi
done

if [ $FAILED_COUNT -eq 0 ]; then
    zenity --info --title="PQPG Tools - Verifica Firma" \
        --text="Tutte le firme verificate sono VALIDE:\n\n$REPORT"
else
    zenity --warning --title="PQPG Tools - Esito Verifica" \
        --text="Risultato verifica firme ($VERIFIED_COUNT valide, $FAILED_COUNT non valide):\n\n$REPORT"
fi
