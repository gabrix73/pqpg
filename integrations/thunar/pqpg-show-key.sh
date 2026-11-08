#!/bin/bash
# pqpg-show-key.sh - Display PQPG public key, copy to clipboard, or show QR code
# Usage: pqpg-show-key.sh

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/pqpg-common.sh"

ensure_keypair

PUB_CONTENT="$(cat "$PQPG_PUBKEY")"

ACTION=$(zenity --list --title="PQPG Tools - Gestione Chiave" \
    --text="Chiave Pubblica: $PQPG_PUBKEY\nAlgoritmi: ML-KEM-768 (FIPS 203) + X25519 + Ed25519" \
    --column="Azione" --column="Descrizione" \
    "Copia negli Appunti" "Copia l'armatura completa della chiave pubblica negli appunti (xclip)" \
    "Mostra Testo Chiave" "Visualizza l'intera chiave pubblica a schermo" \
    "Mostra QR Code" "Visualizza il QR Code per scambio air-gapped in terminale" \
    "Apri Cartella Contatti" "Apri ~/.config/pqpg/recipients per aggiungere chiavi di altri utenti" \
    --width=640 --height=280)

case "$ACTION" in
    "Copia negli Appunti")
        echo -n "$PUB_CONTENT" | xclip -selection clipboard
        zenity --info --title="PQPG Tools" --text="✓ Chiave pubblica copiata negli appunti con successo!"
        ;;
    "Mostra Testo Chiave")
        zenity --text-info --title="PQPG Chiave Pubblica ($PQPG_PUBKEY)" \
            --filename="$PQPG_PUBKEY" --editable=false --width=650 --height=450
        ;;
    "Mostra QR Code")
        RUNNER="$(mktemp /tmp/pqpg-qr-XXXXXX.sh)"
        cat << EOF > "$RUNNER"
#!/bin/bash
trap 'rm -f "\$0"' EXIT
"$PQPG_BIN" qr "$PQPG_PUBKEY"
echo ""
read -n 1 -s -r -p "Premi un tasto per chiudere..."
EOF
        chmod +x "$RUNNER"
        REAL_TERM="$(readlink -f "$(command -v x-terminal-emulator 2>/dev/null)" 2>/dev/null || echo "")"
        if [[ "$REAL_TERM" == *"terminator"* ]] || command -v terminator >/dev/null 2>&1; then
            terminator -u --geometry=950x850 -T "PQPG Air-Gapped QR Code" -x /bin/bash "$RUNNER" &
        elif command -v x-terminal-emulator >/dev/null 2>&1; then
            x-terminal-emulator -T "PQPG Air-Gapped QR Code" -e /bin/bash "$RUNNER" &
        else
            zenity --info --title="PQPG Tools" --text="Terminale non disponibile per visualizzare il QR code."
        fi
        ;;
    "Apri Cartella Contatti")
        mkdir -p -m 0700 "$PQPG_RECIPIENTS"
        thunar "$PQPG_RECIPIENTS" &
        ;;
    *)
        exit 0
        ;;
esac
