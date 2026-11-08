#!/bin/bash
# pqpg-common.sh - Shared definitions and helper routines for PQPG desktop integration

set -e

# Identify binary
if [ -x "$HOME/.cargo/bin/pqpg" ]; then
    PQPG_BIN="$HOME/.cargo/bin/pqpg"
elif command -v pqpg >/dev/null 2>&1; then
    PQPG_BIN="$(command -v pqpg)"
else
    zenity --error --title="PQPG Tools" --text="Eseguibile pqpg non trovato in ~/.cargo/bin/pqpg o nel PATH."
    exit 1
fi

PQPG_DIR="$HOME/.config/pqpg"
PQPG_KEY="$PQPG_DIR/identity.key"
PQPG_PUBKEY="$PQPG_DIR/identity.pub"
PQPG_RECIPIENTS="$PQPG_DIR/recipients"

# Ensure directories and keypair exist
ensure_keypair() {
    mkdir -p -m 0700 "$PQPG_DIR"
    mkdir -p -m 0700 "$PQPG_RECIPIENTS"

    if [ ! -f "$PQPG_KEY" ] || [ ! -f "$PQPG_PUBKEY" ]; then
        if zenity --question --title="PQPG Tools - Inizializzazione" \
            --text="Nessuna coppia di chiavi PQPG trovata in ~/.config/pqpg/\n\nVuoi generare una nuova coppia di chiavi ibrida post-quantum (ML-KEM-768 + X25519 + Ed25519)?" \
            --ok-label="Genera Chiavi" --cancel-label="Annulla"; then
            
            "$PQPG_BIN" keygen -n identity -o "$PQPG_DIR" >/dev/null 2>&1
            chmod 0600 "$PQPG_KEY"
            chmod 0644 "$PQPG_PUBKEY"
            
            zenity --info --title="PQPG Tools" \
                --text="✓ Nuova coppia di chiavi generata con successo:\n\nPrivata: $PQPG_KEY (0600)\nPubblica: $PQPG_PUBKEY"
        else
            zenity --error --title="PQPG Tools" --text="Operazione annullata: chiave privata richiesta."
            exit 1
        fi
    fi
}

# Enforce no mixed file and folder selection
check_selection_type() {
    local has_file=0
    local has_dir=0
    for item in "$@"; do
        [ -d "$item" ] && has_dir=1
        [ -f "$item" ] && has_file=1
    done

    if [ $has_file -eq 1 ] && [ $has_dir -eq 1 ]; then
        zenity --error --title="PQPG Tools" \
            --text="Selezione mista non consentita.\n\nSeleziona solo file oppure solo cartelle, non entrambi contemporaneamente."
        exit 1
    fi
}

# Prompt user to select encryption recipient from ~/.config/pqpg/recipients/ or self
select_recipient() {
    ensure_keypair

    local options=()
    options+=("Personale (Te stesso)" "$PQPG_PUBKEY" "Chiave identità locale ~/.config/pqpg/identity.pub")

    shopt -s nullglob
    local recipient_files=("$PQPG_RECIPIENTS"/*.pub)
    shopt -u nullglob

    for rpub in "${recipient_files[@]}"; do
        local rname
        rname="$(basename "$rpub" .pub)"
        options+=("Contatto: $rname" "$rpub" "$rpub")
    done

    local choice
    choice=$(zenity --list --title="PQPG Tools - Scegli Destinatario" \
        --text="Seleziona la chiave pubblica per cui cifrare i dati:" \
        --column="Destinatario" --column="File Chiave" --column="Percorso Completo" \
        --hide-column=2 --print-column=2 \
        "${options[@]}" \
        --width=620 --height=340)

    if [ -z "$choice" ]; then
        exit 0
    fi

    if [ ! -f "$choice" ]; then
        zenity --error --title="PQPG Tools" --text="Chiave pubblica selezionata non trovata:\n$choice"
        exit 1
    fi

    echo "$choice"
}
