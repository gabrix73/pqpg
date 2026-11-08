# PQPG Text Scratchpad (GUI)

Interfaccia grafica in Python e GTK3 per la cifratura, decifratura, firma e verifica di testo interamente in memoria volatile, basata sul motore crittografico di `pqpg`.

## Caratteristiche

- **Zero Tracce su Disco**: le operazioni di cifratura e decifratura avvengono in RAM tramite pipe `stdin`/`stdout` verso l'eseguibile `pqpg`.
- **Cifratura Ibrida Post-Quantum**: combina NIST FIPS 203 **ML-KEM-768** con **X25519** e cifrario AEAD **ChaCha20-Poly1305** in formato Armored (`-----BEGIN PQPG MESSAGE-----`).
- **Firme Digitali Ed25519**: firma e verifica immediata di testi e comunicazioni (`-----BEGIN PQPG SIGNATURE-----`).
- **Visualizzazione QR Code**: rendering a schermo del QR Code per chiavi pubbliche e ciphertext, ideale per scenari air-gapped o scambio rapido da dispositivo mobile.
- **Gestione Contatti**: selezione rapida delle chiavi pubbliche salvate in `~/.config/pqpg/recipients/*.pub` o caricamento manuale.
- **Igiene della Memoria (Shred Buffer)**: pulsante di pulizia con azzeramento e sovrascrittura esplicita del buffer di testo prima della chiusura.

## Requisiti

- Python 3
- PyGObject / GTK 3:
  - Su Debian/Ubuntu: `sudo apt install python3-gi gir1.2-gtk-3.0`
  - Su Arch Linux: `sudo pacman -S python-gobject gtk3`
- `pqpg` installato in `~/.cargo/bin/pqpg` o presente nel `PATH`.

## Avvio Rapido

```bash
python3 contrib/gui/pqpg-scratchpad.py
```

Per l'installazione nel menu delle applicazioni desktop:

```bash
cp contrib/gui/pqpg-scratchpad.desktop ~/.local/share/applications/
```
Assicurarsi che il percorso specificato nel campo `Exec` del file `.desktop` punti alla posizione corretta dello script (o creare un link simbolico a `pqpg-scratchpad.py` in `~/.local/bin/pqpg-scratchpad`).
