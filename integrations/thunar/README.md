# Integrazione PQPG per Thunar (XFCE / Desktop Linux)

Suite di script wrapper e azioni personalizzate (*Custom Actions*) per integrare le funzionalità crittografiche di `pqpg` direttamente nel menu contestuale del file manager Thunar (o qualsiasi altro desktop environment Linux compatibile con Zenity).

## Componenti

- `pqpg-common.sh`: libreria comune di controllo chiavi, selezione contatti da `~/.config/pqpg/recipients/` e gestione errori Zenity.
- `pqpg-encrypt.sh`: cifratura di singoli file tramite KEM ibrido ML-KEM-768 + X25519 (produce file `.pqpg`).
- `pqpg-encrypt-folder.sh`: archiviazione compressa `tar` e cifratura atomica di intere cartelle (produce archivi `.tar.pqpg`).
- `pqpg-decrypt.sh`: decifratura trasparente di file `.pqpg` o estrazione di archivi `.tar.pqpg` con la chiave privata `~/.config/pqpg/identity.key`.
- `pqpg-sign.sh`: firma digitale staccata Ed25519 (produce file `.pqpg.sig`).
- `pqpg-verify.sh`: verifica dell'integrità e dell'autore del file a partire dalla firma.
- `pqpg-show-key.sh`: visualizzazione e condivisione a video del QR Code della propria chiave pubblica di identità.
- `uca-pqpg.xml`: esportazione delle Custom Actions pronte per essere importate in Thunar.

## Requisiti

- `pqpg` installato nel `PATH` o in `~/.cargo/bin/pqpg`.
- `zenity` per i dialoghi grafici di selezione destinatari e avvisi.
- `thunar` (file manager).

## Installazione

1. Copiare gli script in una directory a scelta (ad esempio `~/.local/bin/pqpg-tools/`):
   ```bash
   mkdir -p ~/.local/bin/pqpg-tools
   cp integrations/thunar/*.sh ~/.local/bin/pqpg-tools/
   chmod +x ~/.local/bin/pqpg-tools/*.sh
   ```

2. Configurare le azioni in Thunar:
   - Aprire Thunar, andare su **Modifica -> Configura azioni personalizzate**.
   - Aggiungere le voci definite in `uca-pqpg.xml` aggiornando il percorso del comando verso `~/.local/bin/pqpg-tools/<script>.sh %F`.
   - In alternativa, è possibile unire i blocchi `<action>` di `uca-pqpg.xml` all'interno del proprio file `~/.config/Thunar/uca.xml`.
