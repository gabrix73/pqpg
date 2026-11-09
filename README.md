# pqpg (Post-Quantum Privacy Guard)

`pqpg` è una CLI crittografica moderna, universale e standalone **scritta interamente in Rust puro** (memory-safe, zero dipendenze esterne in C). Implementa cifrari ibridi Post-Quantum per la cifratura di file/messaggi, firme digitali, gestione e verifica delle chiavi con sincronizzazione con directory PKI Katzenpost/Pigeonhole e supporto nativo per il trasferimento di dati e chiavi via **QR Code Air-Gapped** direttamente nel terminale.

## Caratteristiche Principali

- **Memory Safety & Hygiene**: Zero buffer overflow, zero use-after-free, azzeramento deterministico dei segreti in memoria volatile (`zeroize`) e protezione contro il paging su disco (`mlockall` e bloccaggio delle pagine contenenti le chiavi private).
- **Zero Dipendenze Esterne**: Non richiede OpenSSL, glibc complesse o runtime di terze parti: tutte le primitive crittografiche (ML-KEM-768, X25519, BLAKE2b, ChaCha20-Poly1305, Ed25519) sono implementate nativamente in Rust puro.
- **Interoperabilità Katzenpost / HPQC**: Utilizza il combinatore KEM ibrido standard **Katzenpost HPQC Split-PRF** (`splitprf-v1`), validato contro i Known Answer Tests (KAT) ufficiali di Katzenpost.
- **Client PKI Pigeonhole PQKeys**: Supporto nativo integrato al protocollo wire CBOR incapsulato di `pigeonhole-pqkeys` per pubblicazione, ricerca, revoca ed enumerazione di chiavi pubbliche post-quantistiche con verifica immediata zero-trust della self-signature.
- **Portabilità Assoluta**: Compilabile come singolo binario statico (circa 1.3 MB) per qualsiasi Linux, macOS e Windows.

## Architettura Crittografica

| Primitiva / Funzione | Algoritmo / Standard | Specifiche |
|---|---|---|
| **KEM Post-Quantum** | NIST FIPS 203 **ML-KEM-768** | Chiave pubblica: 1184 B, Ciphertext: 1088 B, Segreto: 2400 B |
| **KEM Classico / PFS** | **X25519** effimero | Chiave effimera: 32 B, Shared Secret: 32 B |
| **Hybrid KEM Combiner** | **Katzenpost HPQC Split-PRF** (`splitprf-v1`) | BLAKE2b-256 PRF-then-XOR su `(ML-KEM-768, X25519)` |
| **Cifratura Simmetrica AEAD** | **ChaCha20-Poly1305** | Chiave 256-bit derivata dal combinatore, nonce 96-bit |
| **Firme Digitali** | **Ed25519** | Chiave 32 B, firma staccata da 64 B con verifica canonica |
| **Formato Busta / Armor** | ASCII Armored (`-----BEGIN PQPG ...-----`) | CRC integrato e codifica Base64 a blocchi di 64 caratteri |

### Combinatore Ibrido HPQC Split-PRF

La derivazione del segreto condiviso unificato combina la sicurezza classica (ECDH X25519) e post-quantistica (Lattice-based ML-KEM-768) seguendo la specifica `github.com/katzenpost/hpqc`:

1. Viene generato il messaggio di legame:
   $$\text{msg} = \text{"splitprf-v1"} \parallel \text{u32be}(2) \parallel \text{u32be}(32) \parallel \text{pk}_{\text{X25519}} \parallel \text{u32be}(1088) \parallel \text{ct}_{\text{ML-KEM-768}}$$
2. Per ogni componente $i \in \{\text{X25519}, \text{ML-KEM-768}\}$:
   $$\text{key}_i = \text{BLAKE2b-256}(\text{ss}_i)$$
   $$\text{digest}_i = \text{BLAKE2b-256-Keyed}(\text{key} = \text{key}_i, \text{msg} = \text{msg})$$
3. Il segreto condiviso finale a 256 bit è il risultato dello XOR:
   $$\text{K} = \text{digest}_{\text{X25519}} \oplus \text{digest}_{\text{ML-KEM-768}}$$

## Installazione

```bash
cargo build --release
cp target/release/pqpg ~/.cargo/bin/
```

## Utilizzo

### 1. Generazione Chiavi Post-Quantum

Genera la coppia di chiavi ibride (Ed25519 + X25519 + ML-KEM-768):

```bash
# Genera identity.key (permessi 0600) e identity.pub
pqpg keygen -n identity

# Con proiezione del QR Code nel terminale (per ambienti air-gapped)
pqpg keygen -n identity --qr
```

### 2. Cifratura di File o Stream

```bash
# Cifra un file per un destinatario fornendo la sua chiave pubblica locale
pqpg encrypt -r alice.pub segreto.txt -o segreto.msg

# Cifra recuperando e verificando automaticamente la chiave pubblica dal keyserver Katzenpost
pqpg encrypt --keyserver 127.0.0.1:9095 -r alice@katzenpost.mix segreto.txt -o segreto.msg

# Cifra da stdin e visualizza il messaggio cifrato come QR code nel terminale
echo "Messaggio riservato" | pqpg encrypt -r alice.pub --qr
```

### 3. Decifratura

```bash
# Decifra un messaggio con la propria chiave privata
pqpg decrypt -s identity.key segreto.msg

# Decifra da pipe Unix
cat segreto.msg | pqpg decrypt -s identity.key
```

### 4. Firma e Verifica

```bash
# Firma un documento
pqpg sign -s identity.key documento.pdf -o documento.sig

# Firma con visualizzazione QR Code della firma staccata
pqpg sign -s identity.key documento.pdf --qr

# Verifica la firma
pqpg verify -k alice.pub -s documento.sig documento.pdf
```

### 5. Gestione Directory PKI Katzenpost (`pigeonhole-pqkeys`)

`pqpg` integra un client diretto per i server di chiavi Katzenpost / Pigeonhole:

```bash
# 1. Pubblica la propria chiave pubblica sul keyserver (con payload canonico e self-signature)
pqpg keyserver publish -k identity.key -u alice@katzenpost.mix --server 127.0.0.1:9095

# 2. Cerca e scarica una chiave pubblica (con validazione crittografica automatica della self-signature)
pqpg keyserver lookup -u alice@katzenpost.mix -o alice.pub --server 127.0.0.1:9095

# 3. Elenca tutte le chiavi attive registrate nel directory server
pqpg keyserver list --server 127.0.0.1:9095

# 4. Revoca crittograficamente la propria chiave con motivazione firmata
pqpg keyserver revoke -k identity.key -u alice@katzenpost.mix -r "Key compromised" --server 127.0.0.1:9095
```

### 6. Visualizzazione QR Code nel Terminale

Visualizza qualsiasi file di chiavi o testo in formato QR Code leggibile da smartphone o fotocamere air-gap:

```bash
pqpg qr chiave_o_messaggio.txt
```

## Applicazioni e Integrazioni Desktop

Oltre alla CLI standalone, il repository include strumenti grafici pronti all'uso:

- **GUI Text Scratchpad (`contrib/gui/`)**:
  Applicazione grafica Python/GTK3 per la cifratura, decifratura, firma e verifica di testi interamente in memoria RAM (zero scritture su disco), con selezione contatti da rubrica locale e visualizzazione QR code a video.
  Consultare [`contrib/gui/README.md`](contrib/gui/README.md) per i dettagli.

- **Integrazione File Manager Thunar (`integrations/thunar/`)**:
  Suite di azioni contestuali e script Zenity per integrare il tasto destro di Thunar: cifratura/decifratura di singoli file o cartelle compresse (`.tar.pqpg`), apposizione e verifica firme Ed25519 e condivisione chiavi via QR.
  Consultare [`integrations/thunar/README.md`](integrations/thunar/README.md) per la configurazione.

## Verifica e Test di Conformità

I test crittografici verificano l'equivalenza bit-a-bit rispetto all'implementazione Go di Katzenpost `hpqc`:

```bash
cargo test
```

Include:
- Verifica del vettore ufficiale KAT di Katzenpost per `MLKEM768-X25519` `splitprf-v1`.
- Roundtrip di cifratura ibrida simmetrica/asimmetrica.
- Roundtrip di firma e verifica Ed25519.
- Test di blocco memoria e zeroizzazione.
- Roundtrip ASCII armor e codifica QR Code.

## Licenza

AGPL-3.0
Autore: Gab Virebent <gabriel1@virebent.art>
