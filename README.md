# pqpg (Post-Quantum Privacy Guard)

`pqpg` è una CLI crittografica moderna, universale e standalone **scritta interamente in Rust puro** (memory-safe, zero dipendenze esterne in C). Implementa cifrari ibridi Post-Quantum per la cifratura di file/messaggi, firme digitali e gestione delle chiavi, con supporto nativo per il trasferimento di dati e chiavi via **QR Code Air-Gapped** direttamente nel terminale.

## Perché Rust?

- **Memory Safety & Hygiene**: Zero buffer overflow, zero use-after-free, azzeramento deterministico dei segreti in memoria volatile (`zeroize`) e protezione contro il paging su disco (`mlock`).
- **Zero Dipendenze Esterne**: Non richiede OpenSSL, glibc complesse o runtime di terze parti: le primitive crittografiche (ML-KEM-768, X25519, ChaCha20-Poly1305, Ed25519) sono implementate nativamente in Rust.
- **Portabilità Assoluta**: Compilabile come singolo binario statico (1.2 MB) per qualsiasi Linux, macOS (Apple Silicon/Intel) e Windows.

## Algoritmi Crittografici

- **KEM (Cifratura)**: NIST FIPS 203 **ML-KEM-768** (1184 byte chiave pubblica, 1088 byte ciphertext, 2400 byte chiave segreta).
- **Diffie-Hellman Ibrido**: **X25519** effimero per garantire Perfect Forward Secrecy (PFS).
- **Cifratura Simmetrica AEAD**: **ChaCha20-Poly1305** con chiave a 256 bit derivata via **HKDF-SHA256**.
- **Firme Digitali**: **Ed25519** (64 byte detached signature).
- **Formato Busta**: Armored ASCII (`-----BEGIN PQPG ...-----`) e binario compatto.

## Installazione

```bash
cargo build --release
cp target/release/pqpg ~/.cargo/bin/
```

## Utilizzo

### 1. Generazione Chiavi Post-Quantum
```bash
# Genera identity.key (0600) e identity.pub
pqpg keygen -n identity

# Con proiezione del QR Code nel terminale (per macchine air-gapped)
pqpg keygen -n identity --qr
```

### 2. Cifratura di File o Stream
```bash
# Cifra un file per un destinatario
pqpg encrypt -r alice.pub segreto.txt -o segreto.msg

# Cifra da stdin e visualizza il QR code nel terminale
echo "Messaggio riservato" | pqpg encrypt -r alice.pub --qr
```

### 3. Decifratura
```bash
# Decifra un messaggio con la propria chiave privata
pqpg decrypt -s identity.key segreto.msg

# Decifra da pipe
cat segreto.msg | pqpg decrypt -s identity.key
```

### 4. Firma e Verifica
```bash
# Firma un documento
pqpg sign -s identity.key documento.pdf -o documento.sig

# Firma con visualizzazione QR Code della firma
pqpg sign -s identity.key documento.pdf --qr

# Verifica la firma
pqpg verify -k alice.pub -s documento.sig documento.pdf
```

### 5. Visualizzazione QR Code di Qualsiasi Dato
```bash
pqpg qr chiave_o_messaggio.txt
```

## Licenza

AGPL-3.0
Autore: Gab Virebent <gabriel1@virebent.art>
