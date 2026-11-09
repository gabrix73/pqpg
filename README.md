# pqpg (Post-Quantum Privacy Guard)

`pqpg` is a modern, universal, standalone cryptographic command-line tool **written entirely in pure Rust** (memory-safe, zero external C dependencies). It implements hybrid Post-Quantum cryptography for file and message encryption, digital signatures, key management, and seamless integration with the **Katzenpost** mixnet ecosystem and the **Pigeonhole PQKeys** public key directory service. It also includes native terminal-rendered **Air-Gapped QR Codes** for zero-network key and data transfer.

## Key Features

- **Memory Safety & Hygiene**: Zero buffer overflows, zero use-after-free, deterministic secret zeroization in volatile RAM (`zeroize`), process-wide address space locking (`mlockall`), and selective physical RAM page locking for sensitive private key material.
- **Pure Rust Cryptographic Stack**: Zero reliance on OpenSSL, C libraries, or complicated external runtimes. All cryptographic primitives (ML-KEM-768, X25519, BLAKE2b, ChaCha20-Poly1305, Ed25519) are compiled directly into a self-contained Rust binary.
- **Katzenpost HPQC Interoperability**: Implements the official **Katzenpost HPQC Split-PRF** (`splitprf-v1`) hybrid KEM combiner specification, strictly validated against official Katzenpost Known Answer Tests (KAT).
- **Pigeonhole PQKeys PKI Integration**: Native client implementation for the Framed-CBOR wire protocol used by the `pigeonhole-pqkeys` directory service in Katzenpost. Supports publishing, looking up, listing, and revoking post-quantum identities with client-side zero-trust self-signature verification.
- **Air-Gapped Operational Ergonomics**: High-density QR code generation directly within terminal emulators and GTK GUI scratchpads for air-gapped workstations and secure offline key ceremonies.
- **Static Portability**: Compiles into a single standalone static binary (~1.3 MB) for Linux, macOS, and Windows.

---

## Cryptographic Architecture

| Primitive / Role | Algorithm / Standard | Parameters & Artifact Sizes |
|---|---|---|
| **Post-Quantum KEM** | NIST FIPS 203 **ML-KEM-768** | Public Key: 1184 B, Ciphertext: 1088 B, Secret Key: 2400 B |
| **Classical KEM / PFS** | Ephemeral **X25519** (ECDH) | Ephemeral Public Key: 32 B, Shared Secret: 32 B |
| **Hybrid KEM Combiner** | **Katzenpost HPQC Split-PRF** (`splitprf-v1`) | BLAKE2b-256 PRF-then-XOR over `(X25519, ML-KEM-768)` |
| **Symmetric AEAD** | **ChaCha20-Poly1305** | 256-bit key from combiner, 96-bit random nonce |
| **Digital Signatures** | **Ed25519** | 32 B public key, 64 B detached signature |
| **Wire & Storage Format** | ASCII Armor (`-----BEGIN PQPG ...-----`) | 64-column Base64 with custom CRC integrity check |

### HPQC Split-PRF Hybrid Combiner

The shared secret derivation combines classical ECDH security (X25519) and lattice-based post-quantum security (NIST FIPS 203 ML-KEM-768) following the specification defined in `github.com/katzenpost/hpqc`:

1. Construct the domain-separated binding message:
   $$\text{msg} = \text{"splitprf-v1"} \parallel \text{u32be}(2) \parallel \text{u32be}(32) \parallel \text{pk}_{\text{X25519}} \parallel \text{u32be}(1088) \parallel \text{ct}_{\text{ML-KEM-768}}$$
2. For each cryptographic component $i \in \{\text{X25519}, \text{ML-KEM-768}\}$:
   $$\text{key}_i = \text{BLAKE2b-256}(\text{ss}_i)$$
   $$\text{digest}_i = \text{BLAKE2b-256-Keyed}(\text{key} = \text{key}_i, \text{msg} = \text{msg})$$
3. Compute the final 256-bit symmetric AEAD master key via XOR:
   $$\text{K} = \text{digest}_{\text{X25519}} \oplus \text{digest}_{\text{ML-KEM-768}}$$

### Wire Envelope Format (`PQPM\x01`)

Encrypted binary messages are packaged with the following header:
- `Magic` (4 bytes): `PQPM` (`0x50 0x51 0x50 0x4d`)
- `Version` (1 byte): `0x01`
- `Ephemeral X25519 Public Key` (32 bytes)
- `ML-KEM-768 Ciphertext` (1088 bytes)
- `ChaCha20-Poly1305 Nonce` (12 bytes)
- `Ciphertext & Poly1305 Tag` (variable length, plaintext length + 16 bytes)

---

## Katzenpost & Pigeonhole PQKeys Directory Service

### The Katzenpost Mixnet Ecosystem

**Katzenpost** is a next-generation anonymous communications network that defends against global passive and active traffic analysis adversaries. It leverages the Sphinx packet format, continuous-time Poisson mixing, and cover traffic loops.

Within Katzenpost, **Pigeonhole** provides an asynchronous rendezvous and mailbox substrate for hosting privacy-preserving services (such as dropboxes, messaging mailboxes, and key directories) without exposing the network location or metadata of either the service operator or the client.

### What is `pigeonhole-pqkeys`?

`pigeonhole-pqkeys` (`github.com/katzenpost/pigeonhole_protocols`) is the decentralized Public Key Infrastructure (PKI) directory designed for post-quantum hybrid identities. It allows users and mixnet endpoints to publish, resolve, and revoke hybrid public keys (`Ed25519` + `X25519` + `ML-KEM-768`) indexed by user alias or 64-character SHA-256 fingerprint.

### Architecture and Operation of `pqkeys-daemon`

The server daemon `pqkeys-daemon` can operate in two complementary modes:

1. **Katzenpost Mixnet Service Mode (`--thinclient_config`)**:
   Connects to the Katzenpost mixnet through a Thin Client configuration (`thin.LoadFile`). The daemon registers as an anonymous Pigeonhole service, advertises itself across the mixnet using Katzenpost service discovery (`discovery.NewAll`), and receives requests through an anonymous 32-byte Service ID (`hex`).
2. **Local Bridge / Gateway Mode (`--listen`)**:
   Exposes a local TCP listener (by default `127.0.0.1:9095`) speaking framed CBOR. This allows local utilities, air-gap gateways, and command-line clients like `pqpg` to publish and query the directory directly without running a full local mixnet client.

Both modes can be backed either by an ephemeral in-memory store or by persistent **BoltDB** storage (`--db`).

#### Running the Server Daemon

```bash
# Standalone local bridge with persistent BoltDB storage:
pqkeys-daemon --listen 127.0.0.1:9095 --db /var/lib/katzenpost/pqkeys.bolt.db

# Production Katzenpost Mixnet Service with simultaneous local bridge:
pqkeys-daemon \
  --thinclient_config /etc/katzenpost/thin_client.toml \
  --datadir ~/.local/share/katzenpost/pqkeys \
  --db /var/lib/katzenpost/pqkeys.bolt.db \
  --listen 127.0.0.1:9095 \
  --log_level INFO
```

### Zero-Trust Verification

`pqpg` enforces strict zero-trust verification for all operations with the directory:
- **Publish**: The owner signs the canonical registration payload (`PQKEYS-PUBLISH-V1|{user_id}|{armored_pk}|{timestamp}`) using their Ed25519 private key.
- **Lookup**: When `pqpg` queries a public key from the keyserver, it parses the self-signature and verifies it against the downloaded Ed25519 verifying key before accepting, saving, or encrypting to that key. If the signature is invalid or forged, `pqpg` immediately rejects the key.
- **Revoke**: A key can only be marked as revoked if the revocation request carries an authentic Ed25519 signature over `PQKEYS-REVOKE-V1|{fingerprint}|{reason}|{timestamp}`.

---

## Installation

```bash
cargo build --release
cp target/release/pqpg ~/.cargo/bin/
```

Verify installation:
```bash
pqpg --version
```

---

## Usage Guide

### 1. Generating Post-Quantum Hybrid Keys

Generate a dual-stack hybrid keypair (Ed25519 signing key + X25519 DH key + ML-KEM-768 lattice KEM key):

```bash
# Generates identity.key (permissions 0600) and identity.pub
pqpg keygen -n identity

# Render public key as a high-density QR code in the terminal (for air-gapped systems)
pqpg keygen -n identity --qr
```

### 2. File and Stream Encryption

```bash
# Encrypt a file using a local recipient public key file:
pqpg encrypt -r alice.pub secret.txt -o secret.msg

# Encrypt directly by resolving and verifying the recipient from a Katzenpost PQKeys server:
pqpg encrypt --keyserver 127.0.0.1:9095 -r alice@katzenpost.mix secret.txt -o secret.msg

# Encrypt from stdin and display the ciphertext as a terminal QR code:
echo "Confidential dispatch" | pqpg encrypt -r alice.pub --qr
```

### 3. Decryption

```bash
# Decrypt a message with your private key:
pqpg decrypt -s identity.key secret.msg

# Decrypt from a Unix pipe:
cat secret.msg | pqpg decrypt -s identity.key
```

### 4. Digital Signatures and Verification

```bash
# Sign a file (produces a detached Ed25519 ASCII armored signature):
pqpg sign -s identity.key document.pdf -o document.sig

# Sign with interactive QR code display of the detached signature:
pqpg sign -s identity.key document.pdf --qr

# Verify the signature:
pqpg verify -k alice.pub -s document.sig document.pdf
```

### 5. Katzenpost PQKeys Directory Client

`pqpg` provides dedicated subcommands to manage post-quantum identities on `pigeonhole-pqkeys`:

```bash
# 1. Publish your post-quantum public key with self-signature:
pqpg keyserver publish -k identity.key -u alice@katzenpost.mix --server 127.0.0.1:9095

# 2. Look up a public key by user ID or fingerprint, verifying its self-signature:
pqpg keyserver lookup -u alice@katzenpost.mix -o alice.pub --server 127.0.0.1:9095

# 3. Look up a public key and project it directly as an air-gapped QR code:
pqpg keyserver lookup -u alice@katzenpost.mix --qr --server 127.0.0.1:9095

# 4. List registered keys on the directory service:
pqpg keyserver list --server 127.0.0.1:9095 --limit 20

# 5. Cryptographically revoke your public key:
pqpg keyserver revoke -k identity.key -u alice@katzenpost.mix -r "Key rotation" --server 127.0.0.1:9095
```

### 6. Terminal QR Code Visualizer

Render any key, armored signature, or message file as a high-density QR code in the terminal:

```bash
pqpg qr identity.pub
```

---

## Desktop Applications and Integrations

In addition to the standalone CLI, the repository provides desktop tools:

- **GTK3 RAM Scratchpad (`contrib/gui/`)**:
  A Python/GTK3 desktop scratchpad for encrypting, decrypting, signing, and verifying text messages purely in volatile RAM (zero disk writes). Includes local address book management and interactive QR code display. See [`contrib/gui/README.md`](contrib/gui/README.md).

- **Thunar File Manager Integration (`integrations/thunar/`)**:
  Contextual right-click actions and Zenity shell dialogs for the Thunar file manager: encrypting/decrypting files and archive bundles (`.tar.pqpg`), signing/verifying files, and displaying public keys via QR code. See [`integrations/thunar/README.md`](integrations/thunar/README.md).

---

## Conformance Verification & Test Suite

The cryptographic implementation is rigorously validated against official Katzenpost `hpqc` Known Answer Tests:

```bash
cargo test
```

Test coverage includes:
- Verification against Katzenpost `hpqc` KAT vector for `MLKEM768-X25519` `splitprf-v1`.
- Symmetric and asymmetric hybrid encryption/decryption roundtrip.
- Ed25519 detached signature and canonical verification roundtrip.
- Memory hygiene: deterministic zeroization and page locking (`mlock`).
- ASCII Armor encoding/decoding with custom CRC integrity.
- Terminal QR code generation and decoding.

---

## License

AGPL-3.0-only  
Author: Gab Virebent <gabriel1@virebent.art>
