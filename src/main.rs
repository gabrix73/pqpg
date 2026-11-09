use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use pqpg::armor::{decode_armored, encode_armored};
use pqpg::crypto::{decrypt_message, encrypt_message, sign_data, verify_data};
use pqpg::keys::{PrivateKey, PublicKey};
use pqpg::keyserver::{
    compute_fingerprint, list_keys, lookup_key, publish_key, revoke_key, DEFAULT_KEYSERVER_ADDR,
};
use pqpg::qr::render_terminal_qr;

#[derive(Parser, Debug)]
#[command(
    name = "pqpg",
    author = "Gab Virebent <gabriel1@virebent.art>",
    version = "0.2.0",
    about = "Post-Quantum Privacy Guard: lightweight CLI for hybrid post-quantum file encryption, signing and key management",
    long_about = "pqpg is a modern, standalone command-line tool implementing NIST FIPS 203 ML-KEM-768\ncombined with X25519 and ChaCha20-Poly1305 (using HPQC Split-PRF KEM combiner architecture)\nfor post-quantum forward-secure encryption, Ed25519 for digital signatures with Air-Gapped\nQR codes, and direct interop with Katzenpost / Pigeonhole PQKeys public key directory service."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new hybrid post-quantum keypair
    Keygen {
        /// Base filename for the keypair
        #[arg(short, long, default_value = "identity")]
        name: String,

        /// Output directory where keys will be saved
        #[arg(short, long, default_value = ".")]
        out_dir: PathBuf,

        /// Display the public key as an Air-Gapped QR code in the terminal
        #[arg(long)]
        qr: bool,
    },

    /// Encrypt a file or stream for a recipient's post-quantum public key
    Encrypt {
        /// Recipient's public key file (.pub), or user ID/fingerprint when resolved via --keyserver
        #[arg(short, long)]
        recipient: String,

        /// Optional PQKeys keyserver address (host:port) to fetch recipient key
        #[arg(long)]
        keyserver: Option<String>,

        /// Input file to encrypt (reads from stdin if omitted)
        input: Option<PathBuf>,

        /// Output file for encrypted armored message (writes to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Display the encrypted ciphertext as a QR code in the terminal
        #[arg(long)]
        qr: bool,
    },

    /// Decrypt an armored post-quantum message using your private key
    Decrypt {
        /// Your private key file (.key)
        #[arg(short, long)]
        secret_key: PathBuf,

        /// Input file to decrypt (reads from stdin if omitted)
        input: Option<PathBuf>,

        /// Output file for decrypted plaintext (writes to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Sign a file or stream with your private key
    Sign {
        /// Your private key file (.key)
        #[arg(short, long)]
        secret_key: PathBuf,

        /// Input file to sign (reads from stdin if omitted)
        input: Option<PathBuf>,

        /// Output file for signature (.sig, writes to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Display the signature as an Air-Gapped QR code in the terminal
        #[arg(long)]
        qr: bool,
    },

    /// Verify a digital signature against a public key
    Verify {
        /// Signer's public key file (.pub)
        #[arg(short = 'k', long)]
        public_key: PathBuf,

        /// Signature file (.sig)
        #[arg(short = 's', long)]
        signature: PathBuf,

        /// Input file that was signed (reads from stdin if omitted)
        input: Option<PathBuf>,
    },

    /// Export the public key from a private key file
    Export {
        /// Your private key file (.key)
        #[arg(short, long)]
        secret_key: PathBuf,

        /// Output file for public key (.pub, writes to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Display the public key as an Air-Gapped QR code in the terminal
        #[arg(long)]
        qr: bool,
    },

    /// Render any file, key or data as a compact Air-Gapped QR code in the terminal
    Qr {
        /// Input file to render as QR code (reads from stdin if omitted)
        input: Option<PathBuf>,
    },

    /// Interoperate with Katzenpost / Pigeonhole PQKeys directory service
    #[command(subcommand)]
    Keyserver(KeyserverCommands),
}

#[derive(Subcommand, Debug)]
enum KeyserverCommands {
    /// Publish your post-quantum public key with self-signature to PQKeys service
    Publish {
        /// Public key file (.pub)
        #[arg(short, long)]
        public_key: PathBuf,

        /// Private key file (.key) to generate self-signature
        #[arg(short = 'k', long)]
        secret_key: PathBuf,

        /// User identifier or alias (e.g. alice@katzenpost.mix)
        #[arg(short, long, default_value = "")]
        user: String,

        /// PQKeys service address (host:port)
        #[arg(long, default_value = DEFAULT_KEYSERVER_ADDR)]
        server: String,
    },

    /// Lookup a post-quantum public key by UserID or fingerprint and verify its self-signature
    Lookup {
        /// Query: User ID (e.g. alice@katzenpost.mix) or 64-character hex fingerprint
        query: String,

        /// Save the verified public key to a file (.pub)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Display public key as terminal QR code
        #[arg(long)]
        qr: bool,

        /// PQKeys service address (host:port)
        #[arg(long, default_value = DEFAULT_KEYSERVER_ADDR)]
        server: String,
    },

    /// Revoke a registered post-quantum public key
    Revoke {
        /// Public key file (.pub) of the key to revoke
        #[arg(short, long)]
        public_key: PathBuf,

        /// Private key file (.key) to authenticate revocation
        #[arg(short = 'k', long)]
        secret_key: PathBuf,

        /// Reason for revocation (e.g. "Key compromised" or "Superseded")
        #[arg(short, long, default_value = "Revoked by owner")]
        reason: String,

        /// PQKeys service address (host:port)
        #[arg(long, default_value = DEFAULT_KEYSERVER_ADDR)]
        server: String,
    },

    /// List registered post-quantum public keys
    List {
        /// Max records to fetch (default: 50)
        #[arg(long, default_value_t = 50)]
        limit: usize,

        /// Pagination offset (default: 0)
        #[arg(long, default_value_t = 0)]
        offset: usize,

        /// PQKeys service address (host:port)
        #[arg(long, default_value = DEFAULT_KEYSERVER_ADDR)]
        server: String,
    },
}

fn read_input(input: Option<&Path>) -> Result<Vec<u8>, anyhow::Error> {
    match input {
        Some(path) => Ok(fs::read(path)?),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn write_output(output: Option<&Path>, data: &[u8]) -> Result<(), anyhow::Error> {
    match output {
        Some(path) => {
            fs::write(path, data)?;
            Ok(())
        }
        None => {
            io::stdout().write_all(data)?;
            io::stdout().flush()?;
            Ok(())
        }
    }
}

fn display_qr(data: &[u8], title: &str) -> Result<(), anyhow::Error> {
    let qr_str = render_terminal_qr(data)?;
    println!("\n--- [AIRGAP QR CODE: {}] ---", title);
    println!("{}", qr_str);
    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    pqpg::mem::lock_process_memory();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { name, out_dir, qr } => {
            fs::create_dir_all(&out_dir)?;
            let (sk, pk) = PrivateKey::generate();

            let sk_armor = Zeroizing::new(encode_armored("PRIVATE KEY", &sk.to_bytes()));
            let pk_armor = encode_armored("PUBLIC KEY", &pk.to_bytes());

            let sk_path = out_dir.join(format!("{}.key", name));
            let pk_path = out_dir.join(format!("{}.pub", name));

            // Write private key with strict 0600 permissions
            let mut f_sk = fs::File::create(&sk_path)?;
            f_sk.write_all(sk_armor.as_bytes())?;
            let mut perms = f_sk.metadata()?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&sk_path, perms)?;

            fs::write(&pk_path, pk_armor.as_bytes())?;

            eprintln!("Generated PQPG hybrid post-quantum keypair:");
            eprintln!("  Private key: {} (mode 0600)", sk_path.display());
            eprintln!("  Public key:  {}", pk_path.display());
            eprintln!("  Fingerprint: {}", compute_fingerprint(&pk_armor));
            eprintln!("  Combiner:    HPQC Split-PRF (ML-KEM-768 + X25519) + Ed25519 (Sign)");

            if qr {
                display_qr(&pk.to_bytes(), "Public Key (Binary)")?;
            }
        }

        Commands::Encrypt {
            recipient,
            keyserver,
            input,
            output,
            qr,
        } => {
            let pk_armored = if Path::new(&recipient).exists() {
                fs::read_to_string(&recipient)?
            } else if let Some(srv) = keyserver.as_deref() {
                eprintln!("[PQKeys] Fetching public key for '{}' from {}...", recipient, srv);
                let rec = lookup_key(srv, &recipient)?;
                eprintln!("[PQKeys] ✓ Verified self-signature for '{}' (Fingerprint: {})", recipient, rec.fingerprint);
                rec.armored_public_key
            } else {
                return Err(anyhow::anyhow!(
                    "Recipient '{}' is not a local file. To resolve via Katzenpost directory, specify --keyserver <host:port>",
                    recipient
                ));
            };

            let pk_bytes = decode_armored(&pk_armored, "PUBLIC KEY")?;
            let pk = PublicKey::from_bytes(&pk_bytes)?;

            let plaintext = Zeroizing::new(read_input(input.as_deref())?);
            let ciphertext = encrypt_message(&pk, &plaintext)?;
            let armored = encode_armored("MESSAGE", &ciphertext);

            if qr {
                display_qr(armored.as_bytes(), "Encrypted Message")?;
            }

            write_output(output.as_deref(), armored.as_bytes())?;
        }

        Commands::Decrypt {
            secret_key,
            input,
            output,
        } => {
            let sk_raw = Zeroizing::new(fs::read_to_string(&secret_key)?);
            let sk_bytes = Zeroizing::new(decode_armored(&sk_raw, "PRIVATE KEY")?);
            let sk = PrivateKey::from_bytes(&sk_bytes)?;

            let raw_input = read_input(input.as_deref())?;
            let input_str = String::from_utf8_lossy(&raw_input);
            let ciphertext = decode_armored(&input_str, "MESSAGE")?;

            let plaintext = Zeroizing::new(decrypt_message(&sk, &ciphertext)?);
            write_output(output.as_deref(), &plaintext)?;
        }

        Commands::Sign {
            secret_key,
            input,
            output,
            qr,
        } => {
            let sk_raw = Zeroizing::new(fs::read_to_string(&secret_key)?);
            let sk_bytes = Zeroizing::new(decode_armored(&sk_raw, "PRIVATE KEY")?);
            let sk = PrivateKey::from_bytes(&sk_bytes)?;

            let data = read_input(input.as_deref())?;
            let sig_bytes = sign_data(&sk.ed25519_sk, &data);
            let armored = encode_armored("SIGNATURE", &sig_bytes);

            if qr {
                display_qr(armored.as_bytes(), "Digital Signature")?;
            }

            write_output(output.as_deref(), armored.as_bytes())?;
        }

        Commands::Verify {
            public_key,
            signature,
            input,
        } => {
            let pk_raw = fs::read_to_string(&public_key)?;
            let pk_bytes = decode_armored(&pk_raw, "PUBLIC KEY")?;
            let pk = PublicKey::from_bytes(&pk_bytes)?;

            let sig_raw = fs::read_to_string(&signature)?;
            let sig_bytes = decode_armored(&sig_raw, "SIGNATURE")?;

            let data = read_input(input.as_deref())?;
            verify_data(&pk.ed25519_pk, &data, &sig_bytes)?;
            eprintln!("Good signature from public key {}", public_key.display());
        }

        Commands::Export {
            secret_key,
            output,
            qr,
        } => {
            let sk_raw = Zeroizing::new(fs::read_to_string(&secret_key)?);
            let sk_bytes = Zeroizing::new(decode_armored(&sk_raw, "PRIVATE KEY")?);
            let sk = PrivateKey::from_bytes(&sk_bytes)?;
            let pk = sk.public_key();

            let pk_armor = encode_armored("PUBLIC KEY", &pk.to_bytes());

            if qr {
                display_qr(&pk.to_bytes(), "Public Key (Binary)")?;
            }

            write_output(output.as_deref(), pk_armor.as_bytes())?;
        }

        Commands::Qr { input } => {
            let data = read_input(input.as_deref())?;
            display_qr(&data, "Terminal QR")?;
        }

        Commands::Keyserver(subcmd) => match subcmd {
            KeyserverCommands::Publish {
                public_key,
                secret_key,
                user,
                server,
            } => {
                let pk_armored = fs::read_to_string(&public_key)?;
                let sk_raw = Zeroizing::new(fs::read_to_string(&secret_key)?);
                let sk_bytes = Zeroizing::new(decode_armored(&sk_raw, "PRIVATE KEY")?);
                let sk = PrivateKey::from_bytes(&sk_bytes)?;

                let rec = publish_key(&server, &user, &pk_armored, &sk.ed25519_sk)?;
                println!("✓ Post-quantum public key successfully published to PQKeys service!");
                println!("  Server:      {}", server);
                println!("  Fingerprint: {}", rec.fingerprint);
                println!("  User ID:     {}", rec.user_id);
                println!("  Timestamp:   {}", rec.timestamp);
            }

            KeyserverCommands::Lookup {
                query,
                output,
                qr,
                server,
            } => {
                let rec = lookup_key(&server, &query)?;
                println!("✓ Public key retrieved and self-signature verified:");
                println!("  Server:      {}", server);
                println!("  Fingerprint: {}", rec.fingerprint);
                println!("  User ID:     {}", rec.user_id);
                println!("  Timestamp:   {}", rec.timestamp);
                println!("  Revoked:     {}", rec.revoked);
                if rec.revoked {
                    println!("  Reason:      {}", rec.revocation_reason);
                }

                if let Some(out_path) = output {
                    fs::write(&out_path, &rec.armored_public_key)?;
                    println!("  Saved to:    {}", out_path.display());
                } else {
                    println!("\n{}", rec.armored_public_key);
                }

                if qr {
                    let raw_pub = decode_armored(&rec.armored_public_key, "PUBLIC KEY")
                        .map_err(|e| anyhow::anyhow!("Decoding public key for QR: {}", e))?;
                    display_qr(&raw_pub, "Verified Public Key")?;
                }
            }

            KeyserverCommands::Revoke {
                public_key,
                secret_key,
                reason,
                server,
            } => {
                let pk_armored = fs::read_to_string(&public_key)?;
                let sk_raw = Zeroizing::new(fs::read_to_string(&secret_key)?);
                let sk_bytes = Zeroizing::new(decode_armored(&sk_raw, "PRIVATE KEY")?);
                let sk = PrivateKey::from_bytes(&sk_bytes)?;

                let rec = revoke_key(&server, &pk_armored, &sk.ed25519_sk, &reason)?;
                println!("✓ Post-quantum public key revoked successfully:");
                println!("  Server:      {}", server);
                println!("  Fingerprint: {}", rec.fingerprint);
                println!("  Revoked:     {}", rec.revoked);
                println!("  Reason:      {}", rec.revocation_reason);
            }

            KeyserverCommands::List {
                limit,
                offset,
                server,
            } => {
                let summaries = list_keys(&server, limit, offset)?;
                println!("=== PQKeys Registered Keys ({}) ===", server);
                if summaries.is_empty() {
                    println!("(No keys found)");
                } else {
                    for (i, item) in summaries.iter().enumerate() {
                        let status = if item.revoked { "[REVOKED]" } else { "[ACTIVE]" };
                        println!(
                            "{:02}. {} {} | User: {} | TS: {}",
                            offset + i + 1,
                            status,
                            item.fingerprint,
                            if item.user_id.is_empty() { "-" } else { &item.user_id },
                            item.timestamp
                        );
                    }
                }
            }
        },
    }

    Ok(())
}
