use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pqpg::armor::{decode_armored, encode_armored};
use pqpg::crypto::{decrypt_message, encrypt_message, sign_data, verify_data};
use pqpg::keys::{PrivateKey, PublicKey};
use pqpg::qr::render_terminal_qr;

#[derive(Parser, Debug)]
#[command(
    name = "pqpg",
    author = "Gab Virebent <gabriel1@virebent.art>",
    version = "0.1.0",
    about = "Post-Quantum Privacy Guard: lightweight CLI for hybrid post-quantum file encryption, signing and key management",
    long_about = "pqpg is a modern, standalone command-line tool implementing NIST FIPS 203 ML-KEM-768\ncombined with X25519 and ChaCha20-Poly1305 for post-quantum forward-secure encryption,\nand Ed25519 for digital signatures with optional Air-Gapped QR code transfer."
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
        /// Recipient's public key file (.pub)
        #[arg(short, long)]
        recipient: PathBuf,

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

fn display_qr(data: &[u8], label: &str) -> Result<(), anyhow::Error> {
    match render_terminal_qr(data) {
        Ok(qr_str) => {
            eprintln!("\n=== Air-Gapped QR Code ({}) ===", label);
            eprintln!("{}", qr_str);
            eprintln!("==============================================\n");
            Ok(())
        }
        Err(e) => {
            eprintln!("Notice: Data exceeds single QR code limit ({} bytes): {}", data.len(), e);
            Ok(())
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { name, out_dir, qr } => {
            fs::create_dir_all(&out_dir)?;
            let (sk, pk) = PrivateKey::generate();

            let sk_armor = encode_armored("PRIVATE KEY", &sk.to_bytes());
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
            eprintln!("  Algorithms:  ML-KEM-768 (FIPS 203) + X25519 (DH) + Ed25519 (Sign)");

            if qr {
                // Render raw binary public key (1253 bytes) into high-density QR code
                display_qr(&pk.to_bytes(), "Public Key (Binary)")?;
            }
        }

        Commands::Encrypt {
            recipient,
            input,
            output,
            qr,
        } => {
            let pk_raw = fs::read_to_string(&recipient)?;
            let pk_bytes = decode_armored(&pk_raw, "PUBLIC KEY")?;
            let pk = PublicKey::from_bytes(&pk_bytes)?;

            let plaintext = read_input(input.as_deref())?;
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
            let sk_raw = fs::read_to_string(&secret_key)?;
            let sk_bytes = decode_armored(&sk_raw, "PRIVATE KEY")?;
            let sk = PrivateKey::from_bytes(&sk_bytes)?;

            let raw_input = read_input(input.as_deref())?;
            let input_str = String::from_utf8_lossy(&raw_input);
            let ciphertext = decode_armored(&input_str, "MESSAGE")?;

            let plaintext = decrypt_message(&sk, &ciphertext)?;
            write_output(output.as_deref(), &plaintext)?;
        }

        Commands::Sign {
            secret_key,
            input,
            output,
            qr,
        } => {
            let sk_raw = fs::read_to_string(&secret_key)?;
            let sk_bytes = decode_armored(&sk_raw, "PRIVATE KEY")?;
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
            let sk_raw = fs::read_to_string(&secret_key)?;
            let sk_bytes = decode_armored(&sk_raw, "PRIVATE KEY")?;
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
    }

    Ok(())
}
