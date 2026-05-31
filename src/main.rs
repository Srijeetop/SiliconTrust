/// Silicon Trust — Hardware Entropy Cryptographic System
/// Phase 4: CLI  (stcs encrypt / stcs decrypt / stcs status / stcs dump)

mod fingerprint;
mod cipher;
mod collect;

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rand::RngCore;

use fingerprint::{derive_master_key, HardwareFingerprint};
use cipher::{decrypt, encrypt_with_salt, extract_salt};
use collect::collect_fingerprint;

#[derive(Parser)]
#[command(
    name = "stcs",
    about = "Silicon Trust Cryptographic System — encrypts files using this machine's physical identity as the key",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}


#[derive(Subcommand)]
enum Command {
    /// Encrypt a file (output: <file>.hec)
    Encrypt {
        file: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Key rotation epoch tag (e.g. "2025-Q2"). Must match on decrypt.
        #[arg(short, long, default_value = "")]
        passphrase: String,
        /// Delete the original plaintext file after successful encryption
        #[arg(short, long)]
        delete: bool,
    },

    /// Decrypt a .hec file (output: original filename)
    Decrypt {
        file: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(short, long, default_value = "")]
        passphrase: String,
    },

    /// Export hardware fingerprint to JSON for emergency recovery
    Export {
        /// Write JSON to this file instead of stdout
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Emergency recovery: decrypt using a previously exported fingerprint and the original passphrase
    Recover {
        /// Encrypted .stcs file
        file: PathBuf,

        /// Hardware fingerprint JSON file (from `stcs export`)
        #[arg(short = 'f', long)]
        fingerprint: PathBuf,

        /// Passphrase used during encryption
        #[arg(short, long, default_value = "")]
        passphrase: String,

        /// Output file (default: <encrypted-file> without .stcs extension)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Show which hardware sources are available (pass/fail per source)
    Status,

    /// Print the full raw value of every hardware source
    Dump {
        /// Only print one specific source by name
        #[arg(short, long)]
        source: Option<String>,

        /// Also show the SHA3-512 hash that HEC derives from each source
        #[arg(long)]
        hashes: bool,
    },
}


fn main() {
    let cli = Cli::parse();

    match cli.command {
        // ── status ───────────────────────────────────────────────────────────
        Command::Status => {
            collect_fingerprint(true);
        }

        // ── dump ─────────────────────────────────────────────────────────────
        Command::Dump { source, hashes } => {
            let fp = collect_fingerprint(false); // silent collection
            let sources = fp.present_sources();
            let all: Vec<(&'static str, &str)> = sources.clone();

            // All 9 labels in canonical order
            let all_labels = [
                "cpuid", "smbios_uuid", "nic_mac", "ssd_serial", "tpm_ek",
                "gpu_device_id", "dimm_spd", "cache_topology", "pcie_topology",
            ];

            // Helper: look up value for a label
            let get = |label: &str| -> Option<&str> {
                all.iter().find(|(l, _)| *l == label).map(|(_, v)| *v)
            };

            let to_print: Vec<&str> = match &source {
                Some(name) => {
                    if !all_labels.contains(&name.as_str()) {
                        eprintln!(
                            "[stcs] Unknown source '{}'. Valid names:\n  {}",
                            name,
                            all_labels.join(", ")
                        );
                        std::process::exit(1);
                    }
                    vec![name.as_str()]
                }
                None => all_labels.to_vec(),
            };

            println!();
            println!("  STCS Hardware Entropy Dump");
            println!("  {}", "=".repeat(72));

            for label in &to_print {
                println!();
                match get(label) {
                    Some(value) => {
                        println!("  \u{2713} {}", label.to_uppercase());
                        println!("  {}", "-".repeat(72));

                        // Pretty-print: split on '|' so each sub-field is on its own line
                        for part in value.split('|').filter(|s| !s.is_empty()) {
                            println!("      {}", part);
                        }

                        if hashes {
                            use sha3::{Digest, Sha3_512};
                            let mut h = Sha3_512::new();
                            h.update(label.as_bytes());
                            h.update(b":");
                            h.update(value.as_bytes());
                            let hash = h.finalize();
                            println!();
                            println!("  SHA3-512:");
                            // Print hash as two 32-byte lines for readability
                            let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
                            println!("      {}", &hex[..64]);
                            println!("      {}", &hex[64..]);
                        }
                    }
                    None => {
                        println!("  \u{2717} {} (not available on this machine)", label.to_uppercase());
                        println!("  {}", "-".repeat(72));
                    }
                }
            }

            println!();
            println!("  {}", "=".repeat(72));
            println!(
                "  {}/{} sources present   (threshold: {}/{})",
                sources.len(),
                fingerprint::TOTAL_SOURCES,
                fingerprint::THRESHOLD,
                fingerprint::TOTAL_SOURCES,
            );
            if sources.len() >= fingerprint::THRESHOLD {
                println!("  Status: READY — this machine can encrypt and decrypt");
            } else {
                println!("  Status: NOT READY — too few sources");
            }
            println!();
        }

        // ── export ───────────────────────────────────────────────────────────
        Command::Export { out } => {
            let fp = collect_fingerprint(false); // silent collection
            let json = serde_json::to_string_pretty(&fp).unwrap_or_else(|e| {
                eprintln!("[stcs] Serialization error: {e}");
                std::process::exit(1);
            });

            if let Some(path) = out {
                fs::write(&path, &json).unwrap_or_else(|e| {
                    eprintln!("[stcs] Cannot write {}: {e}", path.display());
                    std::process::exit(1);
                });
                eprintln!("[stcs] Fingerprint exported to {}", path.display());
            } else {
                println!("{json}");
            }
        }

        // ── recover ──────────────────────────────────────────────────────────
        Command::Recover {
            file,
            fingerprint,
            passphrase,
            out,
        } => {
            // 1. Load the fingerprint JSON
            let json = fs::read_to_string(&fingerprint).unwrap_or_else(|e| {
                eprintln!("[stcs] Cannot read fingerprint file {}: {e}", fingerprint.display());
                std::process::exit(1);
            });
            let fp: HardwareFingerprint = serde_json::from_str(&json).unwrap_or_else(|e| {
                eprintln!("[stcs] Invalid fingerprint JSON: {e}");
                std::process::exit(1);
            });

            // 2. Check threshold (same as original machine)
            check_threshold(&fp);

            // 3. Read the encrypted blob
            let blob = fs::read(&file).unwrap_or_else(|e| {
                eprintln!("[stcs] Cannot read {}: {e}", file.display());
                std::process::exit(1);
            });

            // 4. Extract the public salt from the ciphertext header
            let salt = extract_salt(&blob).unwrap_or_else(|e| {
                eprintln!("[stcs] {e}");
                std::process::exit(1);
            });

            // 5. Derive the master key from the provided fingerprint + passphrase
            eprintln!("[stcs] Deriving key via Argon2id (512 MB, 4 passes) — ~5-15s...");
            let mut key = derive_master_key(&fp, &salt, &passphrase).unwrap_or_else(|e| {
                eprintln!("[stcs] {e}");
                std::process::exit(1);
            });

            // 6. Decrypt
            let plaintext = decrypt(&mut key, &blob).unwrap_or_else(|e| {
                eprintln!("[stcs] {e}");
                std::process::exit(1);
            });

            // 7. Write output
            let out_path = out.unwrap_or_else(|| {
                let name = file.to_string_lossy();
                if name.ends_with(".stcs") {
                    PathBuf::from(&name[..name.len() - 5]) // strip '.stcs'
                } else {
                    let mut p = file.clone();
                    p.set_extension("dec");
                    p
                }
            });

            fs::write(&out_path, &plaintext).unwrap_or_else(|e| {
                eprintln!("[stcs] Cannot write {}: {e}", out_path.display());
                std::process::exit(1);
            });

            eprintln!("[stcs] Recovered -> {} ({} bytes)", out_path.display(), plaintext.len());
        }



        // ── encrypt ──────────────────────────────────────────────────────────
        Command::Encrypt { file, out, passphrase, delete } => {
            let out_path = out.unwrap_or_else(|| {
                let mut p = file.clone();
                let new_ext = match p.extension() {
                    Some(e) => format!("{}.stcs", e.to_string_lossy()),
                    None    => "stcs".to_string(),
                };
                p.set_extension(new_ext);
                p
            });

            let plaintext = fs::read(&file).unwrap_or_else(|e| {
                eprintln!("[stcs] Cannot read {}: {e}", file.display());
                std::process::exit(1);
            });

            let fp = collect_fingerprint(true);
            check_threshold(&fp);

            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);

            eprintln!("[stcs] Deriving key via Argon2id (512 MB, 4 passes) — ~5-15s...");
            let key = derive_master_key(&fp, &salt, &passphrase).unwrap_or_else(|e| {
                eprintln!("[stcs] {e}");
                std::process::exit(1);
            });

            let blob = encrypt_with_salt(&key, &salt, &plaintext);

            fs::write(&out_path, &blob).unwrap_or_else(|e| {
                eprintln!("[stcs] Cannot write {}: {e}", out_path.display());
                std::process::exit(1);
            });

            eprintln!(
                "[stcs] Done. {} bytes -> {} ({} bytes)",
                plaintext.len(), out_path.display(), blob.len()
            );
	    if delete {
    		match fs::remove_file(&file) {
        		Ok(()) => eprintln!("[stcs] Deleted original file: {}", file.display()),
        		Err(e) => eprintln!("[stcs] Warning: could not delete {}: {e}", file.display()),
    		}
	     }
            eprintln!("[stcs] Key wiped from RAM. Zero bytes stored on disk.");
        }

        // ── decrypt ──────────────────────────────────────────────────────────
        Command::Decrypt { file, out, passphrase } => {
            let out_path = out.unwrap_or_else(|| {
                let s = file.to_string_lossy();
                if s.ends_with(".hec") {
                    PathBuf::from(&s[..s.len() - 4])
                } else {
                    let mut p = file.clone();
                    p.set_extension("dec");
                    p
                }
            });

            let blob = fs::read(&file).unwrap_or_else(|e| {
                eprintln!("[stcs] Cannot read {}: {e}", file.display());
                std::process::exit(1);
            });

            let salt = extract_salt(&blob).unwrap_or_else(|e| {
                eprintln!("[stcs] {e}");
                std::process::exit(1);
            });

            let fp = collect_fingerprint(true);
            check_threshold(&fp);

            eprintln!("[stcs] Deriving key via Argon2id (512 MB, 4 passes) — ~5-15s...");
            let mut key = derive_master_key(&fp, &salt, &passphrase).unwrap_or_else(|e| {
                eprintln!("[stcs] {e}");
                std::process::exit(1);
            });

            let plaintext = decrypt(&mut key, &blob).unwrap_or_else(|e| {
                eprintln!("[stcs] {e}");
                std::process::exit(1);
            });

            fs::write(&out_path, &plaintext).unwrap_or_else(|e| {
                eprintln!("[stcs] Cannot write {}: {e}", out_path.display());
                std::process::exit(1);
            });

            eprintln!("[stcs] Decrypted -> {} ({} bytes)", out_path.display(), plaintext.len());
        }
    }
}

fn check_threshold(fp: &fingerprint::HardwareFingerprint) {
    let n = fp.present_sources().len();
    if n < fingerprint::THRESHOLD {
        eprintln!(
            "[stcs] ERROR: need {}/{} hardware sources, only {} available.",
            fingerprint::THRESHOLD, fingerprint::TOTAL_SOURCES, n
        );
        std::process::exit(1);
    }
}