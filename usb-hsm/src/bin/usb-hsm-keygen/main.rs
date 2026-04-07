/// usb-hsm-keygen: manage keys in a usb-hsm .p11k keystore.
mod key_parser;
mod pin;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use usb_hsm::keystore::{KeyEntry, Keystore};

// PBKDF2 iteration count for new keystores (NIST SP 800-132 floor).
// Identical to the private MIN_KDF_ITERATIONS in keystore.rs -- kept in sync
// manually since that constant is not part of the public API.
const KDF_ITERATIONS: u32 = 100_000;

#[derive(Parser)]
#[command(
    name = "usb-hsm-keygen",
    about = "Manage private keys stored in a usb-hsm .p11k keystore"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new .p11k keystore from one or more private key files.
    ///
    /// Each <KEY_FILE> is imported in order. Use --label to assign a name to
    /// each key; if --label is supplied fewer times than there are key files,
    /// the remaining keys are labelled from their filename stems.
    /// Use --cert to attach a certificate to the key at the same position.
    Create {
        /// Private key files to import (PEM or DER, RSA or EC P-256).
        #[arg(required = true)]
        key_files: Vec<PathBuf>,

        /// Label for each key file, positionally paired.
        /// May be repeated; filename stem is used for any unlabelled key.
        #[arg(long, short)]
        label: Vec<String>,

        /// Certificate PEM file, positionally paired with the key at the same index.
        /// May be repeated; keys without a matching --cert get no certificate.
        #[arg(long)]
        cert: Vec<PathBuf>,

        /// Output path for the new .p11k keystore file.
        #[arg(long, short)]
        output: PathBuf,

        /// Overwrite the output file if it already exists.
        #[arg(long)]
        force: bool,
    },

    /// Add a private key to an existing .p11k keystore.
    #[command(name = "key-add")]
    KeyAdd {
        /// Path to the existing .p11k keystore.
        keystore: PathBuf,
        /// Private key file to add (PEM or DER, RSA or EC P-256).
        key_file: PathBuf,
        /// Label for the new key (filename stem used if omitted).
        #[arg(long)]
        label: Option<String>,
    },

    /// Remove a key from an existing .p11k keystore by label or hex ID.
    #[command(name = "key-remove")]
    KeyRemove {
        /// Path to the existing .p11k keystore.
        keystore: PathBuf,
        /// Label of the key to remove (mutually exclusive with --id).
        #[arg(long, conflicts_with = "id", required_unless_present = "id")]
        label: Option<String>,
        /// 32-hex-character key ID of the key to remove (mutually exclusive with --label).
        #[arg(long, conflicts_with = "label", required_unless_present = "label")]
        id: Option<String>,
    },

    /// Attach or replace a certificate on an existing keystore entry.
    ///
    /// Identifies the entry by --label and stores the DER bytes from the
    /// given PEM file in the cert_der field of that entry.
    #[command(name = "cert-add")]
    CertAdd {
        /// Path to the existing .p11k keystore.
        keystore: PathBuf,
        /// Certificate PEM file (BEGIN CERTIFICATE block).
        cert_file: PathBuf,
        /// Label of the keystore entry to attach the certificate to.
        #[arg(long)]
        label: String,
    },

    /// Re-encrypt a .p11k keystore under a new PIN.
    #[command(name = "pin-change")]
    PinChange {
        /// Path to the .p11k keystore to re-encrypt.
        keystore: PathBuf,
    },

    /// Add or update a .p11k file entry in the .usb-hsm manifest.
    ///
    /// The manifest file is created if it does not yet exist. Use this command
    /// to register a keystore that was placed on the drive without going through
    /// `usb-hsm-keygen create`, or to update the label of an existing entry.
    #[command(name = "manifest-add")]
    ManifestAdd {
        /// Path to the .p11k file to register (must be on the USB drive root).
        p11k_path: PathBuf,
        /// Human-readable label for this slot (defaults to filename stem).
        #[arg(long)]
        label: Option<String>,
    },

    /// Remove a .p11k file entry from the .usb-hsm manifest.
    #[command(name = "manifest-remove")]
    ManifestRemove {
        /// Path to the .p11k file to deregister.
        p11k_path: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli.command) {
        eprintln!("usb-hsm-keygen: {e}");
        std::process::exit(1);
    }
}

fn run(cmd: Commands) -> Result<(), String> {
    match cmd {
        Commands::Create { key_files, label, cert, output, force } => {
            cmd_create(key_files, label, cert, output, force)
        }
        Commands::KeyAdd { keystore, key_file, label } => {
            cmd_key_add(keystore, key_file, label)
        }
        Commands::KeyRemove { keystore, label, id } => {
            cmd_key_remove(keystore, label, id)
        }
        Commands::CertAdd { keystore, cert_file, label } => {
            cmd_cert_add(keystore, cert_file, label)
        }
        Commands::PinChange { keystore } => cmd_pin_change(keystore),
        Commands::ManifestAdd { p11k_path, label } => cmd_manifest_add(p11k_path, label),
        Commands::ManifestRemove { p11k_path } => cmd_manifest_remove(p11k_path),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Write `data` to `path` atomically: write to a temp file in the same
/// directory, then rename into place.
///
/// The rename(2) syscall is atomic at the OS level -- the file is either the
/// old version or the new version, never a partial write.  However, this does
/// NOT protect against two concurrent usb-hsm-keygen processes modifying the
/// same keystore simultaneously.  The race is a classic lost-update:
///
///   Process A: load -> modify -> create blob A -> rename A into place
///   Process B: load -> modify -> create blob B -> rename B into place
///
/// Whichever process renames last wins; the other's changes are silently lost.
/// The temp file name includes the PID so the two processes do not interfere
/// with each other's temp files, but the final rename still races.
///
/// Mitigation: usb-hsm-keygen is a single-user CLI tool.  Do not run two
/// instances against the same keystore file concurrently.  A wrapper script
/// that uses `flock(1)` provides mutual exclusion if scripted automation requires it.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".usb-hsm-keygen-{}.tmp", std::process::id()));
    std::fs::write(&tmp, data)
        .map_err(|e| format!("write to {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename to {}: {e}", path.display())
    })
}

/// Derive a label from the filename stem, e.g. "my_rsa_key.pem" -> "my_rsa_key".
fn stem_label(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("key")
        .to_string()
}

// ---------------------------------------------------------------------------
// create subcommand
// ---------------------------------------------------------------------------

fn cmd_create(
    key_files: Vec<PathBuf>,
    labels: Vec<String>,
    cert_files: Vec<PathBuf>,
    output: PathBuf,
    force: bool,
) -> Result<(), String> {
    if output.exists() && !force {
        return Err(format!(
            "{} already exists. Use --force to overwrite.",
            output.display()
        ));
    }

    let mut entries: Vec<KeyEntry> = Vec::new();
    let mut any_failures = false;
    for (idx, path) in key_files.iter().enumerate() {
        let (parsed_keys, failures) = key_parser::parse_key_file(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        for (alias, err) in &failures {
            eprintln!("warning: skipped \"{alias}\": {err}");
            any_failures = true;
        }
        // --cert[idx] is paired with the file, not with individual keys within it.
        // Attach the certificate to the first key from this file only.
        let cert_der_for_file = match cert_files.get(idx) {
            Some(cert_path) => Some(
                key_parser::parse_cert_pem(cert_path)
                    .map_err(|e| format!("{}: {e}", cert_path.display()))?,
            ),
            None => None,
        };
        // --label[idx] is paired with the file. For single-key files (all current
        // formats) key_idx is always 0 and behaviour is unchanged.
        let file_label = labels.get(idx).cloned();
        for (key_idx, parsed) in parsed_keys.into_iter().enumerate() {
            // --label[file_idx] overrides the first key only.  Subsequent keys
            // from the same file (multi-key JKS, multi-bag PKCS#12) use the
            // embedded label hint (alias, friendlyName) and fall back to the
            // filename stem only when no hint is present.
            let label = if key_idx == 0 {
                file_label.clone()
                    .or_else(|| parsed.label_hint.clone())
                    .unwrap_or_else(|| stem_label(path))
            } else {
                parsed.label_hint.clone()
                    .unwrap_or_else(|| stem_label(path))
            };
            // --cert takes precedence; fall back to embedded cert from PKCS#12.
            let cert_der = if key_idx == 0 {
                cert_der_for_file.clone().or(parsed.cert_der)
            } else {
                parsed.cert_der
            };
            entries.push(KeyEntry {
                id: parsed.id,
                label,
                key_type: parsed.key_type,
                der_bytes: parsed.key_bytes,
                cert_der,
                pub_bytes: None,
            });
        }
    }

    // Capture summary before entries are consumed by Keystore::create.
    let summary: Vec<(String, &str, String)> = entries
        .iter()
        .map(|e| {
            let id_hex: String = e.id.iter().map(|b| format!("{b:02x}")).collect();
            let key_type = match e.key_type {
                usb_hsm::keystore::KeyType::Rsa => "RSA",
                usb_hsm::keystore::KeyType::Ec => "EC",
                usb_hsm::keystore::KeyType::MlDsa44 => "ML-DSA-44",
                usb_hsm::keystore::KeyType::MlDsa65 => "ML-DSA-65",
                usb_hsm::keystore::KeyType::MlDsa87 => "ML-DSA-87",
                usb_hsm::keystore::KeyType::MlKem512 => "ML-KEM-512",
                usb_hsm::keystore::KeyType::MlKem768 => "ML-KEM-768",
                usb_hsm::keystore::KeyType::MlKem1024 => "ML-KEM-1024",
            };
            (e.label.clone(), key_type, id_hex)
        })
        .collect();

    let pin = pin::prompt_new_pin().map_err(|e| format!("PIN prompt failed: {e}"))?;
    let blob = Keystore::create(entries, &pin, KDF_ITERATIONS)
        .map_err(|e| format!("keystore creation failed: {e}"))?;
    atomic_write(&output, &blob)?;
    eprintln!("Wrote {} key(s) to {}:", summary.len(), output.display());
    for (i, (label, key_type, id_hex)) in summary.iter().enumerate() {
        eprintln!("  [{}] {} ({}) id={}", i, label, key_type, id_hex);
    }

    // Register the new keystore in the .usb-hsm manifest so the library
    // detects the drive via a single stat(2) instead of a directory scan.
    if let Some(filename) = output.file_name().and_then(|n| n.to_str()) {
        let entry_label = stem_label(&output);
        let manifest_path = output
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(usb_hsm::manifest::DEFAULT_MANIFEST_NAME);
        let existing = std::fs::read_to_string(&manifest_path).unwrap_or_default();
        let updated = usb_hsm::manifest::upsert_entry(&existing, filename, &entry_label);
        atomic_write(&manifest_path, updated.as_bytes())?;
        eprintln!("Updated manifest {}.", manifest_path.display());
    }

    if any_failures {
        return Err("some keys failed to import; see warnings above".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// key-add subcommand
// ---------------------------------------------------------------------------

fn cmd_key_add(keystore_path: PathBuf, key_file: PathBuf, label: Option<String>) -> Result<(), String> {
    let pin = pin::prompt_pin("Enter PIN: ").map_err(|e| format!("PIN prompt failed: {e}"))?;

    let keystore = Keystore::load(&keystore_path, &pin)
        .map_err(|e| format!("{}: {e}", keystore_path.display()))?;

    let (parsed_keys, failures) = key_parser::parse_key_file(&key_file)
        .map_err(|e| format!("{}: {e}", key_file.display()))?;
    for (alias, err) in &failures {
        eprintln!("warning: skipped \"{alias}\": {err}");
    }
    let had_failures = !failures.is_empty();

    let mut entries: Vec<KeyEntry> = keystore.entries().iter().map(|e| e.clone()).collect();
    let file_label = label;
    for (key_idx, parsed) in parsed_keys.into_iter().enumerate() {
        let new_label = if key_idx == 0 {
            file_label.clone()
                .or_else(|| parsed.label_hint.clone())
                .unwrap_or_else(|| stem_label(&key_file))
        } else {
            stem_label(&key_file)
        };
        entries.push(KeyEntry {
            id: parsed.id,
            label: new_label,
            key_type: parsed.key_type,
            der_bytes: parsed.key_bytes,
            cert_der: parsed.cert_der,
            pub_bytes: None,
        });
    }

    let blob = Keystore::create(entries, &pin, KDF_ITERATIONS)
        .map_err(|e| format!("keystore re-encryption failed: {e}"))?;
    atomic_write(&keystore_path, &blob)?;
    eprintln!("Added key to {}.", keystore_path.display());
    if had_failures {
        return Err("some keys failed to import; see warnings above".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// key-remove subcommand
// ---------------------------------------------------------------------------

fn cmd_key_remove(keystore_path: PathBuf, label: Option<String>, id: Option<String>) -> Result<(), String> {
    let pin = pin::prompt_pin("Enter PIN: ").map_err(|e| format!("PIN prompt failed: {e}"))?;

    let keystore = Keystore::load(&keystore_path, &pin)
        .map_err(|e| format!("{}: {e}", keystore_path.display()))?;

    // Collect all entries except the one to remove.
    let before_count = keystore.entries().len();
    let entries: Vec<KeyEntry> = keystore
        .entries()
        .iter()
        .filter(|e| {
            if let Some(ref lbl) = label {
                return e.label != *lbl;
            }
            if let Some(ref hex_id) = id {
                let entry_hex: String = e.id.iter().map(|b| format!("{b:02x}")).collect();
                return entry_hex != hex_id.to_lowercase();
            }
            true
        })
        .map(|e| e.clone())
        .collect();

    if entries.len() == before_count {
        let selector = label.as_deref()
            .map(|l| format!("label \"{l}\""))
            .or_else(|| id.as_deref().map(|i| format!("id \"{i}\"")))
            .unwrap_or_default();
        return Err(format!("no key with {selector} found in keystore"));
    }

    let blob = Keystore::create(entries, &pin, KDF_ITERATIONS)
        .map_err(|e| format!("keystore re-encryption failed: {e}"))?;
    atomic_write(&keystore_path, &blob)?;
    eprintln!("Removed key from {}.", keystore_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// cert-add subcommand
// ---------------------------------------------------------------------------

fn cmd_cert_add(
    keystore_path: PathBuf,
    cert_file: PathBuf,
    label: String,
) -> Result<(), String> {
    let pin = pin::prompt_pin("Enter PIN: ").map_err(|e| format!("PIN prompt failed: {e}"))?;

    let keystore = Keystore::load(&keystore_path, &pin)
        .map_err(|e| format!("{}: {e}", keystore_path.display()))?;

    let cert_der = key_parser::parse_cert_pem(&cert_file)
        .map_err(|e| format!("{}: {e}", cert_file.display()))?;

    let mut found = false;
    let entries: Vec<KeyEntry> = keystore
        .entries()
        .iter()
        .map(|e| {
            let mut entry = e.clone();
            if entry.label == label {
                found = true;
                entry.cert_der = Some(cert_der.clone());
            }
            entry
        })
        .collect();

    if !found {
        return Err(format!("no key with label \"{label}\" found in keystore"));
    }

    let blob = Keystore::create(entries, &pin, KDF_ITERATIONS)
        .map_err(|e| format!("keystore re-encryption failed: {e}"))?;
    atomic_write(&keystore_path, &blob)?;
    eprintln!("Attached certificate to entry \"{label}\" in {}.", keystore_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// manifest-add subcommand
// ---------------------------------------------------------------------------

fn cmd_manifest_add(p11k_path: PathBuf, label: Option<String>) -> Result<(), String> {
    let filename = p11k_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid path: {}", p11k_path.display()))?
        .to_string();
    let entry_label = label.unwrap_or_else(|| stem_label(&p11k_path));
    let manifest_path = p11k_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(usb_hsm::manifest::DEFAULT_MANIFEST_NAME);
    let existing = std::fs::read_to_string(&manifest_path).unwrap_or_default();
    let updated = usb_hsm::manifest::upsert_entry(&existing, &filename, &entry_label);
    atomic_write(&manifest_path, updated.as_bytes())?;
    eprintln!(
        "Added '{}' (label: \"{}\") to manifest {}.",
        filename, entry_label, manifest_path.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// manifest-remove subcommand
// ---------------------------------------------------------------------------

fn cmd_manifest_remove(p11k_path: PathBuf) -> Result<(), String> {
    let filename = p11k_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid path: {}", p11k_path.display()))?
        .to_string();
    let manifest_path = p11k_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(usb_hsm::manifest::DEFAULT_MANIFEST_NAME);
    let existing = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read manifest {}: {e}", manifest_path.display()))?;
    let before_count = usb_hsm::manifest::parse_manifest(&existing).len();
    let updated = usb_hsm::manifest::remove_entry(&existing, &filename);
    if usb_hsm::manifest::parse_manifest(&updated).len() == before_count {
        return Err(format!(
            "'{}' not found in manifest {}",
            filename, manifest_path.display()
        ));
    }
    atomic_write(&manifest_path, updated.as_bytes())?;
    eprintln!("Removed '{}' from manifest {}.", filename, manifest_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// pin-change subcommand
// ---------------------------------------------------------------------------

fn cmd_pin_change(keystore_path: PathBuf) -> Result<(), String> {
    let old_pin = pin::prompt_pin("Enter current PIN: ")
        .map_err(|e| format!("PIN prompt failed: {e}"))?;

    let keystore = Keystore::load(&keystore_path, &old_pin)
        .map_err(|e| format!("{}: {e}", keystore_path.display()))?;

    let new_pin = pin::prompt_new_pin().map_err(|e| format!("PIN prompt failed: {e}"))?;

    let entries: Vec<KeyEntry> = keystore.entries().iter().map(|e| e.clone()).collect();
    let blob = Keystore::create(entries, &new_pin, KDF_ITERATIONS)
        .map_err(|e| format!("keystore re-encryption failed: {e}"))?;
    atomic_write(&keystore_path, &blob)?;
    eprintln!("PIN changed for {}.", keystore_path.display());
    Ok(())
}
