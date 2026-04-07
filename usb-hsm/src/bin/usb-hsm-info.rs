/// usb-hsm-info: inspect the unencrypted header of a .p11k keystore file.
///
/// Reads and displays the magic marker, format version, PBKDF2 iteration
/// count, and ciphertext length -- all of which are stored in the clear
/// and require no PIN.

use std::path::Path;
use std::process;

// Wire-format constants (must be kept in sync with keystore.rs).
const MAGIC: &[u8; 4] = b"P11K";
const HEADER_LEN: usize = 57;
const OFF_VERSION: usize = 4;
const OFF_KDF_ITERATIONS: usize = 37;
const OFF_CIPHERTEXT_LEN: usize = 53;

fn inspect(path: &Path) -> Result<(), String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;

    if data.len() < HEADER_LEN {
        return Err(format!(
            "{}: file too short ({} bytes, need at least {HEADER_LEN})",
            path.display(),
            data.len()
        ));
    }

    if &data[..4] != MAGIC {
        return Err(format!(
            "{}: bad magic (expected P11K, got {:?})",
            path.display(),
            &data[..4]
        ));
    }

    let version = data[OFF_VERSION];
    let kdf_iterations = u32::from_be_bytes(
        data[OFF_KDF_ITERATIONS..OFF_KDF_ITERATIONS + 4]
            .try_into()
            .unwrap(),
    );
    let ciphertext_len = u32::from_be_bytes(
        data[OFF_CIPHERTEXT_LEN..OFF_CIPHERTEXT_LEN + 4]
            .try_into()
            .unwrap(),
    );

    println!("file:           {}", path.display());
    println!("magic:          P11K");
    println!("version:        {version}");
    println!("kdf_iterations: {kdf_iterations}");
    println!("ciphertext_len: {ciphertext_len}");

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 || args[1] == "--help" || args[1] == "-h" {
        eprintln!("usage: usb-hsm-info <keystore.p11k>");
        process::exit(1);
    }
    if let Err(e) = inspect(Path::new(&args[1])) {
        eprintln!("usb-hsm-info: {e}");
        process::exit(1);
    }
}
