/// Integration tests for the usb-hsm-keygen binary.
///
/// Each test invokes the binary as a subprocess, feeds the PIN via stdin
/// (works when stdin is a pipe -- rpassword detects non-tty and reads stdin),
/// and then verifies the resulting .p11k with Keystore::load.
///
/// The oracle for key bytes is openssl, not this codebase.
use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

use usb_hsm::keystore::{KeyEntry, KeyType, Keystore};

const TEST_PIN: &str = "test-pin-1234"; // 14 chars, well above the 6-char minimum

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Generate a 2048-bit RSA private key at `path` using openssl.
fn openssl_genrsa(path: &Path) {
    let status = std::process::Command::new("openssl")
        .args(["genrsa", "-out", path.to_str().unwrap(), "2048"])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn openssl genrsa");
    assert!(status.success(), "openssl genrsa exited {status}");
}

/// Generate a P-256 EC private key at `path` using openssl.
fn openssl_genprime256(path: &Path) {
    let status = std::process::Command::new("openssl")
        .args([
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn openssl ecparam");
    assert!(status.success(), "openssl ecparam exited {status}");
}

/// Sign `message` with the RSA key in `entry` (PSS mode, SHA-256) and verify
/// the signature using openssl with the public key derived from `rsa_pem`.
///
/// The openssl verify step is the external oracle.  `ops::sign` with
/// `CKM_RSA_PKCS_PSS` passes `data` to wolfcrypt's `sign_pss_with_digest`
/// which hashes the data internally -- so `message` is the raw (unhashed)
/// message, matching what `openssl dgst -sha256` expects on the verify side.
fn assert_rsa_key_signs_and_openssl_verifies(entry: &KeyEntry, rsa_pem: &Path, dir: &TempDir) {
    use cryptoki_sys::CKM_RSA_PKCS_PSS;
    use usb_hsm::ops;

    let message = b"oracle-check: does openssl agree with our RSA signing key?";

    let sig = ops::sign(entry, CKM_RSA_PKCS_PSS, message).expect("ops::sign(RSA-PSS) failed");

    // Extract public key; `openssl pkey -pubout` handles both PKCS#1 and PKCS#8 input.
    let pubkey_path = dir.path().join("rsa_pub.pem");
    let status = std::process::Command::new("openssl")
        .args([
            "pkey",
            "-in",
            rsa_pem.to_str().unwrap(),
            "-pubout",
            "-out",
            pubkey_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl pkey -pubout failed");
    assert!(status.success(), "openssl pkey -pubout exited non-zero");

    let msg_path = dir.path().join("rsa_msg.bin");
    let sig_path = dir.path().join("rsa_sig.bin");
    std::fs::write(&msg_path, message).unwrap();
    std::fs::write(&sig_path, &sig).unwrap();

    let status = std::process::Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-sigopt",
            "rsa_padding_mode:pss",
            "-verify",
            pubkey_path.to_str().unwrap(),
            "-signature",
            sig_path.to_str().unwrap(),
            msg_path.to_str().unwrap(),
        ])
        .status()
        .expect("openssl dgst -verify failed");
    assert!(
        status.success(),
        "openssl rejected RSA-PSS signature produced from loaded key"
    );
}

/// Run `usb-hsm-keygen create` with the given key files, writing PIN via stdin.
/// Returns the path to the written .p11k file.
fn run_keygen_create(dir: &TempDir, key_files: &[&Path], labels: &[&str]) -> std::path::PathBuf {
    let output = dir.path().join("test.p11k");
    let mut args = vec!["create"];
    for &label in labels {
        args.extend(["--label", label]);
    }
    args.extend(["--output", output.to_str().unwrap()]);
    for path in key_files {
        args.push(path.to_str().unwrap());
    }
    let pin_input = format!("{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(&args)
        .write_stdin(pin_input.as_bytes())
        .assert()
        .success();
    output
}

/// Encode raw r||s (64 bytes) into a DER SEQUENCE { INTEGER r, INTEGER s }.
///
/// Independent implementation -- NOT the production `rs_to_der` in ops.rs.
/// Used to build a DER signature for openssl to verify.
fn raw_rs_to_der(raw: &[u8]) -> Vec<u8> {
    assert_eq!(raw.len(), 64, "raw r||s must be exactly 64 bytes");
    fn int_der(scalar: &[u8]) -> Vec<u8> {
        let trimmed = &scalar[scalar.iter().position(|&b| b != 0).unwrap_or(scalar.len() - 1)..];
        let pad = trimmed[0] & 0x80 != 0;
        let len = trimmed.len() + usize::from(pad);
        let mut out = vec![0x02, len as u8];
        if pad {
            out.push(0x00);
        }
        out.extend_from_slice(trimmed);
        out
    }
    let r_der = int_der(&raw[..32]);
    let s_der = int_der(&raw[32..]);
    let payload = r_der.len() + s_der.len();
    let mut seq = vec![0x30, payload as u8];
    seq.extend(r_der);
    seq.extend(s_der);
    seq
}

/// Sign `message` with the EC key in `entry` and verify the signature using
/// openssl with the public key derived from `ec_pem`.
///
/// The openssl verify step is the external oracle.
fn assert_ec_key_signs_and_openssl_verifies(entry: &KeyEntry, ec_pem: &Path, dir: &TempDir) {
    use cryptoki_sys::CKM_ECDSA_SHA256;
    use usb_hsm::ops;

    let message = b"oracle-check: does openssl agree with our signing key?";

    let sig_raw = ops::sign(entry, CKM_ECDSA_SHA256, message).expect("ops::sign failed");
    assert_eq!(sig_raw.len(), 64, "expected 64-byte raw r||s signature");

    let sig_der = raw_rs_to_der(&sig_raw);

    // Extract public key with openssl.
    let pubkey_path = dir.path().join("ec_pub.pem");
    let status = std::process::Command::new("openssl")
        .args([
            "ec",
            "-in",
            ec_pem.to_str().unwrap(),
            "-pubout",
            "-out",
            pubkey_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl ec -pubout failed");
    assert!(status.success());

    // Write message and signature to temp files for openssl dgst.
    let msg_path = dir.path().join("msg.bin");
    let sig_path = dir.path().join("sig.der");
    std::fs::write(&msg_path, message).unwrap();
    std::fs::write(&sig_path, &sig_der).unwrap();

    let status = std::process::Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            pubkey_path.to_str().unwrap(),
            "-signature",
            sig_path.to_str().unwrap(),
            msg_path.to_str().unwrap(),
        ])
        .status()
        .expect("openssl dgst -verify failed");
    assert!(
        status.success(),
        "openssl rejected EC signature produced from loaded key"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// End-to-end: create a .p11k with one RSA and one EC key, load it, and
/// verify both entries against independent oracles.
#[test]
fn create_rsa_and_ec_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("rsa.pem");
    let ec_pem = dir.path().join("ec.pem");

    openssl_genrsa(&rsa_pem);
    openssl_genprime256(&ec_pem);

    let p11k_path = run_keygen_create(
        &dir,
        &[&rsa_pem, &ec_pem],
        &["my-rsa-key", "my-ec-key"],
    );

    let keystore = Keystore::load(&p11k_path, TEST_PIN.as_bytes()).unwrap();
    let entries = keystore.entries();

    assert_eq!(entries.len(), 2, "expected 2 key entries");

    // Labels and types
    assert_eq!(entries[0].label, "my-rsa-key");
    assert_eq!(entries[0].key_type, KeyType::Rsa);
    assert_eq!(entries[1].label, "my-ec-key");
    assert_eq!(entries[1].key_type, KeyType::Ec);

    // RSA oracle: sign with loaded key, verify with openssl RSA-PSS.
    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &rsa_pem, &dir);

    // EC oracle: sign with loaded key, verify with openssl.
    assert_ec_key_signs_and_openssl_verifies(&entries[1], &ec_pem, &dir);

    // Sanity: EC scalar must be exactly 32 bytes.
    assert_eq!(entries[1].der_bytes.len(), 32, "EC key must be 32-byte scalar");
}

/// Without --force, keygen must refuse to overwrite an existing .p11k.
#[test]
fn create_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("rsa.pem");
    openssl_genrsa(&rsa_pem);

    let p11k_path = run_keygen_create(&dir, &[&rsa_pem], &["key"]);
    assert!(p11k_path.exists());

    // Second run without --force should fail.
    let pin_input = format!("{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args([
            "create",
            "--output",
            p11k_path.to_str().unwrap(),
            rsa_pem.to_str().unwrap(),
        ])
        .write_stdin(pin_input.as_bytes())
        .assert()
        .failure();
}

/// Labels derived from filename stem when --label is not supplied.
#[test]
fn create_derives_label_from_filename_stem() {
    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("my_production_key.pem");
    openssl_genrsa(&rsa_pem);

    let p11k_path = run_keygen_create(&dir, &[&rsa_pem], &[]); // no --label

    let keystore = Keystore::load(&p11k_path, TEST_PIN.as_bytes()).unwrap();
    assert_eq!(keystore.entries()[0].label, "my_production_key");
}

/// Wrong PIN on load returns an error (not a panic).
#[test]
fn load_with_wrong_pin_fails_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("rsa.pem");
    openssl_genrsa(&rsa_pem);

    let p11k_path = run_keygen_create(&dir, &[&rsa_pem], &["k"]);
    let result = Keystore::load(&p11k_path, b"wrongpassword");
    assert!(result.is_err(), "expected Err on wrong PIN");
}

// ---------------------------------------------------------------------------
// GCP service account JSON import tests
// ---------------------------------------------------------------------------

/// Build a synthetic GCP service account JSON string.
///
/// `pem_data` should contain the raw PEM text (with real newline characters);
/// it is escaped to `\n` sequences as JSON requires.
fn build_gcp_json(private_key_id: &str, pem_data: &str, client_email: &str) -> String {
    let pem_escaped = pem_data.replace('\\', "\\\\").replace('\n', r"\n").replace('"', "\\\"");
    format!(
        r#"{{"type":"service_account","private_key_id":"{private_key_id}","private_key":"{pem_escaped}","client_email":"{client_email}"}}"#
    )
}

/// End-to-end: import a GCP service account JSON file.
///
/// Asserts key type (RSA), key ID (from private_key_id), label (client_email),
/// and functional signing using openssl as the external oracle.
#[test]
fn gcp_json_import_key_id_and_label() {
    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("rsa.pem");
    openssl_genrsa(&rsa_pem);

    let private_key_id = "1234567890abcdef1234567890abcdef12345678";
    let client_email = "test@test-project.iam.gserviceaccount.com";
    let pem_data = std::fs::read_to_string(&rsa_pem).unwrap();
    let gcp_json = build_gcp_json(private_key_id, &pem_data, client_email);

    let json_path = dir.path().join("service_account.json");
    std::fs::write(&json_path, gcp_json.as_bytes()).unwrap();

    // No --label: the binary must derive the label from client_email.
    let p11k_path = run_keygen_create(&dir, &[&json_path], &[]);

    let keystore = Keystore::load(&p11k_path, TEST_PIN.as_bytes()).unwrap();
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1, "expected 1 key entry");

    // Key type must be RSA.
    assert_eq!(entries[0].key_type, KeyType::Rsa);

    // Label must come from client_email (no --label was passed).
    assert_eq!(entries[0].label, client_email);

    // Key ID must equal the first 32 hex chars of private_key_id decoded as 16 bytes.
    let expected_id: [u8; 16] = hex::decode(&private_key_id[..32])
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(entries[0].id, expected_id, "key ID must match private_key_id");

    // Functional oracle: sign with the loaded key, verify with openssl.
    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &rsa_pem, &dir);
}

/// When --label is provided, it overrides the client_email label hint.
#[test]
fn gcp_json_explicit_label_overrides_client_email() {
    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("rsa.pem");
    openssl_genrsa(&rsa_pem);

    let pem_data = std::fs::read_to_string(&rsa_pem).unwrap();
    let gcp_json = build_gcp_json(
        "aabbccdd00112233aabbccdd00112233aabbccdd",
        &pem_data,
        "original@project.iam.gserviceaccount.com",
    );
    let json_path = dir.path().join("svc.json");
    std::fs::write(&json_path, gcp_json.as_bytes()).unwrap();

    let p11k_path = run_keygen_create(&dir, &[&json_path], &["my-override-label"]);

    let keystore = Keystore::load(&p11k_path, TEST_PIN.as_bytes()).unwrap();
    assert_eq!(keystore.entries()[0].label, "my-override-label");
}

/// GCP JSON without the `private_key` field is rejected at import time.
#[test]
fn gcp_json_missing_private_key_field_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let json_path = dir.path().join("bad.json");
    std::fs::write(
        &json_path,
        br#"{"type":"service_account","client_email":"svc@proj.iam.gserviceaccount.com"}"#,
    )
    .unwrap();

    let output = dir.path().join("out.p11k");
    let pin_input = format!("{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), json_path.to_str().unwrap()])
        .write_stdin(pin_input.as_bytes())
        .assert()
        .failure();
}

/// GCP JSON with a `private_key` containing non-PEM content is rejected.
#[test]
fn gcp_json_non_pem_private_key_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let json_path = dir.path().join("bad.json");
    std::fs::write(
        &json_path,
        br#"{"type":"service_account","private_key":"not-a-pem-key","client_email":"svc@proj.iam.gserviceaccount.com"}"#,
    )
    .unwrap();

    let output = dir.path().join("out.p11k");
    let pin_input = format!("{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), json_path.to_str().unwrap()])
        .write_stdin(pin_input.as_bytes())
        .assert()
        .failure();
}

/// A binary file whose first byte is `{` but is not valid JSON does not panic.
#[test]
fn binary_starting_with_brace_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("notjson.bin");
    // Starts with '{' but is random binary -- not valid JSON, not valid PEM, not valid DER.
    std::fs::write(&bin_path, b"{\x00\xff\xfe\x7b garbage data not a real file").unwrap();

    let output = dir.path().join("out.p11k");
    let pin_input = format!("{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), bin_path.to_str().unwrap()])
        .write_stdin(pin_input.as_bytes())
        .assert()
        .failure(); // must not panic; exit code may be any non-zero
}

// ---------------------------------------------------------------------------
// Encrypted PKCS#8 DER auto-detection (soft_PKCS11-en1h)
// ---------------------------------------------------------------------------

/// Encrypt `src` (RSA PEM) to a bare DER PKCS#8 with PBES2 AES-256-CBC.
fn openssl_pkcs8_pbes2_der(src: &Path, dst: &Path, passphrase: &str) {
    let status = std::process::Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-in",
            src.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            dst.to_str().unwrap(),
            "-v2",
            "aes-256-cbc",
            "-passout",
            &format!("pass:{passphrase}"),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn openssl pkcs8 (PBES2)");
    assert!(status.success(), "openssl pkcs8 (PBES2 DER) exited {status}");
}

/// Encrypt `src` (RSA PEM) to a bare DER PKCS#8 with PBES1 PBE-SHA1-3DES.
fn openssl_pkcs8_pbes1_3des_der(src: &Path, dst: &Path, passphrase: &str) {
    let status = std::process::Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-in",
            src.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            dst.to_str().unwrap(),
            "-v1",
            "PBE-SHA1-3DES",
            "-passout",
            &format!("pass:{passphrase}"),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn openssl pkcs8 (PBE-SHA1-3DES)");
    assert!(
        status.success(),
        "openssl pkcs8 (PBE-SHA1-3DES DER) exited {status}"
    );
}

/// Bare DER EncryptedPrivateKeyInfo with PBES2 (AES-256-CBC) imports correctly.
///
/// The passphrase is piped through stdin before the keystore PIN.
#[test]
fn create_from_encrypted_pkcs8_der_pbes2() {
    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("key.pem");
    openssl_genrsa(&rsa_pem);

    const KEY_PASS: &str = "hunter2-testpass";
    let enc_der = dir.path().join("key_pbes2.der");
    openssl_pkcs8_pbes2_der(&rsa_pem, &enc_der, KEY_PASS);

    let p11k = dir.path().join("out.p11k");
    // stdin order: key passphrase, then new-PIN twice (prompt_new_pin loops twice)
    let stdin = format!("{KEY_PASS}\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args([
            "create",
            "--output",
            p11k.to_str().unwrap(),
            enc_der.to_str().unwrap(),
        ])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Rsa);
    eprintln!("Verified OK");
    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &rsa_pem, &dir);
}

/// Bare DER EncryptedPrivateKeyInfo with PBES1 PBE-SHA1-3DES imports correctly.
#[test]
fn create_from_encrypted_pkcs8_der_pbes1_3des() {
    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("key.pem");
    openssl_genrsa(&rsa_pem);

    const KEY_PASS: &str = "hunter2-testpass";
    let enc_der = dir.path().join("key_3des.der");
    openssl_pkcs8_pbes1_3des_der(&rsa_pem, &enc_der, KEY_PASS);

    let p11k = dir.path().join("out.p11k");
    let stdin = format!("{KEY_PASS}\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args([
            "create",
            "--output",
            p11k.to_str().unwrap(),
            enc_der.to_str().unwrap(),
        ])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Rsa);
    eprintln!("Verified OK");
    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &rsa_pem, &dir);
}

// ---------------------------------------------------------------------------
// Encrypted PKCS#8 PEM handler (soft_PKCS11-p9kj)
// ---------------------------------------------------------------------------

/// PEM -----BEGIN ENCRYPTED PRIVATE KEY----- with PBES2 AES-256-CBC imports correctly.
#[test]
fn create_from_encrypted_pkcs8_pem_pbes2() {
    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("key.pem");
    openssl_genrsa(&rsa_pem);

    const KEY_PASS: &str = "hunter2-testpass";
    let enc_pem = dir.path().join("key_enc.pem");
    let status = std::process::Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-in",
            rsa_pem.to_str().unwrap(),
            "-out",
            enc_pem.to_str().unwrap(),
            "-v2",
            "aes-256-cbc",
            "-passout",
            &format!("pass:{KEY_PASS}"),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn openssl pkcs8 (PBES2 PEM)");
    assert!(status.success(), "openssl pkcs8 (PBES2 PEM) exited {status}");

    let p11k = dir.path().join("out.p11k");
    // stdin: key passphrase, then new-PIN twice
    let stdin = format!("{KEY_PASS}\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args([
            "create",
            "--output",
            p11k.to_str().unwrap(),
            enc_pem.to_str().unwrap(),
        ])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Rsa);
    eprintln!("Verified OK");
    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &rsa_pem, &dir);
}

// ---------------------------------------------------------------------------
// Additional encrypted PKCS#8 import tests (soft_PKCS11-ieb6)
// ---------------------------------------------------------------------------

/// Returns true if `openssl` is available in PATH.
fn openssl_available() -> bool {
    std::process::Command::new("openssl")
        .arg("version")
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Encrypt `src` (key PEM) to a PEM PKCS#8 with PBES2 AES-128-CBC.
fn openssl_pkcs8_pbes2_aes128_pem(src: &Path, dst: &Path, passphrase: &str) {
    let status = std::process::Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-in",
            src.to_str().unwrap(),
            "-out",
            dst.to_str().unwrap(),
            "-v2",
            "aes-128-cbc",
            "-passout",
            &format!("pass:{passphrase}"),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn openssl pkcs8 (PBES2 AES-128)");
    assert!(status.success(), "openssl pkcs8 (PBES2 AES-128 PEM) exited {status}");
}

/// Encrypted PKCS#8 PEM with PBES2 AES-128-CBC imports correctly.
#[test]
fn create_from_encrypted_pkcs8_pem_pbes2_aes128() {
    if !openssl_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("key.pem");
    openssl_genrsa(&rsa_pem);

    const KEY_PASS: &str = "hunter2-aes128";
    let enc_pem = dir.path().join("key_aes128.pem");
    openssl_pkcs8_pbes2_aes128_pem(&rsa_pem, &enc_pem, KEY_PASS);

    let p11k = dir.path().join("out.p11k");
    let stdin = format!("{KEY_PASS}\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", p11k.to_str().unwrap(), enc_pem.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Rsa);
    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &rsa_pem, &dir);
}

/// Encrypted PKCS#8 PEM with PBES2 AES-256-CBC wrapping an EC P-256 key imports correctly.
#[test]
fn create_from_encrypted_pkcs8_pem_ec_p256() {
    if !openssl_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let ec_pem = dir.path().join("ec.pem");
    openssl_genprime256(&ec_pem);

    const KEY_PASS: &str = "hunter2-ec-pkcs8";
    let enc_pem = dir.path().join("ec_enc.pem");
    let status = std::process::Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-in",
            ec_pem.to_str().unwrap(),
            "-out",
            enc_pem.to_str().unwrap(),
            "-v2",
            "aes-256-cbc",
            "-passout",
            &format!("pass:{KEY_PASS}"),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl pkcs8 (EC PBES2) failed");
    assert!(status.success(), "openssl pkcs8 (EC PBES2 PEM) exited {status}");

    let p11k = dir.path().join("out.p11k");
    let stdin = format!("{KEY_PASS}\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", p11k.to_str().unwrap(), enc_pem.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Ec);
    assert_ec_key_signs_and_openssl_verifies(&entries[0], &ec_pem, &dir);
}

/// Wrong passphrase on encrypted PKCS#8 produces an error (not a panic).
#[test]
fn encrypted_pkcs8_wrong_passphrase_returns_error() {
    if !openssl_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("key.pem");
    openssl_genrsa(&rsa_pem);

    let enc_pem = dir.path().join("key_enc.pem");
    let status = std::process::Command::new("openssl")
        .args([
            "pkcs8", "-topk8",
            "-in", rsa_pem.to_str().unwrap(),
            "-out", enc_pem.to_str().unwrap(),
            "-v2", "aes-256-cbc",
            "-passout", "pass:correct-passphrase",
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl pkcs8 failed");
    assert!(status.success());

    let p11k = dir.path().join("out.p11k");
    let stdin = format!("wrong-passphrase\n{TEST_PIN}\n{TEST_PIN}\n");
    let output = Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", p11k.to_str().unwrap(), enc_pem.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .output()
        .unwrap();

    assert!(!output.status.success(), "expected non-zero exit on wrong passphrase");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("passphrase") || stderr.contains("decryption") || stderr.contains("decrypt"),
        "expected passphrase/decryption error in stderr, got: {stderr}"
    );
}

/// Importing the same key twice (from separately-encrypted PKCS#8 files) yields the same key ID.
#[test]
fn encrypted_pkcs8_key_id_is_reproducible() {
    if !openssl_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let rsa_pem = dir.path().join("key.pem");
    openssl_genrsa(&rsa_pem);

    // Two independently-encrypted PEM files wrapping the same private key.
    const KEY_PASS: &str = "reproducibility-test-pass";
    let enc1 = dir.path().join("enc1.pem");
    let enc2 = dir.path().join("enc2.pem");
    for dst in [&enc1, &enc2] {
        let status = std::process::Command::new("openssl")
            .args([
                "pkcs8", "-topk8",
                "-in", rsa_pem.to_str().unwrap(),
                "-out", dst.to_str().unwrap(),
                "-v2", "aes-256-cbc",
                "-passout", &format!("pass:{KEY_PASS}"),
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl pkcs8 failed");
        assert!(status.success());
    }

    let p11k1 = dir.path().join("out1.p11k");
    let p11k2 = dir.path().join("out2.p11k");

    for (enc, p11k) in [(&enc1, &p11k1), (&enc2, &p11k2)] {
        let stdin = format!("{KEY_PASS}\n{TEST_PIN}\n{TEST_PIN}\n");
        Command::cargo_bin("usb-hsm-keygen")
            .unwrap()
            .args(["create", "--output", p11k.to_str().unwrap(), enc.to_str().unwrap()])
            .write_stdin(stdin.as_bytes())
            .assert()
            .success();
    }

    let ks1 = Keystore::load(&p11k1, TEST_PIN.as_bytes()).expect("keystore 1 load failed");
    let ks2 = Keystore::load(&p11k2, TEST_PIN.as_bytes()).expect("keystore 2 load failed");
    assert_eq!(
        ks1.entries()[0].id,
        ks2.entries()[0].id,
        "key ID must be reproducible across re-imports of the same key"
    );
}

// ---------------------------------------------------------------------------
// OpenSSH private blob decryption (soft_PKCS11-ng8k)
// ---------------------------------------------------------------------------

/// Generate an RSA key in OpenSSH format with aes256-ctr encryption.
fn ssh_keygen_aes256_ctr(path: &Path, passphrase: &str) {
    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-t", "rsa",
            "-b", "1024",
            "-Z", "aes256-ctr",
            "-f", path.to_str().unwrap(),
            "-N", passphrase,
            "-q",
        ])
        .status()
        .expect("failed to spawn ssh-keygen");
    assert!(status.success(), "ssh-keygen exited {status}");
    // Remove the public key file; we only need the private key.
    let pub_path = format!("{}.pub", path.to_str().unwrap());
    let _ = std::fs::remove_file(&pub_path);
}

/// OpenSSH aes256-ctr RSA key: correct passphrase imports successfully.
/// The key extracted from the SSH wire format must produce signatures that
/// openssl can verify with the public key from ssh-keygen.
#[test]
fn openssh_aes256_ctr_rsa_imports_and_signs() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_rsa");
    const KEY_PASS: &str = "hunter2-openssh";
    ssh_keygen_aes256_ctr(&key_path, KEY_PASS);

    let p11k = dir.path().join("out.p11k");
    // stdin: key passphrase, then new-PIN twice
    let stdin = format!("{KEY_PASS}\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args([
            "create",
            "--output",
            p11k.to_str().unwrap(),
            key_path.to_str().unwrap(),
        ])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Rsa);
    eprintln!("Verified OK");
    // Convert the SSH private key to unencrypted PKCS#8 PEM in-place.
    // This gives assert_rsa_key_signs_and_openssl_verifies the private key
    // it needs to extract the public key for signature verification.
    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-p",
            "-P", KEY_PASS,
            "-N", "",
            "-m", "PKCS8",
            "-f", key_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("ssh-keygen -p (convert to PKCS8) failed");
    assert!(status.success(), "ssh-keygen -p exited {status}");
    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &key_path, &dir);
}

/// OpenSSH aes256-ctr key: wrong passphrase triggers Malformed (check word mismatch).
#[test]
fn openssh_aes256_ctr_wrong_passphrase_returns_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_rsa");
    ssh_keygen_aes256_ctr(&key_path, "correct-passphrase");

    let p11k = dir.path().join("out.p11k");
    // Wrong passphrase piped to stdin
    let stdin = format!("wrong-passphrase\n{TEST_PIN}\n{TEST_PIN}\n");
    let output = Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args([
            "create",
            "--output",
            p11k.to_str().unwrap(),
            key_path.to_str().unwrap(),
        ])
        .write_stdin(stdin.as_bytes())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("check word") || stderr.contains("wrong passphrase"),
        "expected check word error in stderr, got: {stderr}"
    );
}

/// OpenSSH aes256-ctr EC P-256 key: imports and produces correct signatures.
#[test]
fn openssh_aes256_ctr_ec_imports_and_signs() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ecdsa");
    const KEY_PASS: &str = "hunter2-ec-openssh";

    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-t", "ecdsa",
            "-b", "256",
            "-Z", "aes256-ctr",
            "-f", key_path.to_str().unwrap(),
            "-N", KEY_PASS,
            "-q",
        ])
        .status()
        .expect("ssh-keygen (EC) failed");
    assert!(status.success(), "ssh-keygen EC exited {status}");
    let _ = std::fs::remove_file(format!("{}.pub", key_path.to_str().unwrap()));

    let p11k = dir.path().join("out.p11k");
    let stdin = format!("{KEY_PASS}\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args([
            "create",
            "--output",
            p11k.to_str().unwrap(),
            key_path.to_str().unwrap(),
        ])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Ec);
    eprintln!("Verified OK");
    // Convert the SSH private key to unencrypted EC PEM for the openssl oracle.
    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-p",
            "-P", KEY_PASS,
            "-N", "",
            "-m", "PKCS8",
            "-f", key_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("ssh-keygen -p (EC) failed");
    assert!(status.success(), "ssh-keygen -p (EC) exited {status}");
    assert_ec_key_signs_and_openssl_verifies(&entries[0], &key_path, &dir);
}

// ---------------------------------------------------------------------------
// OpenSSH unencrypted key import and binary-file path (soft_PKCS11-t6ws)
// ---------------------------------------------------------------------------

/// Returns true if `ssh-keygen` is available in PATH.
fn ssh_keygen_available() -> bool {
    std::process::Command::new("ssh-keygen")
        .arg("--help")
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .map(|_| true)
        .unwrap_or(false)
}

/// Strip the `-----BEGIN/END OPENSSH PRIVATE KEY-----` PEM headers and base64-decode
/// the content into `out_path` using `openssl enc -base64 -d`.
fn extract_openssh_binary_from_pem(pem_path: &std::path::Path, out_path: &std::path::Path) {
    // Collect the base64 body lines (without the header/footer).
    let text = std::fs::read_to_string(pem_path).expect("failed to read PEM file");
    let b64: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\n");
    let b64_path = out_path.with_extension("b64");
    std::fs::write(&b64_path, b64.as_bytes()).unwrap();

    let status = std::process::Command::new("openssl")
        .args([
            "enc",
            "-base64",
            "-d",
            "-in",
            b64_path.to_str().unwrap(),
            "-out",
            out_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl enc -base64 -d failed");
    assert!(status.success(), "openssl enc -base64 -d exited {status}");
}

/// OpenSSH unencrypted RSA key (no passphrase) imports and produces correct signatures.
#[test]
fn openssh_unencrypted_rsa_pem_imports_and_signs() {
    if !ssh_keygen_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_rsa");

    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "rsa", "-b", "2048", "-f", key_path.to_str().unwrap(), "-N", "", "-q"])
        .status()
        .expect("ssh-keygen failed");
    assert!(status.success(), "ssh-keygen exited {status}");
    let _ = std::fs::remove_file(format!("{}.pub", key_path.to_str().unwrap()));

    let p11k = run_keygen_create(&dir, &[&key_path], &[]);

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Rsa);

    // Convert unencrypted OpenSSH key to PKCS#8 PEM for the openssl oracle.
    let status = std::process::Command::new("ssh-keygen")
        .args(["-p", "-P", "", "-N", "", "-m", "PKCS8", "-f", key_path.to_str().unwrap()])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("ssh-keygen -p (PKCS8) failed");
    assert!(status.success(), "ssh-keygen -p exited {status}");
    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &key_path, &dir);
}

/// OpenSSH unencrypted EC P-256 key (no passphrase) imports and produces correct signatures.
#[test]
fn openssh_unencrypted_ec_pem_imports_and_signs() {
    if !ssh_keygen_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ecdsa");

    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ecdsa", "-b", "256", "-f", key_path.to_str().unwrap(), "-N", "", "-q"])
        .status()
        .expect("ssh-keygen failed");
    assert!(status.success(), "ssh-keygen exited {status}");
    let _ = std::fs::remove_file(format!("{}.pub", key_path.to_str().unwrap()));

    let p11k = run_keygen_create(&dir, &[&key_path], &[]);

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Ec);

    // Convert unencrypted OpenSSH key to PKCS#8 PEM for the openssl oracle.
    let status = std::process::Command::new("ssh-keygen")
        .args(["-p", "-P", "", "-N", "", "-m", "PKCS8", "-f", key_path.to_str().unwrap()])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("ssh-keygen -p (PKCS8 EC) failed");
    assert!(status.success(), "ssh-keygen -p (EC) exited {status}");
    assert_ec_key_signs_and_openssl_verifies(&entries[0], &key_path, &dir);
}

/// Raw binary OpenSSH file (no PEM wrapper) is detected and imported via parse_der_auto.
///
/// Strips the -----BEGIN/END----- wrapper and base64-decodes the PEM content,
/// then passes the resulting binary file to usb-hsm-keygen.  This exercises the
/// `der.starts_with(OPENSSH_MAGIC)` branch in `parse_der_auto`.
#[test]
fn openssh_binary_file_imports_and_signs() {
    if !ssh_keygen_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let pem_path = dir.path().join("id_rsa");

    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "rsa", "-b", "2048", "-f", pem_path.to_str().unwrap(), "-N", "", "-q"])
        .status()
        .expect("ssh-keygen failed");
    assert!(status.success(), "ssh-keygen exited {status}");
    let _ = std::fs::remove_file(format!("{}.pub", pem_path.to_str().unwrap()));

    // Write raw binary (no PEM wrapper).
    let bin_path = dir.path().join("id_rsa.bin");
    extract_openssh_binary_from_pem(&pem_path, &bin_path);

    let p11k = run_keygen_create(&dir, &[&bin_path], &[]);

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Rsa);

    // Convert the original PEM key to PKCS#8 for the oracle.
    let status = std::process::Command::new("ssh-keygen")
        .args(["-p", "-P", "", "-N", "", "-m", "PKCS8", "-f", pem_path.to_str().unwrap()])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("ssh-keygen -p (PKCS8) failed");
    assert!(status.success(), "ssh-keygen -p exited {status}");
    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &pem_path, &dir);
}

// ---------------------------------------------------------------------------
// PKCS#12 (.pfx / .p12) import tests
// ---------------------------------------------------------------------------

fn openssl_make_pfx(key_pem: &Path, cert_pem: &Path, out_pfx: &Path, passphrase: &str) {
    let pass_arg = format!("pass:{passphrase}");
    let s = std::process::Command::new("openssl")
        .args(["pkcs12", "-export",
               "-inkey", key_pem.to_str().unwrap(),
               "-in",    cert_pem.to_str().unwrap(),
               "-out",   out_pfx.to_str().unwrap(),
               "-passout", &pass_arg,
               "-name", "test-key"])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn openssl pkcs12 -export");
    assert!(s.success(), "openssl pkcs12 -export failed");
}

fn openssl_self_signed_cert(key_pem: &Path, cert_pem: &Path) {
    let s = std::process::Command::new("openssl")
        .args(["req", "-new", "-x509",
               "-key",  key_pem.to_str().unwrap(),
               "-out",  cert_pem.to_str().unwrap(),
               "-days", "1", "-subj", "/CN=test"])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn openssl req");
    assert!(s.success(), "openssl req -x509 failed");
}

/// Run `usb-hsm-keygen create` with a PKCS#12 file, passing PIN and PFX
/// passphrase via stdin.  Returns the keystore path on success.
fn run_keygen_create_pfx(
    dir: &TempDir,
    pfx_path: &Path,
    pfx_passphrase: &str,
) -> std::path::PathBuf {
    let output = dir.path().join("test.p11k");
    // In cmd_create, key files are parsed (and passphrase prompted) BEFORE the
    // keystore PIN prompt.  So stdin order is: PFX-passphrase, new-PIN, PIN-confirm.
    let stdin = format!("{pfx_passphrase}\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), pfx_path.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();
    output
}

/// Import an RSA key from a PKCS#12 PFX (non-empty password, PBES2 default).
/// Verifies key type, label, cert_der, and that signing works.
#[test]
fn pkcs12_rsa_import_with_password() {
    if !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let key_pem  = dir.path().join("key.pem");
    let cert_pem = dir.path().join("cert.pem");
    let pfx_path = dir.path().join("test.pfx");

    openssl_genrsa(&key_pem);
    openssl_self_signed_cert(&key_pem, &cert_pem);
    openssl_make_pfx(&key_pem, &cert_pem, &pfx_path, "pfx-pw");

    let p11k = run_keygen_create_pfx(&dir, &pfx_path, "pfx-pw");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Rsa);
    assert_eq!(entries[0].label, "test-key");

    // cert_der must be populated from the embedded CertBag.
    assert!(entries[0].cert_der.is_some(), "cert_der must be populated from PKCS#12 CertBag");

    // Verify the cert matches what openssl embedded.
    let cert_pem_bytes = std::fs::read(&cert_pem).unwrap();
    let cert_pem_block = pem::parse(&cert_pem_bytes).expect("cert PEM must parse");
    assert_eq!(
        entries[0].cert_der.as_deref().unwrap(),
        cert_pem_block.contents(),
        "cert_der must match the DER of the embedded certificate"
    );

    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &key_pem, &dir);
}

/// Import an EC P-256 key from a PKCS#12 PFX.
#[test]
fn pkcs12_ec_import_with_password() {
    if !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let key_pem  = dir.path().join("key.pem");
    let cert_pem = dir.path().join("cert.pem");
    let pfx_path = dir.path().join("test.pfx");

    openssl_genprime256(&key_pem);
    openssl_self_signed_cert(&key_pem, &cert_pem);
    openssl_make_pfx(&key_pem, &cert_pem, &pfx_path, "ec-pw");

    let p11k = run_keygen_create_pfx(&dir, &pfx_path, "ec-pw");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Ec);
    assert_eq!(entries[0].label, "test-key");
    assert!(entries[0].cert_der.is_some(), "cert_der must be populated");

    assert_ec_key_signs_and_openssl_verifies(&entries[0], &key_pem, &dir);
}

/// Import from a passwordless PKCS#12 PFX (-passout pass:).
#[test]
fn pkcs12_empty_password_import() {
    if !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let key_pem  = dir.path().join("key.pem");
    let cert_pem = dir.path().join("cert.pem");
    let pfx_path = dir.path().join("test.pfx");

    openssl_genrsa(&key_pem);
    openssl_self_signed_cert(&key_pem, &cert_pem);
    openssl_make_pfx(&key_pem, &cert_pem, &pfx_path, "");

    // Empty passphrase: stdin is PIN, PIN-confirm, empty line for PFX passphrase.
    let p11k = run_keygen_create_pfx(&dir, &pfx_path, "");

    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_type, KeyType::Rsa);

    assert_rsa_key_signs_and_openssl_verifies(&entries[0], &key_pem, &dir);
}

/// Wrong PKCS#12 passphrase causes `usb-hsm-keygen create` to exit non-zero.
#[test]
fn pkcs12_wrong_passphrase_returns_error() {
    if !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let key_pem  = dir.path().join("key.pem");
    let cert_pem = dir.path().join("cert.pem");
    let pfx_path = dir.path().join("test.pfx");

    openssl_genrsa(&key_pem);
    openssl_self_signed_cert(&key_pem, &cert_pem);
    openssl_make_pfx(&key_pem, &cert_pem, &pfx_path, "correct");

    let output = dir.path().join("test.p11k");
    // PFX passphrase is prompted BEFORE keystore PIN in cmd_create.
    let stdin = format!("wrong-pass\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), pfx_path.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .assert()
        .failure();
}

// ---------------------------------------------------------------------------
// JKS / JCEKS integration tests
// ---------------------------------------------------------------------------

fn keytool_available() -> bool {
    std::process::Command::new("keytool")
        .arg("-help")
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .map(|_| true)
        .unwrap_or(false)
}

/// Create a JKS or JCEKS keystore with one key entry via keytool.
/// Returns false if keytool fails (e.g. because JKS is no longer supported).
fn keytool_genkey(
    jks_path: &std::path::Path,
    alias: &str,
    keyalg: &str,
    keysize_arg: &str,   // e.g. "-keysize 2048" or "-groupname secp256r1"
    storepass: &str,
    storetype: &str,
) -> bool {
    // keytool requires either -keysize or -groupname; split the arg.
    let keysize_parts: Vec<&str> = keysize_arg.split_whitespace().collect();
    let mut args = vec![
        "-genkey".to_string(),
        "-alias".to_string(), alias.to_string(),
        "-keyalg".to_string(), keyalg.to_string(),
        "-keystore".to_string(), jks_path.to_str().unwrap().to_string(),
        "-storepass".to_string(), storepass.to_string(),
        "-keypass".to_string(), storepass.to_string(),
        "-storetype".to_string(), storetype.to_string(),
        "-dname".to_string(), format!("CN={alias}"),
        "-noprompt".to_string(),
    ];
    for part in keysize_parts {
        args.push(part.to_string());
    }
    std::process::Command::new("keytool")
        .args(&args)
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Export the certificate for `alias` from a JKS/JCEKS keystore as DER, then
/// extract the public key as PEM using openssl.  Returns true on success.
fn keytool_export_pubkey_pem(
    jks_path: &std::path::Path,
    alias: &str,
    storepass: &str,
    pubkey_path: &std::path::Path,
) -> bool {
    let cert_der = jks_path.with_extension("cert.der");

    let ok = std::process::Command::new("keytool")
        .args([
            "-exportcert",
            "-alias", alias,
            "-keystore", jks_path.to_str().unwrap(),
            "-storepass", storepass,
            "-file", cert_der.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok { return false; }

    std::process::Command::new("openssl")
        .args([
            "x509", "-inform", "DER",
            "-in", cert_der.to_str().unwrap(),
            "-pubkey", "-noout",
            "-out", pubkey_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `usb-hsm-keygen create` on a JKS/JCEKS file.
/// stdin order: keystore passphrase, new-PIN, PIN-confirm.
fn run_keygen_create_jks(
    dir: &TempDir,
    jks_path: &std::path::Path,
    jks_passphrase: &str,
) -> std::path::PathBuf {
    let output = dir.path().join("test.p11k");
    let stdin = format!("{jks_passphrase}\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), jks_path.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();
    output
}

/// Sign with an RSA key in `entry` (PSS/SHA-256) and verify using a public key PEM.
fn assert_rsa_key_signs_with_pubkey(entry: &KeyEntry, pubkey_pem: &std::path::Path, dir: &TempDir) {
    use cryptoki_sys::CKM_RSA_PKCS_PSS;
    use usb_hsm::ops;

    let message = b"jks-oracle-check: rsa-pss signature";
    let sig = ops::sign(entry, CKM_RSA_PKCS_PSS, message).expect("ops::sign(RSA-PSS) failed");

    let msg_path = dir.path().join("jks_msg.bin");
    let sig_path = dir.path().join("jks_sig.bin");
    std::fs::write(&msg_path, message).unwrap();
    std::fs::write(&sig_path, &sig).unwrap();

    let status = std::process::Command::new("openssl")
        .args([
            "dgst", "-sha256",
            "-sigopt", "rsa_padding_mode:pss",
            "-verify", pubkey_pem.to_str().unwrap(),
            "-signature", sig_path.to_str().unwrap(),
            msg_path.to_str().unwrap(),
        ])
        .status()
        .expect("openssl dgst -verify failed to spawn");
    assert!(status.success(), "openssl rejected RSA-PSS signature from JKS key");
}

/// Sign with an EC key in `entry` (ECDSA-SHA256) and verify using a public key PEM.
fn assert_ec_key_signs_with_pubkey(entry: &KeyEntry, pubkey_pem: &std::path::Path, dir: &TempDir) {
    use cryptoki_sys::CKM_ECDSA_SHA256;
    use usb_hsm::ops;

    let message = b"jks-oracle-check: ec-sha256 signature";
    let sig_raw = ops::sign(entry, CKM_ECDSA_SHA256, message).expect("ops::sign(ECDSA) failed");
    let sig_der = raw_rs_to_der(&sig_raw);

    let msg_path = dir.path().join("jks_msg.bin");
    let sig_path = dir.path().join("jks_sig.der");
    std::fs::write(&msg_path, message).unwrap();
    std::fs::write(&sig_path, &sig_der).unwrap();

    let status = std::process::Command::new("openssl")
        .args([
            "dgst", "-sha256",
            "-verify", pubkey_pem.to_str().unwrap(),
            "-signature", sig_path.to_str().unwrap(),
            msg_path.to_str().unwrap(),
        ])
        .status()
        .expect("openssl dgst -verify failed to spawn");
    assert!(status.success(), "openssl rejected ECDSA signature from JKS key");
}

/// Import an RSA-2048 key from a JKS keystore and verify it signs correctly.
#[test]
fn jks_rsa_import_end_to_end() {
    if !keytool_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let jks_path = dir.path().join("rsa.jks");
    let pubkey_path = dir.path().join("rsa_pub.pem");

    if !keytool_genkey(&jks_path, "rsakey", "RSA", "-keysize 2048", "kspass", "JKS") { return; }
    if !keytool_export_pubkey_pem(&jks_path, "rsakey", "kspass", &pubkey_path) { return; }

    let p11k = run_keygen_create_jks(&dir, &jks_path, "kspass");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 1, "expected one key entry");
    assert_eq!(entries[0].key_type, KeyType::Rsa, "expected RSA key");
    assert_eq!(entries[0].label, "rsakey", "label must match JKS alias");

    assert_rsa_key_signs_with_pubkey(&entries[0], &pubkey_path, &dir);
}

/// Import an EC P-256 key from a JKS keystore and verify it signs correctly.
#[test]
fn jks_ec_import_end_to_end() {
    if !keytool_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let jks_path = dir.path().join("ec.jks");
    let pubkey_path = dir.path().join("ec_pub.pem");

    if !keytool_genkey(&jks_path, "eckey", "EC", "-groupname secp256r1", "kspass", "JKS") { return; }
    if !keytool_export_pubkey_pem(&jks_path, "eckey", "kspass", &pubkey_path) { return; }

    let p11k = run_keygen_create_jks(&dir, &jks_path, "kspass");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 1, "expected one key entry");
    assert_eq!(entries[0].key_type, KeyType::Ec, "expected EC key");
    assert_eq!(entries[0].label, "eckey", "label must match JKS alias");

    assert_ec_key_signs_with_pubkey(&entries[0], &pubkey_path, &dir);
}

/// Import an RSA-2048 key from a JCEKS keystore (PBEWithMD5AndTripleDES).
#[test]
fn jceks_rsa_import_end_to_end() {
    if !keytool_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let jks_path = dir.path().join("rsa.jceks");
    let pubkey_path = dir.path().join("rsa_pub.pem");

    if !keytool_genkey(&jks_path, "rsakey", "RSA", "-keysize 2048", "kspass", "JCEKS") { return; }
    if !keytool_export_pubkey_pem(&jks_path, "rsakey", "kspass", &pubkey_path) { return; }

    let p11k = run_keygen_create_jks(&dir, &jks_path, "kspass");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 1, "expected one key entry");
    assert_eq!(entries[0].key_type, KeyType::Rsa, "expected RSA key");
    assert_eq!(entries[0].label, "rsakey", "label must match JCEKS alias");

    assert_rsa_key_signs_with_pubkey(&entries[0], &pubkey_path, &dir);
}

/// Import all PrivateKeyEntries from a JKS with two keys.
/// Both keys must be imported with distinct key IDs and correct labels.
#[test]
fn jks_multi_key_import() {
    if !keytool_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let jks_path = dir.path().join("multi.jks");

    if !keytool_genkey(&jks_path, "key1", "RSA", "-keysize 2048", "kspass", "JKS") { return; }
    if !keytool_genkey(&jks_path, "key2", "RSA", "-keysize 2048", "kspass", "JKS") { return; }

    let p11k = run_keygen_create_jks(&dir, &jks_path, "kspass");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 2, "expected two key entries");
    // Both keys must be RSA.
    for entry in entries {
        assert_eq!(entry.key_type, KeyType::Rsa);
    }
    // Labels must match the two aliases (order not guaranteed).
    let labels: std::collections::HashSet<&str> = entries.iter().map(|e| e.label.as_str()).collect();
    assert!(labels.contains("key1"), "label 'key1' must be present");
    assert!(labels.contains("key2"), "label 'key2' must be present");
    // Key IDs must be distinct.
    assert_ne!(entries[0].id, entries[1].id, "key IDs must differ");
}

/// Wrong JKS passphrase causes `usb-hsm-keygen create` to exit non-zero.
#[test]
fn jks_wrong_passphrase_returns_error() {
    if !keytool_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let jks_path = dir.path().join("test.jks");

    if !keytool_genkey(&jks_path, "k", "RSA", "-keysize 2048", "correct", "JKS") { return; }

    let output = dir.path().join("test.p11k");
    let stdin = format!("wrongpass\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), jks_path.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .assert()
        .failure();
}

// ---------------------------------------------------------------------------
// PPK (PuTTY) import tests
// ---------------------------------------------------------------------------

fn puttygen_available() -> bool {
    std::process::Command::new("puttygen")
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|_| true)
        .unwrap_or(false)
}

/// Generate a PPK v2 RSA-2048 key.  `passphrase` is the key passphrase
/// (`""` for no encryption).  Returns `false` if puttygen fails.
fn puttygen_gen_rsa2048(path: &std::path::Path, passphrase: &str) -> bool {
    let mut args = vec![
        "-t".to_string(), "rsa".to_string(),
        "-b".to_string(), "2048".to_string(),
        "-O".to_string(), "private".to_string(),
        "-o".to_string(), path.to_str().unwrap().to_string(),
        "--ppk-param".to_string(), "version=2".to_string(),
    ];
    if passphrase.is_empty() {
        args.push("--no-passphrase".to_string());
    } else {
        args.push("-N".to_string());
        args.push(passphrase.to_string());
    }
    std::process::Command::new("puttygen")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Generate a PPK v2 EC P-256 key.  Returns `false` if puttygen fails.
fn puttygen_gen_ec_p256(path: &std::path::Path, passphrase: &str) -> bool {
    let mut args = vec![
        "-t".to_string(), "ecdsa".to_string(),
        "-b".to_string(), "256".to_string(),
        "-O".to_string(), "private".to_string(),
        "-o".to_string(), path.to_str().unwrap().to_string(),
        "--ppk-param".to_string(), "version=2".to_string(),
    ];
    if passphrase.is_empty() {
        args.push("--no-passphrase".to_string());
    } else {
        args.push("-N".to_string());
        args.push(passphrase.to_string());
    }
    std::process::Command::new("puttygen")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Export the public key from a PPK file in OpenSSH authorized_keys format,
/// then convert it to PEM (SubjectPublicKeyInfo) using ssh-keygen.
/// Returns `false` if any step fails.
fn puttygen_export_pub_pem(
    ppk_path: &std::path::Path,
    passphrase: &str,
    pub_pem_path: &std::path::Path,
) -> bool {
    let ossh_path = ppk_path.with_extension("ossh.pub");

    // Export as OpenSSH authorized_keys format.
    let mut args = vec![
        ppk_path.to_str().unwrap().to_string(),
        "-O".to_string(), "public-openssh".to_string(),
        "-o".to_string(), ossh_path.to_str().unwrap().to_string(),
    ];
    if !passphrase.is_empty() {
        args.push("--old-passphrase".to_string());
        args.push(passphrase.to_string());
    }
    let ok = std::process::Command::new("puttygen")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok { return false; }

    // Convert OpenSSH public key to PKCS8 PEM using ssh-keygen.
    std::process::Command::new("ssh-keygen")
        .args([
            "-e", "-f", ossh_path.to_str().unwrap(),
            "-m", "PKCS8",
        ])
        .stdout(std::fs::File::create(pub_pem_path).unwrap())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `usb-hsm-keygen create` on a PPK file.
/// For encrypted PPK: stdin = `{passphrase}\n{PIN}\n{PIN}\n`
/// For unencrypted PPK: stdin = `{PIN}\n{PIN}\n`
fn run_keygen_create_ppk(
    dir: &TempDir,
    ppk_path: &std::path::Path,
    ppk_passphrase: &str,
) -> std::path::PathBuf {
    let output = dir.path().join("ppk_test.p11k");
    let stdin = if ppk_passphrase.is_empty() {
        format!("{TEST_PIN}\n{TEST_PIN}\n")
    } else {
        format!("{ppk_passphrase}\n{TEST_PIN}\n{TEST_PIN}\n")
    };
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), ppk_path.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();
    output
}

/// Import an unencrypted RSA-2048 PPK v2 key and verify it signs correctly.
#[test]
fn ppk_v2_rsa_unencrypted_import_end_to_end() {
    if !puttygen_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let ppk_path = dir.path().join("rsa.ppk");
    let pub_pem = dir.path().join("rsa_pub.pem");

    if !puttygen_gen_rsa2048(&ppk_path, "") { return; }
    if !puttygen_export_pub_pem(&ppk_path, "", &pub_pem) { return; }

    let p11k = run_keygen_create_ppk(&dir, &ppk_path, "");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 1, "expected one key entry");
    assert_eq!(entries[0].key_type, KeyType::Rsa, "expected RSA key");

    assert_rsa_key_signs_with_pubkey(&entries[0], &pub_pem, &dir);
}

/// Import an encrypted RSA-2048 PPK v2 key and verify it signs correctly.
#[test]
fn ppk_v2_rsa_encrypted_import_end_to_end() {
    if !puttygen_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let ppk_path = dir.path().join("rsa_enc.ppk");
    let pub_pem = dir.path().join("rsa_pub.pem");
    const PPK_PASS: &str = "ppkTestPass42";

    if !puttygen_gen_rsa2048(&ppk_path, PPK_PASS) { return; }
    if !puttygen_export_pub_pem(&ppk_path, PPK_PASS, &pub_pem) { return; }

    let p11k = run_keygen_create_ppk(&dir, &ppk_path, PPK_PASS);
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 1, "expected one key entry");
    assert_eq!(entries[0].key_type, KeyType::Rsa, "expected RSA key");

    assert_rsa_key_signs_with_pubkey(&entries[0], &pub_pem, &dir);
}

/// Import an unencrypted EC P-256 PPK v2 key and verify it signs correctly.
#[test]
fn ppk_v2_ec_unencrypted_import_end_to_end() {
    if !puttygen_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let ppk_path = dir.path().join("ec.ppk");
    let pub_pem = dir.path().join("ec_pub.pem");

    if !puttygen_gen_ec_p256(&ppk_path, "") { return; }
    if !puttygen_export_pub_pem(&ppk_path, "", &pub_pem) { return; }

    let p11k = run_keygen_create_ppk(&dir, &ppk_path, "");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 1, "expected one key entry");
    assert_eq!(entries[0].key_type, KeyType::Ec, "expected EC key");

    assert_ec_key_signs_with_pubkey(&entries[0], &pub_pem, &dir);
}

/// Wrong PPK passphrase causes `usb-hsm-keygen create` to exit non-zero.
#[test]
fn ppk_wrong_passphrase_returns_error() {
    if !puttygen_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let ppk_path = dir.path().join("enc.ppk");

    if !puttygen_gen_rsa2048(&ppk_path, "correctpass") { return; }

    let output = dir.path().join("test.p11k");
    let stdin = format!("wrongpass\n{TEST_PIN}\n{TEST_PIN}\n");
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), ppk_path.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .assert()
        .failure();
}

/// Import an unencrypted EC P-256 PPK v3 key using a hardcoded fixture.
///
/// The fixture was generated offline with a known private scalar and the
/// Public/Private blobs encoded in SSH wire format.  The PPK v3 MAC uses
/// HMAC-SHA256 with an empty key (as per the PuTTY spec for unencrypted
/// files).  This test does not require puttygen to be installed.
#[test]
fn ppk_v3_ec_unencrypted_import_end_to_end() {
    if !openssl_available() { return; }

    // EC P-256 key pair generated for this fixture:
    //   private scalar: 0fcd825b0a3ce8a324c6460c991f824a82743e56a6ebae65a7e2fc32f0f51165
    //   public point (04||x||y): 0401aecf6d...
    //
    // MAC computed as HMAC-SHA256(key=b"", mac_input) where mac_input is the
    // length-prefixed concatenation of key_type, encryption, comment,
    // public_blob, private_blob (same construction as PPK v2).
    const PPK_V3_FIXTURE: &str = "\
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256\n\
Encryption: none\n\
Comment: ppk-v3-test-key\n\
Public-Lines: 3\n\
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAGuz234gUZx\n\
xupP0tjM3gEzioNY5whdHzR1z+ABkJjWomo352QmXonlxOYaf0/O06s20d7KQg6T\n\
WQr+PN/HpOw=\n\
Private-Lines: 1\n\
AAAAIA/NglsKPOijJMZGDJkfgkqCdD5WpuuuZafi/DLw9RFl\n\
Private-MAC: 12ac792dbd5a26d3df25f0ba44a92471bd2a0af9ceb098c59cd6cadffec079cc\n";

    // Public key PEM (SubjectPublicKeyInfo) for the same key pair -- used as
    // the independent oracle for signature verification.
    const PUB_PEM: &str = "\
-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAa7PbfiBRnHG6k/S2MzeATOKg1jn\n\
CF0fNHXP4AGQmNaiajfnZCZeieXE5hp/T87TqzbR3spCDpNZCv4838ek7A==\n\
-----END PUBLIC KEY-----\n";

    let dir = tempfile::tempdir().unwrap();
    let ppk_path = dir.path().join("v3.ppk");
    let pub_pem_path = dir.path().join("v3_pub.pem");

    std::fs::write(&ppk_path, PPK_V3_FIXTURE).unwrap();
    std::fs::write(&pub_pem_path, PUB_PEM).unwrap();

    let p11k = run_keygen_create_ppk(&dir, &ppk_path, "");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    assert_eq!(entries.len(), 1, "expected one key entry");
    assert_eq!(entries[0].key_type, KeyType::Ec, "expected EC key");
    assert_eq!(entries[0].label, "ppk-v3-test-key", "label must match PPK comment");

    assert_ec_key_signs_with_pubkey(&entries[0], &pub_pem_path, &dir);
}

// ---------------------------------------------------------------------------
// OpenPGP import tests
// ---------------------------------------------------------------------------

/// Returns true if `gpg` is available in PATH.
fn gpg_available() -> bool {
    std::process::Command::new("gpg")
        .arg("--version")
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Generate a GPG nistp256 key in `gnupghome` with `passphrase` (may be empty).
/// Returns `false` if key generation fails (skip the test in that case).
fn gpg_gen_p256_key(gnupghome: &str, passphrase: &str) -> bool {
    std::process::Command::new("gpg")
        .args([
            "--batch", "--yes",
            "--passphrase", passphrase,
            "--pinentry-mode", "loopback",
            "--quick-generate-key", "gpgtest@test.invalid",
            "nistp256", "default", "0",
        ])
        .env("GNUPGHOME", gnupghome)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Generate a GPG rsa2048 key in `gnupghome` with `passphrase`.
fn gpg_gen_rsa2048_key(gnupghome: &str, passphrase: &str) -> bool {
    std::process::Command::new("gpg")
        .args([
            "--batch", "--yes",
            "--passphrase", passphrase,
            "--pinentry-mode", "loopback",
            "--quick-generate-key", "gpgtest@test.invalid",
            "rsa2048", "default", "0",
        ])
        .env("GNUPGHOME", gnupghome)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Export the armored secret key from `gnupghome` to `path`.
/// Returns `false` if the export fails.
fn gpg_export_armored_secret(gnupghome: &str, passphrase: &str, path: &std::path::Path) -> bool {
    let out = std::process::Command::new("gpg")
        .args([
            "--batch", "--yes",
            "--passphrase", passphrase,
            "--pinentry-mode", "loopback",
            "--export-secret-keys", "--armor",
        ])
        .env("GNUPGHOME", gnupghome)
        .output();
    match out {
        Ok(o) if o.status.success() && !o.stdout.is_empty() => {
            std::fs::write(path, &o.stdout).is_ok()
        }
        _ => false,
    }
}

/// Export the binary (non-armored) secret key from `gnupghome` to `path`.
/// Returns `false` if the export fails.
fn gpg_export_binary_secret(gnupghome: &str, passphrase: &str, path: &std::path::Path) -> bool {
    let out = std::process::Command::new("gpg")
        .args([
            "--batch", "--yes",
            "--passphrase", passphrase,
            "--pinentry-mode", "loopback",
            "--export-secret-keys",
        ])
        .env("GNUPGHOME", gnupghome)
        .output();
    match out {
        Ok(o) if o.status.success() && !o.stdout.is_empty() => {
            std::fs::write(path, &o.stdout).is_ok()
        }
        _ => false,
    }
}

/// Build a minimal SEC1 EC private key PEM for P-256 from a 32-byte scalar.
///
/// This is used as an oracle: `openssl ec -in <pem> -pubout` then verifies
/// that the scalar we imported actually matches the public key.
fn p256_scalar_to_sec1_pem(scalar: &[u8]) -> String {
    assert_eq!(scalar.len(), 32, "P-256 scalar must be 32 bytes");
    // SEC1 ECPrivateKey:
    //   SEQUENCE {
    //     version INTEGER 1,
    //     privateKey OCTET STRING (32 bytes),
    //     [0] EXPLICIT OID prime256v1
    //   }
    let mut der = vec![
        0x30, 0x31,              // SEQUENCE (49 bytes body)
        0x02, 0x01, 0x01,        // version = 1
        0x04, 0x20,              // OCTET STRING (32 bytes)
    ];
    der.extend_from_slice(scalar);
    der.extend_from_slice(&[
        0xa0, 0x0a,              // [0] EXPLICIT (10 bytes)
        0x06, 0x08,              // OID (8 bytes)
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,  // prime256v1
    ]);
    let b64 = base64_encode(&der);
    format!("-----BEGIN EC PRIVATE KEY-----\n{b64}\n-----END EC PRIVATE KEY-----\n")
}

/// Simple base64 encoder (no dependency on the `base64` crate from test code).
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut line_len = 0;
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        let c0 = CHARS[b0 >> 2] as char;
        let c1 = CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char;
        let c2 = if chunk.len() > 1 { CHARS[((b1 & 15) << 2) | (b2 >> 6)] as char } else { '=' };
        let c3 = if chunk.len() > 2 { CHARS[b2 & 63] as char } else { '=' };
        out.push(c0); out.push(c1); out.push(c2); out.push(c3);
        line_len += 4;
        if line_len == 64 { out.push('\n'); line_len = 0; }
    }
    out
}

/// Invoke the keygen `create` command with a GPG armored key file.
/// `pgp_passphrase` is sent on stdin first (before the keystore PIN).
fn run_keygen_create_gpg(
    dir: &TempDir,
    pgp_path: &std::path::Path,
    pgp_passphrase: &str,
) -> std::path::PathBuf {
    let output = dir.path().join("gpg_test.p11k");
    let stdin = if pgp_passphrase.is_empty() {
        // Plain-text key: no passphrase prompt, just PIN + confirm
        format!("{TEST_PIN}\n{TEST_PIN}\n")
    } else {
        format!("{pgp_passphrase}\n{TEST_PIN}\n{TEST_PIN}\n")
    };
    Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output.to_str().unwrap(), pgp_path.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .assert()
        .success();
    output
}

/// Import an encrypted ECDSA P-256 GPG key and verify the imported key signs
/// correctly.  The oracle is the SEC1 PEM derived from the imported scalar.
#[test]
fn gpg_p256_encrypted_import_end_to_end() {
    if !gpg_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let gnupghome = dir.path().join("gpghome");
    std::fs::create_dir_all(&gnupghome).unwrap();
    let gnupghome = gnupghome.to_str().unwrap();
    let passphrase = "gpg-test-pass";

    if !gpg_gen_p256_key(gnupghome, passphrase) { return; }

    let asc_path = dir.path().join("key.asc");
    if !gpg_export_armored_secret(gnupghome, passphrase, &asc_path) { return; }

    let p11k = run_keygen_create_gpg(&dir, &asc_path, passphrase);
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    // The primary key (tag 5) is the P-256 signing key; there may also be a
    // subkey (tag 7, typically for encryption) which we skip if not P-256.
    let ec_entry = entries.iter().find(|e| e.key_type == KeyType::Ec)
        .expect("expected at least one EC key entry");
    assert_eq!(ec_entry.der_bytes.len(), 32, "P-256 scalar must be 32 bytes");

    // Build oracle PEM from the imported scalar and verify signature.
    let sec1_pem = p256_scalar_to_sec1_pem(&ec_entry.der_bytes);
    let oracle_pem_path = dir.path().join("oracle.pem");
    std::fs::write(&oracle_pem_path, sec1_pem).unwrap();
    assert_ec_key_signs_and_openssl_verifies(ec_entry, &oracle_pem_path, &dir);
}

/// Import an encrypted RSA-2048 GPG key and verify the imported key signs
/// correctly.
#[test]
fn gpg_rsa2048_encrypted_import_end_to_end() {
    if !gpg_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let gnupghome = dir.path().join("gpghome");
    std::fs::create_dir_all(&gnupghome).unwrap();
    let gnupghome = gnupghome.to_str().unwrap();
    let passphrase = "gpg-rsa-pass";

    if !gpg_gen_rsa2048_key(gnupghome, passphrase) { return; }

    let asc_path = dir.path().join("rsa_key.asc");
    if !gpg_export_armored_secret(gnupghome, passphrase, &asc_path) { return; }

    let p11k = run_keygen_create_gpg(&dir, &asc_path, passphrase);
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    // Find an RSA key entry (may have both primary RSA key and RSA subkey).
    let rsa_entry = entries.iter().find(|e| e.key_type == KeyType::Rsa)
        .expect("expected at least one RSA key entry");

    // Write the PKCS#1 DER bytes as a PEM for the oracle.
    let b64 = base64_encode(&rsa_entry.der_bytes);
    let rsa_pem_content = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{b64}\n-----END RSA PRIVATE KEY-----\n"
    );
    let rsa_pem_path = dir.path().join("gpg_rsa_oracle.pem");
    std::fs::write(&rsa_pem_path, rsa_pem_content).unwrap();

    assert_rsa_key_signs_and_openssl_verifies(rsa_entry, &rsa_pem_path, &dir);
}

/// Import a plain-text (unencrypted) ECDSA P-256 GPG key.
/// Uses usage=0x00 path; no passphrase is needed.
#[test]
fn gpg_p256_unencrypted_import_end_to_end() {
    if !gpg_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let gnupghome = dir.path().join("gpghome");
    std::fs::create_dir_all(&gnupghome).unwrap();
    let gnupghome = gnupghome.to_str().unwrap();

    if !gpg_gen_p256_key(gnupghome, "") { return; }

    let asc_path = dir.path().join("key.asc");
    if !gpg_export_armored_secret(gnupghome, "", &asc_path) { return; }

    let p11k = run_keygen_create_gpg(&dir, &asc_path, "");
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    let ec_entry = entries.iter().find(|e| e.key_type == KeyType::Ec)
        .expect("expected at least one EC key entry");
    assert_eq!(ec_entry.der_bytes.len(), 32, "P-256 scalar must be 32 bytes");

    let sec1_pem = p256_scalar_to_sec1_pem(&ec_entry.der_bytes);
    let oracle_pem_path = dir.path().join("oracle.pem");
    std::fs::write(&oracle_pem_path, sec1_pem).unwrap();
    assert_ec_key_signs_and_openssl_verifies(ec_entry, &oracle_pem_path, &dir);
}

/// Import a binary (non-armored) encrypted RSA-2048 GPG key.
/// Verifies the binary path produces identical results to the armored path.
#[test]
fn gpg_rsa2048_binary_import_end_to_end() {
    if !gpg_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let gnupghome = dir.path().join("gpghome");
    std::fs::create_dir_all(&gnupghome).unwrap();
    let gnupghome = gnupghome.to_str().unwrap();
    let passphrase = "gpg-rsa-bin-pass";

    if !gpg_gen_rsa2048_key(gnupghome, passphrase) { return; }

    let bin_path = dir.path().join("rsa_key.gpg");
    if !gpg_export_binary_secret(gnupghome, passphrase, &bin_path) { return; }

    let p11k = run_keygen_create_gpg(&dir, &bin_path, passphrase);
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    let rsa_entry = entries.iter().find(|e| e.key_type == KeyType::Rsa)
        .expect("expected at least one RSA key entry");

    let b64 = base64_encode(&rsa_entry.der_bytes);
    let rsa_pem_content = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{b64}\n-----END RSA PRIVATE KEY-----\n"
    );
    let rsa_pem_path = dir.path().join("gpg_rsa_bin_oracle.pem");
    std::fs::write(&rsa_pem_path, rsa_pem_content).unwrap();

    assert_rsa_key_signs_and_openssl_verifies(rsa_entry, &rsa_pem_path, &dir);
}

/// Import a binary (non-armored) encrypted P-256 GPG key.
#[test]
fn gpg_p256_binary_import_end_to_end() {
    if !gpg_available() || !openssl_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let gnupghome = dir.path().join("gpghome");
    std::fs::create_dir_all(&gnupghome).unwrap();
    let gnupghome = gnupghome.to_str().unwrap();
    let passphrase = "gpg-p256-bin-pass";

    if !gpg_gen_p256_key(gnupghome, passphrase) { return; }

    let bin_path = dir.path().join("p256_key.gpg");
    if !gpg_export_binary_secret(gnupghome, passphrase, &bin_path) { return; }

    let p11k = run_keygen_create_gpg(&dir, &bin_path, passphrase);
    let keystore = Keystore::load(&p11k, TEST_PIN.as_bytes()).expect("keystore load failed");
    let entries = keystore.entries();

    let ec_entry = entries.iter().find(|e| e.key_type == KeyType::Ec)
        .expect("expected at least one EC key entry");
    assert_eq!(ec_entry.der_bytes.len(), 32, "P-256 scalar must be 32 bytes");

    let sec1_pem = p256_scalar_to_sec1_pem(&ec_entry.der_bytes);
    let oracle_pem_path = dir.path().join("oracle.pem");
    std::fs::write(&oracle_pem_path, sec1_pem).unwrap();
    assert_ec_key_signs_and_openssl_verifies(ec_entry, &oracle_pem_path, &dir);
}

/// Providing the wrong passphrase for a GPG-encrypted key returns an error
/// whose message contains "passphrase" or "checksum" (indicating decryption
/// failure, not a silent wrong result).
#[test]
fn gpg_wrong_passphrase_returns_error() {
    if !gpg_available() { return; }

    let dir = tempfile::tempdir().unwrap();
    let gnupghome = dir.path().join("gpghome");
    std::fs::create_dir_all(&gnupghome).unwrap();
    let gnupghome = gnupghome.to_str().unwrap();
    let passphrase = "correct-horse-battery";

    if !gpg_gen_p256_key(gnupghome, passphrase) { return; }

    let asc_path = dir.path().join("key.asc");
    if !gpg_export_armored_secret(gnupghome, passphrase, &asc_path) { return; }

    let output_path = dir.path().join("out.p11k");
    // Send wrong passphrase followed by PIN (in case parsing succeeds unexpectedly).
    let stdin = format!("wrong-passphrase\n{TEST_PIN}\n{TEST_PIN}\n");
    let output = Command::cargo_bin("usb-hsm-keygen")
        .unwrap()
        .args(["create", "--output", output_path.to_str().unwrap(), asc_path.to_str().unwrap()])
        .write_stdin(stdin.as_bytes())
        .output()
        .unwrap();

    // The command must fail (non-zero exit).
    assert!(
        !output.status.success(),
        "expected failure with wrong passphrase, got success"
    );

    // The stderr must mention passphrase or checksum to indicate the right failure reason.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let has_passphrase_mention = stderr.contains("passphrase")
        || stderr.contains("checksum")
        || stderr.contains("SHA")
        || stderr.contains("hash");
    assert!(
        has_passphrase_mention,
        "expected error mentioning passphrase/checksum, got: {stderr}"
    );
}
