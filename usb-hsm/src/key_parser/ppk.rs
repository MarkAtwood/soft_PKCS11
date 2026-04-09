use super::*;

// ---------------------------------------------------------------------------
// PPK (PuTTY Private Key) file import: detection -> parse -> decrypt -> extract
// ---------------------------------------------------------------------------

/// Top-level PPK import: called from [`parse_key_file`] when a PPK file is
/// detected.  Prompts for a passphrase when required, verifies the MAC, and
/// extracts the private key.
pub(super) fn parse_ppk_file_data(
    data: &[u8],
    passphrase_fn: &dyn Fn(&str) -> io::Result<String>,
) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let ppk = parse_ppk(data)?;

    let passphrase = if ppk.encryption == "none" {
        String::new()
    } else {
        passphrase_fn("Passphrase for PPK key: ")
            .map_err(KeyParseError::Io)?
    };

    let id = super::random_id()?;
    match ppk_extract_key(&ppk, &passphrase, id) {
        Ok(key) => Ok((vec![key], vec![])),
        Err(e) => {
            let alias = ppk.comment.clone();
            let alias = if alias.is_empty() { ppk.key_type.clone() } else { alias };
            Ok((vec![], vec![(alias, e)]))
        }
    }
}

/// Decrypt, MAC-verify, and extract a [`ParsedKey`] from a parsed [`PpkFile`].
pub(crate) fn ppk_extract_key(
    ppk: &PpkFile,
    passphrase: &str,
    id: [u8; 16],
) -> Result<ParsedKey, KeyParseError> {
    // Decrypt the private blob using the version-appropriate KDF.
    let private_decrypted = if ppk.version == 3 {
        ppk_v3_decrypt_private_blob(ppk, passphrase)?
    } else {
        ppk_v2_decrypt_private_blob(ppk, passphrase)?
    };

    // MAC-verify with the version-appropriate algorithm.
    if ppk.version == 3 {
        ppk_v3_verify_mac(ppk, passphrase, &private_decrypted)?;
    } else {
        ppk_v2_verify_mac(ppk, passphrase, &private_decrypted)?;
    }

    // Extract the key based on the key-type string.
    let label_hint = if ppk.comment.is_empty() { None } else { Some(ppk.comment.clone()) };

    match ppk.key_type.as_str() {
        "ssh-rsa" => ppk_extract_rsa(&ppk.public_blob, &private_decrypted, id, label_hint),
        "ecdsa-sha2-nistp256" => {
            ppk_extract_ec_p256(&ppk.public_blob, &private_decrypted, id, label_hint)
        }
        other => Err(KeyParseError::Unsupported(format!(
            "PPK key type '{other}' is not supported; \
             convert with: puttygen key.ppk -O private-openssh -o key.pem"
        ))),
    }
}

/// Parse a PPK RSA public blob and private blob, assemble the full key, and
/// return a [`ParsedKey`] with PKCS#1 DER.
///
/// Public blob layout:
/// ```text
/// string  "ssh-rsa"
/// mpint   e
/// mpint   n
/// ```
///
/// Private blob layout (after decryption):
/// ```text
/// mpint   d
/// mpint   p
/// mpint   q
/// mpint   iqmp
/// ```
pub(crate) fn ppk_extract_rsa(
    public_blob: &[u8],
    private_blob: &[u8],
    id: [u8; 16],
    label_hint: Option<String>,
) -> Result<ParsedKey, KeyParseError> {
    let mut pub_cur = public_blob;
    let key_type_str = super::read_openssh_str(&mut pub_cur)?;
    if key_type_str != "ssh-rsa" {
        return Err(super::malformed("PPK RSA: unexpected key-type string in public blob"));
    }
    let e_raw = super::read_openssh_bytes(&mut pub_cur)?;
    let n_raw = super::read_openssh_bytes(&mut pub_cur)?;

    let mut priv_cur = private_blob;
    let d_raw   = super::read_openssh_bytes(&mut priv_cur)?;
    let p_raw   = super::read_openssh_bytes(&mut priv_cur)?;
    let q_raw   = super::read_openssh_bytes(&mut priv_cur)?;
    let iqmp_raw = super::read_openssh_bytes(&mut priv_cur)?;

    let n    = super::strip_ssh_mpi_zero(n_raw);
    let e    = super::strip_ssh_mpi_zero(e_raw);
    let d    = super::strip_ssh_mpi_zero(d_raw);
    let p    = super::strip_ssh_mpi_zero(p_raw);
    let q    = super::strip_ssh_mpi_zero(q_raw);
    let iqmp = super::strip_ssh_mpi_zero(iqmp_raw);

    let key = wolfcrypt::NativeRsaKey::from_raw_components(n, e, d, p, q, iqmp)
        .map_err(|e| super::malformed(&format!("PPK RSA: wolfCrypt key load failed: {e:?}")))?;
    let pkcs1_der = key
        .to_pkcs1_der()
        .map_err(|e| super::malformed(&format!("PPK RSA: wolfCrypt DER export failed: {e:?}")))?;

    let derived_id = super::sha256_key_id(&pkcs1_der).unwrap_or(id);

    Ok(ParsedKey {
        key_type: KeyType::Rsa,
        key_bytes: pkcs1_der,
        id: derived_id,
        label_hint,
        cert_der: None,
    })
}

/// Parse a PPK ECDSA P-256 public blob and private blob and return a
/// [`ParsedKey`] with the raw 32-byte private scalar.
///
/// Public blob layout:
/// ```text
/// string  "ecdsa-sha2-nistp256"
/// string  "nistp256"
/// string  public-point  (04 || x || y, 65 bytes)
/// ```
///
/// Private blob layout (after decryption):
/// ```text
/// mpint   private-scalar
/// ```
pub(crate) fn ppk_extract_ec_p256(
    public_blob: &[u8],
    private_blob: &[u8],
    id: [u8; 16],
    label_hint: Option<String>,
) -> Result<ParsedKey, KeyParseError> {
    let mut pub_cur = public_blob;
    let key_type_str = super::read_openssh_str(&mut pub_cur)?;
    if key_type_str != "ecdsa-sha2-nistp256" {
        return Err(super::malformed("PPK EC: unexpected key-type string in public blob"));
    }
    let curve = super::read_openssh_str(&mut pub_cur)?;
    if curve != "nistp256" {
        return Err(KeyParseError::Unsupported(format!(
            "PPK EC curve '{curve}' is not supported; only P-256 (nistp256) is supported"
        )));
    }
    let public_point = super::read_openssh_bytes(&mut pub_cur)?;
    if public_point.len() != 65 || public_point[0] != 0x04 {
        return Err(super::malformed(
            "PPK EC P-256: public point must be 65-byte uncompressed (04 || x || y)",
        ));
    }

    let mut priv_cur = private_blob;
    let scalar_raw = super::read_openssh_bytes(&mut priv_cur)?;
    let scalar = super::strip_ssh_mpi_zero(scalar_raw);
    if scalar.len() != 32 {
        return Err(super::malformed(
            "PPK EC P-256: private scalar must be 32 bytes after stripping MPI zero prefix",
        ));
    }

    // Key ID: SHA-256(65-byte uncompressed public point)[0..16]
    use wolfcrypt::digest::digest_trait::Digest as _;
    let hash = wolfcrypt::Sha256::digest(public_point);
    let mut derived_id = id;
    derived_id.copy_from_slice(&hash[..16]);

    Ok(ParsedKey {
        key_type: KeyType::Ec,
        key_bytes: scalar.to_vec(),
        id: derived_id,
        label_hint,
        cert_der: None,
    })
}

// ---------------------------------------------------------------------------
// PPK (PuTTY Private Key) text-format parser
// ---------------------------------------------------------------------------

/// Parsed representation of a PuTTY `.ppk` file.
///
/// Both v2 and v3 files are represented here.  Crypto operations (key
/// derivation, MAC verification, private blob decryption) are performed
/// by callers; this struct holds only the parsed fields.
// Fields are read by callers in soft_PKCS11-kqz4 once full import is wired.
#[allow(dead_code)]
#[derive(Debug)]
pub struct PpkFile {
    /// PPK format version: 2 or 3.
    pub version: u8,
    /// SSH key-type string (e.g. `"ssh-rsa"`, `"ecdsa-sha2-nistp256"`).
    pub key_type: String,
    /// Encryption algorithm string (e.g. `"none"`, `"aes256-cbc"`).
    pub encryption: String,
    /// Human-readable comment from the Comment header.
    pub comment: String,
    /// Decoded public key blob (SSH wire format).
    pub public_blob: Vec<u8>,
    /// Decoded private blob (encrypted or plaintext SSH wire format).
    pub private_blob: Vec<u8>,
    /// MAC bytes decoded from the `Private-MAC` header.
    /// 20 bytes (SHA-1) for v2; 32 bytes (SHA-256) for v3.
    pub private_mac: Vec<u8>,
    // v3-only KDF fields -- present when version == 3 and encryption != "none":
    /// Argon2 variant string: `"Argon2id"`, `"Argon2i"`, or `"Argon2d"`.
    pub kdf_variant: Option<String>,
    pub argon2_memory: Option<u32>,
    pub argon2_passes: Option<u32>,
    pub argon2_parallelism: Option<u32>,
    pub argon2_salt: Option<Vec<u8>>,
}

/// Return `true` if `data` starts with a PuTTY PPK v2 or v3 magic prefix.
pub fn is_ppk(data: &[u8]) -> bool {
    data.starts_with(b"PuTTY-User-Key-File-2: ")
        || data.starts_with(b"PuTTY-User-Key-File-3: ")
}

/// Parse a PuTTY `.ppk` file from raw bytes and return a [`PpkFile`].
///
/// Only the text structure is parsed here -- no cryptographic operations are
/// performed.  The caller is responsible for MAC verification and private
/// blob decryption.
///
/// # Errors
/// Returns [`KeyParseError::Malformed`] for structural defects (missing
/// required headers, invalid base64, invalid hex).
/// Returns [`KeyParseError::Unsupported`] for unrecognised PPK versions.
pub fn parse_ppk(data: &[u8]) -> Result<PpkFile, KeyParseError> {
    let text = std::str::from_utf8(data)
        .map_err(|_| super::malformed("PPK: file is not valid UTF-8"))?;

    let mut lines = text.lines().peekable();

    // First line: "PuTTY-User-Key-File-N: <key-type>"
    let first = lines.next().ok_or_else(|| super::malformed("PPK: empty file"))?;
    let (version, key_type) = parse_ppk_first_line(first)?;

    let mut encryption: Option<String> = None;
    let mut comment: Option<String> = None;
    let mut public_blob: Option<Vec<u8>> = None;
    let mut kdf_variant: Option<String> = None;
    let mut argon2_memory: Option<u32> = None;
    let mut argon2_passes: Option<u32> = None;
    let mut argon2_parallelism: Option<u32> = None;
    let mut argon2_salt: Option<Vec<u8>> = None;
    let mut private_blob: Option<Vec<u8>> = None;
    let mut private_mac: Option<Vec<u8>> = None;

    while let Some(line) = lines.next() {
        if let Some(val) = ppk_strip_key(line, "Encryption") {
            encryption = Some(val.to_string());
        } else if let Some(val) = ppk_strip_key(line, "Comment") {
            comment = Some(val.to_string());
        } else if let Some(n_str) = ppk_strip_key(line, "Public-Lines") {
            let n: usize = n_str.trim().parse()
                .map_err(|_| super::malformed("PPK: invalid Public-Lines count"))?;
            // 4096 lines * 48 decoded bytes/line ≈ 192 KB — far more than any
            // real RSA-4096 or ECDSA P-256 public key blob.
            const MAX_PPK_BLOB_LINES: usize = 4_096;
            if n > MAX_PPK_BLOB_LINES {
                return Err(super::malformed(&format!(
                    "PPK: Public-Lines count {n} exceeds maximum {MAX_PPK_BLOB_LINES}"
                )));
            }
            public_blob = Some(ppk_read_base64_lines(&mut lines, n)?);
        } else if let Some(val) = ppk_strip_key(line, "Key-Derivation") {
            kdf_variant = Some(val.trim().to_string());
        } else if let Some(val) = ppk_strip_key(line, "Argon2-Memory") {
            argon2_memory = Some(val.trim().parse()
                .map_err(|_| super::malformed("PPK: invalid Argon2-Memory"))?);
        } else if let Some(val) = ppk_strip_key(line, "Argon2-Passes") {
            argon2_passes = Some(val.trim().parse()
                .map_err(|_| super::malformed("PPK: invalid Argon2-Passes"))?);
        } else if let Some(val) = ppk_strip_key(line, "Argon2-Parallelism") {
            argon2_parallelism = Some(val.trim().parse()
                .map_err(|_| super::malformed("PPK: invalid Argon2-Parallelism"))?);
        } else if let Some(val) = ppk_strip_key(line, "Argon2-Salt") {
            argon2_salt = Some(ppk_decode_hex(val.trim())?);
        } else if let Some(n_str) = ppk_strip_key(line, "Private-Lines") {
            let n: usize = n_str.trim().parse()
                .map_err(|_| super::malformed("PPK: invalid Private-Lines count"))?;
            const MAX_PPK_BLOB_LINES: usize = 4_096;
            if n > MAX_PPK_BLOB_LINES {
                return Err(super::malformed(&format!(
                    "PPK: Private-Lines count {n} exceeds maximum {MAX_PPK_BLOB_LINES}"
                )));
            }
            private_blob = Some(ppk_read_base64_lines(&mut lines, n)?);
        } else if let Some(val) = ppk_strip_key(line, "Private-MAC") {
            private_mac = Some(ppk_decode_hex(val.trim())?);
        }
        // Unknown headers are silently tolerated for forward compatibility.
    }

    Ok(PpkFile {
        version,
        key_type,
        encryption: encryption.ok_or_else(|| super::malformed("PPK: missing Encryption header"))?,
        comment: comment.unwrap_or_default(),
        public_blob: public_blob.ok_or_else(|| super::malformed("PPK: missing Public-Lines block"))?,
        private_blob: private_blob.ok_or_else(|| super::malformed("PPK: missing Private-Lines block"))?,
        private_mac: private_mac.ok_or_else(|| super::malformed("PPK: missing Private-MAC"))?,
        kdf_variant,
        argon2_memory,
        argon2_passes,
        argon2_parallelism,
        argon2_salt,
    })
}

/// Parse the first line of a PPK file: `"PuTTY-User-Key-File-N: key-type"`.
/// Returns `(version, key_type)`.
fn parse_ppk_first_line(line: &str) -> Result<(u8, String), KeyParseError> {
    let rest = line.strip_prefix("PuTTY-User-Key-File-")
        .ok_or_else(|| super::malformed("PPK: first line does not start with PuTTY-User-Key-File-"))?;
    // rest is e.g. "2: ssh-rsa" or "3: ecdsa-sha2-nistp256"
    let (ver_str, key_type_part) = rest.split_once(": ")
        .ok_or_else(|| super::malformed("PPK: first line missing ': ' separator"))?;
    let version: u8 = ver_str.parse()
        .map_err(|_| super::malformed("PPK: version field is not a number"))?;
    if version != 2 && version != 3 {
        return Err(KeyParseError::Unsupported(format!(
            "PPK version {version} is not supported (supported: 2, 3)"
        )));
    }
    let key_type = key_type_part.trim().to_string();
    if key_type.is_empty() {
        return Err(super::malformed("PPK: empty key-type on first line"));
    }
    Ok((version, key_type))
}

/// Strip `"key: "` prefix from a PPK header line and return the value, or
/// `None` if the line does not have that prefix.
fn ppk_strip_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?.strip_prefix(": ")
}

/// Read `count` base64 lines from `lines` and return the decoded bytes.
fn ppk_read_base64_lines<'a, I>(lines: &mut I, count: usize) -> Result<Vec<u8>, KeyParseError>
where
    I: Iterator<Item = &'a str>,
{
    let mut b64 = String::new();
    for i in 0..count {
        let line = lines.next().ok_or_else(|| {
            super::malformed(&format!("PPK: unexpected end of file reading base64 line {i}"))
        })?;
        b64.push_str(line.trim());
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| super::malformed(&format!("PPK: invalid base64: {e}")))
}

/// Decode a lowercase hex string to bytes.  Returns [`KeyParseError::Malformed`]
/// for non-hex characters or odd-length strings.
fn ppk_decode_hex(hex: &str) -> Result<Vec<u8>, KeyParseError> {
    if hex.len() % 2 != 0 {
        return Err(super::malformed("PPK: odd-length hex string"));
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = super::hex_nibble(pair[0]).ok_or_else(|| super::malformed("PPK: invalid hex digit"))?;
            let lo = super::hex_nibble(pair[1]).ok_or_else(|| super::malformed("PPK: invalid hex digit"))?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// PPK v2 SHA-1 key derivation and AES-256-CBC decryption
// ---------------------------------------------------------------------------

/// Derive a 32-byte AES-256 key from `passphrase` using the PPK v2 SHA-1 KDF.
///
/// ```text
/// key[ 0..20] = SHA-1("\x00\x00\x00\x00" || passphrase)
/// key[20..32] = SHA-1("\x00\x00\x00\x01" || passphrase)[0..12]
/// ```
// Called by ppk_v2_decrypt_private_blob; wired via parse_key_file in soft_PKCS11-kqz4.
#[allow(dead_code)]
pub fn ppk_v2_derive_key(passphrase: &[u8]) -> [u8; 32] {
    let hash0 = ppk_sha1_with_counter(0, passphrase);
    let hash1 = ppk_sha1_with_counter(1, passphrase);
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(&hash0);
    key[20..].copy_from_slice(&hash1[..12]);
    key
}

/// Compute SHA-1(`counter.to_be_bytes()` || `passphrase`) and return the digest.
fn ppk_sha1_with_counter(counter: u32, passphrase: &[u8]) -> [u8; 20] {
    use wolfcrypt::digest::digest_trait::{Digest, Update};
    let mut sha = wolfcrypt::Sha1::new();
    Update::update(&mut sha, &counter.to_be_bytes());
    Update::update(&mut sha, passphrase);
    let output = sha.finalize();
    let mut block = [0u8; 20];
    block.copy_from_slice(output.as_slice());
    block
}

/// Decrypt the PPK v2 private blob, returning the plaintext.
///
/// - `"none"` encryption: returns the private blob unchanged.
/// - `"aes256-cbc"` encryption: derives a 32-byte key with [`ppk_v2_derive_key`],
///   uses a zero 16-byte IV, and PKCS#7-unpads the result.
///
/// Returns [`KeyParseError::Unsupported`] for unrecognised encryption algorithms.
// Wired via parse_key_file in soft_PKCS11-kqz4.
#[allow(dead_code)]
pub fn ppk_v2_decrypt_private_blob(
    ppk: &PpkFile,
    passphrase: &str,
) -> Result<Vec<u8>, KeyParseError> {
    match ppk.encryption.as_str() {
        "none" => Ok(ppk.private_blob.clone()),
        "aes256-cbc" => {
            let key = ppk_v2_derive_key(passphrase.as_bytes());
            let iv = [0u8; 16];
            super::aes256_cbc_decrypt(&key, &iv, &ppk.private_blob)
        }
        other => Err(KeyParseError::Unsupported(format!(
            "PPK v2: unsupported encryption algorithm '{other}'"
        ))),
    }
}

// ---------------------------------------------------------------------------
// PPK v3 Argon2 KDF and HMAC-SHA256 MAC
// ---------------------------------------------------------------------------

/// Derive `(aes_key[32], aes_iv[16], mac_key[32])` for a PPK v3 file using
/// Argon2 with the parameters stored in `ppk`.
///
/// Returns `Unsupported` for unrecognised `Key-Derivation` variants.
/// Returns `Malformed` for invalid Argon2 parameter values.
pub(crate) fn ppk_v3_derive_key_iv_mac(
    ppk: &PpkFile,
    passphrase: &str,
) -> Result<([u8; 32], [u8; 16], [u8; 32]), KeyParseError> {
    let variant_str = ppk.kdf_variant.as_deref()
        .ok_or_else(|| super::malformed("PPK v3: missing Key-Derivation header"))?;

    let variant = match variant_str {
        "Argon2i"  => argon2::Algorithm::Argon2i,
        "Argon2d"  => argon2::Algorithm::Argon2d,
        "Argon2id" => argon2::Algorithm::Argon2id,
        other => return Err(KeyParseError::Unsupported(format!(
            "PPK v3: unsupported Key-Derivation variant '{other}'; \
             supported: Argon2i, Argon2d, Argon2id"
        ))),
    };

    let m = ppk.argon2_memory
        .ok_or_else(|| super::malformed("PPK v3: missing Argon2-Memory"))?;
    let t = ppk.argon2_passes
        .ok_or_else(|| super::malformed("PPK v3: missing Argon2-Passes"))?;
    let p = ppk.argon2_parallelism
        .ok_or_else(|| super::malformed("PPK v3: missing Argon2-Parallelism"))?;
    let salt = ppk.argon2_salt.as_deref()
        .ok_or_else(|| super::malformed("PPK v3: missing Argon2-Salt"))?;

    // Cap Argon2 parameters before calling the crate to prevent a crafted PPK
    // file from triggering an OOM allocation (m) or unbounded CPU stall (t, p).
    // Caps match PuTTY's own defaults (256 MiB / 13 passes / 1 thread) with
    // comfortable headroom for strong configurations. (soft_PKCS11-snkm)
    const MAX_ARGON2_M: u32 = 1_048_576; // 1 GiB in KiB
    const MAX_ARGON2_T: u32 = 2_048;
    const MAX_ARGON2_P: u32 = 64;
    if m > MAX_ARGON2_M {
        return Err(super::malformed(&format!("PPK v3: Argon2-Memory {m} KiB exceeds maximum {MAX_ARGON2_M} KiB")));
    }
    if t > MAX_ARGON2_T {
        return Err(super::malformed(&format!("PPK v3: Argon2-Passes {t} exceeds maximum {MAX_ARGON2_T}")));
    }
    if p > MAX_ARGON2_P {
        return Err(super::malformed(&format!("PPK v3: Argon2-Parallelism {p} exceeds maximum {MAX_ARGON2_P}")));
    }

    let params = argon2::Params::new(m, t, p, None)
        .map_err(|e| super::malformed(&format!("PPK v3: invalid Argon2 parameters: {e}")))?;
    let kdf = argon2::Argon2::new(variant, argon2::Version::V0x13, params);

    let mut derived = [0u8; 80];
    kdf.hash_password_into(passphrase.as_bytes(), salt, &mut derived)
        .map_err(|e| super::malformed(&format!("PPK v3: Argon2 derivation failed: {e}")))?;

    let mut aes_key = [0u8; 32];
    let mut aes_iv  = [0u8; 16];
    let mut mac_key = [0u8; 32];
    aes_key.copy_from_slice(&derived[..32]);
    aes_iv.copy_from_slice(&derived[32..48]);
    mac_key.copy_from_slice(&derived[48..]);
    Ok((aes_key, aes_iv, mac_key))
}

/// Decrypt the PPK v3 private blob, returning the plaintext.
///
/// - `"none"` encryption: returns the private blob unchanged.
/// - `"aes256-cbc"` encryption: derives key + IV with Argon2, then AES-256-CBC-decrypts.
///
/// Returns `Unsupported` for unrecognised encryption or KDF-variant strings.
// Wired via parse_key_file in soft_PKCS11-kqz4.
#[allow(dead_code)]
pub fn ppk_v3_decrypt_private_blob(
    ppk: &PpkFile,
    passphrase: &str,
) -> Result<Vec<u8>, KeyParseError> {
    match ppk.encryption.as_str() {
        "none" => Ok(ppk.private_blob.clone()),
        "aes256-cbc" => {
            let (key, iv, _) = ppk_v3_derive_key_iv_mac(ppk, passphrase)?;
            super::aes256_cbc_decrypt(&key, &iv, &ppk.private_blob)
        }
        other => Err(KeyParseError::Unsupported(format!(
            "PPK v3: unsupported encryption algorithm '{other}'"
        ))),
    }
}

/// Verify the PPK v3 `Private-MAC` field using HMAC-SHA256.
///
/// `private_blob_decrypted` must be the **decrypted** private blob (the output
/// of [`ppk_v3_decrypt_private_blob`]).
///
/// The MAC key is:
/// - The empty slice for unencrypted files (`encryption == "none"`).
/// - `Argon2(...)[48..80]` for encrypted files.
///
/// Returns `Ok(())` if the MAC matches, or [`KeyParseError::Malformed`] if it
/// does not (wrong passphrase or corrupted file).
// Wired via parse_key_file in soft_PKCS11-kqz4.
#[allow(dead_code)]
pub fn ppk_v3_verify_mac(
    ppk: &PpkFile,
    passphrase: &str,
    private_blob_decrypted: &[u8],
) -> Result<(), KeyParseError> {
    let mac_key: Vec<u8> = if ppk.encryption == "none" {
        vec![]
    } else {
        let (_, _, mk) = ppk_v3_derive_key_iv_mac(ppk, passphrase)?;
        mk.to_vec()
    };

    let mac_input = ppk_v2_mac_input(
        &ppk.key_type,
        &ppk.encryption,
        &ppk.comment,
        &ppk.public_blob,
        private_blob_decrypted,
    );
    let computed = super::hmac_sha256(&mac_key, &mac_input);

    if ppk.private_mac.as_slice() != computed {
        return Err(super::malformed(
            "PPK v3: MAC verification failed (wrong passphrase or corrupted file)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PPK v2 HMAC-SHA1 MAC verification
// ---------------------------------------------------------------------------

/// The string prepended to the passphrase when deriving the PPK MAC key.
pub(crate) const PPK_MAC_KEY_PREFIX: &[u8] = b"putty-private-key-file-mac-key";

/// Derive the 20-byte HMAC-SHA1 MAC key for a PPK v2 file.
///
/// ```text
/// mac_key = SHA-1("putty-private-key-file-mac-key" || passphrase)
/// ```
///
/// For unencrypted files (`encryption == "none"`) the passphrase is the empty
/// string, so `passphrase` should be passed as an empty slice in that case.
pub(crate) fn ppk_v2_derive_mac_key(passphrase: &[u8]) -> [u8; 20] {
    use wolfcrypt::digest::digest_trait::{Digest, Update};
    let mut sha = wolfcrypt::Sha1::new();
    Update::update(&mut sha, PPK_MAC_KEY_PREFIX);
    Update::update(&mut sha, passphrase);
    let output = sha.finalize();
    let mut mac_key = [0u8; 20];
    mac_key.copy_from_slice(output.as_slice());
    mac_key
}

/// Build the MAC input buffer for a PPK v2 file.
///
/// The input is a concatenation of five length-prefixed fields (u32 big-endian
/// length followed by the field bytes):
///   1. key_type string
///   2. encryption string
///   3. comment string
///   4. public blob
///   5. decrypted private blob
pub(crate) fn ppk_v2_mac_input(
    key_type: &str,
    encryption: &str,
    comment: &str,
    public_blob: &[u8],
    private_blob_decrypted: &[u8],
) -> Vec<u8> {
    let fields: &[&[u8]] = &[
        key_type.as_bytes(),
        encryption.as_bytes(),
        comment.as_bytes(),
        public_blob,
        private_blob_decrypted,
    ];
    let total = fields.iter().map(|f| 4 + f.len()).sum();
    let mut buf = Vec::with_capacity(total);
    for field in fields {
        let len = field.len() as u32;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(field);
    }
    buf
}

/// Verify the PPK v2 `Private-MAC` field.
///
/// `private_blob_decrypted` must be the **decrypted** private blob (the output
/// of [`ppk_v2_decrypt_private_blob`]).
///
/// Returns `Ok(())` if the MAC matches, or [`KeyParseError::Malformed`] if it
/// does not (wrong passphrase or corrupted file).
// Wired via parse_key_file in soft_PKCS11-kqz4.
#[allow(dead_code)]
pub fn ppk_v2_verify_mac(ppk: &PpkFile, passphrase: &str, private_blob_decrypted: &[u8]) -> Result<(), KeyParseError> {
    let mac_key = ppk_v2_derive_mac_key(passphrase.as_bytes());
    let mac_input = ppk_v2_mac_input(
        &ppk.key_type,
        &ppk.encryption,
        &ppk.comment,
        &ppk.public_blob,
        private_blob_decrypted,
    );
    let computed = super::hmac_sha1(&mac_key, &mac_input);
    if ppk.private_mac.as_slice() != computed {
        return Err(super::malformed(
            "PPK: MAC verification failed (wrong passphrase or corrupted file)",
        ));
    }
    Ok(())
}
