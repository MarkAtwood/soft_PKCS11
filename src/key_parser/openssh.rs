use super::*;

// ---------------------------------------------------------------------------
// OpenSSH new-format binary frame parser
// ---------------------------------------------------------------------------

pub(crate) const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

#[derive(Debug)]
/// Parsed outer frame of an OpenSSH new-format private key file (`openssh-key-v1\0`).
///
/// The frame carries the cipher/KDF metadata and the raw private blob.
/// The private blob may be encrypted (when `ciphername != "none"`) or
/// unencrypted (when `ciphername == "none"` and `kdfname == "none"`).
/// Inner private blob decoding is handled by a subsequent step.
pub struct OpensshFrame {
    /// Cipher name, e.g. `"aes256-ctr"` or `"none"`.
    pub ciphername: String,
    /// KDF name, e.g. `"bcrypt"` or `"none"`.
    pub kdfname: String,
    /// Raw KDF options bytes.  Empty when `kdfname == "none"`.
    pub kdfoptions_raw: Vec<u8>,
    /// Raw private key blob.  Encrypted when `ciphername != "none"`.
    pub private_blob: Vec<u8>,
}

/// Parse the outer frame of an OpenSSH new-format private key file.
///
/// The caller supplies the raw bytes -- either the base64-decoded body of an
/// `-----BEGIN OPENSSH PRIVATE KEY-----` PEM block, or the raw binary file.
///
/// # Errors
/// - `Malformed` -- wrong magic, truncated data, or non-UTF-8 string fields.
/// - `Unsupported` -- the file contains more than one key.
pub fn parse_openssh_binary(data: &[u8]) -> Result<OpensshFrame, KeyParseError> {
    if !data.starts_with(OPENSSH_MAGIC) {
        return Err(KeyParseError::Malformed(
            "not an openssh-key-v1 file (wrong magic)".to_string(),
        ));
    }
    let mut cur = &data[OPENSSH_MAGIC.len()..];

    let ciphername = super::read_openssh_str(&mut cur)?;
    let kdfname = super::read_openssh_str(&mut cur)?;
    let kdfoptions_raw = super::read_openssh_bytes(&mut cur)?.to_vec();

    if cur.len() < 4 {
        return Err(KeyParseError::Malformed(
            "OpenSSH: truncated nkeys field".to_string(),
        ));
    }
    let nkeys = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]);
    cur = &cur[4..];

    if nkeys != 1 {
        return Err(KeyParseError::Unsupported(format!(
            "OpenSSH files with {nkeys} keys are not supported; \
             extract each key separately with: \
             ssh-keygen -f <keyfile> -e -m PKCS8"
        )));
    }

    // Skip public key blob (derivable from the private key).
    let _ = super::read_openssh_bytes(&mut cur)?;

    // Private key blob (may be encrypted).
    let private_blob = super::read_openssh_bytes(&mut cur)?.to_vec();

    Ok(OpensshFrame { ciphername, kdfname, kdfoptions_raw, private_blob })
}

// ---------------------------------------------------------------------------
// OpenSSH private blob decryption (soft_PKCS11-ng8k)
// ---------------------------------------------------------------------------

/// Decrypt (or pass through) the private blob from an OpenSSH key frame.
///
/// - `ciphername == "none"`: blob is plaintext; returned as-is.
/// - `ciphername == "aes256-ctr"`: KDF options are parsed (SSH wire format:
///   `string salt | uint32 rounds`), 48 bytes are derived with `bcrypt_pbkdf`,
///   and the blob is decrypted in-place with AES-256-CTR.
/// - Other values: returns `Unsupported`.
///
/// The returned bytes include the two check words at the start; callers should
/// call [`verify_openssh_check_words`] to confirm the passphrase was correct.
pub(crate) fn decrypt_openssh_blob(frame: &OpensshFrame, passphrase: &str) -> Result<Vec<u8>, KeyParseError> {
    match frame.ciphername.as_str() {
        "none" => Ok(frame.private_blob.clone()),

        "aes256-ctr" => {
            if frame.kdfname != "bcrypt" {
                return Err(super::malformed(
                    "OpenSSH: ciphername is aes256-ctr but kdfname is not bcrypt",
                ));
            }
            // kdfoptions SSH wire format: string(salt) || uint32(rounds)
            let opts = &frame.kdfoptions_raw;
            if opts.len() < 4 {
                return Err(super::malformed("OpenSSH: kdfoptions too short for bcrypt salt length"));
            }
            let salt_len =
                u32::from_be_bytes([opts[0], opts[1], opts[2], opts[3]]) as usize;
            // OpenSSH always uses 16-byte bcrypt salts; cap generously at 64.
            const MAX_OPENSSH_BCRYPT_SALT: usize = 64;
            if salt_len > MAX_OPENSSH_BCRYPT_SALT {
                return Err(super::malformed(&format!(
                    "OpenSSH: bcrypt salt length {salt_len} exceeds maximum {MAX_OPENSSH_BCRYPT_SALT}"
                )));
            }
            // Use checked arithmetic to avoid overflow on 32-bit targets.
            let after_salt = 4usize.checked_add(salt_len)
                .ok_or_else(|| super::malformed("OpenSSH: bcrypt kdfoptions salt length overflow"))?;
            let end_of_rounds = after_salt.checked_add(4)
                .ok_or_else(|| super::malformed("OpenSSH: bcrypt kdfoptions salt length overflow"))?;
            if opts.len() < end_of_rounds {
                return Err(super::malformed("OpenSSH: kdfoptions truncated before rounds field"));
            }
            let salt = &opts[4..after_salt];
            let rounds = u32::from_be_bytes([
                opts[after_salt],
                opts[after_salt + 1],
                opts[after_salt + 2],
                opts[after_salt + 3],
            ]);
            // Cap round count to prevent a crafted key file from causing a
            // multi-hour bcrypt_pbkdf computation. OpenSSH defaults to 16;
            // 1,024 provides generous headroom for high-security keys.
            // (soft_PKCS11-e9qp)
            const MAX_OPENSSH_BCRYPT_ROUNDS: u32 = 1_024;
            if rounds == 0 || rounds > MAX_OPENSSH_BCRYPT_ROUNDS {
                return Err(super::malformed(&format!(
                    "OpenSSH: bcrypt rounds {rounds} out of range \
                     (must be 1..={MAX_OPENSSH_BCRYPT_ROUNDS})"
                )));
            }

            // bcrypt_pbkdf: derive 32-byte AES key + 16-byte CTR IV.
            let mut key_iv = [0u8; 48];
            bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut key_iv)
                .map_err(|_| super::malformed("OpenSSH: bcrypt_pbkdf failed (rounds must be > 0)"))?;

            let key: &[u8; 32] = key_iv[..32].try_into().unwrap();
            let iv: &[u8; 16] = key_iv[32..].try_into().unwrap();

            // AES-256-CTR decryption in-place.
            use cipher::{KeyIvInit, StreamCipher};
            use generic_array::GenericArray;
            use wolfcrypt::Aes256Ctr;

            let mut blob = frame.private_blob.clone();
            let mut cipher =
                Aes256Ctr::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
            cipher.apply_keystream(&mut blob);
            Ok(blob)
        }

        "aes256-gcm@openssh.com" => Err(KeyParseError::Unsupported(
            "OpenSSH aes256-gcm@openssh.com ciphername requires AES-GCM decryption; \
             convert with: ssh-keygen -p -f <keyfile> -m PEM"
                .to_string(),
        )),

        other => Err(KeyParseError::Unsupported(format!(
            "OpenSSH unsupported ciphername '{other}'; \
             convert with: ssh-keygen -p -f <keyfile> -m PEM"
        ))),
    }
}

/// Verify the two 32-bit check words at the start of a decrypted OpenSSH
/// private blob.  Returns the slice after the check words on success.
///
/// Per the OpenSSH format, the first two u32 big-endian words in a correctly
/// decrypted blob must be equal.  A mismatch means the passphrase was wrong
/// or the key data is corrupted.
pub(crate) fn verify_openssh_check_words(blob: &[u8]) -> Result<&[u8], KeyParseError> {
    if blob.len() < 8 {
        return Err(super::malformed("OpenSSH: private blob too short for check words"));
    }
    let check1 = u32::from_be_bytes(blob[..4].try_into().unwrap());
    let check2 = u32::from_be_bytes(blob[4..8].try_into().unwrap());
    if check1 != check2 {
        return Err(super::malformed(
            "OpenSSH: check word mismatch (wrong passphrase or corrupted key)",
        ));
    }
    Ok(&blob[8..])
}

// ---------------------------------------------------------------------------
// OpenSSH private blob key extraction (soft_PKCS11-3044 / ua43)
// ---------------------------------------------------------------------------

/// Validate the padding sequence at the end of a decrypted OpenSSH private blob.
///
/// Per the OpenSSH format spec, after all key fields are consumed the remaining
/// bytes must be the incrementing sequence 0x01, 0x02, 0x03, ... (mod 256).
/// This padding fills the private blob to the cipher block boundary and its
/// correctness is evidence that the check-word pair was not a false positive.
/// An empty remainder (perfectly block-aligned content) is also accepted.
/// (soft_PKCS11-e9qp)
fn validate_openssh_padding(padding: &[u8]) -> Result<(), KeyParseError> {
    for (i, &b) in padding.iter().enumerate() {
        if b != ((i + 1) as u8) {
            return Err(super::malformed(
                "OpenSSH: private blob has invalid padding after key fields \
                 (corrupted key or wrong passphrase)",
            ));
        }
    }
    Ok(())
}

/// Parse key data from a decrypted OpenSSH private blob (bytes after the two
/// check words).
///
/// Dispatches on the key-type string to EC or RSA extraction.  Returns
/// `Unsupported` for any key type that is not yet handled.
pub(crate) fn parse_openssh_key_data(blob: &[u8], id: [u8; 16]) -> Result<ParsedKey, KeyParseError> {
    let mut cur = blob;
    let keytype = super::read_openssh_str(&mut cur)?;
    let key = match keytype.as_str() {
        "ecdsa-sha2-nistp256" => extract_openssh_ec_p256(&mut cur, id),
        "ssh-rsa" => extract_openssh_rsa(&mut cur, id),
        other => Err(KeyParseError::Unsupported(format!(
            "OpenSSH key type '{other}' is not supported; \
             convert with: ssh-keygen -p -N '' -m PKCS8 -f <keyfile>"
        ))),
    }?;
    validate_openssh_padding(cur)?;
    Ok(key)
}

/// Extract an ECDSA P-256 private key from SSH wire-format blob data.
///
/// Wire layout (after key-type string has been consumed):
/// ```text
/// string  curve-name    ("nistp256")
/// string  public-point  (uncompressed: 04 || x || y, 65 bytes)
/// string  private       (scalar, big-endian; may have a leading 0x00)
/// string  comment
/// ```
fn extract_openssh_ec_p256(cur: &mut &[u8], _id: [u8; 16]) -> Result<ParsedKey, KeyParseError> {
    let curve = super::read_openssh_str(cur)?;
    if curve != "nistp256" {
        return Err(KeyParseError::Unsupported(format!(
            "OpenSSH EC curve '{curve}' is not P-256 (nistp256)"
        )));
    }

    let public_point = super::read_openssh_bytes(cur)?;
    if public_point.len() != 65 || public_point[0] != 0x04 {
        return Err(super::malformed(
            "OpenSSH EC P-256: public point must be 65-byte uncompressed (04 || x || y)",
        ));
    }

    let scalar_raw = super::read_openssh_bytes(cur)?;
    let scalar_bytes = super::strip_ssh_mpi_zero(scalar_raw);
    if scalar_bytes.len() != 32 {
        return Err(super::malformed(
            "OpenSSH EC P-256: private scalar must be 32 bytes after stripping MPI zero prefix",
        ));
    }
    if scalar_bytes.iter().all(|&b| b == 0) {
        return Err(super::malformed("OpenSSH EC P-256: private scalar is zero"));
    }

    let comment = super::read_openssh_str(cur).unwrap_or_default();
    let label_hint = if comment.is_empty() { None } else { Some(comment) };

    // Key ID: SHA-256(65-byte uncompressed public point)[0..16]
    use wolfcrypt::digest::digest_trait::Digest as _;
    let hash = wolfcrypt::Sha256::digest(public_point);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[..16]);

    Ok(ParsedKey {
        key_type: KeyType::Ec,
        key_bytes: scalar_bytes.to_vec(),
        id,
        label_hint,
        cert_der: None,
    })
}

/// Extract an RSA private key from SSH wire-format blob data and return it
/// as a PKCS#1 DER `RSAPrivateKey`.
///
/// Wire layout (after key-type string has been consumed):
/// ```text
/// mpint   n      (modulus)
/// mpint   e      (public exponent)
/// mpint   d      (private exponent)
/// mpint   iqmp   (CRT coefficient: q^-1 mod p)
/// mpint   p      (first prime factor)
/// mpint   q      (second prime factor)
/// string  comment
/// ```
///
/// wolfCrypt computes `dmp1` and `dmq1` internally when the key is loaded
/// via `NativeRsaKey::from_raw_components`.
fn extract_openssh_rsa(cur: &mut &[u8], _id: [u8; 16]) -> Result<ParsedKey, KeyParseError> {
    let n_raw = super::read_openssh_bytes(cur)?;
    let e_raw = super::read_openssh_bytes(cur)?;
    let d_raw = super::read_openssh_bytes(cur)?;
    let iqmp_raw = super::read_openssh_bytes(cur)?;
    let p_raw = super::read_openssh_bytes(cur)?;
    let q_raw = super::read_openssh_bytes(cur)?;

    let n = super::strip_ssh_mpi_zero(n_raw);
    let e = super::strip_ssh_mpi_zero(e_raw);
    let d = super::strip_ssh_mpi_zero(d_raw);
    let iqmp = super::strip_ssh_mpi_zero(iqmp_raw);
    let p = super::strip_ssh_mpi_zero(p_raw);
    let q = super::strip_ssh_mpi_zero(q_raw);

    let comment = super::read_openssh_str(cur).unwrap_or_default();
    let label_hint = if comment.is_empty() { None } else { Some(comment) };

    // Load into wolfCrypt and export as PKCS#1 DER.  wolfCrypt computes
    // dmp1 = d mod (p-1) and dmq1 = d mod (q-1) from the raw components.
    let key = wolfcrypt::NativeRsaKey::from_raw_components(n, e, d, p, q, iqmp)
        .map_err(|e| super::malformed(&format!("OpenSSH RSA: wolfCrypt key load failed: {e:?}")))?;
    let pkcs1_der = key
        .to_pkcs1_der()
        .map_err(|e| super::malformed(&format!("OpenSSH RSA: wolfCrypt DER export failed: {e:?}")))?;

    // Key ID: SHA-256(RSAPublicKey DER)[0..16] for reproducibility.
    let id = super::sha256_key_id(&pkcs1_der)
        .ok_or_else(|| super::malformed("OpenSSH RSA: could not derive key ID from PKCS#1 DER"))?;

    Ok(ParsedKey {
        key_type: KeyType::Rsa,
        key_bytes: pkcs1_der,
        id,
        label_hint,
        cert_der: None,
    })
}
