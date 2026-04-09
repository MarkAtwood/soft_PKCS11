/// # Security Model
/// The .p11k keystore is encrypted at rest on the USB with AES-256-GCM.
/// The key is derived from a user PIN via PBKDF2-HMAC-SHA256 with at least
/// 100,000 iterations (production, NIST SP 800-132 floor) to resist brute-force.
/// Decrypted key bytes are mlock(2)'d to prevent paging to swap.
/// On drop, all key bytes are zeroized via the `zeroize` crate.
///
/// # Threat Model
/// Protects against: theft of machine (without USB), theft of USB (without PIN),
/// offline disk forensics.
/// Does NOT protect against: root-level in-memory attack on a running machine.
/// The USB is a possession factor only.

use std::path::Path;
use aead::{AeadInPlace, KeyInit};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use wolfcrypt::Aes256Gcm;

// Wire format constants — exported so usb-hsm-info can read the unencrypted
// header without duplicating offsets that must stay in sync. (soft_PKCS11-dq7h)
pub const MAGIC: &[u8; 4] = b"P11K";

// KDF iteration floor.
//
// An attacker who controls the .p11k file could set iterations to 0 or 1,
// eliminating the PIN-derivation cost and enabling trivial offline brute-force.
// We refuse to load any keystore below this minimum.
//
// Production: 100,000 (NIST SP 800-132 recommended floor for PBKDF2-SHA256).
// Test builds with `test-helpers` feature: relaxed to 1 so tests can create
// fast keystores without burning CPU. `test-helpers` is never compiled into
// the production .so (Cargo.toml enforces this).
//
// Safety net: if test-helpers is somehow enabled in an optimized (release)
// build, refuse to compile. debug_assertions are enabled by default in `cargo
// test` and disabled in `cargo build --release`, giving us a reliable proxy
// for "this is a production build."
#[cfg(all(feature = "test-helpers", not(debug_assertions)))]
compile_error!(
    "test-helpers feature is enabled in an optimized build. \
     This weakens PBKDF2 key derivation from 100,000 iterations to 1, \
     making stored keys trivially brute-forceable. \
     Only enable test-helpers via `cargo test` or `cargo t`."
);

/// PBKDF2-HMAC-SHA256 iteration count used when creating a new keystore.
///
/// Matches the NIST SP 800-132 minimum recommendation and the floor enforced
/// by [`Keystore::load`] (`MIN_KDF_ITERATIONS`). Export this constant so that
/// the `usb-hsm-keygen` binary can use the same value without duplicating it.
/// (soft_PKCS11-bv7u)
pub const DEFAULT_KDF_ITERATIONS: u32 = 100_000;

#[cfg(not(feature = "test-helpers"))]
const MIN_KDF_ITERATIONS: u32 = DEFAULT_KDF_ITERATIONS;
#[cfg(feature = "test-helpers")]
const MIN_KDF_ITERATIONS: u32 = 1;
const VERSION: u8 = 0x01;
const KDF_SALT_LEN: usize = 32;
const AES_GCM_NONCE_LEN: usize = 12;
const AES_GCM_TAG_LEN: usize = 16;
const AES_KEY_LEN: usize = 32;

// Offsets into the wire format (big-endian layout)
//   [0..4]   magic
//   [4]      version
//   [5..37]  kdf_salt        (32 bytes)
//   [37..41] kdf_iterations  (u32 BE)
//   [41..53] aes_gcm_nonce   (12 bytes)
//   [53..57] ciphertext_len  (u32 BE)
//   [57..]   ciphertext, then 16-byte tag
pub const OFF_VERSION: usize = 4;
const OFF_KDF_SALT: usize = 5;
pub const OFF_KDF_ITERATIONS: usize = 37;
const OFF_AES_NONCE: usize = 41;
pub const OFF_CIPHERTEXT_LEN: usize = 53;
const OFF_CIPHERTEXT: usize = 57;
pub const HEADER_LEN: usize = OFF_CIPHERTEXT; // 57 bytes before ciphertext

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum KeyType {
    Rsa,
    Ec,
    /// ML-DSA-44 (NIST security level 2, FIPS 204).
    MlDsa44,
    /// ML-DSA-65 (NIST security level 3, FIPS 204).
    MlDsa65,
    /// ML-DSA-87 (NIST security level 5, FIPS 204).
    MlDsa87,
    /// ML-KEM-512 (NIST security level 1, FIPS 203).
    MlKem512,
    /// ML-KEM-768 (NIST security level 3, FIPS 203).
    MlKem768,
    /// ML-KEM-1024 (NIST security level 5, FIPS 203).
    MlKem1024,
}

// Clone is intentionally derived: the keygen binary needs to copy entries
// from a loaded Keystore when adding, removing, or re-encrypting. The
// derived clone is NOT mlock'd (only Keystore::load's entries are mlock'd),
// but the clone has ZeroizeOnDrop so key bytes are wiped when the clone drops.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyEntry {
    pub id: [u8; 16],
    pub label: String,
    pub key_type: KeyType,
    /// RSA: PKCS#1 DER; EC: raw 32-byte private key scalar;
    /// ML-DSA-*: raw private key bytes; ML-KEM-*: raw private key bytes.
    pub der_bytes: Vec<u8>,
    /// Optional DER-encoded X.509 certificate associated with this key.
    /// Absent for keystores created before cert support was added (CBOR
    /// omits the field; serde(default) treats missing as None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_der: Option<Vec<u8>>,
    /// Public key bytes for PQC key types (ML-DSA-*, ML-KEM-*).
    ///
    /// Absent for RSA and EC keys (public key is derived from the private key
    /// on the fly by wolfcrypt).  For PQC types this field is populated at
    /// keygen / keystore-import time and is mlock'd alongside `der_bytes`.
    /// CBOR omits the field when None so old keystores remain readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pub_bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum KeystoreError {
    BadMagic,
    Truncated(usize),
    BadPin,
    Io(std::io::Error),
    CborDecode(String),
    Crypto(String),
    UnsupportedFormat(String),
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let min_len = HEADER_LEN + AES_GCM_TAG_LEN;
        match self {
            KeystoreError::BadMagic => write!(f, "bad magic bytes"),
            KeystoreError::Truncated(n) => write!(
                f,
                "file too short to be a valid .p11k keystore (got {n} bytes, need at least {min_len})"
            ),
            KeystoreError::BadPin => write!(f, "bad PIN (authentication tag mismatch)"),
            KeystoreError::Io(e) => write!(f, "I/O error: {e}"),
            KeystoreError::CborDecode(s) => write!(f, "CBOR decode error: {s}"),
            KeystoreError::Crypto(s) => write!(f, "crypto error: {s}"),
            KeystoreError::UnsupportedFormat(s) => write!(f, "unsupported format: {s}"),
        }
    }
}

impl From<std::io::Error> for KeystoreError {
    fn from(e: std::io::Error) -> Self {
        KeystoreError::Io(e)
    }
}

pub struct Keystore {
    entries: Vec<KeyEntry>,
}

impl Keystore {
    pub fn load(path: &Path, pin: &[u8]) -> Result<Self, KeystoreError> {
        let data = std::fs::read(path)?;
        match data.get(..4) {
            Some(magic) if magic == MAGIC => load_p11k(&data, pin),
            // FUTURE: format dispatch point -- add recognized format magic bytes here
            // (PKCS#12, OpenSSH, OpenPGP, etc.) before this catch-all. Each known
            // format returns UnsupportedFormat; completely unrecognized bytes return BadMagic.
            Some(_) | None => Err(KeystoreError::BadMagic),
        }
    }

    pub fn entries(&self) -> &[KeyEntry] {
        &self.entries
    }

    /// Encode `entries` into an encrypted `.p11k` blob and return the bytes.
    pub fn create(
        entries: Vec<KeyEntry>,
        pin: &[u8],
        iterations: u32,
    ) -> Result<Vec<u8>, KeystoreError> {
        // --- CBOR-encode the entries ---
        let mut cbor_payload = Vec::new();
        ciborium::into_writer(&entries, &mut cbor_payload)
            .map_err(|e| KeystoreError::CborDecode(e.to_string()))?;

        // --- Generate random salt and nonce ---
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        let mut aes_gcm_nonce = [0u8; AES_GCM_NONCE_LEN];
        fill_random(&mut kdf_salt)?;
        fill_random(&mut aes_gcm_nonce)?;

        // --- Derive AES-256 key ---
        let mut aes_key = [0u8; AES_KEY_LEN];
        wolfcrypt::pbkdf2_hmac_sha256(pin, &kdf_salt, iterations, &mut aes_key)
            .map_err(|e| KeystoreError::Crypto(format!("PBKDF2 failed: {e:?}")))?;

        // --- Encrypt in place ---
        let key_ga = GenericArray::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key_ga);
        let nonce_ga = GenericArray::from_slice(&aes_gcm_nonce);

        let mut ciphertext = cbor_payload;
        let tag = cipher
            .encrypt_in_place_detached(nonce_ga, b"", &mut ciphertext)
            .map_err(|e| KeystoreError::Crypto(format!("AES-GCM encrypt failed: {e:?}")))?;

        // Zeroize key material
        aes_key.zeroize();
        // ciphertext has replaced cbor_payload; the plaintext is gone
        // (Vec was encrypted in place -- original allocation is now ciphertext)

        // --- Serialise wire format ---
        let ciphertext_len = ciphertext.len() as u32;
        let total = HEADER_LEN + ciphertext.len() + AES_GCM_TAG_LEN;
        let mut out = Vec::with_capacity(total);

        out.extend_from_slice(MAGIC);                         // [0..4]
        out.push(VERSION);                                    // [4]
        out.extend_from_slice(&kdf_salt);                     // [5..37]
        out.extend_from_slice(&iterations.to_be_bytes());     // [37..41]
        out.extend_from_slice(&aes_gcm_nonce);                // [41..53]
        out.extend_from_slice(&ciphertext_len.to_be_bytes()); // [53..57]
        out.extend_from_slice(&ciphertext);                   // [57..57+len]
        out.extend_from_slice(tag.as_slice());                // [57+len..57+len+16]

        Ok(out)
    }
}

impl Drop for Keystore {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            // SECURITY: Zeroize key bytes WHILE the page is still mlock'd, THEN munlock.
            // If we munlock first, the OS could swap the page before ZeroizeOnDrop fires.
            // IMPORTANT: Vec::zeroize() calls clear() -> len() becomes 0.  Save len BEFORE
            // calling zeroize(), or munlock(ptr, 0) is a Linux no-op (pages stay locked).
            if !entry.der_bytes.is_empty() {
                let len = entry.der_bytes.len();
                entry.der_bytes.zeroize();
                // SAFETY: der_bytes is heap-allocated and was mlock'd in load_p11k.
                unsafe {
                    libc::munlock(entry.der_bytes.as_ptr() as *const libc::c_void, len);
                }
            }
            if let Some(ref mut pb) = entry.pub_bytes {
                if !pb.is_empty() {
                    let len = pb.len();
                    pb.zeroize();
                    // SAFETY: pub_bytes is heap-allocated and was mlock'd in load_p11k.
                    unsafe {
                        libc::munlock(pb.as_ptr() as *const libc::c_void, len);
                    }
                }
            }
        }
        // ZeroizeOnDrop on KeyEntry fires after this; double-zero is harmless.
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Maximum RSA modulus size in bytes (= 4096 bits).
///
/// `sign_max_output` in lib.rs allocates 512 bytes for RSA output. A key with
/// a modulus larger than 512 bytes would produce a signature that overflows the
/// caller's pre-allocated buffer. Keep this constant in sync with `sign_max_output`.
const MAX_RSA_MODULUS_BYTES: usize = 512;
/// P-256 private key scalar size in bytes. The only EC curve supported by usb-hsm.
const EC_P256_SCALAR_BYTES: usize = 32;

// PQC key sizes (FIPS 203/204 values; must match wolfcrypt constants).
const ML_DSA_44_PRIV_BYTES: usize = 2560;
const ML_DSA_44_PUB_BYTES: usize  = 1312;
const ML_DSA_65_PRIV_BYTES: usize = 4032;
const ML_DSA_65_PUB_BYTES: usize  = 1952;
const ML_DSA_87_PRIV_BYTES: usize = 4896;
const ML_DSA_87_PUB_BYTES: usize  = 2592;
const ML_KEM_512_PRIV_BYTES: usize  = 1632;
const ML_KEM_512_PUB_BYTES: usize   = 800;
const ML_KEM_768_PRIV_BYTES: usize  = 2400;
const ML_KEM_768_PUB_BYTES: usize   = 1184;
const ML_KEM_1024_PRIV_BYTES: usize = 3168;
const ML_KEM_1024_PUB_BYTES: usize  = 1568;

/// Parse a DER definite-length field from `data[*pos..]`.
///
/// On success advances `*pos` past the length bytes and returns the content length.
/// Returns `None` for truncated data, indefinite form (0x80), or length encodings
/// that require more than 4 bytes (no valid RSA key DER component exceeds 4 GB).
fn parse_der_len(data: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *data.get(*pos)?;
    *pos += 1;
    if first & 0x80 == 0 {
        // Short form: the byte itself is the content length (0-127).
        Some(first as usize)
    } else {
        // Long form: lower 7 bits = number of subsequent bytes encoding the length.
        // Reject indefinite form (first == 0x80) and lengths > 4 bytes.
        let n_bytes = (first & 0x7F) as usize;
        if n_bytes == 0 || n_bytes > 4 || *pos + n_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n_bytes {
            let b = *data.get(*pos)?;
            *pos += 1;
            len = len.checked_shl(8)?.checked_add(b as usize)?;
        }
        Some(len)
    }
}

/// Extract the RSA modulus byte count from a DER-encoded RSA private key.
///
/// Accepts both formats produced by wolfCrypt:
/// - **PKCS#1** `RSAPrivateKey`: `SEQUENCE { version, modulus, ... }`
/// - **PKCS#8** `PrivateKeyInfo`: `SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { RSAPrivateKey } }`
///
/// Reads only as far as the modulus INTEGER -- intentionally stops before the
/// private exponent and other secret fields to minimise exposure to sensitive data.
///
/// Returns the modulus length in bytes, excluding any DER-inserted leading 0x00
/// byte that preserves positive-integer encoding.
///
/// Returns `None` if the bytes do not match either expected layout.
fn rsa_modulus_bytes(der: &[u8]) -> Option<usize> {
    let mut pos = 0;

    // Outer SEQUENCE
    if *der.get(pos)? != 0x30 {
        return None;
    }
    pos += 1;
    let _seq_len = parse_der_len(der, &mut pos)?;

    // version INTEGER: exactly 02 01 00 (version 0, the only defined version)
    if der.get(pos..pos + 3)? != [0x02, 0x01, 0x00] {
        return None;
    }
    pos += 3;

    // Peek at the next tag to distinguish PKCS#1 from PKCS#8:
    //   PKCS#1: 0x02 (modulus INTEGER follows immediately)
    //   PKCS#8: 0x30 (AlgorithmIdentifier SEQUENCE follows, then OCTET STRING with inner PKCS#1)
    let next_tag = *der.get(pos)?;

    if next_tag == 0x02 {
        // PKCS#1: modulus INTEGER follows the version directly.
        pos += 1; // consume INTEGER tag
        return read_rsa_modulus_len(der, &mut pos);
    }

    if next_tag == 0x30 {
        // PKCS#8: skip the AlgorithmIdentifier SEQUENCE, then unwrap the OCTET STRING
        // that contains an embedded PKCS#1 RSAPrivateKey.
        pos += 1; // consume SEQUENCE tag
        let alg_len = parse_der_len(der, &mut pos)?;
        // Skip AlgorithmIdentifier content entirely -- we only need the modulus length,
        // not the OID, so there is no reason to touch it.
        pos = pos.checked_add(alg_len)?;

        // privateKey OCTET STRING
        if *der.get(pos)? != 0x04 {
            return None;
        }
        pos += 1;
        let _octet_len = parse_der_len(der, &mut pos)?;

        // Embedded PKCS#1 RSAPrivateKey SEQUENCE
        if *der.get(pos)? != 0x30 {
            return None;
        }
        pos += 1;
        let _inner_seq_len = parse_der_len(der, &mut pos)?;

        // Inner version: must also be 02 01 00
        if der.get(pos..pos + 3)? != [0x02, 0x01, 0x00] {
            return None;
        }
        pos += 3;

        // Inner modulus INTEGER
        if *der.get(pos)? != 0x02 {
            return None;
        }
        pos += 1;
        return read_rsa_modulus_len(der, &mut pos);
    }

    None
}

/// Read the modulus length from a DER INTEGER value at `*pos`.
///
/// `*pos` must be positioned immediately after the INTEGER tag (0x02).
/// Advances `*pos` to the first byte of the INTEGER value and returns the
/// modulus size in bytes, with any DER leading 0x00 byte excluded.
fn read_rsa_modulus_len(der: &[u8], pos: &mut usize) -> Option<usize> {
    let modulus_len = parse_der_len(der, pos)?;
    if modulus_len == 0 || *pos >= der.len() {
        // Zero-length modulus is invalid; bounds check guards the leading-zero read.
        return None;
    }
    // A DER positive INTEGER prepends 0x00 when the high bit of the first byte is set
    // (to distinguish from a negative number in two's-complement encoding).
    let leading_zero = usize::from(*der.get(*pos)? == 0x00);
    modulus_len.checked_sub(leading_zero)
}

/// If `der` is a PKCS#8 PrivateKeyInfo wrapping an RSA key, extract and return
/// the inner PKCS#1 RSAPrivateKey bytes.
///
/// Returns:
/// - `Ok(Some(pkcs1_bytes))` -- input was PKCS#8; inner PKCS#1 bytes returned
/// - `Ok(None)` -- input is already PKCS#1; no conversion needed
/// - `Err(())` -- input is malformed (not valid PKCS#1 or PKCS#8)
///
/// ops.rs calls `RsaPrivateKey::from_pkcs1_der` which accepts only PKCS#1.
/// A PKCS#8 key passes keystore load (the modulus-size check handles both)
/// but silently fails at the first sign/decrypt. Convert at load time so
/// der_bytes always holds PKCS#1 after validation.
fn pkcs8_rsa_unwrap(der: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    let mut pos = 0;

    // Outer SEQUENCE
    if der.get(pos) != Some(&0x30) {
        return Err(());
    }
    pos += 1;
    let _seq_len = parse_der_len(der, &mut pos).ok_or(())?;

    // version INTEGER: exactly 02 01 00
    if der.get(pos..pos + 3) != Some(&[0x02, 0x01, 0x00]) {
        return Err(());
    }
    pos += 3;

    let next_tag = *der.get(pos).ok_or(())?;

    if next_tag == 0x02 {
        // Already PKCS#1 (modulus INTEGER follows version directly)
        return Ok(None);
    }

    if next_tag == 0x30 {
        // PKCS#8: skip AlgorithmIdentifier SEQUENCE
        pos += 1;
        let alg_len = parse_der_len(der, &mut pos).ok_or(())?;
        pos = pos.checked_add(alg_len).ok_or(())?;

        // privateKey OCTET STRING containing embedded PKCS#1 RSAPrivateKey
        if der.get(pos) != Some(&0x04) {
            return Err(());
        }
        pos += 1;
        let octet_len = parse_der_len(der, &mut pos).ok_or(())?;
        let end = pos.checked_add(octet_len).ok_or(())?;
        if end > der.len() {
            return Err(());
        }

        return Ok(Some(der[pos..end].to_vec()));
    }

    Err(())
}

fn load_p11k(data: &[u8], pin: &[u8]) -> Result<Keystore, KeystoreError> {
    // Minimum length check: header (57) + empty ciphertext (0) + tag (16) = 73
    let min_len = HEADER_LEN + AES_GCM_TAG_LEN;
    if data.len() < min_len {
        return Err(KeystoreError::Truncated(data.len()));
    }

    // Magic already verified by caller; check version
    if data[OFF_VERSION] != VERSION {
        return Err(KeystoreError::UnsupportedFormat(format!(
            "unsupported .p11k version: 0x{:02x}",
            data[OFF_VERSION]
        )));
    }

    let kdf_salt = &data[OFF_KDF_SALT..OFF_KDF_ITERATIONS];
    let kdf_iterations = u32::from_be_bytes(
        data[OFF_KDF_ITERATIONS..OFF_AES_NONCE]
            .try_into()
            .map_err(|_| KeystoreError::BadMagic)?,
    );
    // Reject attackers who tamper with the iteration count to weaken the KDF.
    if kdf_iterations < MIN_KDF_ITERATIONS {
        return Err(KeystoreError::Crypto(format!(
            "kdf_iterations {kdf_iterations} is below minimum {MIN_KDF_ITERATIONS}"
        )));
    }
    let aes_gcm_nonce = &data[OFF_AES_NONCE..OFF_CIPHERTEXT_LEN];
    let ciphertext_len = u32::from_be_bytes(
        data[OFF_CIPHERTEXT_LEN..OFF_CIPHERTEXT]
            .try_into()
            .map_err(|_| KeystoreError::BadMagic)?,
    ) as usize;

    // Use checked_add to guard against a crafted ciphertext_len near usize::MAX
    // that would silently overflow on 32-bit platforms and pass the length check
    // with a small computed total while accepting arbitrarily large input.
    let expected_total = HEADER_LEN
        .checked_add(ciphertext_len)
        .and_then(|n| n.checked_add(AES_GCM_TAG_LEN))
        .ok_or(KeystoreError::BadMagic)?;
    if data.len() != expected_total {
        return Err(KeystoreError::BadMagic);
    }

    let ciphertext_end = OFF_CIPHERTEXT + ciphertext_len;
    let tag_bytes = &data[ciphertext_end..ciphertext_end + AES_GCM_TAG_LEN];

    // --- Derive AES-256 key ---
    let mut aes_key = [0u8; AES_KEY_LEN];
    wolfcrypt::pbkdf2_hmac_sha256(pin, kdf_salt, kdf_iterations, &mut aes_key)
        .map_err(|e| KeystoreError::Crypto(format!("PBKDF2 failed: {e:?}")))?;

    // --- Decrypt ---
    let key_ga = GenericArray::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key_ga);
    let nonce_ga = GenericArray::from_slice(aes_gcm_nonce);
    let tag_ga = GenericArray::from_slice(tag_bytes);

    // Zeroizing<Vec<u8>> ensures the decrypted plaintext is wiped on ALL exit
    // paths, including the CborDecode error path where the ? operator returns
    // early before the explicit plaintext.zeroize() call below.
    // Previously a plain Vec<u8> would drop without zeroing if ciborium returned
    // Err (e.g. loading a future-format keystore that passes GCM auth but has
    // different CBOR). (soft_PKCS11-ptnt)
    let mut plaintext = Zeroizing::new(data[OFF_CIPHERTEXT..ciphertext_end].to_vec());

    let decrypt_result =
        cipher.decrypt_in_place_detached(nonce_ga, b"", &mut *plaintext, tag_ga);

    // Zeroize key immediately regardless of outcome
    aes_key.zeroize();

    decrypt_result.map_err(|_| KeystoreError::BadPin)?;

    // --- CBOR decode ---
    //
    // Panic risk analysis (soft_PKCS11-pun): ciborium 0.2.x contains internal
    // `assert!()` calls in the low-level decoder that can panic on certain protocol
    // violations (e.g., inconsistent buffer state). A panic from ciborium would unwind
    // through the cdylib C ABI boundary, which aborts the process in Rust 2021.
    //
    // WHY catch_unwind is NOT needed here: `plaintext` is the decrypted content of
    // the .p11k AES-256-GCM ciphertext. AES-GCM with a 16-byte authentication tag
    // provides 128-bit forgery resistance. An attacker who can deliver malformed CBOR
    // to this line must have constructed a ciphertext that passes GCM authentication,
    // which requires knowing the AES key = knowing the PIN (threat model: out-of-scope).
    // A self-consistent, well-formed .p11k file written by Keystore::create() never
    // produces CBOR that triggers the ciborium assertions. (Researched: soft_PKCS11-pun)
    let mut entries: Vec<KeyEntry> =
        ciborium::from_reader(&plaintext[..]).map_err(|e| KeystoreError::CborDecode(e.to_string()))?;

    // Explicit zeroize before entries are constructed from the plaintext.
    // Zeroizing<Vec<u8>> would also zeroize on drop, but zeroing here
    // minimizes the window during which plaintext and entries coexist in RAM.
    plaintext.zeroize();

    // --- Validate key sizes and formats ---
    for entry in &mut entries {
        match entry.key_type {
            KeyType::Rsa => {
                // Convert PKCS#8 -> PKCS#1 before mlock and before crypto ops.
                match pkcs8_rsa_unwrap(&entry.der_bytes) {
                    Ok(Some(pkcs1_bytes)) => {
                        entry.der_bytes.zeroize();
                        entry.der_bytes = pkcs1_bytes;
                    }
                    Ok(None) => {}
                    Err(()) => {
                        return Err(KeystoreError::UnsupportedFormat(format!(
                            "RSA key '{}': could not parse PKCS#1 or PKCS#8 DER",
                            entry.label
                        )));
                    }
                }
                let mod_bytes = rsa_modulus_bytes(&entry.der_bytes).ok_or_else(|| {
                    KeystoreError::UnsupportedFormat(format!(
                        "RSA key '{}': could not parse PKCS#1 DER modulus",
                        entry.label
                    ))
                })?;
                if mod_bytes > MAX_RSA_MODULUS_BYTES {
                    return Err(KeystoreError::UnsupportedFormat(format!(
                        "RSA key '{}': modulus {} bits exceeds maximum supported {} bits",
                        entry.label,
                        mod_bytes * 8,
                        MAX_RSA_MODULUS_BYTES * 8,
                    )));
                }
            }
            KeyType::Ec => {
                if entry.der_bytes.len() != EC_P256_SCALAR_BYTES {
                    return Err(KeystoreError::UnsupportedFormat(format!(
                        "EC key '{}': expected {EC_P256_SCALAR_BYTES}-byte P-256 scalar, \
                         got {} bytes",
                        entry.label,
                        entry.der_bytes.len(),
                    )));
                }
            }
            // PQC types: validate private and public key sizes.
            // Both der_bytes (private) and pub_bytes (public) must be present and
            // exactly the FIPS 203/204 sizes -- ops.rs will pass them directly to
            // wolfcrypt without further length checking.
            KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87
            | KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => {
                let (expected_priv, expected_pub) = match entry.key_type {
                    KeyType::MlDsa44  => (ML_DSA_44_PRIV_BYTES,  ML_DSA_44_PUB_BYTES),
                    KeyType::MlDsa65  => (ML_DSA_65_PRIV_BYTES,  ML_DSA_65_PUB_BYTES),
                    KeyType::MlDsa87  => (ML_DSA_87_PRIV_BYTES,  ML_DSA_87_PUB_BYTES),
                    KeyType::MlKem512  => (ML_KEM_512_PRIV_BYTES,  ML_KEM_512_PUB_BYTES),
                    KeyType::MlKem768  => (ML_KEM_768_PRIV_BYTES,  ML_KEM_768_PUB_BYTES),
                    KeyType::MlKem1024 => (ML_KEM_1024_PRIV_BYTES, ML_KEM_1024_PUB_BYTES),
                    _ => unreachable!(),
                };
                if entry.der_bytes.len() != expected_priv {
                    return Err(KeystoreError::UnsupportedFormat(format!(
                        "{:?} key '{}': expected {expected_priv}-byte private key, got {} bytes",
                        entry.key_type, entry.label, entry.der_bytes.len(),
                    )));
                }
                let pub_len = entry.pub_bytes.as_ref().map(|v| v.len()).unwrap_or(0);
                if pub_len != expected_pub {
                    return Err(KeystoreError::UnsupportedFormat(format!(
                        "{:?} key '{}': expected {expected_pub}-byte public key, got {} bytes",
                        entry.key_type, entry.label, pub_len,
                    )));
                }
            }
        }
    }

    // --- mlock each entry's key bytes ---
    // A silent mlock failure is a security issue: key material can page to swap
    // where it persists after process exit. We treat mlock failure as fatal.
    //
    // CRITICAL ORDER: zeroize BEFORE munlock (same as Keystore::drop).
    //
    // We extract raw pointers and owned values before each cleanup loop so
    // that no reference into `entries[i]` lives across the mutable borrow
    // needed for `entries[..i].iter_mut()`.
    for i in 0..entries.len() {
        // Capture all info from entries[i] as non-reference types; borrows end here.
        let der_ptr: *const libc::c_void = entries[i].der_bytes.as_ptr() as *const _;
        let der_len: usize               = entries[i].der_bytes.len();
        let pub_info: Option<(*const libc::c_void, usize)> = entries[i]
            .pub_bytes.as_deref()
            .filter(|v| !v.is_empty())
            .map(|v| (v.as_ptr() as *const libc::c_void, v.len()));
        let label: String = entries[i].label.clone();
        // All borrows of entries[i] are released after the statements above.

        // mlock der_bytes
        if der_len > 0 {
            // SAFETY: der_bytes is heap-allocated and valid.
            let ret = unsafe { libc::mlock(der_ptr, der_len) };
            if ret != 0 {
                let errno = unsafe { *libc::__errno_location() };
                for prev in entries[..i].iter_mut() {
                    if !prev.der_bytes.is_empty() {
                        let len = prev.der_bytes.len();
                        prev.der_bytes.zeroize();
                        unsafe { libc::munlock(prev.der_bytes.as_ptr() as *const libc::c_void, len); }
                    }
                    if let Some(ref mut pb) = prev.pub_bytes {
                        if !pb.is_empty() {
                            let len = pb.len();
                            pb.zeroize();
                            unsafe { libc::munlock(pb.as_ptr() as *const libc::c_void, len); }
                        }
                    }
                }
                return Err(KeystoreError::Crypto(format!(
                    "mlock failed for key '{label}' (errno {errno}): key material may be swapped to disk"
                )));
            }
        }
        // mlock pub_bytes (PQC key types only)
        if let Some((pub_ptr, pub_len)) = pub_info {
            // SAFETY: pub_bytes is heap-allocated and valid.
            let ret = unsafe { libc::mlock(pub_ptr, pub_len) };
            if ret != 0 {
                let errno = unsafe { *libc::__errno_location() };
                // der_bytes for entry i was already mlock'd -- clean up entries[0..=i].
                // pub_bytes for entry i was NOT mlock'd; munlock on it is a no-op.
                for prev in entries[..=i].iter_mut() {
                    if !prev.der_bytes.is_empty() {
                        let len = prev.der_bytes.len();
                        prev.der_bytes.zeroize();
                        unsafe { libc::munlock(prev.der_bytes.as_ptr() as *const libc::c_void, len); }
                    }
                    if let Some(ref mut pb) = prev.pub_bytes {
                        if !pb.is_empty() {
                            let len = pb.len();
                            pb.zeroize();
                            unsafe { libc::munlock(pb.as_ptr() as *const libc::c_void, len); }
                        }
                    }
                }
                return Err(KeystoreError::Crypto(format!(
                    "mlock failed for pub key '{label}' (errno {errno}): key material may be swapped to disk"
                )));
            }
        }
    }

    Ok(Keystore { entries })
}

fn fill_random(buf: &mut [u8]) -> Result<(), KeystoreError> {
    let ret = unsafe {
        // SAFETY: buf is a valid mutable slice; getrandom fills it from kernel CSPRNG
        libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
    };
    if ret < 0 {
        // Negative return value means the syscall failed (e.g., ENOSYS, EINTR).
        return Err(KeystoreError::Crypto("getrandom failed".to_string()));
    }
    // ret >= 0 here; safe to cast ssize_t -> usize (positive values are identical).
    // getrandom(2) may return fewer bytes than requested in rare cases; treat a short
    // read as an error rather than silently returning a partially-filled buffer.
    if ret as usize != buf.len() {
        return Err(KeystoreError::Crypto("getrandom short read".to_string()));
    }
    Ok(())
}
