use super::*;

// ---------------------------------------------------------------------------
// JKS / JCEKS binary format reader
// ---------------------------------------------------------------------------

/// Magic bytes at the start of a JKS keystore file.
const JKS_MAGIC: u32 = 0xFEED_FEED;
/// Magic bytes at the start of a JCEKS keystore file.
const JCEKS_MAGIC: u32 = 0xCECE_CECE;

/// A single PrivateKeyEntry read from a JKS or JCEKS keystore.
///
/// The encrypted key blob is in JKS proprietary or JCEKS PKCS#8 format
/// depending on the keystore type; decryption is handled by a later stage.
pub struct JksPrivateKeyEntry {
    /// The alias string from the keystore (Java DataOutputStream UTF).
    pub alias: String,
    /// Java timestamp (milliseconds since Unix epoch; informational only).
    pub timestamp_ms: u64,
    /// Raw encrypted private key blob.  For JKS: proprietary SHA-1-chained XOR;
    /// for JCEKS: EncryptedPrivateKeyInfo in a PKCS#8-compatible format.
    pub encrypted_key: Vec<u8>,
    /// Leaf certificate DER bytes (the first cert in the chain), if present.
    pub cert_der: Option<Vec<u8>>,
}

/// All entries collected from a JKS or JCEKS keystore.
pub struct JksKeystoreEntries {
    pub private_key_entries: Vec<JksPrivateKeyEntry>,
}

/// A big-endian byte cursor for reading Java `DataOutputStream` encoded data.
struct JksCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> JksCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], KeyParseError> {
        if self.remaining() < n {
            return Err(super::malformed("JKS: unexpected end of file"));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, KeyParseError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, KeyParseError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, KeyParseError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Read a Java `DataOutputStream.writeUTF` string: u16 length in bytes,
    /// then Modified UTF-8 content.
    fn read_mutf8(&mut self) -> Result<String, KeyParseError> {
        let len = self.read_u16()? as usize;
        let raw = self.read_bytes(len)?;
        mutf8_to_string(raw)
    }

    /// Read a u32-length-prefixed blob.
    fn read_len32_bytes(&mut self) -> Result<Vec<u8>, KeyParseError> {
        let len = self.read_u32()? as usize;
        Ok(self.read_bytes(len)?.to_vec())
    }
}

/// Decode Java Modified UTF-8 to a Rust `String`.
///
/// The only MUTF-8 extension used in practice is the two-byte NUL encoding
/// `0xC0 0x80` -> U+0000.  All ASCII passphrases round-trip without conversion.
fn mutf8_to_string(raw: &[u8]) -> Result<String, KeyParseError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b == 0xC0 && i + 1 < raw.len() && raw[i + 1] == 0x80 {
            // MUTF-8 NUL encoding: 0xC0 0x80 -> U+0000
            out.push(0x00);
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| super::malformed("JKS: alias is not valid UTF-8"))
}

/// Return `true` if `data` begins with the JKS or JCEKS magic word.
pub fn is_jks_or_jceks(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    magic == JKS_MAGIC || magic == JCEKS_MAGIC
}

/// Parse the binary structure of a JKS or JCEKS keystore.
///
/// Reads all PrivateKeyEntry records and their first cert.
/// TrustedCertEntry and SecretKeyEntry records are silently skipped.
/// An empty result (all entries are certificates) is not an error.
///
/// Only the *structure* is parsed here; the encrypted private key blobs are
/// returned as-is for the caller to decrypt.  The SHA-1 integrity fingerprint
/// at the end of the file is not verified here (handled by a later stage).
pub fn parse_jks_structure(data: &[u8]) -> Result<JksKeystoreEntries, KeyParseError> {
    let mut cur = JksCursor::new(data);

    let magic = cur.read_u32()?;
    let is_jceks = match magic {
        JKS_MAGIC => false,
        JCEKS_MAGIC => true,
        _ => return Err(super::malformed("JKS: unrecognised magic (not a JKS or JCEKS file)")),
    };

    let version = cur.read_u32()?;
    match (is_jceks, version) {
        (false, 1) | (false, 2) => {}
        (true, 2) => {}
        _ => return Err(super::malformed(&format!("JKS: unsupported version {version}"))),
    }

    let entry_count = cur.read_u32()? as usize;
    // Cap to prevent a crafted file from causing an extremely long parse loop.
    // 10,000 is far more entries than any legitimate keystore would hold.
    // (soft_PKCS11-10qe)
    if entry_count > 10_000 {
        return Err(super::malformed("JKS: entry count exceeds maximum (10000)"));
    }
    let mut private_key_entries = Vec::new();

    for _ in 0..entry_count {
        let tag = cur.read_u32()?;
        let alias = cur.read_mutf8()?;
        let timestamp_ms = cur.read_u64()?;

        match tag {
            1 => {
                // PrivateKeyEntry: encrypted key blob + cert chain
                // RSA-4096 PKCS#8 wrapped in JKS ≈ 2 KB; cap at 64 KB.
                const MAX_JKS_KEY_BLOB: usize = 65_536;
                let encrypted_key = cur.read_len32_bytes()?;
                if encrypted_key.len() > MAX_JKS_KEY_BLOB {
                    return Err(super::malformed(&format!(
                        "JKS: encrypted key blob ({} bytes) exceeds maximum ({MAX_JKS_KEY_BLOB})",
                        encrypted_key.len()
                    )));
                }

                let cert_count = cur.read_u32()? as usize;
                // Cap certificate chain length; a legitimate chain is 1-5 entries.
                // (soft_PKCS11-10qe)
                if cert_count > 100 {
                    return Err(super::malformed("JKS: certificate chain length exceeds maximum (100)"));
                }
                let mut cert_der = None;
                // A DER-encoded certificate is typically 1-4 KB; cap at 64 KB.
                const MAX_JKS_CERT_DER: usize = 65_536;
                for cert_idx in 0..cert_count {
                    // cert type: u16-length UTF string (e.g. "X.509")
                    let _cert_type = cur.read_mutf8()?;
                    let cert_bytes = cur.read_len32_bytes()?;
                    if cert_bytes.len() > MAX_JKS_CERT_DER {
                        return Err(super::malformed(&format!(
                            "JKS: certificate DER ({} bytes) exceeds maximum ({MAX_JKS_CERT_DER})",
                            cert_bytes.len()
                        )));
                    }
                    if cert_idx == 0 {
                        cert_der = Some(cert_bytes);
                    }
                }

                private_key_entries.push(JksPrivateKeyEntry {
                    alias,
                    timestamp_ms,
                    encrypted_key,
                    cert_der,
                });
            }
            2 => {
                // TrustedCertEntry: cert type + DER; no private key -- skip
                let _cert_type = cur.read_mutf8()?;
                let _cert_bytes = cur.read_len32_bytes()?;
            }
            3 if is_jceks => {
                // SecretKeyEntry (JCEKS only): sealed object wrapping a symmetric key.
                // Symmetric keys cannot be imported as PKCS#11 private key entries.
                // Consume the blob to keep the parse cursor valid, then return
                // Unsupported so the caller knows the alias was not a private key.
                // (soft_PKCS11-10qe)
                let _sealed = cur.read_len32_bytes()?;
                return Err(KeyParseError::Unsupported(format!(
                    "JKS: alias \"{alias}\" is a JCEKS SecretKeyEntry (symmetric key); \
                     only PrivateKeyEntry (tag 1) entries can be imported"
                )));
            }
            _ => {
                return Err(super::malformed(&format!(
                    "JKS: unknown entry tag {tag} for alias \"{}\"",
                    alias
                )));
            }
        }
    }

    Ok(JksKeystoreEntries { private_key_entries })
}

/// Verify the SHA-1 integrity fingerprint at the end of a JKS or JCEKS file.
///
/// The hash covers:
/// ```text
/// SHA-1( passphrase_utf16be || b"Mighty Aphrodite" || keystore_bytes[0..len-20] )
/// ```
///
/// where `passphrase_utf16be` is the passphrase encoded as big-endian UTF-16
/// (2 bytes per character, no BOM, no NUL terminator).
///
/// Returns `Malformed` on mismatch (wrong passphrase or corrupted keystore).
pub fn verify_jks_integrity(data: &[u8], passphrase: &str) -> Result<(), KeyParseError> {
    if data.len() < 20 {
        return Err(super::malformed("JKS: file too short to contain integrity fingerprint"));
    }
    let (body, stored_hash) = data.split_at(data.len() - 20);

    use wolfcrypt::digest::digest_trait::Digest as _;
    let mut sha = wolfcrypt::Sha1::new();

    // UTF-16BE encoding of the passphrase (no BOM, no NUL terminator).
    for cu in passphrase.encode_utf16() {
        wolfcrypt::digest::digest_trait::Update::update(
            &mut sha,
            &[(cu >> 8) as u8, (cu & 0xff) as u8],
        );
    }
    wolfcrypt::digest::digest_trait::Update::update(&mut sha, b"Mighty Aphrodite");
    wolfcrypt::digest::digest_trait::Update::update(&mut sha, body);

    let computed = sha.finalize();
    if computed.as_slice() != stored_hash {
        return Err(super::malformed(
            "JKS: integrity check failed (wrong passphrase or corrupted keystore)",
        ));
    }
    Ok(())
}

/// Compute SHA-1(passphrase encoded as UTF-16BE || extra) and return the
/// 20-byte digest.  Used exclusively by the JKS proprietary cipher.
fn jks_sha1_block(passphrase: &str, extra: &[u8]) -> [u8; 20] {
    use wolfcrypt::digest::digest_trait::Digest as _;
    let mut sha = wolfcrypt::Sha1::new();
    for cu in passphrase.encode_utf16() {
        wolfcrypt::digest::digest_trait::Update::update(
            &mut sha,
            &[(cu >> 8) as u8, (cu & 0xff) as u8],
        );
    }
    wolfcrypt::digest::digest_trait::Update::update(&mut sha, extra);
    let output = sha.finalize();
    let mut block = [0u8; 20];
    block.copy_from_slice(output.as_slice());
    block
}

// JKS proprietary cipher OID: 1.3.6.1.4.1.42.2.17.1.1
const OID_SUN_JKS_CIPHER: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x11, 0x01, 0x01];

/// Decrypt a JKS or JCEKS `EncryptedPrivateKeyInfo` DER blob and parse the
/// resulting PKCS#8.
///
/// Dispatches on the AlgorithmIdentifier OID:
/// - `1.3.6.1.4.1.42.2.17.1.1` (JKS): SHA-1-chained XOR stream cipher
/// - `1.3.6.1.4.1.42.2.19.1` (JCEKS `PBEWithMD5AndTripleDES`): Sun MD5/3DES KDF
pub(crate) fn decrypt_jks_private_key_entry(
    encrypted: &[u8],
    passphrase: &str,
    id: [u8; 16],
) -> Result<ParsedKey, KeyParseError> {
    // Parse EncryptedPrivateKeyInfo DER.
    let (_, outer_content, _) = super::tlv(encrypted, 0x30)
        .ok_or_else(|| super::malformed("JKS/JCEKS PrivateKeyEntry: outer SEQUENCE missing"))?;
    // AlgorithmIdentifier SEQUENCE -> extract OID and remaining params.
    let (_, alg_id_body, rest) = super::tlv(outer_content, 0x30)
        .ok_or_else(|| super::malformed("JKS/JCEKS PrivateKeyEntry: AlgorithmIdentifier missing"))?;
    let (_, oid, alg_params) = super::tlv(alg_id_body, 0x06)
        .ok_or_else(|| super::malformed("JKS/JCEKS PrivateKeyEntry: algorithm OID missing"))?;
    // Encrypted data OCTET STRING.
    let (_, enc_data, _) = super::tlv(rest, 0x04)
        .ok_or_else(|| super::malformed("JKS/JCEKS PrivateKeyEntry: encrypted OCTET STRING missing"))?;

    if oid == OID_SUN_JKS_CIPHER {
        // JKS proprietary XOR stream cipher.
        // enc_data layout: salt (20) || ciphertext || check (20).
        if enc_data.len() < 40 {
            return Err(super::malformed("JKS PrivateKeyEntry: cipher data too short"));
        }
        let salt = &enc_data[..20];
        let mid = enc_data.len() - 20;
        let ciphertext = &enc_data[20..mid];
        let check = &enc_data[mid..];

        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut block = jks_sha1_block(passphrase, salt);
        let mut offset = 0;
        while offset < ciphertext.len() {
            let take = (ciphertext.len() - offset).min(20);
            for i in 0..take {
                plaintext[offset + i] = ciphertext[offset + i] ^ block[i];
            }
            offset += take;
            if offset < ciphertext.len() {
                block = jks_sha1_block(passphrase, &block);
            }
        }
        let computed = jks_sha1_block(passphrase, &plaintext);
        if check != computed.as_ref() {
            return Err(super::malformed(
                "JKS PrivateKeyEntry: wrong passphrase or corrupted key",
            ));
        }
        super::parse_pkcs8(&plaintext, id)
    } else if oid == OID_JCEKS_PBE_MD5_3DES {
        // JCEKS PBEWithMD5AndTripleDES: Sun MD5 KDF + 3DES-CBC.
        let plaintext = super::jce_pbe_md5_3des_decrypt(alg_params, passphrase, enc_data)?;
        super::parse_pkcs8(&plaintext, id)
    } else {
        Err(KeyParseError::Unsupported(format!(
            "JKS/JCEKS PrivateKeyEntry: unsupported algorithm OID {oid:02x?}"
        )))
    }
}
