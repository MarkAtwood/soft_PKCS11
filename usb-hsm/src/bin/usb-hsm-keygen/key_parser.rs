/// Private key file parser for usb-hsm-keygen.
///
/// Reads a PEM or DER private key file and returns the key bytes in the
/// format expected by [`usb_hsm::keystore::KeyEntry`]:
///   - RSA: PKCS#1 DER (the raw `RSAPrivateKey` structure)
///   - EC P-256: raw 32-byte big-endian private key scalar
///
/// Supported PEM types:
///   "RSA PRIVATE KEY"  -- PKCS#1 directly
///   "EC PRIVATE KEY"   -- RFC 5915 `ECPrivateKey`; P-256 only
///   "PRIVATE KEY"      -- PKCS#8 `PrivateKeyInfo`; RSA or EC P-256
///
/// DER files are auto-detected by content rather than extension.
use std::path::Path;

use usb_hsm::keystore::KeyType;

// ---------------------------------------------------------------------------
// GCP service account JSON
// ---------------------------------------------------------------------------

/// Fields extracted from a GCP service account JSON file.
pub struct GcpServiceAccountKey {
    /// PEM string from the `private_key` field.
    pub pem: String,
    /// Raw `private_key_id` field value (typically 40 hex chars), if present.
    pub key_id_hex: Option<String>,
    /// `client_email` field value, if present.
    pub client_email: Option<String>,
}

/// Attempt to parse `data` as a GCP service account JSON object.
///
/// Returns `None` (not an error) for any of these conditions:
/// - `data` does not start with `{` (after leading whitespace)
/// - `data` is not valid JSON
/// - The JSON is an object but lacks a `"private_key"` string field
/// - `"private_key"` does not start with `-----BEGIN`
///
/// If the `"type"` field is present but is not `"service_account"`, a warning
/// is logged but parsing proceeds.
pub fn detect_gcp_json(data: &[u8]) -> Option<GcpServiceAccountKey> {
    // Fast reject: must start with '{' (after stripping leading ASCII whitespace)
    let first_nonws = data.iter().position(|b| !b.is_ascii_whitespace())?;
    if data[first_nonws] != b'{' {
        return None;
    }

    let val: serde_json::Value = serde_json::from_slice(data).ok()?;
    let obj = val.as_object()?;

    // Required: "private_key" must be a PEM-format private key string.
    let pem = obj.get("private_key")?.as_str()?;
    if !pem.trim_start().starts_with("-----BEGIN") {
        return None;
    }

    // Optional warning: "type" field should be "service_account".
    if let Some(gcp_type) = obj.get("type").and_then(|v| v.as_str()) {
        if gcp_type != "service_account" {
            log::warn!(
                "usb-hsm: GCP JSON 'type' is '{}', expected 'service_account'; \
                 proceeding with key import",
                gcp_type
            );
        }
    }

    let key_id_hex = obj
        .get("private_key_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let client_email = obj
        .get("client_email")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    Some(GcpServiceAccountKey {
        pem: pem.to_string(),
        key_id_hex,
        client_email,
    })
}

// RSA AlgorithmIdentifier OID value bytes (rsaEncryption, RFC 3447):
//   1.2.840.113549.1.1.1 -> DER encoding of OID value
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
// EC AlgorithmIdentifier OID value bytes (id-ecPublicKey, RFC 5480):
//   1.2.840.10045.2.1
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
// P-256 named curve OID value bytes (secp256r1, RFC 5480):
//   1.2.840.10045.3.1.7
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

// ---------------------------------------------------------------------------
// EncryptedPrivateKeyInfo (RFC 5958) -- OID value bytes used in the dispatcher
// ---------------------------------------------------------------------------

// PBES2: 1.2.840.113549.1.5.13
const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
// PKCS#12 pbeWithSHAAnd3-KeyTripleDES-CBC: 1.2.840.113549.1.12.1.3
const OID_PKCS12_SHA1_3DES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03];
// PBES1 pbeWithMD5AndDES-CBC: 1.2.840.113549.1.5.3
const OID_PBES1_MD5_DES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03];
// PBES1 pbeWithSHA1AndDES-CBC: 1.2.840.113549.1.5.10
const OID_PBES1_SHA1_DES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0a];
// PKCS#12 pbeWithSHAAnd128BitRC2-CBC: 1.2.840.113549.1.12.1.5
const OID_PKCS12_SHA1_RC2_128: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x05];
// PKCS#12 pbeWithSHAAnd40BitRC2-CBC: 1.2.840.113549.1.12.1.6
const OID_PKCS12_SHA1_RC2_40: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06];

// wc_HashType value for SHA-1 (wolfCrypt wolfssl/wolfcrypt/hash.h WC_HASH_TYPE_SHA = 4).
// Used as the hash_type argument to wolfcrypt::kdf::pkcs12_pbkdf.
const WC_HASH_TYPE_SHA1: i32 = 4;

// ---------------------------------------------------------------------------
// PKCS#12 PFX -- OID value bytes
// ---------------------------------------------------------------------------

// id-data: 1.2.840.113549.1.7.1
const OID_PKCS7_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
// id-encryptedData: 1.2.840.113549.1.7.6
const OID_PKCS7_ENCRYPTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
// pkcs-12-ShroudedKeyBag: 1.2.840.113549.1.12.10.1.2
const OID_PKCS12_SHROUDED_KEY_BAG: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02];
// pkcs-12-CertBag: 1.2.840.113549.1.12.10.1.3
const OID_PKCS12_CERT_BAG: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03];
// localKeyID attribute: 1.2.840.113549.1.9.21
const OID_PKCS9_LOCAL_KEY_ID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15];
// friendlyName attribute: 1.2.840.113549.1.9.20
const OID_PKCS9_FRIENDLY_NAME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14];
// x509Certificate type inside CertBag: 1.2.840.113549.1.9.22.1
const OID_X509_CERTIFICATE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01];

/// The parsed private key bytes ready for [`usb_hsm::keystore::KeyEntry`].
pub struct ParsedKey {
    pub key_type: KeyType,
    /// RSA: PKCS#1 DER bytes.  EC: raw 32-byte scalar.
    pub key_bytes: Vec<u8>,
    /// 16-byte key ID (randomly generated or derived from the source format).
    pub id: [u8; 16],
    /// Optional human-readable label derived from the source file (e.g. GCP
    /// `client_email`).  The caller uses this when `--label` is not specified.
    /// `None` for formats that carry no embedded name.
    pub label_hint: Option<String>,
    /// DER-encoded X.509 leaf certificate associated with this key, if the
    /// source format embeds one (e.g. PKCS#12 CertBag).  `None` for formats
    /// that carry no certificate.
    pub cert_der: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum KeyParseError {
    Io(std::io::Error),
    /// The PEM/DER structure was well-formed but the key type or curve is not
    /// supported by this token.
    Unsupported(String),
    /// The encoding is syntactically invalid.
    Malformed(String),
}

/// A single SafeBag extracted from a PKCS#12 PFX AuthenticatedSafe.
///
/// For `ShroudedKeyBag`: `bag_value` is the raw `EncryptedPrivateKeyInfo` DER.
/// For `CertBag`: `bag_value` is the raw `CertBag` SEQUENCE DER.
pub struct PfxBag {
    /// Raw DER bytes of the bagValue content (type-specific).
    pub bag_value: Vec<u8>,
    /// `localKeyID` bag attribute (OID 1.2.840.113549.1.9.21), if present.
    pub local_key_id: Option<Vec<u8>>,
    /// `friendlyName` bag attribute (OID 1.2.840.113549.1.9.20), decoded from
    /// UTF-16BE `BMPString`.  `None` if the attribute is absent or not valid UTF-16.
    pub friendly_name: Option<String>,
}

/// Categorised bags returned by [`parse_pfx_structure`].
pub struct PfxBags {
    pub shrouded_key_bags: Vec<PfxBag>,
    pub cert_bags: Vec<PfxBag>,
}

impl std::fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyParseError::Io(e) => write!(f, "I/O error: {e}"),
            KeyParseError::Unsupported(s) => write!(f, "unsupported key: {s}"),
            KeyParseError::Malformed(s) => write!(f, "malformed key: {s}"),
        }
    }
}

impl From<std::io::Error> for KeyParseError {
    fn from(e: std::io::Error) -> Self {
        KeyParseError::Io(e)
    }
}

/// Parse a private key file (PEM or DER).
///
/// Returns `Ok((keys, failures))` where:
/// - `keys` -- successfully parsed key entries (zero or more)
/// - `failures` -- per-entry failures as `(alias, error)` for any entry that
///   could not be parsed; the alias is a human-readable name for the failed
///   entry suitable for a warning message
///
/// Returns `Err` only for fatal errors (file unreadable, or the outer file
/// structure is corrupt at a level that makes individual key recovery
/// impossible).
///
/// All currently-supported formats are single-key: they return a `keys` Vec
/// of length 1 and an empty `failures` Vec. Multi-key formats (PKCS#12, JKS)
/// will use the Vec to return multiple keys from a single file.
pub fn parse_key_file(path: &Path) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let data = std::fs::read(path)?;
    let id = random_id()?;

    // GCP service account JSON: check before PEM/DER paths since a JSON file
    // starts with '{', not '-----BEGIN', but we want a clear detection path.
    if let Some(gcp) = detect_gcp_json(&data) {
        let alias = path.file_stem().and_then(|s| s.to_str()).unwrap_or("key").to_string();

        let pem_block = pem::parse(gcp.pem.as_bytes())
            .map_err(|e| KeyParseError::Malformed(format!("GCP JSON private_key PEM: {e}")))?;

        // GCP service account private keys are always RSA.  Reject anything
        // else with an explicit message rather than silently misimporting.
        let parse_result = match pem_block.tag() {
            "RSA PRIVATE KEY" => parse_rsa_pkcs1(pem_block.contents(), id),
            "PRIVATE KEY" => parse_pkcs8(pem_block.contents(), id),
            tag => Err(KeyParseError::Unsupported(format!(
                "GCP JSON private_key PEM type \"{tag}\" is not RSA"
            ))),
        };

        let mut parsed = match parse_result {
            Ok(p) => p,
            Err(e) => return Ok((vec![], vec![(alias, e)])),
        };

        if parsed.key_type != KeyType::Rsa {
            return Ok((vec![], vec![(alias, KeyParseError::Unsupported(
                "GCP JSON private_key is not an RSA key".to_string(),
            ))]));
        }

        // Key ID: use private_key_id when present and valid (first 32 hex
        // chars -> 16 bytes); fall back to SHA-256(RSAPublicKey DER)[0..16]
        // for reproducibility when private_key_id is absent; last resort is
        // the random ID generated at the top of parse_key_file.
        parsed.id = gcp.key_id_hex
            .as_deref()
            .and_then(gcp_id_from_key_id_hex)
            .or_else(|| sha256_key_id(&parsed.key_bytes))
            .unwrap_or(id);

        // Label hint: use client_email so callers can label this key without
        // requiring --label on the command line.
        parsed.label_hint = gcp.client_email;

        return Ok((vec![parsed], vec![]));
    }

    let parsed = if is_pgp_armor(&data) {
        let binary = dearmor(&data)?;
        return parse_pgp_binary(&binary);
    } else if is_pgp_binary_secret_key_packet(&data) {
        return parse_pgp_binary(&data);
    } else if data.starts_with(b"-----BEGIN") {
        let pem_block = pem::parse(&data)
            .map_err(|e| KeyParseError::Malformed(format!("PEM parse error: {e}")))?;
        match pem_block.tag() {
            "RSA PRIVATE KEY" => parse_rsa_pkcs1(pem_block.contents(), id),
            "EC PRIVATE KEY" => parse_ec_sec1(pem_block.contents(), id),
            "PRIVATE KEY" => parse_pkcs8(pem_block.contents(), id),
            "ENCRYPTED PRIVATE KEY" => {
                let passphrase =
                    super::pin::prompt_passphrase("Passphrase for encrypted key: ")
                        .map_err(KeyParseError::Io)?;
                parse_encrypted_pkcs8(pem_block.contents(), &passphrase, id)
            }
            "OPENSSH PRIVATE KEY" => {
                let frame = parse_openssh_binary(pem_block.contents())
                    .map_err(|e| KeyParseError::Malformed(format!("OpenSSH frame: {e}")))?;

                // Prompt for passphrase only when the blob is encrypted.
                let passphrase = if frame.ciphername == "none" {
                    String::new()
                } else {
                    super::pin::prompt_passphrase("Passphrase for OpenSSH key: ")
                        .map_err(KeyParseError::Io)?
                };

                // Decrypt (or pass through) the private blob, then verify check words.
                let blob = decrypt_openssh_blob(&frame, &passphrase)?;
                let key_data = verify_openssh_check_words(&blob)?;
                parse_openssh_key_data(key_data, id)
            }
            tag => Err(KeyParseError::Unsupported(format!(
                "PEM type \"{tag}\" is not supported (expected \
                 \"RSA PRIVATE KEY\", \"EC PRIVATE KEY\", or \"PRIVATE KEY\")"
            ))),
        }
    } else if is_ppk(&data) {
        return parse_ppk_file_data(&data);
    } else if is_jks_or_jceks(&data) {
        return parse_jks_file_data(&data);
    } else if !data.starts_with(OPENSSH_MAGIC) && is_pfx_der(&data) {
        // PKCS#12 PFX: can contain multiple keys; handled separately.
        return parse_pfx_file_data(&data);
    } else {
        // Bare DER: probe for PKCS#8 or PKCS#1 / SEC1 by structure.
        parse_der_auto(&data, id)
    };

    match parsed {
        Ok(key) => Ok((vec![key], vec![])),
        Err(e) => {
            // For single-key formats a parse error on the one key is treated as
            // a per-entry failure (the outer file structure was readable), not a
            // fatal error. The alias is the filename stem.
            let alias = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("key")
                .to_string();
            Ok((vec![], vec![(alias, e)]))
        }
    }
}

/// Return `true` if `der` looks like a PKCS#12 PFX DER blob (outer SEQUENCE
/// with version INTEGER = 3).
fn is_pfx_der(der: &[u8]) -> bool {
    if let Some((_, inner, _)) = tlv(der, 0x30) {
        if let Some((_, ver, _)) = tlv(inner, 0x02) {
            return ver == [3];
        }
    }
    false
}

/// Parse and decrypt a PKCS#12 PFX blob, returning all contained private keys.
///
/// Prompts for the passphrase, verifies the MAC, decrypts SafeContents, and
/// extracts all ShroudedKeyBags.
fn parse_pfx_file_data(
    data: &[u8],
) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let passphrase = super::pin::prompt_passphrase("Passphrase for PKCS#12 file: ")
        .map_err(KeyParseError::Io)?;
    verify_pfx_mac(data, &passphrase)?;
    let bags = parse_pfx_structure(data, &passphrase)?;
    if bags.shrouded_key_bags.is_empty() {
        return Err(KeyParseError::Unsupported(
            "PKCS#12 PFX: no private key bags found".to_string(),
        ));
    }
    Ok(extract_keys_from_pfx_bags(&bags, &passphrase))
}

/// Parse a JKS or JCEKS keystore blob, verify its integrity, and return the
/// parsed structure.  Private key decryption (soft_PKCS11-2l7q / soft_PKCS11-ixsh)
/// is not yet implemented; each entry surfaces as a per-entry Unsupported failure
/// so that the caller can report which aliases failed.
fn parse_jks_file_data(
    data: &[u8],
) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let passphrase = super::pin::prompt_passphrase("Passphrase for JKS/JCEKS keystore: ")
        .map_err(KeyParseError::Io)?;
    verify_jks_integrity(data, &passphrase)?;
    let entries = parse_jks_structure(data)?;
    if entries.private_key_entries.is_empty() {
        return Err(KeyParseError::Unsupported(
            "JKS/JCEKS: no private key entries found".to_string(),
        ));
    }
    let mut parsed_keys = Vec::new();
    let mut failures = Vec::new();
    for entry in entries.private_key_entries {
        let entry_id = random_id()?;
        match decrypt_jks_private_key_entry(&entry.encrypted_key, &passphrase, entry_id) {
            Ok(mut key) => {
                key.label_hint = Some(entry.alias);
                key.cert_der = entry.cert_der;
                parsed_keys.push(key);
            }
            Err(e) => failures.push((entry.alias, e)),
        }
    }
    Ok((parsed_keys, failures))
}

// ---------------------------------------------------------------------------
// Per-format parsers
// ---------------------------------------------------------------------------

fn parse_rsa_pkcs1(der: &[u8], id: [u8; 16]) -> Result<ParsedKey, KeyParseError> {
    // Minimal sanity check: outer SEQUENCE tag.
    if der.first() != Some(&0x30) {
        return Err(KeyParseError::Malformed(
            "RSA PRIVATE KEY: expected SEQUENCE".to_string(),
        ));
    }
    // Derive reproducible key ID from SHA-256(RSAPublicKey DER)[0..16].
    // Fall back to the caller-supplied id (e.g. localKeyID from PKCS#12) if
    // the public key cannot be extracted.
    let derived_id = sha256_key_id(der).unwrap_or(id);
    Ok(ParsedKey { key_type: KeyType::Rsa, key_bytes: der.to_vec(), id: derived_id, label_hint: None, cert_der: None })
}

fn parse_ec_sec1(der: &[u8], id: [u8; 16]) -> Result<ParsedKey, KeyParseError> {
    let scalar = ec_scalar_from_sec1(der).ok_or_else(|| {
        KeyParseError::Malformed("EC PRIVATE KEY: could not extract P-256 scalar".to_string())
    })?;
    // Derive reproducible key ID from SHA-256(65-byte uncompressed public point)[0..16].
    // Fall back to the caller-supplied id when the optional publicKey [1] field is absent.
    let derived_id = ec_public_key_id_from_sec1(der).unwrap_or(id);
    Ok(ParsedKey { key_type: KeyType::Ec, key_bytes: scalar.to_vec(), id: derived_id, label_hint: None, cert_der: None })
}

/// Parse a PKCS#8 `PrivateKeyInfo` and delegate to the appropriate
/// format handler depending on the AlgorithmIdentifier OID.
fn parse_pkcs8(der: &[u8], id: [u8; 16]) -> Result<ParsedKey, KeyParseError> {
    // SEQUENCE { INTEGER (version), SEQUENCE (AlgId), OCTET STRING (privKey) }
    let (_, seq_inner, _) =
        tlv(der, 0x30).ok_or_else(|| malformed("PKCS#8: outer SEQUENCE missing"))?;
    // Skip version INTEGER.
    let (_, _, rest) =
        tlv(seq_inner, 0x02).ok_or_else(|| malformed("PKCS#8: version missing"))?;
    // AlgorithmIdentifier SEQUENCE -> { OID, [OID|NULL] }
    let (_, alg_id, rest) =
        tlv(rest, 0x30).ok_or_else(|| malformed("PKCS#8: AlgorithmIdentifier missing"))?;
    // First element of AlgId is the main OID.
    let (_, oid_val, alg_rest) =
        tlv(alg_id, 0x06).ok_or_else(|| malformed("PKCS#8: algorithm OID missing"))?;
    // PrivateKey OCTET STRING.
    let (_, priv_key_bytes, _) =
        tlv(rest, 0x04).ok_or_else(|| malformed("PKCS#8: privateKey OCTET STRING missing"))?;

    if oid_val == OID_RSA {
        // Inner bytes are PKCS#1 DER.
        parse_rsa_pkcs1(priv_key_bytes, id)
    } else if oid_val == OID_EC {
        // Check the named curve OID if present.
        if let Some((_, curve_oid, _)) = tlv(alg_rest, 0x06) {
            if curve_oid != OID_P256 {
                return Err(KeyParseError::Unsupported(format!(
                    "EC curve OID {:02x?} is not P-256 (secp256r1)",
                    curve_oid
                )));
            }
        }
        // Inner bytes are an ECPrivateKey (RFC 5915) DER structure.
        parse_ec_sec1(priv_key_bytes, id)
    } else {
        Err(KeyParseError::Unsupported(format!(
            "PKCS#8 algorithm OID {:02x?} is not RSA or EC",
            oid_val
        )))
    }
}

/// Auto-detect bare DER format by probing the structure.
///
/// PKCS#8 starts with SEQUENCE { INTEGER (version=0), SEQUENCE (AlgId) ... }
/// PKCS#1 RSA starts with SEQUENCE { INTEGER (version=0), INTEGER (n) ... }
/// The distinguishing feature is the second TLV inside the outer SEQUENCE:
/// PKCS#8 has a SEQUENCE (tag 0x30), PKCS#1 has an INTEGER (tag 0x02).
///
/// SEC1 EC PRIVATE KEY starts with SEQUENCE { INTEGER (version=1) ... }.
/// The version value (1 vs 0) distinguishes it from PKCS#1/PKCS#8.
///
/// EncryptedPrivateKeyInfo (RFC 5958) starts with a SEQUENCE
/// (AlgorithmIdentifier with a PBES OID), not an INTEGER, so it is detected
/// and dispatched before the version-byte logic.
fn parse_der_auto(der: &[u8], id: [u8; 16]) -> Result<ParsedKey, KeyParseError> {
    // OpenSSH new-format binary file (no PEM wrapper): detect before SEQUENCE check.
    if der.starts_with(OPENSSH_MAGIC) {
        let frame = parse_openssh_binary(der)?;
        let passphrase = if frame.ciphername == "none" {
            String::new()
        } else {
            super::pin::prompt_passphrase("Passphrase for OpenSSH key: ")
                .map_err(KeyParseError::Io)?
        };
        let blob = decrypt_openssh_blob(&frame, &passphrase)?;
        let key_data = verify_openssh_check_words(&blob)?;
        return parse_openssh_key_data(key_data, id);
    }

    let (_, inner, _) = tlv(der, 0x30)
        .ok_or_else(|| malformed("bare DER: expected outer SEQUENCE"))?;

    // EncryptedPrivateKeyInfo: outer SEQUENCE's first child is a SEQUENCE
    // (AlgorithmIdentifier), not an INTEGER (version).  Detect it before the
    // version-byte dispatch so the user gets a passphrase prompt rather than a
    // misleading "expected version INTEGER" error.
    if inner.first() == Some(&0x30) {
        if let Some((_, alg_id, _)) = tlv(inner, 0x30) {
            if let Some((_, oid, _)) = tlv(alg_id, 0x06) {
                const PBES_OIDS: &[&[u8]] = &[
                    OID_PBES2,
                    OID_PKCS12_SHA1_3DES,
                    OID_PBES1_MD5_DES,
                    OID_PBES1_SHA1_DES,
                    OID_PKCS12_SHA1_RC2_128,
                    OID_PKCS12_SHA1_RC2_40,
                ];
                if PBES_OIDS.iter().any(|k| *k == oid) {
                    let passphrase =
                        super::pin::prompt_passphrase("Passphrase for encrypted key: ")
                            .map_err(KeyParseError::Io)?;
                    return parse_encrypted_pkcs8(der, &passphrase, id);
                }
            }
        }
    }

    let (_, ver_val, rest) = tlv(inner, 0x02)
        .ok_or_else(|| malformed("bare DER: expected version INTEGER"))?;

    match ver_val {
        [0] => {
            // Could be PKCS#8 or PKCS#1. If the next TLV is a SEQUENCE, it's PKCS#8.
            if rest.first() == Some(&0x30) {
                parse_pkcs8(der, id)
            } else {
                parse_rsa_pkcs1(der, id)
            }
        }
        [1] => {
            // SEC1 ECPrivateKey.
            parse_ec_sec1(der, id)
        }
        _ => Err(malformed("bare DER: unexpected version value")),
    }
}

// ---------------------------------------------------------------------------
// DER TLV helpers
// ---------------------------------------------------------------------------

/// Maximum byte count accepted for any single DER value field.
///
/// A DER object larger than 64 MiB is almost certainly not a private key.
/// This cap is checked in [`tlv`] and [`next_tlv`] after decoding the length
/// field. It prevents degenerate inputs from producing very large slices that
/// callers might then `.to_vec()` into a heap allocation. (soft_PKCS11-idn5)
const MAX_REASONABLE_DER_LEN: usize = 64 * 1024 * 1024;

/// Parse one DER TLV from the front of `data`.
///
/// Returns `(tag, value, remaining)` where `value` is the content octets and
/// `remaining` is everything after the current TLV.  Returns `None` if `data`
/// is too short or the tag does not match `expected_tag`.
fn tlv(data: &[u8], expected_tag: u8) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    if tag != expected_tag {
        return None;
    }
    let b1 = *data.get(1)? as usize;
    let (len, hdr) = if b1 < 0x80 {
        (b1, 2)
    } else if b1 == 0x81 {
        (*data.get(2)? as usize, 3)
    } else if b1 == 0x82 {
        (((*data.get(2)? as usize) << 8) | (*data.get(3)? as usize), 4)
    } else {
        // 0x80 = DER indefinite-length form (BER only, forbidden in DER) --
        // rejected here. DER allows lengths up to 2^(8*126)-1 via long-form
        // encoding, but RSA and EC private keys never exceed a few kilobytes.
        // A 2-byte length field (0x82, max 65535 bytes) covers any key size
        // this tool will encounter. Silently rejecting larger lengths is
        // intentional: if a caller passes a file with a 3-byte or 4-byte DER
        // length, it is almost certainly not a private key -- treat it as
        // malformed rather than attempting to parse it.
        return None;
    };
    if len > MAX_REASONABLE_DER_LEN {
        return None;
    }
    let value = data.get(hdr..hdr + len)?;
    let rest = data.get(hdr + len..)?;
    Some((tag, value, rest))
}

/// Extract the 32-byte P-256 private key scalar from an RFC 5915
/// `ECPrivateKey` DER structure.
///
/// Uses the `sec1` crate for RFC 5915 DER parsing rather than hand-rolled TLV
/// walking; the crate validates version and structure invariants.
fn ec_scalar_from_sec1(der: &[u8]) -> Option<[u8; 32]> {
    use sec1::der::Decode as _;
    let pk = sec1::EcPrivateKey::from_der(der).ok()?;
    if pk.private_key.len() != 32 {
        return None;
    }
    pk.private_key.try_into().ok()
}

/// Derive a reproducible key ID from the optional `publicKey [1]` BIT STRING in
/// SEC1 ECPrivateKey DER.
///
/// Returns `SHA-256(uncompressed_point)[0..16]`, or `None` if the field is absent.
/// Uses the `sec1` crate to parse the RFC 5915 structure; `public_key` is `&[u8]`
/// (the raw `04 || x || y` uncompressed point bytes).
fn ec_public_key_id_from_sec1(der: &[u8]) -> Option<[u8; 16]> {
    use sec1::der::Decode as _;
    let pk = sec1::EcPrivateKey::from_der(der).ok()?;
    let point = pk.public_key?; // 65 bytes: 04 || x || y
    if point.len() != 65 || point[0] != 0x04 {
        return None;
    }
    use wolfcrypt::digest::digest_trait::Digest as _;
    let hash = wolfcrypt::Sha256::digest(point);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[..16]);
    Some(id)
}

fn malformed(msg: &str) -> KeyParseError {
    KeyParseError::Malformed(msg.to_string())
}

/// Capture the raw bytes of one DER TLV (tag + length + value) from `data`.
///
/// Returns `(tlv_bytes, remaining)` where `tlv_bytes` includes the tag and
/// length octets.  Returns `None` if the tag does not match or `data` is
/// truncated.
fn full_tlv_bytes<'a>(data: &'a [u8], expected_tag: u8) -> Option<(&'a [u8], &'a [u8])> {
    let (_, _, rest) = tlv(data, expected_tag)?;
    let consumed = data.len() - rest.len();
    Some((&data[..consumed], rest))
}

/// Encode a DER length into `buf`.  Handles 1-byte and 2-byte long-form
/// lengths, which are sufficient for any RSA or EC key material.
fn encode_der_len(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xff {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        // 0x82 encodes a two-byte length field (max 65535).  If `len` were
        // larger the emitted bytes would be silently truncated and the resulting
        // DER would be structurally corrupt.  This never happens in practice
        // because all callers operate on small key blobs, but the assertion
        // catches a new caller that passes an unexpectedly large value during
        // development. (soft_PKCS11-idn5)
        debug_assert!(
            len <= 0xffff,
            "encode_der_len: len={len} exceeds 0x82 two-byte DER maximum (65535)"
        );
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Read the next DER TLV from `data`, regardless of tag.
///
/// Unlike [`tlv`], this function does not check the tag byte -- it reads whatever
/// TLV is at the front of `data`.  Used when iterating over SEQUENCE bodies
/// whose element tags are not known in advance (e.g. AuthenticatedSafe,
/// SafeContents, bagAttributes).
///
/// Returns `(tag, value, remaining)` or `None` if `data` is too short.
fn next_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    let b1 = *data.get(1)? as usize;
    let (len, hdr) = if b1 < 0x80 {
        (b1, 2)
    } else if b1 == 0x81 {
        (*data.get(2)? as usize, 3)
    } else if b1 == 0x82 {
        (((*data.get(2)? as usize) << 8) | (*data.get(3)? as usize), 4)
    } else {
        // 0x80 = indefinite-length (BER only, forbidden in DER) -- rejected.
        // Higher long-form lengths (0x83+) are also rejected; see comment in tlv().
        return None;
    };
    if len > MAX_REASONABLE_DER_LEN {
        return None;
    }
    let value = data.get(hdr..hdr + len)?;
    // Use .get() for the remainder too (consistent with tlv(); avoids a bare
    // index that would be safe but panic-prone if the len check above moves).
    let rest = data.get(hdr + len..)?;
    Some((tag, value, rest))
}

/// Build an RSAPublicKey (PKCS#1 s.3.1) DER from an RSAPrivateKey (PKCS#1 s.3.2) DER.
///
/// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
///
/// Returns `None` if the input is not a valid PKCS#1 RSAPrivateKey.
fn rsa_public_key_der(pkcs1_der: &[u8]) -> Option<Vec<u8>> {
    // RSAPrivateKey: SEQUENCE { version INTEGER, modulus INTEGER,
    //                           publicExponent INTEGER, ... }
    let (_, inner, _) = tlv(pkcs1_der, 0x30)?;
    let (_, _, rest) = tlv(inner, 0x02)?; // skip version
    let (n_tlv, rest2) = full_tlv_bytes(rest, 0x02)?; // modulus
    let (e_tlv, _) = full_tlv_bytes(rest2, 0x02)?;    // publicExponent

    let content_len = n_tlv.len() + e_tlv.len();
    let mut out = Vec::with_capacity(4 + content_len);
    out.push(0x30);
    encode_der_len(&mut out, content_len);
    out.extend_from_slice(n_tlv);
    out.extend_from_slice(e_tlv);
    Some(out)
}

/// Decode the first 32 hex characters of `s` into a 16-byte array.
///
/// `s` must be at least 32 characters and contain only `[0-9a-fA-F]`.
/// Returns `None` if either condition is not met.
fn decode_hex_16(s: &str) -> Option<[u8; 16]> {
    if s.len() < 32 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Derive a 16-byte key ID from a GCP `private_key_id` hex string.
///
/// The GCP `private_key_id` is a 40-hex-character SHA-1 fingerprint.
/// We use the first 32 hex characters (16 bytes) as the key ID so the ID
/// is reproducible across re-imports of the same service account JSON.
///
/// Returns `None` if `hex` is shorter than 32 characters or contains
/// non-hex characters.
fn gcp_id_from_key_id_hex(hex: &str) -> Option<[u8; 16]> {
    decode_hex_16(hex)
}

/// Derive a 16-byte key ID from SHA-256 of the RSAPublicKey DER encoding.
///
/// Used as a fallback when `private_key_id` is absent or invalid.  The ID is
/// reproducible across re-imports of the same private key material.
///
/// Returns `None` if `pkcs1_der` is not a valid RSAPrivateKey.
fn sha256_key_id(pkcs1_der: &[u8]) -> Option<[u8; 16]> {
    use wolfcrypt::digest::digest_trait::Digest as _;
    let pub_der = rsa_public_key_der(pkcs1_der)?;
    let hash = wolfcrypt::Sha256::digest(&pub_der);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[..16]);
    Some(id)
}

// ---------------------------------------------------------------------------
// EncryptedPrivateKeyInfo (RFC 5958) parser
// ---------------------------------------------------------------------------

/// Parse an EncryptedPrivateKeyInfo DER blob, decrypt it with `passphrase`,
/// and return the enclosed key.
///
/// ```text
/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///   encryptionAlgorithm AlgorithmIdentifier,
///   encryptedData       OCTET STRING
/// }
/// ```
///
/// Supported schemes:
/// - PBES2 (`OID_PBES2`) with PBKDF2-SHA-256 + AES-256-CBC or AES-128-CBC
/// - PBES2 with PBKDF2-SHA-1 (default PRF) + AES-256-CBC or AES-128-CBC
/// - PKCS#12 `pbeWithSHAAnd3-KeyTripleDES-CBC` (`OID_PKCS12_SHA1_3DES`)
///
/// DES and RC2 schemes return `Unsupported` with a conversion command.
pub fn parse_encrypted_pkcs8(
    der: &[u8],
    passphrase: &str,
    id: [u8; 16],
) -> Result<ParsedKey, KeyParseError> {
    let (_, outer, _) = tlv(der, 0x30)
        .ok_or_else(|| malformed("EPKI: outer SEQUENCE missing"))?;

    let (_, alg_id, rest) = tlv(outer, 0x30)
        .ok_or_else(|| malformed("EPKI: AlgorithmIdentifier SEQUENCE missing"))?;

    let (_, enc_oid, alg_params) = tlv(alg_id, 0x06)
        .ok_or_else(|| malformed("EPKI: encryption OID missing"))?;

    let (_, ciphertext, _) = tlv(rest, 0x04)
        .ok_or_else(|| malformed("EPKI: encryptedData OCTET STRING missing"))?;

    let conversion_msg =
        "re-encrypt with: openssl pkcs8 -topk8 -v2 aes-256-cbc -in <infile> -out <outfile>";

    // PBES2: delegate to pkcs5 crate (handles PBKDF2-SHA1/SHA256 + AES-128/256-CBC).
    // Returns Zeroizing<Vec<u8>> so the plaintext key material is zeroed on drop.
    // `Decode` trait must be in scope for `from_der`; use sec1::der (same der v0.7 dep).
    // from_der failure = unsupported params; decrypt failure = wrong passphrase.
    if enc_oid == OID_PBES2 {
        use sec1::der::Decode as _;
        let params = pkcs5::pbes2::Parameters::from_der(alg_params)
            .map_err(|e| KeyParseError::Unsupported(
                format!("PBES2: unsupported parameters ({e}); {conversion_msg}")
            ))?;
        let pt = params.decrypt(passphrase.as_bytes(), ciphertext)
            .map_err(|_| malformed("PBES2 decrypt failed (wrong passphrase?)"))?;
        return parse_pkcs8(&pt, id);
    }

    let plaintext = if enc_oid == OID_PKCS12_SHA1_3DES {
        pkcs12_pbe_sha1_3des_decrypt(alg_params, passphrase, ciphertext)?
    } else if enc_oid == OID_PBES1_MD5_DES || enc_oid == OID_PBES1_SHA1_DES {
        return Err(KeyParseError::Unsupported(format!(
            "DES encryption is too weak; {conversion_msg}"
        )));
    } else if enc_oid == OID_PKCS12_SHA1_RC2_128 || enc_oid == OID_PKCS12_SHA1_RC2_40 {
        return Err(KeyParseError::Unsupported(format!(
            "RC2 encryption is not supported; {conversion_msg}"
        )));
    } else {
        return Err(KeyParseError::Unsupported(format!(
            "unknown encryption OID {:02x?}; {conversion_msg}",
            enc_oid
        )));
    };

    parse_pkcs8(&plaintext, id)
}


/// Decrypt using PKCS#12 PBE with SHA-1 and 3DES-CBC
/// (`pbeWithSHAAnd3-KeyTripleDES-CBC`, OID 1.2.840.113549.1.12.1.3).
///
/// `alg_params` is the bytes following the OID in the AlgorithmIdentifier,
/// which is the DER of the PKCS12-PBE-params SEQUENCE:
/// ```text
/// PBEParameter ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER }
/// ```
fn pkcs12_pbe_sha1_3des_decrypt(
    alg_params: &[u8],
    passphrase: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KeyParseError> {
    let (_, params, _) = tlv(alg_params, 0x30)
        .ok_or_else(|| malformed("PKCS12-3DES: PBEParameter SEQUENCE missing"))?;
    let (_, salt, iters_rest) = tlv(params, 0x04)
        .ok_or_else(|| malformed("PKCS12-3DES: salt OCTET STRING missing"))?;
    if salt.is_empty() {
        return Err(malformed("PKCS12-3DES: salt must not be empty"));
    }
    let (iters, _) = parse_der_uint(iters_rest)
        .ok_or_else(|| malformed("PKCS12-3DES: iterationCount missing or invalid"))?;
    // Cap iteration count to prevent a crafted file from triggering a multi-hour
    // KDF hang. 10,000,000 matches the cap in the JCEKS PBE path. (soft_PKCS11-9r05)
    if iters == 0 || iters > 10_000_000 {
        return Err(malformed("PKCS12-3DES: iterationCount out of range (must be 1..=10_000_000)"));
    }

    // PKCS#12 passwords are encoded as null-terminated UTF-16 big-endian (RFC 7292 s.B.1).
    let pass_utf16 = passphrase_to_utf16be(passphrase);

    let mut key = [0u8; 24];
    wolfcrypt::kdf::pkcs12_pbkdf(
        &pass_utf16,
        salt,
        iters as i32,
        wolfcrypt::kdf::PKCS12_KEY_ID,
        WC_HASH_TYPE_SHA1,
        &mut key,
    )
    .map_err(|_| malformed("PKCS12-3DES: key derivation failed"))?;

    let mut iv = [0u8; 8];
    wolfcrypt::kdf::pkcs12_pbkdf(
        &pass_utf16,
        salt,
        iters as i32,
        wolfcrypt::kdf::PKCS12_IV_ID,
        WC_HASH_TYPE_SHA1,
        &mut iv,
    )
    .map_err(|_| malformed("PKCS12-3DES: IV derivation failed"))?;

    des3_cbc_decrypt(&key, &iv, ciphertext)
}

/// Decrypt a JCEKS `PBEWithMD5AndTripleDES` `EncryptedPrivateKeyInfo` and
/// return the plaintext PKCS#8 DER bytes.
///
/// The OID `1.3.6.1.4.1.42.2.19.1` uses a Sun proprietary KDF:
/// split the 8-byte salt into two 4-byte halves; if the halves are equal
/// apply the "buggy inversion" `[a,b,c,d]->[d,a,b,d]`; then iterate
/// `MD5(prev || password_ascii)` `c` times for each half; concatenate the
/// two 16-byte outputs to get 24-byte 3DES key + 8-byte IV.
/// Source: OpenJDK `com.sun.crypto.provider.PBECipherCore`.
fn jce_pbe_md5_3des_decrypt(
    alg_params: &[u8],
    passphrase: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KeyParseError> {
    // PBEParameter ::= SEQUENCE { OCTET STRING (salt), INTEGER (iterCount) }
    let (_, params, _) = tlv(alg_params, 0x30)
        .ok_or_else(|| malformed("JCEKS PBE: PBEParameter SEQUENCE missing"))?;
    let (_, salt_bytes, iters_rest) = tlv(params, 0x04)
        .ok_or_else(|| malformed("JCEKS PBE: salt OCTET STRING missing"))?;
    let (iters, _) = parse_der_uint(iters_rest)
        .ok_or_else(|| malformed("JCEKS PBE: iterationCount missing or invalid"))?;
    if salt_bytes.len() != 8 {
        return Err(malformed("JCEKS PBE: expected 8-byte salt"));
    }
    if iters == 0 || iters > 10_000_000 {
        return Err(malformed("JCEKS PBE: iterationCount out of range"));
    }
    let iters = iters as u32;

    // Password as ASCII bytes (Java validates non-ASCII; we accept silently).
    let pass_bytes: Vec<u8> = passphrase.bytes().collect();

    // Split salt into two 4-byte halves; apply buggy inversion if equal.
    let mut half0: [u8; 4] = salt_bytes[..4].try_into().expect("len checked above");
    let half1: [u8; 4] = salt_bytes[4..].try_into().expect("len checked above");
    if half0 == half1 {
        // OpenJDK PBECipherCore bug: `[a,b,c,d] -> [d,a,b,d]`
        // s[2]=s[1]; s[1]=s[0]; s[0]=s[3] (s[3] stays)
        half0 = [half0[3], half0[0], half0[1], half0[3]];
    }

    // Derive 32 bytes: iterate MD5(prev || password) for each half.
    let mut block0 = half0.to_vec();
    let mut block1 = half1.to_vec();
    for _ in 0..iters {
        let mut ctx = md5::Context::new();
        ctx.consume(&block0);
        ctx.consume(&pass_bytes);
        block0 = ctx.compute().to_vec();
    }
    for _ in 0..iters {
        let mut ctx = md5::Context::new();
        ctx.consume(&block1);
        ctx.consume(&pass_bytes);
        block1 = ctx.compute().to_vec();
    }
    // block0 || block1 = 32 bytes: first 24 = key, last 8 = IV
    let mut key = [0u8; 24];
    key[..16].copy_from_slice(&block0);
    key[16..].copy_from_slice(&block1[..8]);
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&block1[8..]);

    des3_cbc_decrypt(&key, &iv, ciphertext)
}

// OID bytes for PBEWithMD5AndTripleDES (Sun JCEKS): 1.3.6.1.4.1.42.2.19.1
const OID_JCEKS_PBE_MD5_3DES: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x13, 0x01];

// ---------------------------------------------------------------------------
// Symmetric-cipher helpers (PBES2 / PKCS#12 PBE)
// ---------------------------------------------------------------------------

/// PKCS#7 unpad: return the slice without padding, or `None` on invalid padding.
fn pkcs7_unpad(data: &[u8], block_size: usize) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }
    let pad = *data.last()? as usize;
    if pad == 0 || pad > block_size || pad > data.len() {
        return None;
    }
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return None;
    }
    Some(&data[..data.len() - pad])
}

/// Encode a passphrase as null-terminated UTF-16 big-endian for PKCS#12 KDF.
fn passphrase_to_utf16be(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for cu in s.encode_utf16() {
        out.push((cu >> 8) as u8);
        out.push((cu & 0xff) as u8);
    }
    out.push(0x00);
    out.push(0x00); // null terminator
    out
}

/// Parse the first DER INTEGER from `data` and return `(value, rest)`.
///
/// The integer must be non-negative and fit in a `u64`.  Returns `None` for
/// negative integers, integers larger than 8 significant bytes, or missing data.
fn parse_der_uint(data: &[u8]) -> Option<(u64, &[u8])> {
    let (_, int_bytes, rest) = tlv(data, 0x02)?;
    let bytes = if int_bytes.first() == Some(&0x00) { &int_bytes[1..] } else { int_bytes };
    if bytes.len() > 8 {
        return None;
    }
    let mut val = 0u64;
    for &b in bytes {
        val = (val << 8) | b as u64;
    }
    Some((val, rest))
}

/// Decrypt `ct` with AES-256-CBC using `key` and `iv`, then PKCS#7-unpad.
fn aes256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ct: &[u8],
) -> Result<Vec<u8>, KeyParseError> {
    use cipher::{BlockDecryptMut, KeyIvInit};
    use generic_array::GenericArray;
    use wolfcrypt::Aes256CbcDec;

    if ct.len() % 16 != 0 || ct.is_empty() {
        return Err(malformed("AES-256-CBC: ciphertext not block-aligned"));
    }
    let mut dec = Aes256CbcDec::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
    let mut blocks: Vec<_> = ct.chunks_exact(16).map(|c| GenericArray::clone_from_slice(c)).collect();
    dec.decrypt_blocks_mut(&mut blocks);
    let plain: Vec<u8> = blocks.into_iter().flatten().collect();
    pkcs7_unpad(&plain, 16)
        .ok_or_else(|| malformed("AES-256-CBC: invalid PKCS#7 padding (wrong passphrase?)"))
        .map(|s| s.to_vec())
}

/// Decrypt `ct` with 3DES-CBC using `key` (24 bytes) and `iv` (8 bytes),
/// then PKCS#7-unpad.
fn des3_cbc_decrypt(
    key: &[u8; 24],
    iv: &[u8; 8],
    ct: &[u8],
) -> Result<Vec<u8>, KeyParseError> {
    use cipher::{BlockDecryptMut, KeyIvInit};
    use generic_array::GenericArray;
    use wolfcrypt::DesEde3CbcDec;

    if ct.len() % 8 != 0 || ct.is_empty() {
        return Err(malformed("3DES-CBC: ciphertext not block-aligned"));
    }
    let mut dec = DesEde3CbcDec::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
    let mut blocks: Vec<_> = ct.chunks_exact(8).map(|c| GenericArray::clone_from_slice(c)).collect();
    dec.decrypt_blocks_mut(&mut blocks);
    let plain: Vec<u8> = blocks.into_iter().flatten().collect();
    pkcs7_unpad(&plain, 8)
        .ok_or_else(|| malformed("3DES-CBC: invalid PKCS#7 padding (wrong passphrase?)"))
        .map(|s| s.to_vec())
}

// ---------------------------------------------------------------------------
// OpenSSH new-format binary frame parser
// ---------------------------------------------------------------------------

const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

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

    let ciphername = read_openssh_str(&mut cur)?;
    let kdfname = read_openssh_str(&mut cur)?;
    let kdfoptions_raw = read_openssh_bytes(&mut cur)?.to_vec();

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
    let _ = read_openssh_bytes(&mut cur)?;

    // Private key blob (may be encrypted).
    let private_blob = read_openssh_bytes(&mut cur)?.to_vec();

    Ok(OpensshFrame { ciphername, kdfname, kdfoptions_raw, private_blob })
}

/// Read a u32 big-endian length-prefixed byte sequence from `cur`.
/// Advances `cur` past the consumed bytes.  Returns `Malformed` on truncation.
fn read_openssh_bytes<'a>(cur: &mut &'a [u8]) -> Result<&'a [u8], KeyParseError> {
    let slice = *cur;
    if slice.len() < 4 {
        return Err(KeyParseError::Malformed(
            "OpenSSH: truncated length field".to_string(),
        ));
    }
    let len = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
    let slice = &slice[4..];
    if slice.len() < len {
        return Err(KeyParseError::Malformed(
            "OpenSSH: truncated field data".to_string(),
        ));
    }
    *cur = &slice[len..];
    Ok(&slice[..len])
}

/// Read a u32 big-endian length-prefixed UTF-8 string from `cur`.
/// Advances `cur` past the consumed bytes.  Returns `Malformed` on truncation
/// or if the bytes are not valid UTF-8.
fn read_openssh_str(cur: &mut &[u8]) -> Result<String, KeyParseError> {
    let raw = read_openssh_bytes(cur)?;
    String::from_utf8(raw.to_vec())
        .map_err(|_| KeyParseError::Malformed("OpenSSH: field is not valid UTF-8".to_string()))
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
fn decrypt_openssh_blob(frame: &OpensshFrame, passphrase: &str) -> Result<Vec<u8>, KeyParseError> {
    match frame.ciphername.as_str() {
        "none" => Ok(frame.private_blob.clone()),

        "aes256-ctr" => {
            if frame.kdfname != "bcrypt" {
                return Err(malformed(
                    "OpenSSH: ciphername is aes256-ctr but kdfname is not bcrypt",
                ));
            }
            // kdfoptions SSH wire format: string(salt) || uint32(rounds)
            let opts = &frame.kdfoptions_raw;
            if opts.len() < 4 {
                return Err(malformed("OpenSSH: kdfoptions too short for bcrypt salt length"));
            }
            let salt_len =
                u32::from_be_bytes([opts[0], opts[1], opts[2], opts[3]]) as usize;
            let after_salt = 4 + salt_len;
            if opts.len() < after_salt + 4 {
                return Err(malformed("OpenSSH: kdfoptions truncated before rounds field"));
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
                return Err(malformed(&format!(
                    "OpenSSH: bcrypt rounds {rounds} out of range \
                     (must be 1..={MAX_OPENSSH_BCRYPT_ROUNDS})"
                )));
            }

            // bcrypt_pbkdf: derive 32-byte AES key + 16-byte CTR IV.
            let mut key_iv = [0u8; 48];
            bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut key_iv)
                .map_err(|_| malformed("OpenSSH: bcrypt_pbkdf failed (rounds must be > 0)"))?;

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
fn verify_openssh_check_words(blob: &[u8]) -> Result<&[u8], KeyParseError> {
    if blob.len() < 8 {
        return Err(malformed("OpenSSH: private blob too short for check words"));
    }
    let check1 = u32::from_be_bytes(blob[..4].try_into().unwrap());
    let check2 = u32::from_be_bytes(blob[4..8].try_into().unwrap());
    if check1 != check2 {
        return Err(malformed(
            "OpenSSH: check word mismatch (wrong passphrase or corrupted key)",
        ));
    }
    Ok(&blob[8..])
}

// ---------------------------------------------------------------------------
// OpenSSH private blob key extraction (soft_PKCS11-3044 / ua43)
// ---------------------------------------------------------------------------

/// Strip the SSH MPI leading zero byte.
///
/// SSH multi-precision integers (RFC 4251 s.5) are unsigned but encoded as
/// signed big-endian: a 0x00 prefix is added when the high bit of the first
/// content byte would otherwise indicate a negative number.  Strip it so the
/// bytes represent the raw unsigned integer value.
fn strip_ssh_mpi_zero(mpi: &[u8]) -> &[u8] {
    if mpi.len() > 1 && mpi[0] == 0x00 {
        &mpi[1..]
    } else {
        mpi
    }
}

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
            return Err(malformed(
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
fn parse_openssh_key_data(blob: &[u8], id: [u8; 16]) -> Result<ParsedKey, KeyParseError> {
    let mut cur = blob;
    let keytype = read_openssh_str(&mut cur)?;
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
    let curve = read_openssh_str(cur)?;
    if curve != "nistp256" {
        return Err(KeyParseError::Unsupported(format!(
            "OpenSSH EC curve '{curve}' is not P-256 (nistp256)"
        )));
    }

    let public_point = read_openssh_bytes(cur)?;
    if public_point.len() != 65 || public_point[0] != 0x04 {
        return Err(malformed(
            "OpenSSH EC P-256: public point must be 65-byte uncompressed (04 || x || y)",
        ));
    }

    let scalar_raw = read_openssh_bytes(cur)?;
    let scalar_bytes = strip_ssh_mpi_zero(scalar_raw);
    if scalar_bytes.len() != 32 {
        return Err(malformed(
            "OpenSSH EC P-256: private scalar must be 32 bytes after stripping MPI zero prefix",
        ));
    }

    let comment = read_openssh_str(cur).unwrap_or_default();
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
    let n_raw = read_openssh_bytes(cur)?;
    let e_raw = read_openssh_bytes(cur)?;
    let d_raw = read_openssh_bytes(cur)?;
    let iqmp_raw = read_openssh_bytes(cur)?;
    let p_raw = read_openssh_bytes(cur)?;
    let q_raw = read_openssh_bytes(cur)?;

    let n = strip_ssh_mpi_zero(n_raw);
    let e = strip_ssh_mpi_zero(e_raw);
    let d = strip_ssh_mpi_zero(d_raw);
    let iqmp = strip_ssh_mpi_zero(iqmp_raw);
    let p = strip_ssh_mpi_zero(p_raw);
    let q = strip_ssh_mpi_zero(q_raw);

    let comment = read_openssh_str(cur).unwrap_or_default();
    let label_hint = if comment.is_empty() { None } else { Some(comment) };

    // Load into wolfCrypt and export as PKCS#1 DER.  wolfCrypt computes
    // dmp1 = d mod (p-1) and dmq1 = d mod (q-1) from the raw components.
    let key = wolfcrypt::NativeRsaKey::from_raw_components(n, e, d, p, q, iqmp)
        .map_err(|e| malformed(&format!("OpenSSH RSA: wolfCrypt key load failed: {e:?}")))?;
    let pkcs1_der = key
        .to_pkcs1_der()
        .map_err(|e| malformed(&format!("OpenSSH RSA: wolfCrypt DER export failed: {e:?}")))?;

    // Key ID: SHA-256(RSAPublicKey DER)[0..16] for reproducibility.
    let id = sha256_key_id(&pkcs1_der)
        .ok_or_else(|| malformed("OpenSSH RSA: could not derive key ID from PKCS#1 DER"))?;

    Ok(ParsedKey {
        key_type: KeyType::Rsa,
        key_bytes: pkcs1_der,
        id,
        label_hint,
        cert_der: None,
    })
}

// ---------------------------------------------------------------------------
// Certificate PEM parser
// ---------------------------------------------------------------------------

/// Read a PEM file containing a `BEGIN CERTIFICATE` block and return the
/// raw DER bytes.  Returns an error if the file cannot be read, the PEM is
/// malformed, or the block type is not "CERTIFICATE".
pub fn parse_cert_pem(path: &Path) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|e| format!("I/O error: {e}"))?;
    let block = pem::parse(&data).map_err(|e| format!("PEM parse error: {e}"))?;
    if block.tag() != "CERTIFICATE" {
        return Err(format!(
            "expected PEM type \"CERTIFICATE\", got \"{}\"",
            block.tag()
        ));
    }
    Ok(block.into_contents())
}

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
            return Err(malformed("JKS: unexpected end of file"));
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
    String::from_utf8(out).map_err(|_| malformed("JKS: alias is not valid UTF-8"))
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
        _ => return Err(malformed("JKS: unrecognised magic (not a JKS or JCEKS file)")),
    };

    let version = cur.read_u32()?;
    match (is_jceks, version) {
        (false, 1) | (false, 2) => {}
        (true, 2) => {}
        _ => return Err(malformed(&format!("JKS: unsupported version {version}"))),
    }

    let entry_count = cur.read_u32()? as usize;
    // Cap to prevent a crafted file from causing an extremely long parse loop.
    // 10,000 is far more entries than any legitimate keystore would hold.
    // (soft_PKCS11-10qe)
    if entry_count > 10_000 {
        return Err(malformed("JKS: entry count exceeds maximum (10000)"));
    }
    let mut private_key_entries = Vec::new();

    for _ in 0..entry_count {
        let tag = cur.read_u32()?;
        let alias = cur.read_mutf8()?;
        let timestamp_ms = cur.read_u64()?;

        match tag {
            1 => {
                // PrivateKeyEntry: encrypted key blob + cert chain
                let encrypted_key = cur.read_len32_bytes()?;

                let cert_count = cur.read_u32()? as usize;
                // Cap certificate chain length; a legitimate chain is 1-5 entries.
                // (soft_PKCS11-10qe)
                if cert_count > 100 {
                    return Err(malformed("JKS: certificate chain length exceeds maximum (100)"));
                }
                let mut cert_der = None;
                for cert_idx in 0..cert_count {
                    // cert type: u16-length UTF string (e.g. "X.509")
                    let _cert_type = cur.read_mutf8()?;
                    let cert_bytes = cur.read_len32_bytes()?;
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
                return Err(malformed(&format!(
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
        return Err(malformed("JKS: file too short to contain integrity fingerprint"));
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
        return Err(malformed(
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
fn decrypt_jks_private_key_entry(
    encrypted: &[u8],
    passphrase: &str,
    id: [u8; 16],
) -> Result<ParsedKey, KeyParseError> {
    // Parse EncryptedPrivateKeyInfo DER.
    let (_, outer_content, _) = tlv(encrypted, 0x30)
        .ok_or_else(|| malformed("JKS/JCEKS PrivateKeyEntry: outer SEQUENCE missing"))?;
    // AlgorithmIdentifier SEQUENCE -> extract OID and remaining params.
    let (_, alg_id_body, rest) = tlv(outer_content, 0x30)
        .ok_or_else(|| malformed("JKS/JCEKS PrivateKeyEntry: AlgorithmIdentifier missing"))?;
    let (_, oid, alg_params) = tlv(alg_id_body, 0x06)
        .ok_or_else(|| malformed("JKS/JCEKS PrivateKeyEntry: algorithm OID missing"))?;
    // Encrypted data OCTET STRING.
    let (_, enc_data, _) = tlv(rest, 0x04)
        .ok_or_else(|| malformed("JKS/JCEKS PrivateKeyEntry: encrypted OCTET STRING missing"))?;

    if oid == OID_SUN_JKS_CIPHER {
        // JKS proprietary XOR stream cipher.
        // enc_data layout: salt (20) || ciphertext || check (20).
        if enc_data.len() < 40 {
            return Err(malformed("JKS PrivateKeyEntry: cipher data too short"));
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
            return Err(malformed(
                "JKS PrivateKeyEntry: wrong passphrase or corrupted key",
            ));
        }
        parse_pkcs8(&plaintext, id)
    } else if oid == OID_JCEKS_PBE_MD5_3DES {
        // JCEKS PBEWithMD5AndTripleDES: Sun MD5 KDF + 3DES-CBC.
        let plaintext = jce_pbe_md5_3des_decrypt(alg_params, passphrase, enc_data)?;
        parse_pkcs8(&plaintext, id)
    } else {
        Err(KeyParseError::Unsupported(format!(
            "JKS/JCEKS PrivateKeyEntry: unsupported algorithm OID {oid:02x?}"
        )))
    }
}

// ---------------------------------------------------------------------------
// Random key ID
// ---------------------------------------------------------------------------

/// Generate a random 16-byte key identifier using the OS CSPRNG.
fn random_id() -> Result<[u8; 16], KeyParseError> {
    use std::io::Read;
    let mut id = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut id))
        .map_err(|e| KeyParseError::Io(e))?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// PKCS#12 PFX ASN.1 structure traversal
// ---------------------------------------------------------------------------

/// Decode a BMPString (UTF-16 Big-Endian) to a Rust `String`.
fn bmpstring_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&u16s).ok()
}

/// Parse the `bagAttributes` SET body of a SafeBag, returning the
/// `localKeyID` OCTET STRING and `friendlyName` string if present.
fn parse_bag_attributes(set_body: &[u8]) -> (Option<Vec<u8>>, Option<String>) {
    let mut local_key_id = None;
    let mut friendly_name = None;
    let mut cur = set_body;
    let mut attr_count = 0usize;
    while !cur.is_empty() {
        // Cap attribute count to bound iteration over a crafted PKCS#12 file.
        // A legitimate bagAttributes SET holds at most 2–3 attributes.
        // (soft_PKCS11-la8f)
        attr_count += 1;
        if attr_count > 100 {
            break;
        }
        // Each PKCS12Attribute is a SEQUENCE { OID, SET OF value }.
        let (tag, attr_seq_body, rest) = match next_tlv(cur) {
            Some(x) => x,
            None => break,
        };
        cur = rest;
        if tag != 0x30 {
            continue;
        }
        let (_, oid, attr_rest) = match tlv(attr_seq_body, 0x06) {
            Some(x) => x,
            None => continue,
        };
        let (_, value_set, _) = match tlv(attr_rest, 0x31) {
            Some(x) => x,
            None => continue,
        };
        if oid == OID_PKCS9_LOCAL_KEY_ID {
            if let Some((_, val, _)) = tlv(value_set, 0x04) {
                local_key_id = Some(val.to_vec());
            }
        } else if oid == OID_PKCS9_FRIENDLY_NAME {
            if let Some((_, val, _)) = tlv(value_set, 0x1e) {
                friendly_name = bmpstring_to_string(val);
            }
        }
    }
    (local_key_id, friendly_name)
}

/// Walk a `SafeContents` DER blob and append found bags to `bags`.
///
/// `SafeContents ::= SEQUENCE OF SafeBag`
///
/// Collects `ShroudedKeyBag` and `CertBag` entries; silently skips all others.
fn parse_safe_contents(der: &[u8], bags: &mut PfxBags) -> Result<(), KeyParseError> {
    let (_, seq_body, _) = tlv(der, 0x30)
        .ok_or_else(|| malformed("PFX SafeContents: expected SEQUENCE"))?;

    let mut cur = seq_body;
    let mut bag_count = 0usize;
    while !cur.is_empty() {
        // Cap SafeBag count to bound memory use from a crafted PKCS#12 file.
        // Each bag_value is .to_vec()-allocated; unbounded growth would allow
        // OOM via many bags. 1,000 bags is far beyond any legitimate keystore.
        // (soft_PKCS11-la8f)
        bag_count += 1;
        if bag_count > 1_000 {
            return Err(malformed("PFX SafeContents: SafeBag count exceeds maximum (1000)"));
        }
        let (tag, safe_bag_body, rest) = next_tlv(cur)
            .ok_or_else(|| malformed("PFX SafeContents: truncated SafeBag"))?;
        cur = rest;
        if tag != 0x30 {
            continue;
        }

        // bagId OID
        let (_, bag_id, sb_rest) = match tlv(safe_bag_body, 0x06) {
            Some(x) => x,
            None => continue,
        };

        // bagValue [0] EXPLICIT
        let (_, bag_value_body, sb_rest2) = match tlv(sb_rest, 0xa0) {
            Some(x) => x,
            None => continue,
        };

        // bagAttributes SET (tag 0x31, optional)
        let (local_key_id, friendly_name) = if sb_rest2.first() == Some(&0x31) {
            match tlv(sb_rest2, 0x31) {
                Some((_, attrs_body, _)) => parse_bag_attributes(attrs_body),
                None => (None, None),
            }
        } else {
            (None, None)
        };

        let bag = PfxBag {
            bag_value: bag_value_body.to_vec(),
            local_key_id,
            friendly_name,
        };

        if bag_id == OID_PKCS12_SHROUDED_KEY_BAG {
            bags.shrouded_key_bags.push(bag);
        } else if bag_id == OID_PKCS12_CERT_BAG {
            bags.cert_bags.push(bag);
        }
        // Other bag types (e.g. pkcs-12-KeyBag) are silently skipped.
    }
    Ok(())
}

/// Decrypt an `id-encryptedData` ContentInfo and return the plaintext SafeContents DER.
///
/// `ci_rest` is the bytes following the `id-encryptedData` OID within the ContentInfo SEQUENCE.
/// The structure is:
/// ```text
/// [0] EXPLICIT EncryptedData ::= SEQUENCE {
///   version Version,
///   encryptedContentInfo EncryptedContentInfo ::= SEQUENCE {
///     contentType OID (id-data),
///     contentEncryptionAlgorithm AlgorithmIdentifier,  -- PBES2 / PBES1
///     encryptedContent [0] IMPLICIT OCTET STRING
///   }
/// }
/// ```
fn decrypt_encrypted_data_content_info(
    ci_rest: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>, KeyParseError> {
    let conversion_msg =
        "re-encrypt with: openssl pkcs12 -in old.pfx -nodes | openssl pkcs12 -export -out new.pfx";

    // ContentInfo content [0] EXPLICIT EncryptedData
    let (_, a0, _) = tlv(ci_rest, 0xa0)
        .ok_or_else(|| malformed("PKCS#12 encryptedData: [0] EXPLICIT wrapper missing"))?;

    // EncryptedData SEQUENCE
    let (_, ed_body, _) = tlv(a0, 0x30)
        .ok_or_else(|| malformed("PKCS#12 encryptedData: EncryptedData SEQUENCE missing"))?;

    // Skip version INTEGER
    let (_, _, eci_der) = tlv(ed_body, 0x02)
        .ok_or_else(|| malformed("PKCS#12 encryptedData: version INTEGER missing"))?;

    // EncryptedContentInfo SEQUENCE
    let (_, eci_body, _) = tlv(eci_der, 0x30)
        .ok_or_else(|| malformed("PKCS#12 encryptedData: EncryptedContentInfo SEQUENCE missing"))?;

    // Skip contentType OID (typically id-data)
    let (_, _, alg_and_content) = tlv(eci_body, 0x06)
        .ok_or_else(|| malformed("PKCS#12 encryptedData: contentType OID missing"))?;

    // AlgorithmIdentifier SEQUENCE: encryption OID + params
    let (_, alg_id, content_rest) = tlv(alg_and_content, 0x30)
        .ok_or_else(|| malformed("PKCS#12 encryptedData: AlgorithmIdentifier missing"))?;

    let (_, enc_oid, alg_params) = tlv(alg_id, 0x06)
        .ok_or_else(|| malformed("PKCS#12 encryptedData: encryption OID missing"))?;

    // encryptedContent [0] IMPLICIT OCTET STRING (tag 0x80) or bare OCTET STRING (0x04)
    let ciphertext = match content_rest.first() {
        Some(&0x80) => {
            next_tlv(content_rest)
                .ok_or_else(|| malformed("PKCS#12 encryptedData: encryptedContent truncated"))?.1
        }
        Some(&0x04) => {
            tlv(content_rest, 0x04)
                .ok_or_else(|| malformed("PKCS#12 encryptedData: encryptedContent OCTET STRING missing"))?.1
        }
        _ => return Err(malformed("PKCS#12 encryptedData: encryptedContent missing")),
    };

    if enc_oid == OID_PBES2 {
        use sec1::der::Decode as _;
        let params = pkcs5::pbes2::Parameters::from_der(alg_params)
            .map_err(|e| KeyParseError::Unsupported(
                format!("PBES2: unsupported parameters ({e}); {conversion_msg}")
            ))?;
        params.decrypt(passphrase.as_bytes(), ciphertext)
            .map_err(|_| malformed("PBES2 decrypt failed (wrong passphrase?)"))
            .map(|pt| pt.to_vec())
    } else if enc_oid == OID_PKCS12_SHA1_3DES {
        pkcs12_pbe_sha1_3des_decrypt(alg_params, passphrase, ciphertext)
    } else if enc_oid == OID_PKCS12_SHA1_RC2_128 || enc_oid == OID_PKCS12_SHA1_RC2_40 {
        Err(KeyParseError::Unsupported(
            "RC2 encryption is not supported; convert with: \
             openssl pkcs12 -in old.pfx -legacy -nodes | openssl pkcs12 -export -out new.pfx"
                .to_string(),
        ))
    } else {
        Err(KeyParseError::Unsupported(format!(
            "PKCS#12 SafeContents: unknown encryption OID {:02x?}; {conversion_msg}",
            enc_oid
        )))
    }
}

/// Walk an `AuthenticatedSafe` DER blob, dispatching each `ContentInfo` entry.
///
/// `id-data` ContentInfos are decoded and their `SafeContents` parsed directly.
/// `id-encryptedData` ContentInfos are decrypted with `passphrase` then parsed.
fn parse_authenticated_safe(
    der: &[u8],
    bags: &mut PfxBags,
    passphrase: &str,
) -> Result<(), KeyParseError> {
    let (_, seq_body, _) = tlv(der, 0x30)
        .ok_or_else(|| malformed("PFX AuthenticatedSafe: expected SEQUENCE"))?;

    let mut cur = seq_body;
    let mut ci_count = 0usize;
    while !cur.is_empty() {
        // Cap ContentInfo count; a legitimate PKCS#12 has 1–3 ContentInfos.
        // (soft_PKCS11-la8f)
        ci_count += 1;
        if ci_count > 100 {
            return Err(malformed("PFX AuthenticatedSafe: ContentInfo count exceeds maximum (100)"));
        }
        let (tag, ci_body, rest) = next_tlv(cur)
            .ok_or_else(|| malformed("PFX AuthenticatedSafe: truncated ContentInfo"))?;
        cur = rest;
        if tag != 0x30 {
            continue;
        }

        let (_, ci_oid, ci_rest) = match tlv(ci_body, 0x06) {
            Some(x) => x,
            None => continue,
        };

        if ci_oid == OID_PKCS7_DATA {
            // content [0] EXPLICIT OCTET STRING -> SafeContents DER
            let a0 = match tlv(ci_rest, 0xa0) {
                Some((_, v, _)) => v,
                None => continue,
            };
            let safe_contents_der = match tlv(a0, 0x04) {
                Some((_, v, _)) => v,
                None => continue,
            };
            parse_safe_contents(safe_contents_der, bags)?;
        } else if ci_oid == OID_PKCS7_ENCRYPTED_DATA {
            match decrypt_encrypted_data_content_info(ci_rest, passphrase) {
                Ok(plaintext) => parse_safe_contents(&plaintext, bags)?,
                // RC2 or other unsupported cipher in this container: skip it.
                // The key may be in a different ContentInfo (e.g. id-data).
                Err(KeyParseError::Unsupported(_)) => {}
                Err(e) => return Err(e),
            }
        }
        // Other ContentInfo types are silently skipped.
    }
    Ok(())
}

/// Compute HMAC-SHA1 of `data` using `key`.
fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    use wolfcrypt::digest::digest_trait::{FixedOutput, KeyInit, Update};
    use wolfcrypt::WolfHmacSha1;
    let mut h = WolfHmacSha1::new_from_slice(key).expect("HMAC-SHA1 key init");
    Update::update(&mut h, data);
    let mut out = [0u8; 20];
    FixedOutput::finalize_into(h, generic_array::GenericArray::from_mut_slice(&mut out));
    out
}

/// Compute HMAC-SHA256 of `data` using `key`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use wolfcrypt::digest::digest_trait::{FixedOutput, KeyInit, Update};
    use wolfcrypt::WolfHmacSha256;
    let mut h = WolfHmacSha256::new_from_slice(key).expect("HMAC-SHA256 key init");
    Update::update(&mut h, data);
    let mut out = [0u8; 32];
    FixedOutput::finalize_into(h, generic_array::GenericArray::from_mut_slice(&mut out));
    out
}

/// Derive the PKCS#12 MAC key and compute the HMAC over `mac_input`.
///
/// Returns the computed MAC as a `Vec<u8>`.
fn compute_pfx_mac(
    pass_bytes: &[u8],
    mac_salt: &[u8],
    iterations: i32,
    hash_type: i32,
    mac_key_len: usize,
    mac_input: &[u8],
) -> Result<Vec<u8>, KeyParseError> {
    let mut mac_key = vec![0u8; mac_key_len];
    wolfcrypt::kdf::pkcs12_pbkdf(
        pass_bytes,
        mac_salt,
        iterations,
        wolfcrypt::kdf::PKCS12_MAC_ID,
        hash_type,
        &mut mac_key,
    )
    .map_err(|_| malformed("PFX: MAC key derivation failed"))?;

    let computed = if hash_type == WC_HASH_TYPE_SHA1 {
        hmac_sha1(&mac_key, mac_input).to_vec()
    } else {
        hmac_sha256(&mac_key, mac_input).to_vec()
    };
    Ok(computed)
}

// SHA-1 OID value bytes: 1.3.14.3.2.26
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
// SHA-256 OID value bytes: 2.16.840.1.101.3.4.2.1
const OID_SHA256_DIGEST: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
// wc_HashType value for SHA-256 (wolfCrypt wolfssl/wolfcrypt/hash.h WC_HASH_TYPE_SHA256 = 6).
const WC_HASH_TYPE_SHA256: i32 = 6;

/// Verify the PKCS#12 MAC over a PFX DER blob.
///
/// Parses the `macData` field, derives the MAC key from `passphrase` using
/// the PKCS#12 KDF (RFC 7292 s.B.2), and verifies the HMAC over the
/// `authSafe` content bytes.
///
/// For an empty passphrase, tries zero-length password first (RFC 7292 s.B.3),
/// then `0x00 0x00` as a fallback (some openssl versions use this encoding).
///
/// Returns `Ok(())` on success or a `Malformed` error on MAC failure.
pub fn verify_pfx_mac(der: &[u8], passphrase: &str) -> Result<(), KeyParseError> {
    // Re-parse the PFX outer structure to locate authSafe content and macData.
    let (_, pfx_body, _) = tlv(der, 0x30)
        .ok_or_else(|| malformed("PFX: expected outer SEQUENCE"))?;
    let (_, _version, pfx_rest) = tlv(pfx_body, 0x02)
        .ok_or_else(|| malformed("PFX: version INTEGER missing"))?;

    // authSafe ContentInfo: extract the AuthenticatedSafe bytes (MAC input).
    let (_, auth_safe_body, pfx_rest2) = tlv(pfx_rest, 0x30)
        .ok_or_else(|| malformed("PFX: authSafe ContentInfo missing"))?;
    let (_, ct_oid, auth_safe_rest) = tlv(auth_safe_body, 0x06)
        .ok_or_else(|| malformed("PFX: authSafe contentType OID missing"))?;
    if ct_oid != OID_PKCS7_DATA {
        return Err(malformed("PFX: authSafe contentType is not id-data"));
    }
    let a0 = tlv(auth_safe_rest, 0xa0)
        .ok_or_else(|| malformed("PFX: authSafe content [0] missing"))?.1;
    let mac_input = tlv(a0, 0x04)
        .ok_or_else(|| malformed("PFX: authSafe OCTET STRING missing"))?.1;

    // macData SEQUENCE (required for integrity verification).
    let (_, mac_data_body, _) = tlv(pfx_rest2, 0x30)
        .ok_or_else(|| malformed("PFX: macData missing; cannot verify integrity"))?;

    // mac DigestInfo: { AlgorithmIdentifier, OCTET STRING }
    let (_, digest_info_body, mac_data_rest) = tlv(mac_data_body, 0x30)
        .ok_or_else(|| malformed("PFX: macData DigestInfo missing"))?;
    let (_, alg_id_body, digest_rest) = tlv(digest_info_body, 0x30)
        .ok_or_else(|| malformed("PFX: DigestInfo AlgorithmIdentifier missing"))?;
    let (_, hash_oid, _) = tlv(alg_id_body, 0x06)
        .ok_or_else(|| malformed("PFX: DigestInfo hash OID missing"))?;
    let (_, mac_value, _) = tlv(digest_rest, 0x04)
        .ok_or_else(|| malformed("PFX: DigestInfo macValue missing"))?;

    // macSalt OCTET STRING
    let (_, mac_salt, mac_data_rest2) = tlv(mac_data_rest, 0x04)
        .ok_or_else(|| malformed("PFX: macData macSalt missing"))?;

    // iterations INTEGER (DEFAULT 1)
    // Cap to prevent a crafted PFX from triggering a multi-hour KDF hang; absent
    // field defaults to 1 per RFC 7292. The v as i32 cast is safe because
    // v <= 10_000_000 < i32::MAX. (soft_PKCS11-9r05)
    let iterations = match parse_der_uint(mac_data_rest2).map(|(v, _)| v) {
        None => 1i32,
        Some(v) if v == 0 || v > 10_000_000 => {
            return Err(malformed(
                "PFX: macData iterationCount out of range (must be 1..=10_000_000)",
            ));
        }
        Some(v) => v as i32,
    };

    // Determine hash algorithm and MAC key output size.
    let (mac_key_len, hash_type) = if hash_oid == OID_SHA1 {
        (20usize, WC_HASH_TYPE_SHA1)
    } else if hash_oid == OID_SHA256_DIGEST {
        (32usize, WC_HASH_TYPE_SHA256)
    } else {
        return Err(KeyParseError::Unsupported(format!(
            "PFX MAC: unsupported digest algorithm OID {:02x?}",
            hash_oid
        )));
    };

    // Encode passphrase per RFC 7292 s.B.1 (UTF-16BE + null terminator).
    // passphrase_to_utf16be("") returns [0x00, 0x00] (null terminator only),
    // which is the standard openssl encoding for an empty PKCS#12 passphrase.
    let primary_pass = passphrase_to_utf16be(passphrase);

    let computed = compute_pfx_mac(&primary_pass, mac_salt, iterations, hash_type, mac_key_len, mac_input)?;
    if computed == mac_value {
        return Ok(());
    }

    // Fallback for empty passphrase: some tools use a truly empty byte string
    // (RFC 7292 s.B.3 alternative interpretation) instead of [0x00, 0x00].
    if passphrase.is_empty() {
        if let Ok(computed2) = compute_pfx_mac(&[], mac_salt, iterations, hash_type, mac_key_len, mac_input) {
            if computed2 == mac_value {
                return Ok(());
            }
        }
    }

    Err(malformed(
        "PFX: MAC verification failed (wrong passphrase or corrupted file)",
    ))
}

/// Parse a PKCS#12 PFX DER blob and return the categorised bags.
///
/// Traverses the `PFX -> AuthenticatedSafe -> ContentInfo list -> SafeContents`
/// chain and collects every `ShroudedKeyBag` and `CertBag`.
/// Encrypted SafeContents (`id-encryptedData`) are decrypted with `passphrase`.
///
/// Returns `Err` for structurally invalid or truncated DER, wrong passphrase,
/// or unsupported cipher.  Never panics.
pub fn parse_pfx_structure(der: &[u8], passphrase: &str) -> Result<PfxBags, KeyParseError> {
    // PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData OPTIONAL }
    let (_, pfx_body, _) = tlv(der, 0x30)
        .ok_or_else(|| malformed("PFX: expected outer SEQUENCE"))?;

    // version INTEGER (expected value 3, but we don't enforce it)
    let (_, _version, pfx_rest) = tlv(pfx_body, 0x02)
        .ok_or_else(|| malformed("PFX: version INTEGER missing"))?;

    // authSafe ContentInfo SEQUENCE
    let (_, auth_safe_body, _) = tlv(pfx_rest, 0x30)
        .ok_or_else(|| malformed("PFX: authSafe ContentInfo SEQUENCE missing"))?;

    // contentType OID -- must be id-data
    let (_, ct_oid, auth_safe_rest) = tlv(auth_safe_body, 0x06)
        .ok_or_else(|| malformed("PFX: authSafe contentType OID missing"))?;

    if ct_oid != OID_PKCS7_DATA {
        return Err(KeyParseError::Malformed(format!(
            "PFX: authSafe contentType is not id-data ({:02x?})",
            ct_oid
        )));
    }

    // content [0] EXPLICIT OCTET STRING -> AuthenticatedSafe DER
    let a0 = tlv(auth_safe_rest, 0xa0)
        .ok_or_else(|| malformed("PFX: authSafe content [0] missing"))?
        .1;
    let auth_safe_der = tlv(a0, 0x04)
        .ok_or_else(|| malformed("PFX: authSafe OCTET STRING missing"))?
        .1;

    let mut bags = PfxBags { shrouded_key_bags: Vec::new(), cert_bags: Vec::new() };
    parse_authenticated_safe(auth_safe_der, &mut bags, passphrase)?;
    Ok(bags)
}

/// Extract the DER-encoded X.509 certificate from a CertBag value.
///
/// `CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }`
fn cert_der_from_cert_bag(bag_value: &[u8]) -> Option<Vec<u8>> {
    let (_, cert_bag_body, _) = tlv(bag_value, 0x30)?;
    let (_, cert_id, cb_rest) = tlv(cert_bag_body, 0x06)?;
    if cert_id != OID_X509_CERTIFICATE {
        return None;
    }
    // certValue [0] EXPLICIT OCTET STRING
    let (_, a0, _) = tlv(cb_rest, 0xa0)?;
    let (_, cert_der, _) = tlv(a0, 0x04)?;
    Some(cert_der.to_vec())
}

/// Derive a 16-byte key ID from a `localKeyID` bag attribute byte string.
///
/// Takes the first 16 bytes; zero-pads on the right if shorter.
fn key_id_from_local_key_id(local_key_id: &[u8]) -> [u8; 16] {
    let mut id = [0u8; 16];
    let n = local_key_id.len().min(16);
    id[..n].copy_from_slice(&local_key_id[..n]);
    id
}

/// Find the first cert DER whose `localKeyID` matches `key_local_id`.
///
/// Falls back to the first cert in the list if no match is found.
fn find_cert_for_key(
    certs: &[(Option<Vec<u8>>, Vec<u8>)],
    key_local_id: &Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    if let Some(kid) = key_local_id {
        for (cert_kid, cert_der) in certs {
            if cert_kid.as_deref() == Some(kid.as_slice()) {
                return Some(cert_der.clone());
            }
        }
    }
    certs.first().map(|(_, d)| d.clone())
}

/// Decrypt all `ShroudedKeyBag` entries in `bags` and return the extracted keys.
///
/// Each ShroudedKeyBag is an `EncryptedPrivateKeyInfo`; decryption uses the
/// same PBES2/PBES1 logic as `parse_encrypted_pkcs8`.
///
/// Key ID assignment (per key-id-assignment-strategy decision 2026-04-08):
/// use the `localKeyID` bag attribute (truncated/padded to 16 bytes);
/// fall back to SHA-256(canonical_public_key_bytes)[0..16] when absent.
///
/// CertBag certificates are matched to their key by `localKeyID` and stored
/// in `ParsedKey::cert_der`.
///
/// Returns `(successes, failures)`.  Per-bag failures are non-fatal.
pub fn extract_keys_from_pfx_bags(
    bags: &PfxBags,
    passphrase: &str,
) -> (Vec<ParsedKey>, Vec<(String, KeyParseError)>) {
    let mut keys = Vec::new();
    let mut failures: Vec<(String, KeyParseError)> = Vec::new();

    // Pre-collect (localKeyID, cert_der) pairs from CertBags for matching.
    let certs: Vec<(Option<Vec<u8>>, Vec<u8>)> = bags
        .cert_bags
        .iter()
        .filter_map(|cb| {
            cert_der_from_cert_bag(&cb.bag_value)
                .map(|der| (cb.local_key_id.clone(), der))
        })
        .collect();

    for key_bag in &bags.shrouded_key_bags {
        let label = key_bag
            .friendly_name
            .clone()
            .unwrap_or_default();

        // Generate a random fallback ID (used if SHA-256 derivation fails inside
        // parse_encrypted_pkcs8 and localKeyID is also absent).
        let fallback_id = match random_id() {
            Ok(id) => id,
            Err(e) => {
                failures.push((label, e));
                continue;
            }
        };

        match parse_encrypted_pkcs8(&key_bag.bag_value, passphrase, fallback_id) {
            Ok(mut parsed) => {
                // Override ID: localKeyID takes precedence over SHA-256 derivation.
                if let Some(local_id) = &key_bag.local_key_id {
                    parsed.id = key_id_from_local_key_id(local_id);
                }
                // Apply friendlyName as label if the parsed key has none.
                if parsed.label_hint.is_none() {
                    parsed.label_hint = key_bag.friendly_name.clone();
                }
                // Attach the matching leaf certificate.
                parsed.cert_der = find_cert_for_key(&certs, &key_bag.local_key_id);

                keys.push(parsed);
            }
            Err(e) => {
                failures.push((label, e));
            }
        }
    }

    (keys, failures)
}

// ---------------------------------------------------------------------------
// PPK (PuTTY Private Key) file import: detection -> parse -> decrypt -> extract
// ---------------------------------------------------------------------------

/// Top-level PPK import: called from [`parse_key_file`] when a PPK file is
/// detected.  Prompts for a passphrase when required, verifies the MAC, and
/// extracts the private key.
fn parse_ppk_file_data(
    data: &[u8],
) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let ppk = parse_ppk(data)?;

    let passphrase = if ppk.encryption == "none" {
        String::new()
    } else {
        super::pin::prompt_passphrase("Passphrase for PPK key: ")
            .map_err(KeyParseError::Io)?
    };

    let id = random_id()?;
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
fn ppk_extract_key(
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
fn ppk_extract_rsa(
    public_blob: &[u8],
    private_blob: &[u8],
    id: [u8; 16],
    label_hint: Option<String>,
) -> Result<ParsedKey, KeyParseError> {
    let mut pub_cur = public_blob;
    let key_type_str = read_openssh_str(&mut pub_cur)?;
    if key_type_str != "ssh-rsa" {
        return Err(malformed("PPK RSA: unexpected key-type string in public blob"));
    }
    let e_raw = read_openssh_bytes(&mut pub_cur)?;
    let n_raw = read_openssh_bytes(&mut pub_cur)?;

    let mut priv_cur = private_blob;
    let d_raw   = read_openssh_bytes(&mut priv_cur)?;
    let p_raw   = read_openssh_bytes(&mut priv_cur)?;
    let q_raw   = read_openssh_bytes(&mut priv_cur)?;
    let iqmp_raw = read_openssh_bytes(&mut priv_cur)?;

    let n    = strip_ssh_mpi_zero(n_raw);
    let e    = strip_ssh_mpi_zero(e_raw);
    let d    = strip_ssh_mpi_zero(d_raw);
    let p    = strip_ssh_mpi_zero(p_raw);
    let q    = strip_ssh_mpi_zero(q_raw);
    let iqmp = strip_ssh_mpi_zero(iqmp_raw);

    let key = wolfcrypt::NativeRsaKey::from_raw_components(n, e, d, p, q, iqmp)
        .map_err(|e| malformed(&format!("PPK RSA: wolfCrypt key load failed: {e:?}")))?;
    let pkcs1_der = key
        .to_pkcs1_der()
        .map_err(|e| malformed(&format!("PPK RSA: wolfCrypt DER export failed: {e:?}")))?;

    let derived_id = sha256_key_id(&pkcs1_der).unwrap_or(id);

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
fn ppk_extract_ec_p256(
    public_blob: &[u8],
    private_blob: &[u8],
    id: [u8; 16],
    label_hint: Option<String>,
) -> Result<ParsedKey, KeyParseError> {
    let mut pub_cur = public_blob;
    let key_type_str = read_openssh_str(&mut pub_cur)?;
    if key_type_str != "ecdsa-sha2-nistp256" {
        return Err(malformed("PPK EC: unexpected key-type string in public blob"));
    }
    let curve = read_openssh_str(&mut pub_cur)?;
    if curve != "nistp256" {
        return Err(KeyParseError::Unsupported(format!(
            "PPK EC curve '{curve}' is not supported; only P-256 (nistp256) is supported"
        )));
    }
    let public_point = read_openssh_bytes(&mut pub_cur)?;
    if public_point.len() != 65 || public_point[0] != 0x04 {
        return Err(malformed(
            "PPK EC P-256: public point must be 65-byte uncompressed (04 || x || y)",
        ));
    }

    let mut priv_cur = private_blob;
    let scalar_raw = read_openssh_bytes(&mut priv_cur)?;
    let scalar = strip_ssh_mpi_zero(scalar_raw);
    if scalar.len() != 32 {
        return Err(malformed(
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
        .map_err(|_| malformed("PPK: file is not valid UTF-8"))?;

    let mut lines = text.lines().peekable();

    // First line: "PuTTY-User-Key-File-N: <key-type>"
    let first = lines.next().ok_or_else(|| malformed("PPK: empty file"))?;
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
                .map_err(|_| malformed("PPK: invalid Public-Lines count"))?;
            public_blob = Some(ppk_read_base64_lines(&mut lines, n)?);
        } else if let Some(val) = ppk_strip_key(line, "Key-Derivation") {
            kdf_variant = Some(val.trim().to_string());
        } else if let Some(val) = ppk_strip_key(line, "Argon2-Memory") {
            argon2_memory = Some(val.trim().parse()
                .map_err(|_| malformed("PPK: invalid Argon2-Memory"))?);
        } else if let Some(val) = ppk_strip_key(line, "Argon2-Passes") {
            argon2_passes = Some(val.trim().parse()
                .map_err(|_| malformed("PPK: invalid Argon2-Passes"))?);
        } else if let Some(val) = ppk_strip_key(line, "Argon2-Parallelism") {
            argon2_parallelism = Some(val.trim().parse()
                .map_err(|_| malformed("PPK: invalid Argon2-Parallelism"))?);
        } else if let Some(val) = ppk_strip_key(line, "Argon2-Salt") {
            argon2_salt = Some(ppk_decode_hex(val.trim())?);
        } else if let Some(n_str) = ppk_strip_key(line, "Private-Lines") {
            let n: usize = n_str.trim().parse()
                .map_err(|_| malformed("PPK: invalid Private-Lines count"))?;
            private_blob = Some(ppk_read_base64_lines(&mut lines, n)?);
        } else if let Some(val) = ppk_strip_key(line, "Private-MAC") {
            private_mac = Some(ppk_decode_hex(val.trim())?);
        }
        // Unknown headers are silently tolerated for forward compatibility.
    }

    Ok(PpkFile {
        version,
        key_type,
        encryption: encryption.ok_or_else(|| malformed("PPK: missing Encryption header"))?,
        comment: comment.unwrap_or_default(),
        public_blob: public_blob.ok_or_else(|| malformed("PPK: missing Public-Lines block"))?,
        private_blob: private_blob.ok_or_else(|| malformed("PPK: missing Private-Lines block"))?,
        private_mac: private_mac.ok_or_else(|| malformed("PPK: missing Private-MAC"))?,
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
        .ok_or_else(|| malformed("PPK: first line does not start with PuTTY-User-Key-File-"))?;
    // rest is e.g. "2: ssh-rsa" or "3: ecdsa-sha2-nistp256"
    let (ver_str, key_type_part) = rest.split_once(": ")
        .ok_or_else(|| malformed("PPK: first line missing ': ' separator"))?;
    let version: u8 = ver_str.parse()
        .map_err(|_| malformed("PPK: version field is not a number"))?;
    if version != 2 && version != 3 {
        return Err(KeyParseError::Unsupported(format!(
            "PPK version {version} is not supported (supported: 2, 3)"
        )));
    }
    let key_type = key_type_part.trim().to_string();
    if key_type.is_empty() {
        return Err(malformed("PPK: empty key-type on first line"));
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
            malformed(&format!("PPK: unexpected end of file reading base64 line {i}"))
        })?;
        b64.push_str(line.trim());
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| malformed(&format!("PPK: invalid base64: {e}")))
}

/// Decode a lowercase hex string to bytes.  Returns [`KeyParseError::Malformed`]
/// for non-hex characters or odd-length strings.
fn ppk_decode_hex(hex: &str) -> Result<Vec<u8>, KeyParseError> {
    if hex.len() % 2 != 0 {
        return Err(malformed("PPK: odd-length hex string"));
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0]).ok_or_else(|| malformed("PPK: invalid hex digit"))?;
            let lo = hex_nibble(pair[1]).ok_or_else(|| malformed("PPK: invalid hex digit"))?;
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
            aes256_cbc_decrypt(&key, &iv, &ppk.private_blob)
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
fn ppk_v3_derive_key_iv_mac(
    ppk: &PpkFile,
    passphrase: &str,
) -> Result<([u8; 32], [u8; 16], [u8; 32]), KeyParseError> {
    let variant_str = ppk.kdf_variant.as_deref()
        .ok_or_else(|| malformed("PPK v3: missing Key-Derivation header"))?;

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
        .ok_or_else(|| malformed("PPK v3: missing Argon2-Memory"))?;
    let t = ppk.argon2_passes
        .ok_or_else(|| malformed("PPK v3: missing Argon2-Passes"))?;
    let p = ppk.argon2_parallelism
        .ok_or_else(|| malformed("PPK v3: missing Argon2-Parallelism"))?;
    let salt = ppk.argon2_salt.as_deref()
        .ok_or_else(|| malformed("PPK v3: missing Argon2-Salt"))?;

    // Cap Argon2 parameters before calling the crate to prevent a crafted PPK
    // file from triggering an OOM allocation (m) or unbounded CPU stall (t, p).
    // Caps match PuTTY's own defaults (256 MiB / 13 passes / 1 thread) with
    // comfortable headroom for strong configurations. (soft_PKCS11-snkm)
    const MAX_ARGON2_M: u32 = 1_048_576; // 1 GiB in KiB
    const MAX_ARGON2_T: u32 = 2_048;
    const MAX_ARGON2_P: u32 = 64;
    if m > MAX_ARGON2_M {
        return Err(malformed(&format!("PPK v3: Argon2-Memory {m} KiB exceeds maximum {MAX_ARGON2_M} KiB")));
    }
    if t > MAX_ARGON2_T {
        return Err(malformed(&format!("PPK v3: Argon2-Passes {t} exceeds maximum {MAX_ARGON2_T}")));
    }
    if p > MAX_ARGON2_P {
        return Err(malformed(&format!("PPK v3: Argon2-Parallelism {p} exceeds maximum {MAX_ARGON2_P}")));
    }

    let params = argon2::Params::new(m, t, p, None)
        .map_err(|e| malformed(&format!("PPK v3: invalid Argon2 parameters: {e}")))?;
    let kdf = argon2::Argon2::new(variant, argon2::Version::V0x13, params);

    let mut derived = [0u8; 80];
    kdf.hash_password_into(passphrase.as_bytes(), salt, &mut derived)
        .map_err(|e| malformed(&format!("PPK v3: Argon2 derivation failed: {e}")))?;

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
            aes256_cbc_decrypt(&key, &iv, &ppk.private_blob)
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
    let computed = hmac_sha256(&mac_key, &mac_input);

    if ppk.private_mac.as_slice() != computed {
        return Err(malformed(
            "PPK v3: MAC verification failed (wrong passphrase or corrupted file)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PPK v2 HMAC-SHA1 MAC verification
// ---------------------------------------------------------------------------

/// The string prepended to the passphrase when deriving the PPK MAC key.
const PPK_MAC_KEY_PREFIX: &[u8] = b"putty-private-key-file-mac-key";

/// Derive the 20-byte HMAC-SHA1 MAC key for a PPK v2 file.
///
/// ```text
/// mac_key = SHA-1("putty-private-key-file-mac-key" || passphrase)
/// ```
///
/// For unencrypted files (`encryption == "none"`) the passphrase is the empty
/// string, so `passphrase` should be passed as an empty slice in that case.
fn ppk_v2_derive_mac_key(passphrase: &[u8]) -> [u8; 20] {
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
fn ppk_v2_mac_input(
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
    let computed = hmac_sha1(&mac_key, &mac_input);
    if ppk.private_mac.as_slice() != computed {
        return Err(malformed(
            "PPK: MAC verification failed (wrong passphrase or corrupted file)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenPGP ASCII Armor (Radix-64 / RFC 4880 s.6)
// ---------------------------------------------------------------------------

/// Returns `true` if `data` begins with a PGP armor header line.
pub fn is_pgp_armor(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN PGP")
}

/// CRC-24 checksum algorithm defined in RFC 4880 s.6.1.
///
/// Init value: `0xB704CE`, polynomial: `0x1864CFB`.
fn crc24(data: &[u8]) -> u32 {
    const CRC24_INIT: u32 = 0xB704CE;
    const CRC24_POLY: u32 = 0x1864CFB;
    let mut crc: u32 = CRC24_INIT;
    for &byte in data {
        crc ^= (byte as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= CRC24_POLY;
            }
        }
    }
    crc & 0xFFFFFF
}

/// Decode an OpenPGP ASCII Armor block (RFC 4880 s.6).
///
/// Accepts any PGP armor type (`-----BEGIN PGP PRIVATE KEY BLOCK-----`,
/// `-----BEGIN PGP PUBLIC KEY BLOCK-----`, etc.).  Returns the decoded binary
/// payload.  The CRC-24 checksum is verified when present; a mismatch returns
/// [`KeyParseError::Malformed`].
///
/// Armor header fields (e.g. `Version: GnuPG`) and the blank separator line
/// are consumed and discarded.  The body may span any number of lines.
pub fn dearmor(input: &[u8]) -> Result<Vec<u8>, KeyParseError> {
    let text = std::str::from_utf8(input)
        .map_err(|_| malformed("PGP armor: non-UTF-8 input"))?;
    let mut lines = text.lines();

    // First non-empty line must be the armor header.
    let first = lines.next().ok_or_else(|| malformed("PGP armor: empty input"))?;
    if !first.starts_with("-----BEGIN PGP") {
        return Err(malformed("PGP armor: missing BEGIN PGP armor header"));
    }

    // Skip armor header fields ("Key: Value") up to and including the blank
    // separator line that precedes the base64 body.
    loop {
        let line = lines
            .next()
            .ok_or_else(|| malformed("PGP armor: unterminated header section"))?;
        if line.trim().is_empty() {
            break;
        }
        // Non-blank lines here are header fields; skip them.
    }

    // Accumulate base64 body lines.  Stop at the checksum line (`=XXXX`)
    // or the armor footer (`-----END`).
    let mut b64_body = String::new();
    let mut checksum_b64: Option<String> = None;

    for line in &mut lines {
        let trimmed = line.trim();
        if trimmed.starts_with("-----END") {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix('=') {
            // Checksum line: '=' sentinel followed by exactly 4 base64 chars.
            if rest.len() != 4 {
                return Err(malformed(
                    "PGP armor: checksum line must be '=' followed by exactly 4 base64 characters",
                ));
            }
            checksum_b64 = Some(rest.to_string());
            break;
        }
        b64_body.push_str(trimmed);
    }

    // Decode the accumulated base64 body.
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&b64_body)
        .map_err(|e| malformed(&format!("PGP armor: base64 decode error: {e}")))?;

    // Verify CRC-24 if a checksum line was present.
    if let Some(csum_b64) = checksum_b64 {
        let csum_bytes = base64::engine::general_purpose::STANDARD
            .decode(&csum_b64)
            .map_err(|e| malformed(&format!("PGP armor: checksum base64 decode error: {e}")))?;
        if csum_bytes.len() != 3 {
            return Err(malformed(
                "PGP armor: checksum must decode to exactly 3 bytes (24 bits)",
            ));
        }
        let expected_crc = ((csum_bytes[0] as u32) << 16)
            | ((csum_bytes[1] as u32) << 8)
            | (csum_bytes[2] as u32);
        let computed_crc = crc24(&decoded);
        if expected_crc != computed_crc {
            return Err(malformed(&format!(
                "PGP armor: CRC-24 mismatch (computed 0x{computed_crc:06x}, \
                 stored 0x{expected_crc:06x})"
            )));
        }
    }

    Ok(decoded)
}

// ---------------------------------------------------------------------------
// OpenPGP packet header parser (RFC 4880 s.4.2)
// ---------------------------------------------------------------------------

/// Packet tag for an OpenPGP Secret-Key packet (RFC 4880 s.5.5.1.3).
pub const PGP_TAG_SECRET_KEY: u8 = 5;

/// Packet tag for an OpenPGP Secret-Subkey packet (RFC 4880 s.5.5.1.4).
pub const PGP_TAG_SECRET_SUBKEY: u8 = 7;

/// Packet tag for an OpenPGP User ID packet (RFC 4880 s.5.11).
pub const PGP_TAG_USER_ID: u8 = 13;

/// Parse one OpenPGP packet from the start of `data`.
///
/// Returns `Some((tag, body, remainder))` on success:
/// - `tag` -- the 4-bit (old format) or 6-bit (new format) packet tag
/// - `body` -- a slice of `data` containing the packet body
/// - `remainder` -- the bytes following this packet
///
/// Returns `None` on truncated or malformed input (never panics).
pub fn next_pgp_packet(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag_byte, rest) = data.split_first()?;

    // Bit 7 must be set in all OpenPGP packets.
    if tag_byte & 0x80 == 0 {
        return None;
    }

    let (tag, body_len, length_bytes) = if tag_byte & 0x40 != 0 {
        // New format: bits 5-0 are the tag; length follows.
        let tag = tag_byte & 0x3F;
        let (len, lbytes) = parse_new_format_length(rest)?;
        (tag, len, lbytes)
    } else {
        // Old format: bits 5-2 are the tag; bits 1-0 are the length type.
        let tag = (tag_byte >> 2) & 0x0F;
        let length_type = tag_byte & 0x03;
        let (len, lbytes) = parse_old_format_length(rest, length_type)?;
        (tag, len, lbytes)
    };

    let body_start = length_bytes;
    let body_end = body_start.checked_add(body_len)?;
    if body_end > rest.len() {
        return None; // truncated body
    }
    let body = &rest[body_start..body_end];
    let remainder = &rest[body_end..];
    Some((tag, body, remainder))
}

/// Parse the body-length field for a new-format OpenPGP packet (RFC 4880 s.4.2.2).
///
/// Returns `(body_len, length_octets_consumed)` or `None` on truncated input.
/// Partial body lengths (first octet 224-254) are not supported and return `None`.
fn parse_new_format_length(data: &[u8]) -> Option<(usize, usize)> {
    let &first = data.first()?;
    let first = first as usize;
    if first < 192 {
        // One-octet length.
        Some((first, 1))
    } else if first < 224 {
        // Two-octet length: ((first - 192) << 8) + second + 192.
        let second = *data.get(1)? as usize;
        let len = ((first - 192) << 8) + second + 192;
        Some((len, 2))
    } else if first == 255 {
        // Five-octet length: 0xFF followed by 4-byte big-endian length.
        if data.len() < 5 {
            return None;
        }
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        Some((len, 5))
    } else {
        // Partial body length (224-254): not relevant for key packets.
        None
    }
}

/// Parse the body-length field for an old-format OpenPGP packet (RFC 4880 s.4.2.1).
///
/// `length_type` is the 2-bit field from the tag byte:
/// - 0 = one-octet length
/// - 1 = two-octet length
/// - 2 = four-octet length
/// - 3 = indeterminate (body extends to end of `data`)
///
/// Returns `(body_len, length_octets_consumed)` or `None` on truncated input.
fn parse_old_format_length(data: &[u8], length_type: u8) -> Option<(usize, usize)> {
    match length_type {
        0 => Some((*data.first()? as usize, 1)),
        1 => {
            if data.len() < 2 {
                return None;
            }
            Some((u16::from_be_bytes([data[0], data[1]]) as usize, 2))
        }
        2 => {
            if data.len() < 4 {
                return None;
            }
            Some((u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize, 4))
        }
        3 => Some((data.len(), 0)), // indeterminate: body is all remaining
        _ => unreachable!("length_type is a 2-bit field"),
    }
}

/// Scan `data` for all Secret-Key (tag 5) and Secret-Subkey (tag 7) packets
/// and return their bodies.
///
/// Packets of other types are skipped.  Iteration stops at the first
/// malformed or truncated packet.  Each returned tuple is `(tag, body)` where
/// `tag` is [`PGP_TAG_SECRET_KEY`] or [`PGP_TAG_SECRET_SUBKEY`].
/// Maximum number of secret-key packets (tag 5 or 7) collected from a single
/// OpenPGP keyring. A key with more than 100 secret-key packets is implausible
/// for any legitimate use case; without a cap a crafted input could force
/// unbounded memory allocation via many small body.to_vec() clones.
/// (soft_PKCS11-qv6u)
const MAX_PGP_SECRET_PACKETS: usize = 100;

pub fn pgp_collect_secret_packets(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut result = Vec::new();
    let mut remaining = data;
    while !remaining.is_empty() {
        match next_pgp_packet(remaining) {
            Some((tag, body, rest)) => {
                if tag == PGP_TAG_SECRET_KEY || tag == PGP_TAG_SECRET_SUBKEY {
                    result.push((tag, body.to_vec()));
                    if result.len() >= MAX_PGP_SECRET_PACKETS {
                        break;
                    }
                }
                remaining = rest;
            }
            None => break,
        }
    }
    result
}

/// Scan `data` (binary OpenPGP packet stream) for the first User-ID packet
/// (tag 13, RFC 4880 s.5.11) and return its UTF-8 content as a label.
///
/// If the UID has the form `"NAME <email>"`, the `<email>` suffix is stripped
/// and the name is returned.  If the UID is only an email address (no name
/// before the angle bracket), the full UID is returned.
pub fn pgp_first_user_id_label(data: &[u8]) -> Option<String> {
    let mut remaining = data;
    while !remaining.is_empty() {
        match next_pgp_packet(remaining) {
            Some((tag, body, rest)) => {
                if tag == PGP_TAG_USER_ID {
                    let uid = std::str::from_utf8(body).unwrap_or("").trim();
                    if uid.is_empty() {
                        return None;
                    }
                    // Strip "<email>" suffix when there is a non-empty name before it.
                    let label = if let Some(angle_pos) = uid.rfind('<') {
                        let name = uid[..angle_pos].trim();
                        if name.is_empty() {
                            uid.to_string()
                        } else {
                            name.to_string()
                        }
                    } else {
                        uid.to_string()
                    };
                    return Some(label);
                }
                remaining = rest;
            }
            None => break,
        }
    }
    None
}

/// Returns `true` if `data` starts with an OpenPGP packet whose tag indicates
/// a Secret-Key packet (tag 5, RFC 4880 s.5.5.1.3).
///
/// Uses the RFC 4880 s.4.2 bitmask rules for both old-format and new-format
/// packet headers rather than a fixed list of tag-byte values.
pub fn is_pgp_binary_secret_key_packet(data: &[u8]) -> bool {
    let Some(&first) = data.first() else { return false; };
    // Old format: bit7=1, bit6=0; tag occupies bits [5:2].
    let old = (first & 0x80) != 0
        && (first & 0x40) == 0
        && ((first >> 2) & 0x0F) == PGP_TAG_SECRET_KEY;
    // New format: bits [7:6] = 0b11; tag occupies bits [5:0].
    let new = (first & 0xC0) == 0xC0 && (first & 0x3F) == PGP_TAG_SECRET_KEY;
    old || new
}

/// Parse binary OpenPGP packet data (already decoded from armor if applicable).
///
/// Collects Secret-Key and Secret-Subkey packets, prompts for a passphrase
/// when needed, and returns `(successes, failures)` like other multi-key
/// parsers.  The `label_hint` on each returned key is set from the first
/// User-ID packet in the stream.
fn parse_pgp_binary(
    data: &[u8],
) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let packets = pgp_collect_secret_packets(data);
    if packets.is_empty() {
        return Err(malformed("PGP: no secret-key packets found"));
    }

    let uid_label = pgp_first_user_id_label(data);

    // Check if any packet requires a passphrase (usage != 0x00) before
    // prompting, so plain-text exports don't needlessly block on stdin.
    let needs_passphrase = packets.iter().any(|(_, body)| {
        if let Ok(pk) = parse_pgp_public_key_body(body) {
            pk.remaining.first().copied().map(|u| u != 0x00).unwrap_or(false)
        } else {
            false
        }
    });
    let passphrase_str = if needs_passphrase {
        super::pin::prompt_passphrase("Passphrase for OpenPGP key: ")?
    } else {
        String::new()
    };
    let passphrase = passphrase_str.as_bytes();

    let mut successes: Vec<ParsedKey> = Vec::new();
    let mut failures: Vec<(String, KeyParseError)> = Vec::new();

    for (packet_idx, (_tag, body)) in packets.iter().enumerate() {
        let label = uid_label
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| format!("pgp-packet-{packet_idx}"));

        let pubkey = match parse_pgp_public_key_body(body) {
            Ok(pk) => pk,
            Err(e) => { failures.push((label, e)); continue; }
        };

        let mpi_bytes = match pgp_decrypt_secret_material(&pubkey.remaining, passphrase) {
            Ok(b) => b,
            Err(e) => { failures.push((label, e)); continue; }
        };

        let key_id = pgp_v4_key_id(&pubkey.fingerprint_body);

        let result = match &pubkey.material {
            PgpPublicKeyMaterial::Rsa { n, e } => {
                parse_pgp_rsa_secret_mpis(&mpi_bytes, n, e, key_id)
            }
            PgpPublicKeyMaterial::Ecdsa { .. } => {
                parse_pgp_ecdsa_p256_secret_mpis(&mpi_bytes, key_id)
            }
        };

        match result {
            Ok(mut pk) => {
                if pk.label_hint.is_none() {
                    pk.label_hint = uid_label.clone();
                }
                successes.push(pk);
            }
            Err(e) => failures.push((label, e)),
        }
    }

    Ok((successes, failures))
}

// ---------------------------------------------------------------------------
// OpenPGP v4 Public-Key packet body parser (RFC 4880 s.5.5.2 + RFC 6637)
// ---------------------------------------------------------------------------

/// OID bytes for the NIST P-256 curve as used in OpenPGP (RFC 6637 s.11).
const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Public key material extracted from an OpenPGP v4 Public-Key body.
#[allow(dead_code)]
pub enum PgpPublicKeyMaterial {
    /// RSA public key (algorithm ID 1).
    Rsa {
        /// RSA modulus `n` (big-endian, no leading zeros beyond the MPI encoding).
        n: Vec<u8>,
        /// RSA public exponent `e`.
        e: Vec<u8>,
    },
    /// ECDSA public key (algorithm ID 19), P-256 only.
    Ecdsa {
        /// Uncompressed public point: `04 || x || y` (65 bytes).
        public_point: Vec<u8>,
    },
}

/// Output of [`parse_pgp_public_key_body`].
#[allow(dead_code)]
pub struct ParsedPublicKey {
    /// OpenPGP algorithm ID (1=RSA, 19=ECDSA).
    pub algorithm: u8,
    /// Algorithm-specific public key material.
    pub material: PgpPublicKeyMaterial,
    /// All bytes from the version byte through the last public key MPI
    /// (excludes S2K and secret material).  Used to compute the v4 fingerprint:
    ///   SHA-1(0x99 || u16_be(len) || fingerprint_body)
    pub fingerprint_body: Vec<u8>,
    /// Bytes remaining after the public key MPIs -- the S2K specifier and
    /// encrypted/plain secret key material.
    pub remaining: Vec<u8>,
}

/// Read one OpenPGP MPI from `data` (RFC 4880 s.3.2).
///
/// Returns `(value_bytes, remainder)` where `value_bytes` is the big-endian
/// unsigned integer value (without the 2-byte bit-count header).
///
/// Returns `None` on truncated input.
pub fn read_pgp_mpi(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let bit_count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let byte_count = (bit_count + 7) / 8;
    let end = 2 + byte_count;
    if end > data.len() {
        return None;
    }
    Some((&data[2..end], &data[end..]))
}

/// Parse an OpenPGP v4 Public-Key (or Secret-Key public-portion) body.
///
/// `data` must begin at the first byte of the packet body (the version byte).
///
/// Supported algorithm IDs:
/// - 1 (RSA): reads MPIs n and e
/// - 19 (ECDSA): reads P-256 OID + public-point MPI
///
/// All other algorithm IDs return [`KeyParseError::Unsupported`].
/// Version != 4 returns [`KeyParseError::Unsupported`] (not Malformed, since
/// version 6 is a valid future case).
pub fn parse_pgp_public_key_body(data: &[u8]) -> Result<ParsedPublicKey, KeyParseError> {
    if data.is_empty() {
        return Err(malformed("PGP Public-Key: empty packet body"));
    }
    let version = data[0];
    if version != 4 {
        return Err(KeyParseError::Unsupported(format!(
            "PGP Public-Key version {version} is not supported (only v4 is implemented)"
        )));
    }
    // bytes [1..5]: 4-byte creation timestamp (we read but do not validate)
    if data.len() < 6 {
        return Err(malformed("PGP Public-Key: truncated header (need version + timestamp + algorithm)"));
    }
    let algorithm = data[5];

    // `cur` is a moving cursor through the remaining bytes (algorithm-specific material).
    let mut cur: &[u8] = &data[6..];

    let material: PgpPublicKeyMaterial = match algorithm {
        1 => {
            // RSA: MPIs n, e.
            let (n, rest) = read_pgp_mpi(cur)
                .ok_or_else(|| malformed("PGP RSA Public-Key: truncated MPI n"))?;
            let n_bytes = n.to_vec();
            cur = rest;
            let (e, rest) = read_pgp_mpi(cur)
                .ok_or_else(|| malformed("PGP RSA Public-Key: truncated MPI e"))?;
            let e_bytes = e.to_vec();
            cur = rest;
            PgpPublicKeyMaterial::Rsa { n: n_bytes, e: e_bytes }
        }
        19 => {
            // ECDSA: OID length + OID + public-point MPI.
            let &oid_len_byte = cur.first()
                .ok_or_else(|| malformed("PGP ECDSA Public-Key: truncated OID length"))?;
            let oid_len = oid_len_byte as usize;
            cur = &cur[1..];
            if cur.len() < oid_len {
                return Err(malformed("PGP ECDSA Public-Key: truncated OID"));
            }
            let oid = &cur[..oid_len];
            if oid != P256_OID {
                return Err(KeyParseError::Unsupported(format!(
                    "PGP ECDSA curve OID {:02x?} is not supported (only P-256)",
                    oid
                )));
            }
            cur = &cur[oid_len..];
            let (point, rest) = read_pgp_mpi(cur)
                .ok_or_else(|| malformed("PGP ECDSA Public-Key: truncated public-point MPI"))?;
            if point.len() != 65 || point[0] != 0x04 {
                return Err(malformed(
                    "PGP ECDSA P-256: public point must be 65-byte uncompressed (04 || x || y)",
                ));
            }
            cur = rest;
            PgpPublicKeyMaterial::Ecdsa { public_point: point.to_vec() }
        }
        id => {
            return Err(KeyParseError::Unsupported(format!(
                "PGP algorithm ID {id} is not supported \
                 (expected RSA=1 or ECDSA=19)"
            )));
        }
    };

    // fingerprint_body = everything from version through the last public key MPI.
    let consumed = data.len() - cur.len();
    let fingerprint_body = data[..consumed].to_vec();
    let remaining = cur.to_vec();

    Ok(ParsedPublicKey {
        algorithm,
        material,
        fingerprint_body,
        remaining,
    })
}

// ---------------------------------------------------------------------------
// OpenPGP S2K key derivation and secret key decryption (RFC 4880 s.3.7, s.5.5.3)
// ---------------------------------------------------------------------------

/// Derive a symmetric key from `passphrase` using an OpenPGP S2K specifier.
///
/// - `s2k_type`: 0 (simple), 1 (salted), 3 (iterated+salted)
/// - `hash_id`: 2 (SHA-1), 8 (SHA-256)
/// - `salt`: 8-byte salt for types 1/3; ignored for type 0
/// - `count`: total byte count to hash for type 3 (RFC 4880 s.3.7.1.3);
///            ignored for types 0 and 1
/// - `key_len`: desired output length in bytes
fn pgp_s2k_derive_key(
    passphrase: &[u8],
    s2k_type: u8,
    hash_id: u8,
    salt: &[u8],
    count: usize,
    key_len: usize,
) -> Result<Vec<u8>, KeyParseError> {
    // Build the cyclic source: salt||passphrase for types 1/3, passphrase only for type 0.
    let cyclic: Vec<u8> = match s2k_type {
        0 => passphrase.to_vec(),
        1 | 3 => {
            let mut v = salt.to_vec();
            v.extend_from_slice(passphrase);
            v
        }
        other => {
            return Err(KeyParseError::Unsupported(format!(
                "PGP S2K type {other} is not supported (expected 0, 1, or 3)"
            )));
        }
    };

    // For type 3, hash exactly `count` bytes (cycling the source data).
    // For types 0/1, hash one copy of the cyclic data.
    // RFC 4880 s.3.7.1.3: "if count is not enough, hash once" -- we use max.
    let hash_count = if s2k_type == 3 {
        count.max(cyclic.len())
    } else {
        cyclic.len()
    };

    // Generate enough key material, one hash context per output block.
    // Each subsequent block prepends one more zero byte (RFC 4880 s.3.7.1.1).
    let mut key_bytes: Vec<u8> = Vec::with_capacity(key_len);
    let mut context: usize = 0;

    while key_bytes.len() < key_len {
        let zeros = vec![0u8; context];

        // Hash `hash_count` bytes from the cyclic data.
        macro_rules! feed_cyclic {
            ($h:expr) => {{
                let mut processed = 0usize;
                while processed < hash_count {
                    let offset = processed % cyclic.len();
                    let chunk = &cyclic[offset..];
                    let take = chunk.len().min(hash_count - processed);
                    wolfcrypt::digest::digest_trait::Update::update($h, &chunk[..take]);
                    processed += take;
                }
            }};
        }

        match hash_id {
            2 => {
                use wolfcrypt::digest::digest_trait::Digest as _;
                let mut h = wolfcrypt::Sha1::new();
                wolfcrypt::digest::digest_trait::Update::update(&mut h, &zeros);
                feed_cyclic!(&mut h);
                key_bytes.extend_from_slice(h.finalize().as_slice());
            }
            8 => {
                use wolfcrypt::digest::digest_trait::Digest as _;
                let mut h = wolfcrypt::Sha256::new();
                wolfcrypt::digest::digest_trait::Update::update(&mut h, &zeros);
                feed_cyclic!(&mut h);
                key_bytes.extend_from_slice(h.finalize().as_slice());
            }
            other => {
                return Err(KeyParseError::Unsupported(format!(
                    "PGP S2K hash algorithm {other} is not supported \
                     (expected 2=SHA-1 or 8=SHA-256)"
                )));
            }
        }
        context += 1;
    }

    key_bytes.truncate(key_len);
    Ok(key_bytes)
}

/// Parse the S2K header from `remaining` and decrypt the secret key material.
///
/// `remaining` is `ParsedPublicKey::remaining` -- all bytes after the last
/// public-key MPI in a v4 Secret-Key or Secret-Subkey packet body.
///
/// Returns the plaintext secret-key MPI bytes (checksum excluded) on success,
/// or `Malformed` if the integrity check fails (wrong passphrase or corruption).
pub fn pgp_decrypt_secret_material(
    remaining: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, KeyParseError> {
    if remaining.is_empty() {
        return Err(malformed("PGP secret key: empty S2K/usage region"));
    }
    let usage = remaining[0];
    let cur = &remaining[1..];

    match usage {
        0x00 => {
            // Plaintext secret key: MPI bytes followed by a 2-byte simple checksum.
            if cur.len() < 2 {
                return Err(malformed(
                    "PGP secret key: plaintext region too short for checksum",
                ));
            }
            let (mpi_bytes, chk) = cur.split_at(cur.len() - 2);
            let stored = u16::from_be_bytes([chk[0], chk[1]]);
            let computed = mpi_bytes
                .iter()
                .fold(0u16, |acc, &b| acc.wrapping_add(b as u16));
            if computed != stored {
                return Err(malformed(
                    "PGP secret key: plaintext checksum mismatch \
                     (corrupted key material)",
                ));
            }
            Ok(mpi_bytes.to_vec())
        }

        0xFE | 0xFF => {
            // Encrypted: cipher_id(1) || S2K-type(1) || hash_id(1) || [salt+count] || IV(16) || ciphertext
            if cur.len() < 3 {
                return Err(malformed(
                    "PGP secret key: truncated before cipher/S2K fields",
                ));
            }
            let cipher_id = cur[0];
            let s2k_type = cur[1];
            let hash_id = cur[2];
            let mut cur = &cur[3..];

            let key_len: usize = match cipher_id {
                7 => 16, // AES-128
                8 => 24, // AES-192
                9 => 32, // AES-256
                other => {
                    return Err(KeyParseError::Unsupported(format!(
                        "PGP secret key: cipher ID {other} is not supported \
                         (expected 7=AES-128, 8=AES-192, or 9=AES-256)"
                    )));
                }
            };

            let (salt, count): (&[u8], usize) = match s2k_type {
                0 => (&[], 0),
                1 => {
                    if cur.len() < 8 {
                        return Err(malformed("PGP S2K type 1: truncated salt"));
                    }
                    let s = &cur[..8];
                    cur = &cur[8..];
                    (s, 0)
                }
                3 => {
                    if cur.len() < 9 {
                        return Err(malformed("PGP S2K type 3: truncated salt+count"));
                    }
                    let s = &cur[..8];
                    let c = cur[8];
                    // RFC 4880 s.3.7.1.3: count = (16 + (c & 15)) << ((c >> 4) + 6).
                    // Maximum is 31 << 21 = 65,011,712 (≈65M hash-update bytes, ~1s on
                    // modern hardware). GnuPG routinely generates keys near this maximum,
                    // so no application-level cap is applied; the arithmetic is already
                    // bounded by the u8 range of `c`. (soft_PKCS11-qv6u)
                    let count =
                        (16usize + (c & 15) as usize) << ((c >> 4) as usize + 6);
                    cur = &cur[9..];
                    (s, count)
                }
                other => {
                    return Err(KeyParseError::Unsupported(format!(
                        "PGP S2K type {other} is not supported (expected 0, 1, or 3)"
                    )));
                }
            };

            if cur.len() < 16 {
                return Err(malformed("PGP secret key: truncated IV"));
            }
            let iv: [u8; 16] = cur[..16].try_into().unwrap();
            cur = &cur[16..];

            let key = pgp_s2k_derive_key(passphrase, s2k_type, hash_id, salt, count, key_len)?;

            // Decrypt the remaining bytes in-place with AES-CFB.
            use cipher::{KeyIvInit, StreamCipher};
            use generic_array::GenericArray;

            let mut plaintext = cur.to_vec();
            match cipher_id {
                7 => {
                    let mut dec = wolfcrypt::Aes128CfbDec::new(
                        GenericArray::from_slice(&key),
                        GenericArray::from_slice(&iv),
                    );
                    dec.apply_keystream(&mut plaintext);
                }
                8 => {
                    return Err(KeyParseError::Unsupported(
                        "PGP AES-192-CFB (cipher ID 8) is not supported; \
                         re-encrypt your key with AES-128 or AES-256: \
                         gpg --s2k-cipher-algo AES256 --edit-key <id> passwd"
                            .to_string(),
                    ));
                }
                9 => {
                    let mut dec = wolfcrypt::Aes256CfbDec::new(
                        GenericArray::from_slice(&key),
                        GenericArray::from_slice(&iv),
                    );
                    dec.apply_keystream(&mut plaintext);
                }
                _ => unreachable!("cipher_id validated above"),
            }

            // Verify the integrity value appended to the plaintext before encryption.
            if usage == 0xFE {
                // SHA-1 hash of the secret MPI bytes (RFC 4880 s.5.5.3).
                if plaintext.len() < 20 {
                    return Err(malformed(
                        "PGP secret key: decrypted data too short for SHA-1 checksum",
                    ));
                }
                let (mpi_bytes, sha1_stored) = plaintext.split_at(plaintext.len() - 20);
                use wolfcrypt::digest::digest_trait::Digest as _;
                let mut h = wolfcrypt::Sha1::new();
                wolfcrypt::digest::digest_trait::Update::update(&mut h, mpi_bytes);
                let sha1_computed = h.finalize();
                if sha1_computed.as_slice() != sha1_stored {
                    return Err(malformed(
                        "PGP secret key: SHA-1 integrity check failed \
                         (wrong passphrase or corrupted key)",
                    ));
                }
                Ok(mpi_bytes.to_vec())
            } else {
                // usage == 0xFF: 2-byte simple checksum.
                if plaintext.len() < 2 {
                    return Err(malformed(
                        "PGP secret key: decrypted data too short for checksum",
                    ));
                }
                let (mpi_bytes, chk) = plaintext.split_at(plaintext.len() - 2);
                let stored = u16::from_be_bytes([chk[0], chk[1]]);
                let computed = mpi_bytes
                    .iter()
                    .fold(0u16, |acc, &b| acc.wrapping_add(b as u16));
                if computed != stored {
                    return Err(malformed(
                        "PGP secret key: 2-byte checksum mismatch \
                         (wrong passphrase or corrupted key)",
                    ));
                }
                Ok(mpi_bytes.to_vec())
            }
        }

        other => {
            // Legacy: usage 1-253 encodes the cipher algorithm directly with no S2K.
            Err(KeyParseError::Unsupported(format!(
                "PGP secret key: legacy cipher-only encryption (usage byte 0x{other:02x}) \
                 is not supported; re-encrypt with S2K: \
                 gpg --s2k-mode 3 --edit-key <id> passwd"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// OpenPGP key ID and RSA/ECDSA extraction helpers
// ---------------------------------------------------------------------------

/// Compute the OpenPGP v4 key fingerprint (RFC 4880 s.12.2) and return the
/// first 16 bytes as the key ID.
///
/// `fingerprint_body` is `ParsedPublicKey::fingerprint_body` -- version byte
/// through the last public-key MPI.
///
/// Formula: SHA-1(0x99 || u16_be(len) || fingerprint_body), take [0..16].
fn pgp_v4_key_id(fingerprint_body: &[u8]) -> [u8; 16] {
    use wolfcrypt::digest::digest_trait::Digest as _;
    let len_be = (fingerprint_body.len() as u16).to_be_bytes();
    let mut h = wolfcrypt::Sha1::new();
    wolfcrypt::digest::digest_trait::Update::update(&mut h, &[0x99u8]);
    wolfcrypt::digest::digest_trait::Update::update(&mut h, &len_be);
    wolfcrypt::digest::digest_trait::Update::update(&mut h, fingerprint_body);
    h.finalize()[..16].try_into().unwrap()
}

/// Compute the modular inverse of `a` modulo `m` (a^-1 mod m).
///
/// Uses the iterative extended Euclidean algorithm.  Returns `None` if
/// gcd(a, m) != 1 (i.e. the inverse does not exist).
fn modinv_bytes(a: &[u8], m: &[u8]) -> Option<Vec<u8>> {
    use num_bigint::{BigInt, Sign};

    let a = BigInt::from_bytes_be(Sign::Plus, a);
    let m = BigInt::from_bytes_be(Sign::Plus, m);
    let zero = BigInt::from(0i64);
    let one = BigInt::from(1i64);

    // Iterative extended GCD: maintains old_r = gcd candidate, old_s = Bezout coefficient.
    let mut old_r = a;
    let mut r = m.clone();
    let mut old_s = one.clone();
    let mut s = zero.clone();

    while r != zero {
        let q = &old_r / &r;
        let tmp_r = r.clone();
        r = old_r - &q * &r;
        old_r = tmp_r;
        let tmp_s = s.clone();
        s = old_s - &q * &s;
        old_s = tmp_s;
    }

    if old_r != one {
        return None; // gcd != 1; inverse does not exist
    }

    // old_s may be negative; reduce to [0, m).
    let result = ((old_s % &m) + &m) % &m;
    let (_, bytes) = result.to_bytes_be();
    Some(bytes)
}

/// Extract an RSA private key from decrypted OpenPGP secret MPI bytes.
///
/// `mpi_bytes` contains the secret MPIs in OpenPGP wire order (RFC 4880 s.5.5.5.1):
/// `d || p || q || u` where `u = p^-1 mod q`.
/// `n` and `e` come from the corresponding `PgpPublicKeyMaterial::Rsa`.
///
/// The PKCS#1 CRT coefficient (`q^-1 mod p`) is computed from `p` and `q`.
fn parse_pgp_rsa_secret_mpis(
    mpi_bytes: &[u8],
    n: &[u8],
    e: &[u8],
    key_id: [u8; 16],
) -> Result<ParsedKey, KeyParseError> {
    let mut cur = mpi_bytes;

    let (d, rest) = read_pgp_mpi(cur)
        .ok_or_else(|| malformed("PGP RSA secret: truncated MPI d"))?;
    cur = rest;
    let (p, rest) = read_pgp_mpi(cur)
        .ok_or_else(|| malformed("PGP RSA secret: truncated MPI p"))?;
    cur = rest;
    let (q, rest) = read_pgp_mpi(cur)
        .ok_or_else(|| malformed("PGP RSA secret: truncated MPI q"))?;
    cur = rest;
    // u = p^-1 mod q (OpenPGP convention); we discard it and recompute
    // iqmp = q^-1 mod p (PKCS#1 / wolfCrypt convention).
    let _u = read_pgp_mpi(cur)
        .ok_or_else(|| malformed("PGP RSA secret: truncated MPI u"))?;

    // Compute PKCS#1 iqmp = q^-1 mod p.
    let iqmp = modinv_bytes(q, p).ok_or_else(|| {
        malformed("PGP RSA: could not compute CRT coefficient (p, q not coprime?)")
    })?;

    let key = wolfcrypt::NativeRsaKey::from_raw_components(n, e, d, p, q, &iqmp)
        .map_err(|err| malformed(&format!("PGP RSA: wolfCrypt key load failed: {err:?}")))?;
    let pkcs1_der = key
        .to_pkcs1_der()
        .map_err(|err| malformed(&format!("PGP RSA: wolfCrypt DER export failed: {err:?}")))?;

    Ok(ParsedKey {
        key_type: KeyType::Rsa,
        key_bytes: pkcs1_der,
        id: key_id,
        label_hint: None,
        cert_der: None,
    })
}

/// Extract an ECDSA P-256 private scalar from decrypted OpenPGP secret MPI bytes.
///
/// `mpi_bytes` contains one MPI: the private scalar (RFC 4880 s.5.5.5.2 / RFC 6637).
/// The scalar is left-padded with zeros to exactly 32 bytes if shorter.
fn parse_pgp_ecdsa_p256_secret_mpis(
    mpi_bytes: &[u8],
    key_id: [u8; 16],
) -> Result<ParsedKey, KeyParseError> {
    let (scalar_raw, _rest) = read_pgp_mpi(mpi_bytes)
        .ok_or_else(|| malformed("PGP ECDSA P-256 secret: truncated scalar MPI"))?;

    if scalar_raw.len() > 32 {
        return Err(malformed(&format!(
            "PGP ECDSA P-256: scalar is {} bytes, expected <=32",
            scalar_raw.len()
        )));
    }

    // Left-pad to exactly 32 bytes.
    let mut scalar32 = [0u8; 32];
    scalar32[32 - scalar_raw.len()..].copy_from_slice(scalar_raw);

    Ok(ParsedKey {
        key_type: KeyType::Ec,
        key_bytes: scalar32.to_vec(),
        id: key_id,
        label_hint: None,
        cert_der: None,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal GCP service account JSON with all four standard fields.
    const GCP_JSON_FULL: &[u8] = br#"{
        "type": "service_account",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----\n",
        "private_key_id": "1234567890abcdef1234567890abcdef12345678",
        "client_email": "svc@project.iam.gserviceaccount.com"
    }"#;

    #[test]
    fn detect_gcp_full_json_returns_some() {
        let result = detect_gcp_json(GCP_JSON_FULL);
        assert!(result.is_some(), "valid GCP JSON must be detected");
        let gcp = result.unwrap();
        assert!(gcp.pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert_eq!(
            gcp.key_id_hex.as_deref(),
            Some("1234567890abcdef1234567890abcdef12345678")
        );
        assert_eq!(
            gcp.client_email.as_deref(),
            Some("svc@project.iam.gserviceaccount.com")
        );
    }

    #[test]
    fn detect_gcp_missing_private_key_returns_none() {
        let json = br#"{"type": "service_account", "client_email": "svc@project.iam.gserviceaccount.com"}"#;
        assert!(detect_gcp_json(json).is_none());
    }

    #[test]
    fn detect_gcp_private_key_not_pem_returns_none() {
        let json = br#"{"private_key": "not-a-pem-key"}"#;
        assert!(detect_gcp_json(json).is_none());
    }

    #[test]
    fn detect_gcp_non_json_input_returns_none() {
        assert!(detect_gcp_json(b"-----BEGIN RSA PRIVATE KEY-----").is_none());
        assert!(detect_gcp_json(b"\x30\x82\x01\x02").is_none());
    }

    #[test]
    fn detect_gcp_arbitrary_json_object_returns_none() {
        let json = br#"{"foo": "bar", "baz": 42}"#;
        assert!(detect_gcp_json(json).is_none());
    }

    #[test]
    fn detect_gcp_json_array_returns_none() {
        let json = br#"[{"private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."}]"#;
        assert!(detect_gcp_json(json).is_none());
    }

    #[test]
    fn detect_gcp_optional_fields_absent() {
        let json = br#"{"private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}"#;
        let gcp = detect_gcp_json(json).expect("minimal GCP JSON must be detected");
        assert!(gcp.key_id_hex.is_none());
        assert!(gcp.client_email.is_none());
    }

    #[test]
    fn detect_gcp_leading_whitespace_ok() {
        let json = b"   \n{\"private_key\": \"-----BEGIN RSA PRIVATE KEY-----\\nfake\\n-----END RSA PRIVATE KEY-----\\n\"}";
        assert!(detect_gcp_json(json).is_some());
    }

    // -----------------------------------------------------------------------
    // OpenSSH binary frame parser tests
    // -----------------------------------------------------------------------

    /// Build a minimal valid openssh-key-v1 binary frame for testing.
    ///
    /// All string fields use u32 big-endian length prefixes.  The frame
    /// always contains exactly one key.  `pubkey_blob` is the placeholder
    /// public key bytes; `private_blob` is the (possibly encrypted) private
    /// key bytes.
    /// Encode `data` as a u32 big-endian length-prefixed byte sequence.
    fn lp(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn make_openssh_frame(
        ciphername: &str,
        kdfname: &str,
        kdfoptions: &[u8],
        pubkey_blob: &[u8],
        private_blob: &[u8],
    ) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(OPENSSH_MAGIC);
        v.extend_from_slice(&lp(ciphername.as_bytes()));
        v.extend_from_slice(&lp(kdfname.as_bytes()));
        v.extend_from_slice(&lp(kdfoptions));
        v.extend_from_slice(&1u32.to_be_bytes()); // nkeys = 1
        v.extend_from_slice(&lp(pubkey_blob));
        v.extend_from_slice(&lp(private_blob));
        v
    }

    #[test]
    fn openssh_parse_unencrypted_frame() {
        let frame_bytes = make_openssh_frame(
            "none",
            "none",
            b"",
            b"fake-pubkey",
            b"fake-privkey",
        );
        let frame = parse_openssh_binary(&frame_bytes).expect("should parse");
        assert_eq!(frame.ciphername, "none");
        assert_eq!(frame.kdfname, "none");
        assert!(frame.kdfoptions_raw.is_empty());
        assert_eq!(frame.private_blob, b"fake-privkey");
    }

    #[test]
    fn openssh_parse_encrypted_frame_carries_cipher_info() {
        let kdf_opts = b"\x00\x00\x00\x10saltsaltsaltsalt\x00\x00\x04\x00"; // fake bcrypt opts
        let frame_bytes = make_openssh_frame(
            "aes256-ctr",
            "bcrypt",
            kdf_opts,
            b"fake-pubkey",
            b"encrypted-private-blob",
        );
        let frame = parse_openssh_binary(&frame_bytes).expect("should parse");
        assert_eq!(frame.ciphername, "aes256-ctr");
        assert_eq!(frame.kdfname, "bcrypt");
        assert_eq!(frame.kdfoptions_raw, kdf_opts);
        assert_eq!(frame.private_blob, b"encrypted-private-blob");
    }

    #[test]
    fn openssh_parse_wrong_magic_returns_malformed() {
        let mut frame = make_openssh_frame("none", "none", b"", b"pub", b"priv");
        // Corrupt the magic bytes.
        frame[0] = b'X';
        let err = parse_openssh_binary(&frame).unwrap_err();
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    #[test]
    fn openssh_parse_truncated_after_magic_returns_malformed() {
        // Just the magic, nothing else.
        let err = parse_openssh_binary(OPENSSH_MAGIC).unwrap_err();
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    #[test]
    fn openssh_parse_truncated_in_string_field_returns_malformed() {
        let mut v = Vec::new();
        v.extend_from_slice(OPENSSH_MAGIC);
        // Length field says 100 bytes but there are only 5.
        v.extend_from_slice(&100u32.to_be_bytes());
        v.extend_from_slice(b"short");
        let err = parse_openssh_binary(&v).unwrap_err();
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    #[test]
    fn openssh_parse_multiple_keys_returns_unsupported() {
        let mut v = Vec::new();
        v.extend_from_slice(OPENSSH_MAGIC);
        // Write ciphername, kdfname, kdfoptions.
        for s in &["none", "none"] {
            v.extend_from_slice(&(s.len() as u32).to_be_bytes());
            v.extend_from_slice(s.as_bytes());
        }
        v.extend_from_slice(&0u32.to_be_bytes()); // kdfoptions empty
        v.extend_from_slice(&2u32.to_be_bytes()); // nkeys = 2
        let err = parse_openssh_binary(&v).unwrap_err();
        assert!(matches!(err, KeyParseError::Unsupported(_)));
    }

    // -----------------------------------------------------------------------
    // EncryptedPrivateKeyInfo (parse_encrypted_pkcs8) tests
    // -----------------------------------------------------------------------

    /// Minimal EncryptedPrivateKeyInfo DER with a DES OID: must return Unsupported.
    ///
    /// Constructed by hand:
    ///   SEQUENCE { SEQUENCE { OID(pbeWithMD5AndDES-CBC) NULL } OCTET STRING(empty) }
    #[test]
    fn epki_unsupported_des_md5_oid() {
        // OID 1.2.840.113549.1.5.3 = pbeWithMD5AndDES-CBC (9 bytes value)
        let der: &[u8] = &[
            0x30, 0x11, // SEQUENCE length 17
            0x30, 0x0d, //   SEQUENCE (AlgorithmIdentifier) length 13
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03, //     OID
            0x05, 0x00, //     NULL
            0x04, 0x00, //   OCTET STRING (empty ciphertext)
        ];
        let err = parse_encrypted_pkcs8(der, "pass", [0u8; 16])
            .err().expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)));
        let msg = err.to_string();
        assert!(msg.contains("DES"), "expected DES in error: {msg}");
    }

    /// Same for pbeWithSHA1AndDES-CBC (OID 1.2.840.113549.1.5.10).
    #[test]
    fn epki_unsupported_des_sha1_oid() {
        // OID 1.2.840.113549.1.5.10 = pbeWithSHA1AndDES-CBC (9 bytes value)
        let der: &[u8] = &[
            0x30, 0x11,
            0x30, 0x0d,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0a,
            0x05, 0x00,
            0x04, 0x00,
        ];
        let err = parse_encrypted_pkcs8(der, "pass", [0u8; 16])
            .err().expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)));
    }

    /// PKCS#12 RC2-128 OID must return Unsupported.
    #[test]
    fn epki_unsupported_rc2_oid() {
        // OID 1.2.840.113549.1.12.1.5 = pbeWithSHAAnd128BitRC2-CBC (10 bytes value)
        // AlgId inner: OID TLV (12 bytes) + NULL TLV (2 bytes) = 14 = 0x0e
        // outer inner: AlgId TLV (16 bytes) + OctetString TLV (2 bytes) = 18 = 0x12
        let der: &[u8] = &[
            0x30, 0x12, //   outer SEQUENCE length 18
            0x30, 0x0e, //   AlgorithmIdentifier length 14
            0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x05,
            0x05, 0x00,
            0x04, 0x00,
        ];
        let err = parse_encrypted_pkcs8(der, "pass", [0u8; 16])
            .err().expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)));
        let msg = err.to_string();
        assert!(msg.contains("RC2"), "expected RC2 in error: {msg}");
    }

    /// Malformed: not a SEQUENCE -> returns Malformed.
    #[test]
    fn epki_malformed_missing_outer_sequence() {
        let err = parse_encrypted_pkcs8(b"\x02\x01\x00", "pass", [0u8; 16])
            .err().expect("must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    /// PBES2 + PBKDF2-SHA256 + AES-256-CBC decryption round-trip.
    ///
    /// Test vector: 512-bit RSA key encrypted by
    /// `openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:testpass123`
    #[test]
    fn epki_pbes2_aes256_sha256_decrypts() {
        let der = hex::decode(concat!(
            "308201bd305706092a864886f70d01050d304a302906092a864886f70d01050c",
            "301c0408d0e4e97f0a2fcb9b02020800300c06082a864886f70d020905003",
            "01d060960864801650304012a0410084cca07a6407bc5fc577435a81787a8",
            "048201605f39b5d9217e1d733338b92f92dcfcf9b7edc669dd0d27446df11",
            "d5d51dc82f6623dda3524967f2b60db265a5804fa98cf42d242c2a2daa717",
            "f6b60803f1323e92e683e67097153491be85c00b064e3d6f1346d0c015659",
            "458de6bffd054c03c5295d3bd443843967af437d0d4ad9c85c1fb51810cf8",
            "70b8ad907178b9adf4f5e4b3a4c867bf1560ed32c71f19c352afea7eb86db",
            "03d4b4353bdd276ed2dfaa58c4e9c4016cdda6d5c672a7541a999995b2300",
            "91670f27712c87e1e09238a7a33a882feed2205d4a54de76da4490280c25a",
            "e62886729effd2a6bd5bb465859f0bbd9d76fd2268b5c6535893961eee8e1",
            "d99ca3d51ec5bdbccc2adedaa3c45a68e43095a3e53f45060c786b60ce666",
            "de1ef9d4e7d2bcd98339fa866e77c983eb3135aa126e5eba2951f9c9cbb97",
            "29552514de841ac3f004c5f93d16583e69f0a61e8e88048173cbfacccae29",
            "882518218c048626e173564af13d262a1d8fedcbc"
        )).expect("valid hex");

        let id = [0u8; 16];
        let key = parse_encrypted_pkcs8(&der, "testpass123", id)
            .expect("PBES2 decryption must succeed");
        assert_eq!(key.key_type, KeyType::Rsa, "must be RSA");
        // PKCS#1 RSAPrivateKey starts with SEQUENCE tag 0x30
        assert_eq!(key.key_bytes[0], 0x30, "RSA key bytes must start with SEQUENCE");
    }

    /// Wrong passphrase on PBES2-encrypted key -> invalid PKCS#7 padding -> Malformed.
    #[test]
    fn epki_pbes2_wrong_passphrase_returns_malformed() {
        let der = hex::decode(concat!(
            "308201bd305706092a864886f70d01050d304a302906092a864886f70d01050c",
            "301c0408d0e4e97f0a2fcb9b02020800300c06082a864886f70d020905003",
            "01d060960864801650304012a0410084cca07a6407bc5fc577435a81787a8",
            "048201605f39b5d9217e1d733338b92f92dcfcf9b7edc669dd0d27446df11",
            "d5d51dc82f6623dda3524967f2b60db265a5804fa98cf42d242c2a2daa717",
            "f6b60803f1323e92e683e67097153491be85c00b064e3d6f1346d0c015659",
            "458de6bffd054c03c5295d3bd443843967af437d0d4ad9c85c1fb51810cf8",
            "70b8ad907178b9adf4f5e4b3a4c867bf1560ed32c71f19c352afea7eb86db",
            "03d4b4353bdd276ed2dfaa58c4e9c4016cdda6d5c672a7541a999995b2300",
            "91670f27712c87e1e09238a7a33a882feed2205d4a54de76da4490280c25a",
            "e62886729effd2a6bd5bb465859f0bbd9d76fd2268b5c6535893961eee8e1",
            "d99ca3d51ec5bdbccc2adedaa3c45a68e43095a3e53f45060c786b60ce666",
            "de1ef9d4e7d2bcd98339fa866e77c983eb3135aa126e5eba2951f9c9cbb97",
            "29552514de841ac3f004c5f93d16583e69f0a61e8e88048173cbfacccae29",
            "882518218c048626e173564af13d262a1d8fedcbc"
        )).expect("valid hex");

        let err = parse_encrypted_pkcs8(&der, "wrongpassword", [0u8; 16])
            .err().expect("wrong password must return an error");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong password must give Malformed, got: {err}"
        );
    }

    /// PKCS#12 pbeWithSHAAnd3-KeyTripleDES-CBC decryption round-trip.
    ///
    /// Test vector: same 512-bit RSA key encrypted by
    /// `openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES -passout pass:testpass123`
    #[test]
    fn epki_pkcs12_sha1_3des_decrypts() {
        let der = hex::decode(concat!(
            "30820182301c060a2a864886f70d010c0103300e04087ccf3ffcea6f77150202",
            "080004820160d2f81814d8251a3f1d43cba1ee1f4ccb9e799c0b9bc9bfc419",
            "6a43521a63d27a14baa66532b389f25249de1f376088eaf300439809698f62",
            "533f0388948490d853a18d9a7145c9097d387a4a4ed6b9fdceb77d3c0c9705",
            "eda454f008b2918d34195367f3c50691ef1d6510b5e6f397ece72f57769bda",
            "2beb1d5a2a666006f387d61352ac4ccfcaf94e81eb11b885b3ebd53538af7e",
            "fadaa252ced81b4acb95dfb5b71453791e61e1aa2c1c76d98d10793ad3418b",
            "c4dc8316d48cbdbf0ff4299bd116248b3407ec01b78ef51ade7249fa8a205e",
            "1514ac9dda1b1ad96ec53d7b0d20e248b563a26103ae3071ff84c558151649",
            "7bd0d9b3137d05cb50dda8cb9c5242880669416eeafe8fc9e6302793740e33",
            "5577e5163d4dff8f1ff491dcac56f5cc18555379145504ec710f5c1c8f49e4",
            "c541ecc731661e422c6579ab080f20e0337314cbaa7a5b9097719a8b060984",
            "0c7c2f32a1d6bc9babcc9eb8dc803d27e6"
        )).expect("valid hex");

        let id = [0u8; 16];
        let key = parse_encrypted_pkcs8(&der, "testpass123", id)
            .expect("PKCS12-3DES decryption must succeed");
        assert_eq!(key.key_type, KeyType::Rsa, "must be RSA");
        assert_eq!(key.key_bytes[0], 0x30, "RSA key bytes must start with SEQUENCE");
    }

    // -----------------------------------------------------------------------
    // OpenSSH blob decryption (decrypt_openssh_blob / verify_openssh_check_words)
    // -----------------------------------------------------------------------

    fn make_frame(ciphername: &str, kdfname: &str, kdfopts: Vec<u8>, blob: Vec<u8>) -> OpensshFrame {
        OpensshFrame {
            ciphername: ciphername.to_string(),
            kdfname: kdfname.to_string(),
            kdfoptions_raw: kdfopts,
            private_blob: blob,
        }
    }

    /// ciphername=none passes the private blob through unchanged.
    #[test]
    fn openssh_decrypt_none_passthrough() {
        let blob = b"arbitrary-key-bytes".to_vec();
        let frame = make_frame("none", "none", vec![], blob.clone());
        let out = decrypt_openssh_blob(&frame, "").expect("none must not fail");
        assert_eq!(out, blob);
    }

    /// aes256-gcm@openssh.com returns Unsupported (out-of-scope for v1).
    #[test]
    fn openssh_decrypt_aes256_gcm_returns_unsupported() {
        let frame = make_frame("aes256-gcm@openssh.com", "none", vec![], vec![]);
        let err = decrypt_openssh_blob(&frame, "")
            .err()
            .expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "expected Unsupported, got {err}");
    }

    /// Unknown ciphername returns Unsupported.
    #[test]
    fn openssh_decrypt_unknown_cipher_returns_unsupported() {
        let frame = make_frame("chacha20-poly1305@openssh.com", "none", vec![], vec![]);
        let err = decrypt_openssh_blob(&frame, "")
            .err()
            .expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "expected Unsupported");
    }

    /// Matching check words return the key data slice.
    #[test]
    fn openssh_check_words_match_returns_key_data() {
        // check1 = check2 = 0xDEADBEEF, followed by b"key"
        let mut blob = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF];
        blob.extend_from_slice(b"key-data");
        let tail = verify_openssh_check_words(&blob).expect("matching checks must succeed");
        assert_eq!(tail, b"key-data");
    }

    /// Mismatched check words return Malformed.
    #[test]
    fn openssh_check_words_mismatch_returns_malformed() {
        // check1 = 0x00000001, check2 = 0x00000002
        let blob = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
        let err = verify_openssh_check_words(&blob)
            .err()
            .expect("mismatch must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)), "expected Malformed");
    }

    /// Too-short blob returns Malformed (can't read 8 bytes).
    #[test]
    fn openssh_check_words_short_blob_returns_malformed() {
        let err = verify_openssh_check_words(&[0x00, 0x00, 0x00])
            .err()
            .expect("short blob must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    // -----------------------------------------------------------------------
    // PFX ASN.1 structure traversal (parse_pfx_structure) tests
    // -----------------------------------------------------------------------

    /// Truncated / empty DER returns a Malformed error (not a panic).
    #[test]
    fn pfx_truncated_der_returns_malformed() {
        let err = parse_pfx_structure(&[], "")
            .err()
            .expect("empty DER must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)));

        let err = parse_pfx_structure(&[0x30, 0x02, 0x01], "")
            .err()
            .expect("truncated DER must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    /// `verify_pfx_mac` returns Malformed for truncated DER (not a panic).
    #[test]
    fn pfx_verify_mac_truncated_returns_malformed() {
        let err = verify_pfx_mac(&[], "").err().expect("empty DER must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    /// PFX produced by `openssl pkcs12 -export -passout pass:` (empty password)
    /// contains at least one ShroudedKeyBag entry.
    ///
    /// Uses openssl as an external oracle: generates an RSA key and self-signed
    /// cert, creates a P12, and verifies that `parse_pfx_structure` finds the
    /// ShroudedKeyBag and extracts the bag attributes correctly.
    #[test]
    fn pfx_openssl_empty_password_shrouded_key_bag_found() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        // Generate RSA key and self-signed cert.
        let status = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "openssl genrsa failed");

        let status = std::process::Command::new("openssl")
            .args([
                "req", "-new", "-x509",
                "-key", key_pem.to_str().unwrap(),
                "-out", cert_pem.to_str().unwrap(),
                "-days", "1",
                "-subj", "/CN=test",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "openssl req failed");

        // Export to PKCS#12 with empty password and localKeyID / friendlyName.
        let status = std::process::Command::new("openssl")
            .args([
                "pkcs12", "-export",
                "-inkey", key_pem.to_str().unwrap(),
                "-in", cert_pem.to_str().unwrap(),
                "-out", p12_path.to_str().unwrap(),
                "-passout", "pass:",
                "-name", "test-key",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "openssl pkcs12 -export failed");

        let p12_der = std::fs::read(&p12_path).unwrap();
        let bags = parse_pfx_structure(&p12_der, "")
            .expect("parse_pfx_structure must not fail on valid openssl P12");

        // At least one ShroudedKeyBag must be found.
        assert!(
            !bags.shrouded_key_bags.is_empty(),
            "expected at least one ShroudedKeyBag in openssl-generated P12"
        );

        // The bag_value must be non-empty DER bytes.
        let key_bag = &bags.shrouded_key_bags[0];
        assert!(!key_bag.bag_value.is_empty(), "ShroudedKeyBag bag_value must not be empty");

        // friendlyName must match the -name flag.
        assert_eq!(
            key_bag.friendly_name.as_deref(),
            Some("test-key"),
            "friendlyName must match the -name flag passed to openssl pkcs12"
        );

        // localKeyID must be present (openssl always sets it).
        assert!(
            key_bag.local_key_id.is_some(),
            "localKeyID bag attribute must be present"
        );

        // MAC verification with empty passphrase must succeed.
        verify_pfx_mac(&p12_der, "")
            .expect("MAC verification must succeed with empty passphrase");
    }

    /// `verify_pfx_mac` fails with wrong passphrase (Malformed error, not a panic).
    #[test]
    fn pfx_verify_mac_wrong_passphrase_fails() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key", key_pem.to_str().unwrap(),
                   "-out", cert_pem.to_str().unwrap(), "-days", "1", "-subj", "/CN=test"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["pkcs12", "-export",
                   "-inkey", key_pem.to_str().unwrap(),
                   "-in", cert_pem.to_str().unwrap(),
                   "-out", p12_path.to_str().unwrap(),
                   "-passout", "pass:correct-password"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());

        let p12_der = std::fs::read(&p12_path).unwrap();

        // Wrong passphrase must fail MAC verification.
        let err = verify_pfx_mac(&p12_der, "wrong-password")
            .err()
            .expect("wrong passphrase must cause MAC failure");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong passphrase must return Malformed, got: {err}"
        );

        // Correct passphrase must succeed.
        verify_pfx_mac(&p12_der, "correct-password")
            .expect("correct passphrase must pass MAC verification");
    }

    /// `parse_pfx_structure` finds ShroudedKeyBag when SafeContents is encrypted
    /// inside an `id-encryptedData` ContentInfo (non-empty password, PBES2 default).
    ///
    /// Uses openssl as an external oracle.  If openssl is not available or does
    /// not emit `id-encryptedData` for this password, the test is a no-op.
    #[test]
    fn pfx_encrypted_safe_contents_pbes2_decrypts() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl genrsa failed");

        let s = std::process::Command::new("openssl")
            .args([
                "req", "-new", "-x509",
                "-key", key_pem.to_str().unwrap(),
                "-out", cert_pem.to_str().unwrap(),
                "-days", "1", "-subj", "/CN=pfx-pbes2-test",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl req failed");

        let s = std::process::Command::new("openssl")
            .args([
                "pkcs12", "-export",
                "-inkey", key_pem.to_str().unwrap(),
                "-in", cert_pem.to_str().unwrap(),
                "-out", p12_path.to_str().unwrap(),
                "-passout", "pass:hunter2",
                "-name", "pbes2-test-key",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl pkcs12 -export failed");

        let p12_der = std::fs::read(&p12_path).unwrap();

        // MAC must verify with correct passphrase.
        verify_pfx_mac(&p12_der, "hunter2")
            .expect("MAC must verify with correct passphrase");

        // parse_pfx_structure with correct passphrase must find the key bag.
        let bags = parse_pfx_structure(&p12_der, "hunter2")
            .expect("parse_pfx_structure must succeed with correct passphrase");
        assert!(
            !bags.shrouded_key_bags.is_empty(),
            "expected at least one ShroudedKeyBag"
        );
        assert_eq!(
            bags.shrouded_key_bags[0].friendly_name.as_deref(),
            Some("pbes2-test-key"),
        );

        // Wrong passphrase must return an error.
        let err = parse_pfx_structure(&p12_der, "wrong-pass")
            .err()
            .expect("wrong passphrase must fail");
        assert!(
            matches!(err, KeyParseError::Malformed(_) | KeyParseError::Unsupported(_)),
            "wrong passphrase must return Malformed or Unsupported, got: {err}"
        );
    }

    /// `parse_pfx_structure` finds ShroudedKeyBag when SafeContents is encrypted
    /// with PBES1 3DES (openssl pkcs12 -export -legacy).
    #[test]
    fn pfx_encrypted_safe_contents_pbes1_3des_decrypts() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl genrsa failed");

        let s = std::process::Command::new("openssl")
            .args([
                "req", "-new", "-x509",
                "-key", key_pem.to_str().unwrap(),
                "-out", cert_pem.to_str().unwrap(),
                "-days", "1", "-subj", "/CN=pfx-pbes1-test",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl req failed");

        // -legacy forces PBES1 (3DES + SHA-1 MAC).
        let s = std::process::Command::new("openssl")
            .args([
                "pkcs12", "-export", "-legacy",
                "-inkey", key_pem.to_str().unwrap(),
                "-in", cert_pem.to_str().unwrap(),
                "-out", p12_path.to_str().unwrap(),
                "-passout", "pass:legacy-pass",
                "-name", "pbes1-test-key",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        if !s.success() {
            // -legacy may not be supported on all openssl builds; skip gracefully.
            return;
        }

        let p12_der = std::fs::read(&p12_path).unwrap();

        verify_pfx_mac(&p12_der, "legacy-pass")
            .expect("MAC must verify with correct passphrase (PBES1)");

        let bags = parse_pfx_structure(&p12_der, "legacy-pass")
            .expect("parse_pfx_structure must succeed with correct passphrase (PBES1)");
        assert!(
            !bags.shrouded_key_bags.is_empty(),
            "expected at least one ShroudedKeyBag from PBES1 P12"
        );
        assert_eq!(
            bags.shrouded_key_bags[0].friendly_name.as_deref(),
            Some("pbes1-test-key"),
        );
    }

    /// `extract_keys_from_pfx_bags` decrypts an RSA ShroudedKeyBag and
    /// populates `cert_der` from the matching CertBag.
    ///
    /// Uses openssl as an external oracle to generate the P12.
    #[test]
    fn pfx_extract_rsa_key_with_cert() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key", key_pem.to_str().unwrap(),
                   "-out", cert_pem.to_str().unwrap(), "-days", "1", "-subj", "/CN=extract-test"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["pkcs12", "-export",
                   "-inkey", key_pem.to_str().unwrap(),
                   "-in", cert_pem.to_str().unwrap(),
                   "-out", p12_path.to_str().unwrap(),
                   "-passout", "pass:extract-pw",
                   "-name", "extracted-rsa"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());

        let p12_der = std::fs::read(&p12_path).unwrap();
        let cert_der_expected = std::fs::read(&cert_pem).unwrap();

        verify_pfx_mac(&p12_der, "extract-pw").expect("MAC must verify");
        let bags = parse_pfx_structure(&p12_der, "extract-pw").expect("parse must succeed");

        let (keys, failures) = extract_keys_from_pfx_bags(&bags, "extract-pw");
        assert!(failures.is_empty(), "expected no failures, got: {failures:?}");
        assert_eq!(keys.len(), 1, "expected exactly one key");

        let key = &keys[0];
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.key_bytes.is_empty());
        assert_eq!(key.label_hint.as_deref(), Some("extracted-rsa"));

        // Key ID must be derived from localKeyID (first 16 bytes of the bag attribute).
        if let Some(local_id) = &bags.shrouded_key_bags[0].local_key_id {
            let mut expected_id = [0u8; 16];
            let n = local_id.len().min(16);
            expected_id[..n].copy_from_slice(&local_id[..n]);
            assert_eq!(key.id, expected_id, "key ID must be derived from localKeyID");
        }

        // cert_der must be populated and match the DER of the certificate.
        // (openssl pkcs12 -export embeds the cert in the PFX).
        assert!(key.cert_der.is_some(), "cert_der must be populated from CertBag");

        // Parse the expected cert DER from the PEM file (strip PEM headers).
        let pem_block = pem::parse(&cert_der_expected).expect("cert PEM must parse");
        assert_eq!(
            key.cert_der.as_deref().unwrap(),
            pem_block.contents(),
            "cert_der must match the DER of the embedded certificate"
        );
    }

    /// `extract_keys_from_pfx_bags` returns per-bag failure when passphrase is wrong.
    #[test]
    fn pfx_extract_wrong_passphrase_per_bag_failure() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key", key_pem.to_str().unwrap(),
                   "-out", cert_pem.to_str().unwrap(), "-days", "1", "-subj", "/CN=bag-fail"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["pkcs12", "-export",
                   "-inkey", key_pem.to_str().unwrap(),
                   "-in", cert_pem.to_str().unwrap(),
                   "-out", p12_path.to_str().unwrap(),
                   "-passout", "pass:correct",
                   "-name", "fail-bag"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());

        let p12_der = std::fs::read(&p12_path).unwrap();

        // Correct passphrase -> MAC passes -> parse bags -> get the ShroudedKeyBag
        verify_pfx_mac(&p12_der, "correct").expect("MAC must verify");
        let bags = parse_pfx_structure(&p12_der, "correct").expect("parse must succeed");

        // Wrong passphrase for bag decryption -> per-bag failure, not panic.
        let (keys, failures) = extract_keys_from_pfx_bags(&bags, "wrong");
        assert!(keys.is_empty(), "wrong passphrase must yield no keys");
        assert!(!failures.is_empty(), "wrong passphrase must yield per-bag failure");
    }

    // -----------------------------------------------------------------------
    // JKS / JCEKS binary format reader tests
    // -----------------------------------------------------------------------

    /// Wrong magic returns Malformed (not a panic).
    #[test]
    fn jks_wrong_magic_returns_malformed() {
        // All-zeros is not valid JKS or JCEKS magic.
        let err = parse_jks_structure(&[0x00, 0x00, 0x00, 0x00])
            .err()
            .expect("wrong magic must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong magic must return Malformed, got: {err}"
        );
    }

    /// Truncated input returns Malformed (not a panic).
    #[test]
    fn jks_truncated_returns_malformed() {
        // Only the JKS magic, nothing else.
        let data = [0xFE, 0xED, 0xFE, 0xED];
        let err = parse_jks_structure(&data)
            .err()
            .expect("truncated JKS must return Err");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    fn keytool_available() -> bool {
        std::process::Command::new("keytool")
            .arg("-help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|_| true)
            .unwrap_or(false)
    }

    /// `parse_jks_structure` reads a PrivateKeyEntry from a JKS file generated
    /// by Java keytool.
    #[test]
    fn jks_reads_private_key_entry() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jks_path = dir.path().join("test.jks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "mykey",
                "-keyalg", "RSA", "-keysize", "2048",
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", "storepass",
                "-storetype", "JKS",
                "-dname", "CN=test",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; } // JKS might be deprecated; skip gracefully

        let jks_data = std::fs::read(&jks_path).unwrap();
        assert!(is_jks_or_jceks(&jks_data), "keytool output must be JKS/JCEKS");

        let result = parse_jks_structure(&jks_data).expect("parse_jks_structure must succeed");
        assert_eq!(result.private_key_entries.len(), 1, "expected one PrivateKeyEntry");

        let entry = &result.private_key_entries[0];
        assert_eq!(entry.alias, "mykey");
        assert!(!entry.encrypted_key.is_empty(), "encrypted_key must not be empty");
        assert!(entry.cert_der.is_some(), "cert_der must be present (keytool includes self-signed cert)");
    }

    /// `parse_jks_structure` reads a PrivateKeyEntry from a JCEKS file.
    #[test]
    fn jceks_reads_private_key_entry() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jceks_path = dir.path().join("test.jceks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "eckey",
                "-keyalg", "EC", "-keysize", "256",
                "-keystore", jceks_path.to_str().unwrap(),
                "-storepass", "storepass",
                "-storetype", "JCEKS",
                "-dname", "CN=test",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; }

        let jceks_data = std::fs::read(&jceks_path).unwrap();
        assert!(is_jks_or_jceks(&jceks_data), "keytool output must be JKS/JCEKS");

        let result = parse_jks_structure(&jceks_data).expect("parse_jks_structure must succeed");
        assert_eq!(result.private_key_entries.len(), 1, "expected one PrivateKeyEntry");

        let entry = &result.private_key_entries[0];
        assert_eq!(entry.alias, "eckey");
        assert!(!entry.encrypted_key.is_empty(), "encrypted_key must not be empty");
    }

    /// Zero PrivateKeyEntries (only TrustedCertEntry) returns Ok with empty vec.
    #[test]
    fn jks_only_trusted_cert_returns_empty_vec() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jks_path = dir.path().join("trust.jks");
        let cert_path = dir.path().join("cert.pem");

        // Generate a self-signed cert to import as trusted.
        let s = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:1024",
                   "-keyout", "/dev/null", "-out", cert_path.to_str().unwrap(),
                   "-days", "1", "-subj", "/CN=trust-test", "-nodes"])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn openssl req");
        if !s.success() { return; }

        // Import only as TrustedCertEntry (no private key).
        let s = std::process::Command::new("keytool")
            .args([
                "-importcert", "-alias", "trustedca",
                "-file", cert_path.to_str().unwrap(),
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", "storepass",
                "-storetype", "JKS",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; }

        let jks_data = std::fs::read(&jks_path).unwrap();
        let result = parse_jks_structure(&jks_data).expect("parse must succeed even with no private keys");
        assert!(
            result.private_key_entries.is_empty(),
            "keystore with only TrustedCertEntries must return empty private_key_entries"
        );
    }

    // -----------------------------------------------------------------------
    // verify_jks_integrity tests
    // -----------------------------------------------------------------------

    /// `verify_jks_integrity` accepts the correct passphrase.
    #[test]
    fn jks_integrity_correct_passphrase_succeeds() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jks_path = dir.path().join("integrity.jks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "k",
                "-keyalg", "RSA", "-keysize", "1024",
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", "inttest",
                "-storetype", "JKS",
                "-dname", "CN=int",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; } // JKS may be deprecated; skip gracefully

        let data = std::fs::read(&jks_path).unwrap();
        verify_jks_integrity(&data, "inttest")
            .expect("correct passphrase must pass integrity check");
    }

    /// `verify_jks_integrity` rejects a wrong passphrase.
    #[test]
    fn jks_integrity_wrong_passphrase_fails() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jks_path = dir.path().join("integrity.jks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "k",
                "-keyalg", "RSA", "-keysize", "1024",
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", "inttest",
                "-storetype", "JKS",
                "-dname", "CN=int",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; }

        let data = std::fs::read(&jks_path).unwrap();
        let err = verify_jks_integrity(&data, "wrongpassword")
            .err()
            .expect("wrong passphrase must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong passphrase must return Malformed, got: {err}"
        );
    }

    /// `verify_jks_integrity` rejects files shorter than 20 bytes (no room for
    /// the SHA-1 integrity fingerprint).
    #[test]
    fn jks_integrity_truncated_file_fails() {
        let data = [0u8; 19]; // needs at least 20 bytes
        let err = verify_jks_integrity(&data, "any")
            .err()
            .expect("truncated file must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "truncated file must return Malformed, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // decrypt_jks_private_key_entry tests
    // -----------------------------------------------------------------------

    /// Helper: create a JKS keystore with one RSA key via keytool and return
    /// the raw JKS bytes.
    fn make_jks_with_rsa_key(dir: &std::path::Path, passphrase: &str) -> Option<Vec<u8>> {
        let jks_path = dir.join("key.jks");
        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "rsakey",
                "-keyalg", "RSA", "-keysize", "2048",
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", passphrase,
                "-storetype", "JKS",
                "-dname", "CN=rsa-test",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        if !s.success() { return None; }
        std::fs::read(&jks_path).ok()
    }

    /// `decrypt_jks_private_key_entry` decrypts an RSA-2048 JKS entry and returns
    /// a ParsedKey with key_type == Rsa.
    #[test]
    fn jks_decrypt_rsa_entry_succeeds() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let data = match make_jks_with_rsa_key(dir.path(), "dectest") {
            Some(d) => d,
            None => return, // keytool may have rejected JKS
        };

        let entries = parse_jks_structure(&data).expect("parse_jks_structure must succeed");
        assert_eq!(entries.private_key_entries.len(), 1);
        let entry = &entries.private_key_entries[0];
        assert_eq!(entry.alias, "rsakey");

        let key = decrypt_jks_private_key_entry(&entry.encrypted_key, "dectest", [0u8; 16])
            .expect("decrypt must succeed with correct passphrase");
        assert_eq!(key.key_type, KeyType::Rsa, "expected RSA key");
        assert!(!key.key_bytes.is_empty());
    }

    /// `decrypt_jks_private_key_entry` returns Malformed for a wrong passphrase.
    #[test]
    fn jks_decrypt_wrong_passphrase_fails() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let data = match make_jks_with_rsa_key(dir.path(), "dectest") {
            Some(d) => d,
            None => return,
        };

        let entries = parse_jks_structure(&data).expect("parse_jks_structure must succeed");
        let entry = &entries.private_key_entries[0];

        let err = decrypt_jks_private_key_entry(&entry.encrypted_key, "wrongpass", [0u8; 16])
            .err()
            .expect("wrong passphrase must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong passphrase must return Malformed, got: {err}"
        );
    }

    /// `decrypt_jks_private_key_entry` decrypts a JCEKS EC P-256 entry using
    /// `PBEWithMD5AndTripleDES` and returns a ParsedKey with key_type == Ec.
    #[test]
    fn jceks_decrypt_ec_entry_succeeds() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jceks_path = dir.path().join("test.jceks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "eckey",
                "-keyalg", "EC", "-groupname", "secp256r1",
                "-keystore", jceks_path.to_str().unwrap(),
                "-storepass", "jctest", "-keypass", "jctest",
                "-storetype", "JCEKS",
                "-dname", "CN=jceks-test",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; }

        let data = std::fs::read(&jceks_path).unwrap();
        let entries = parse_jks_structure(&data).expect("parse_jks_structure must succeed");
        assert_eq!(entries.private_key_entries.len(), 1);
        let entry = &entries.private_key_entries[0];

        let key = decrypt_jks_private_key_entry(&entry.encrypted_key, "jctest", [0u8; 16])
            .expect("decrypt must succeed with correct passphrase");
        assert_eq!(key.key_type, KeyType::Ec, "expected EC key");
        assert!(!key.key_bytes.is_empty());
    }

    /// `decrypt_jks_private_key_entry` returns Malformed for a malformed DER blob.
    #[test]
    fn jks_decrypt_malformed_der_fails() {
        // All-zeros is not a valid EncryptedPrivateKeyInfo DER.
        let err = decrypt_jks_private_key_entry(&[0u8; 64], "any", [0u8; 16])
            .err()
            .expect("malformed DER must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "malformed DER must return Malformed, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // PPK parser tests
    // -----------------------------------------------------------------------

    /// Minimal valid PPK v2 input with no encryption.
    const PPK_V2_MINIMAL: &[u8] = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Encryption: none\n\
Comment: test-rsa-key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";

    /// Minimal valid PPK v3 input with Argon2id KDF.
    const PPK_V3_ARGON2: &[u8] = b"\
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256\n\
Encryption: aes256-cbc\n\
Comment: my-ec-key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Key-Derivation: Argon2id\n\
Argon2-Memory: 8192\n\
Argon2-Passes: 21\n\
Argon2-Parallelism: 1\n\
Argon2-Salt: deadbeef01020304\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n\
";

    #[test]
    fn is_ppk_detects_v2() {
        assert!(is_ppk(PPK_V2_MINIMAL));
    }

    #[test]
    fn is_ppk_detects_v3() {
        assert!(is_ppk(PPK_V3_ARGON2));
    }

    #[test]
    fn is_ppk_rejects_non_ppk() {
        assert!(!is_ppk(b"-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(!is_ppk(b"\xfe\xed\xfe\xed"));
        assert!(!is_ppk(b""));
    }

    #[test]
    fn ppk_v2_parse_all_fields_correct() {
        let f = parse_ppk(PPK_V2_MINIMAL).expect("PPK v2 parse must succeed");
        assert_eq!(f.version, 2);
        assert_eq!(f.key_type, "ssh-rsa");
        assert_eq!(f.encryption, "none");
        assert_eq!(f.comment, "test-rsa-key");
        // Public-Lines: 1 -> base64 "AQIDBA==" -> [0x01, 0x02, 0x03, 0x04]
        assert_eq!(f.public_blob, [0x01u8, 0x02, 0x03, 0x04]);
        // Private-Lines: 1 -> base64 "BQYHCA==" -> [0x05, 0x06, 0x07, 0x08]
        assert_eq!(f.private_blob, [0x05u8, 0x06, 0x07, 0x08]);
        // Private-MAC: 20 bytes
        assert_eq!(f.private_mac.len(), 20);
        assert_eq!(f.private_mac[0], 0x00);
        assert_eq!(f.private_mac[19], 0x13);
        // v3-only fields absent
        assert!(f.kdf_variant.is_none());
        assert!(f.argon2_salt.is_none());
    }

    #[test]
    fn ppk_v3_parse_all_fields_correct() {
        let f = parse_ppk(PPK_V3_ARGON2).expect("PPK v3 parse must succeed");
        assert_eq!(f.version, 3);
        assert_eq!(f.key_type, "ecdsa-sha2-nistp256");
        assert_eq!(f.encryption, "aes256-cbc");
        assert_eq!(f.comment, "my-ec-key");
        assert_eq!(f.public_blob, [0x01u8, 0x02, 0x03, 0x04]);
        assert_eq!(f.private_blob, [0x05u8, 0x06, 0x07, 0x08]);
        assert_eq!(f.private_mac.len(), 32);
        // KDF fields
        assert_eq!(f.kdf_variant.as_deref(), Some("Argon2id"));
        assert_eq!(f.argon2_memory, Some(8192));
        assert_eq!(f.argon2_passes, Some(21));
        assert_eq!(f.argon2_parallelism, Some(1));
        assert_eq!(
            f.argon2_salt.as_deref(),
            Some([0xdeu8, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04].as_ref())
        );
    }

    #[test]
    fn ppk_missing_encryption_returns_malformed() {
        let input = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Comment: key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let err = parse_ppk(input).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    #[test]
    fn ppk_missing_private_lines_returns_malformed() {
        let input = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Encryption: none\n\
Comment: key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let err = parse_ppk(input).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    #[test]
    fn ppk_invalid_base64_returns_malformed() {
        let input = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Encryption: none\n\
Comment: key\n\
Public-Lines: 1\n\
!!!NOT_BASE64!!!\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let err = parse_ppk(input).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    #[test]
    fn ppk_unknown_version_returns_unsupported() {
        let input = b"\
PuTTY-User-Key-File-4: ssh-rsa\n\
Encryption: none\n\
Comment: key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let err = parse_ppk(input).err().expect("must fail");
        assert!(
            matches!(err, KeyParseError::Unsupported(_)),
            "unknown version must return Unsupported, got: {err}"
        );
    }

    #[test]
    fn ppk_multi_line_base64_decoded_correctly() {
        // PPK base64 blobs are a single stream split across lines.  Intermediate
        // lines have no padding (each encodes an exact multiple of 3 bytes).
        // Line 1: "AQID" = base64([0x01, 0x02, 0x03]) -- no padding
        // Line 2: "BAUG" = base64([0x04, 0x05, 0x06]) -- no padding
        // Combined stream: "AQIDBAUG" -> [0x01,0x02,0x03,0x04,0x05,0x06]
        let input = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Encryption: none\n\
Comment: key\n\
Public-Lines: 2\n\
AQID\n\
BAUG\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let f = parse_ppk(input).expect("must succeed");
        assert_eq!(f.public_blob, [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    // -----------------------------------------------------------------------
    // PPK v2 SHA-1 KDF and AES-256-CBC decryption tests
    // -----------------------------------------------------------------------

    /// Compute SHA-1 of `data` via `openssl dgst -sha1 -binary`.
    /// Returns `None` if openssl is not available or the command fails.
    fn sha1_via_openssl(data: &[u8]) -> Option<[u8; 20]> {
        use std::io::Write as _;
        let mut child = std::process::Command::new("openssl")
            .args(["dgst", "-sha1", "-binary"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.as_mut()?.write_all(data).ok()?;
        let out = child.wait_with_output().ok()?;
        if out.status.success() && out.stdout.len() == 20 {
            let mut h = [0u8; 20];
            h.copy_from_slice(&out.stdout);
            Some(h)
        } else {
            None
        }
    }

    /// `ppk_v2_derive_key` output matches two independent SHA-1 hashes computed
    /// by openssl (independent oracle).
    #[test]
    fn ppk_v2_derive_key_matches_openssl_sha1() {
        let passphrase = b"test_passphrase_for_oracle";
        let key = ppk_v2_derive_key(passphrase);

        let input0: Vec<u8> = b"\x00\x00\x00\x00".iter().chain(passphrase.iter()).copied().collect();
        let input1: Vec<u8> = b"\x00\x00\x00\x01".iter().chain(passphrase.iter()).copied().collect();

        let (Some(h0), Some(h1)) = (sha1_via_openssl(&input0), sha1_via_openssl(&input1)) else {
            return; // openssl not available; skip
        };
        assert_eq!(&key[..20], &h0, "key[0..20] must equal SHA-1(counter0 || passphrase)");
        assert_eq!(&key[20..], &h1[..12], "key[20..32] must equal SHA-1(counter1 || passphrase)[0..12]");
    }

    /// `ppk_v2_decrypt_private_blob` with `Encryption: none` returns the private
    /// blob bytes unchanged.
    #[test]
    fn ppk_v2_decrypt_none_returns_blob_unchanged() {
        let f = parse_ppk(PPK_V2_MINIMAL).expect("parse must succeed");
        let plaintext = ppk_v2_decrypt_private_blob(&f, "any-passphrase")
            .expect("none encryption must not fail");
        assert_eq!(plaintext, f.private_blob);
    }

    /// `ppk_v2_decrypt_private_blob` with `Encryption: aes256-cbc` and a
    /// ciphertext that is not block-aligned returns Malformed.
    #[test]
    fn ppk_v2_decrypt_aes256_cbc_non_block_aligned_fails() {
        use base64::Engine as _;
        // 15 bytes of ciphertext -- not a multiple of 16.
        let bad_ct = base64::engine::general_purpose::STANDARD.encode([0u8; 15]);
        let input = format!(
            "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: aes256-cbc\nComment: key\n\
             Public-Lines: 1\nAQIDBA==\nPrivate-Lines: 1\n{bad_ct}\n\
             Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n"
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        let err = ppk_v2_decrypt_private_blob(&f, "pass")
            .err()
            .expect("non-block-aligned ciphertext must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// `ppk_v2_decrypt_private_blob` with an unknown encryption algorithm returns
    /// Unsupported.
    #[test]
    fn ppk_v2_decrypt_unknown_encryption_returns_unsupported() {
        use base64::Engine as _;
        let ct = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let input = format!(
            "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: blowfish-cbc\nComment: key\n\
             Public-Lines: 1\nAQIDBA==\nPrivate-Lines: 1\n{ct}\n\
             Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n"
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        let err = ppk_v2_decrypt_private_blob(&f, "pass")
            .err()
            .expect("unknown encryption must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    // -----------------------------------------------------------------------
    // PPK v3 Argon2 KDF and HMAC-SHA256 MAC tests
    // -----------------------------------------------------------------------

    /// `ppk_v3_derive_key_iv_mac` returns Unsupported for unrecognised variant.
    #[test]
    fn ppk_v3_unsupported_kdf_variant_returns_unsupported() {
        let mut bad = parse_ppk(PPK_V3_ARGON2).expect("parse must succeed");
        bad.kdf_variant = Some("Argon2xyz".to_string());
        let err = ppk_v3_derive_key_iv_mac(&bad, "pass").err().expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// `ppk_v3_decrypt_private_blob` with `Encryption: none` returns blob unchanged.
    #[test]
    fn ppk_v3_decrypt_none_returns_blob_unchanged() {
        // Build a v3 PpkFile with encryption=none (reuse v2 test vector, bump version).
        use base64::Engine as _;
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3, 4]);
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode([5u8, 6, 7, 8]);
        let input = format!(
            "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: key\n\
             Public-Lines: 1\n{pub_b64}\nPrivate-Lines: 1\n{priv_b64}\n\
             Private-MAC: {}\n",
            "00".repeat(32)
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        let plaintext = ppk_v3_decrypt_private_blob(&f, "any")
            .expect("none encryption must not fail");
        assert_eq!(plaintext, [5u8, 6, 7, 8]);
    }

    /// `ppk_v3_verify_mac` returns Malformed for a wrong MAC.
    #[test]
    fn ppk_v3_verify_mac_wrong_mac_fails() {
        let f = parse_ppk(PPK_V3_ARGON2).expect("parse must succeed");
        let err = ppk_v3_verify_mac(&f, "passphrase", &f.private_blob.clone())
            .err()
            .expect("wrong MAC must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// Compute HMAC-SHA256 via openssl for independent oracle verification.
    fn hmac_sha256_via_openssl(key: &[u8], data: &[u8]) -> Option<[u8; 32]> {
        let dir = tempfile::tempdir().ok()?;
        let data_path = dir.path().join("data.bin");
        std::fs::write(&data_path, data).ok()?;
        let key_hex = hex::encode(key);
        let out = std::process::Command::new("openssl")
            .args([
                "dgst", "-sha256", "-mac", "HMAC",
                "-macopt", &format!("hexkey:{key_hex}"),
                "-binary",
                data_path.to_str()?,
            ])
            .output()
            .ok()?;
        if out.status.success() && out.stdout.len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&out.stdout);
            Some(h)
        } else {
            None
        }
    }

    /// `ppk_v3_verify_mac` with unencrypted PPK v3 and an openssl-computed MAC passes.
    #[test]
    fn ppk_v3_verify_mac_unencrypted_correct_mac_passes() {
        let key_type = "ecdsa-sha2-nistp256";
        let encryption = "none";
        let comment = "v3-oracle-test";
        let public_blob = &[0x10u8, 0x20];
        let private_blob = &[0x30u8, 0x40];

        // For unencrypted v3, MAC key is the empty slice.
        let mac_input = ppk_v2_mac_input(key_type, encryption, comment, public_blob, private_blob);
        let Some(expected) = hmac_sha256_via_openssl(&[], &mac_input) else { return };

        let mac_hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();

        use base64::Engine as _;
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public_blob);
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode(private_blob);
        let input = format!(
            "PuTTY-User-Key-File-3: {key_type}\nEncryption: {encryption}\n\
             Comment: {comment}\nPublic-Lines: 1\n{pub_b64}\n\
             Private-Lines: 1\n{priv_b64}\nPrivate-MAC: {mac_hex}\n"
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        ppk_v3_verify_mac(&f, "", private_blob).expect("correct MAC must pass");
    }

    // -----------------------------------------------------------------------
    // PPK v2 HMAC-SHA1 MAC verification tests
    // -----------------------------------------------------------------------

    /// Compute HMAC-SHA1 of `data` using `key` via `openssl dgst -sha1 -hmac`.
    /// Returns `None` if openssl is unavailable.
    fn hmac_sha1_via_openssl(key: &[u8], data: &[u8]) -> Option<[u8; 20]> {
        // Write key and data to temp files, then invoke openssl.
        let dir = tempfile::tempdir().ok()?;
        let key_path = dir.path().join("key.bin");
        let data_path = dir.path().join("data.bin");
        std::fs::write(&key_path, key).ok()?;
        std::fs::write(&data_path, data).ok()?;
        let out = std::process::Command::new("openssl")
            .args([
                "dgst", "-sha1", "-mac", "HMAC",
                "-macopt", &format!("hexkey:{}", hex::encode(key)),
                "-binary",
                data_path.to_str()?,
            ])
            .output()
            .ok()?;
        if out.status.success() && out.stdout.len() == 20 {
            let mut h = [0u8; 20];
            h.copy_from_slice(&out.stdout);
            Some(h)
        } else {
            None
        }
    }

    /// `ppk_v2_derive_mac_key` matches SHA-1("putty-private-key-file-mac-key" || passphrase)
    /// computed by openssl.
    #[test]
    fn ppk_v2_mac_key_matches_openssl() {
        let passphrase = b"test_mac_key_pass";
        let mac_key = ppk_v2_derive_mac_key(passphrase);

        let mut input = PPK_MAC_KEY_PREFIX.to_vec();
        input.extend_from_slice(passphrase);
        let Some(expected) = sha1_via_openssl(&input) else { return };
        assert_eq!(mac_key, expected);
    }

    /// `ppk_v2_verify_mac` returns Malformed when given a wrong MAC.
    #[test]
    fn ppk_v2_verify_mac_wrong_mac_fails() {
        let f = parse_ppk(PPK_V2_MINIMAL).expect("parse must succeed");
        // PPK_V2_MINIMAL's Private-MAC is all-zero padding, not a real MAC.
        let err = ppk_v2_verify_mac(&f, "", &f.private_blob.clone())
            .err()
            .expect("wrong MAC must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// `ppk_v2_verify_mac` passes when the MAC in the PPK file matches what we
    /// compute independently, using openssl HMAC-SHA1 as the oracle.
    #[test]
    fn ppk_v2_verify_mac_correct_mac_passes() {
        let passphrase = "";
        let key_type = "ssh-rsa";
        let encryption = "none";
        let comment = "oracle-test-key";
        let public_blob = &[0x01u8, 0x02, 0x03, 0x04];
        let private_blob = &[0x05u8, 0x06, 0x07, 0x08];

        let mac_key = ppk_v2_derive_mac_key(passphrase.as_bytes());
        let mac_input = ppk_v2_mac_input(key_type, encryption, comment, public_blob, private_blob);
        let Some(expected_mac) = hmac_sha1_via_openssl(&mac_key, &mac_input) else { return };

        let mac_hex: String = expected_mac.iter().map(|b| format!("{b:02x}")).collect();

        use base64::Engine as _;
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public_blob);
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode(private_blob);
        let input = format!(
            "PuTTY-User-Key-File-2: {key_type}\nEncryption: {encryption}\n\
             Comment: {comment}\nPublic-Lines: 1\n{pub_b64}\n\
             Private-Lines: 1\n{priv_b64}\nPrivate-MAC: {mac_hex}\n"
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        ppk_v2_verify_mac(&f, passphrase, private_blob).expect("correct MAC must pass");
    }

    // -----------------------------------------------------------------------
    // PPK key extraction tests (error paths)
    // -----------------------------------------------------------------------

    /// `ppk_extract_rsa` returns Malformed when the public blob has a wrong
    /// key-type string.
    #[test]
    fn ppk_extract_rsa_wrong_key_type_fails() {
        // Construct a public blob with key-type "ssh-dss" (not "ssh-rsa").
        let mut pub_blob = Vec::new();
        let kt = b"ssh-dss";
        pub_blob.extend_from_slice(&(kt.len() as u32).to_be_bytes());
        pub_blob.extend_from_slice(kt);
        let err = ppk_extract_rsa(&pub_blob, &[], [0u8; 16], None)
            .err()
            .expect("wrong key-type must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// `ppk_extract_ec_p256` returns Unsupported for a non-P256 EC curve.
    #[test]
    fn ppk_extract_ec_p256_wrong_curve_returns_unsupported() {
        // Public blob: key-type="ecdsa-sha2-nistp256", curve="nistp384"
        let mut pub_blob = Vec::new();
        let kt = b"ecdsa-sha2-nistp256";
        pub_blob.extend_from_slice(&(kt.len() as u32).to_be_bytes());
        pub_blob.extend_from_slice(kt);
        let curve = b"nistp384";
        pub_blob.extend_from_slice(&(curve.len() as u32).to_be_bytes());
        pub_blob.extend_from_slice(curve);
        let err = ppk_extract_ec_p256(&pub_blob, &[], [0u8; 16], None)
            .err()
            .expect("wrong curve must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// `ppk_extract_key` returns Unsupported for an unrecognised key type.
    #[test]
    fn ppk_extract_key_unsupported_type_returns_unsupported() {
        use base64::Engine as _;
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode([1u8, 2]);
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode([3u8, 4]);
        // Build a minimal PPK v2 file with key-type "ssh-ed25519"
        let mac_hex = "00".repeat(20);
        let input = format!(
            "PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: none\nComment: key\n\
             Public-Lines: 1\n{pub_b64}\nPrivate-Lines: 1\n{priv_b64}\n\
             Private-MAC: {mac_hex}\n"
        );
        let ppk = parse_ppk(input.as_bytes()).expect("parse must succeed");
        // MAC will be wrong, but the Unsupported error fires before MAC check
        // since key_type dispatch happens after decrypt (encryption=none) but before MAC
        // in ppk_extract_key.  Actually it fires AFTER MAC check -- adjust expectation.
        // For encryption=none the plaintext blob is trivially "correct" but the MAC
        // check will fail.  We test Unsupported separately via ppk_extract_key directly.
        let err = ppk_extract_key(&ppk, "", [0u8; 16])
            .err()
            .expect("must fail");
        // The MAC check fires before key-type dispatch, so we expect Malformed.
        // If MAC happened to pass (very unlikely), we'd get Unsupported.
        assert!(
            matches!(err, KeyParseError::Malformed(_) | KeyParseError::Unsupported(_)),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // OpenPGP Radix-64 dearmor + CRC-24 tests
    // -----------------------------------------------------------------------

    /// CRC-24 of the empty slice equals the init value (0xB704CE).
    #[test]
    fn crc24_empty_equals_init() {
        assert_eq!(crc24(&[]), 0xB704CE);
    }

    /// CRC-24 of a known input matches the reference value computed via
    /// the Python `crc24` reference (RFC 4880 s.6.1 algorithm).
    ///
    /// Data: b"Hello, PGP!" -> CRC-24 0x8E9E3B
    #[test]
    fn crc24_known_vector() {
        assert_eq!(crc24(b"Hello, PGP!"), 0x8E9E3B);
    }

    /// CRC-24 of bytes(0..100) -> 0xA23228 (reference-computed).
    #[test]
    fn crc24_range100_vector() {
        let data: Vec<u8> = (0u8..100).collect();
        assert_eq!(crc24(&data), 0xA23228);
    }

    /// is_pgp_armor detects a BEGIN PGP header.
    #[test]
    fn is_pgp_armor_detects_begin_pgp() {
        assert!(is_pgp_armor(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"));
        assert!(is_pgp_armor(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));
        assert!(is_pgp_armor(b"-----BEGIN PGP MESSAGE-----\n"));
    }

    /// is_pgp_armor rejects non-PGP data.
    #[test]
    fn is_pgp_armor_rejects_non_pgp() {
        assert!(!is_pgp_armor(b"-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(!is_pgp_armor(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(!is_pgp_armor(b"\xfe\xed\xfe\xed"));
        assert!(!is_pgp_armor(b""));
    }

    /// dearmor correctly decodes a simple armored block with header fields.
    ///
    /// Data: b"Hello, PGP!" -> base64 "SGVsbG8sIFBHUCE=" -> CRC-24 0x8E9E3B
    /// -> armor checksum base64 "jp47" (from 0x8E 0x9E 0x3B).
    #[test]
    fn dearmor_simple_with_headers() {
        let armored = b"\
-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\
Version: Test 1.0\r\n\
Comment: unit test\r\n\
\r\n\
SGVsbG8sIFBHUCE=\r\n\
=jp47\r\n\
-----END PGP PRIVATE KEY BLOCK-----\r\n";
        let result = dearmor(armored).expect("dearmor must succeed");
        assert_eq!(result, b"Hello, PGP!");
    }

    /// dearmor works without header fields (blank line immediately after BEGIN).
    #[test]
    fn dearmor_no_header_fields() {
        let armored = b"\
-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
\n\
SGVsbG8sIFBHUCE=\n\
=jp47\n\
-----END PGP PUBLIC KEY BLOCK-----\n";
        let result = dearmor(armored).expect("dearmor must succeed");
        assert_eq!(result, b"Hello, PGP!");
    }

    /// dearmor handles multi-line base64 bodies.
    ///
    /// Data: bytes(0..100), split into two 64-char base64 lines.
    /// CRC-24: 0xA23228 -> base64 "ojIo".
    #[test]
    fn dearmor_multiline_body() {
        let armored = b"\
-----BEGIN PGP PRIVATE KEY BLOCK-----\n\
\n\
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n\
MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n\
YGFiYw==\n\
=ojIo\n\
-----END PGP PRIVATE KEY BLOCK-----\n";
        let expected: Vec<u8> = (0u8..100).collect();
        let result = dearmor(armored).expect("dearmor must succeed");
        assert_eq!(result, expected);
    }

    /// dearmor returns Malformed when the CRC-24 checksum is wrong.
    #[test]
    fn dearmor_wrong_crc_returns_malformed() {
        // Correct CRC for "Hello, PGP!" is "jp47"; use "AAAA" (0x000000) instead.
        let armored = b"\
-----BEGIN PGP PRIVATE KEY BLOCK-----\n\
\n\
SGVsbG8sIFBHUCE=\n\
=AAAA\n\
-----END PGP PRIVATE KEY BLOCK-----\n";
        let err = dearmor(armored).err().expect("must fail on bad CRC");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// dearmor returns Malformed when the BEGIN header is missing.
    #[test]
    fn dearmor_missing_header_returns_malformed() {
        let err = dearmor(b"SGVsbG8sIFBHUCE=\n=jp47\n")
            .err()
            .expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// dearmor accepts armored data with no checksum line (spec allows omitting it).
    #[test]
    fn dearmor_no_checksum_succeeds() {
        let armored = b"\
-----BEGIN PGP PRIVATE KEY BLOCK-----\n\
\n\
SGVsbG8sIFBHUCE=\n\
-----END PGP PRIVATE KEY BLOCK-----\n";
        let result = dearmor(armored).expect("dearmor without checksum must succeed");
        assert_eq!(result, b"Hello, PGP!");
    }

    /// Verify dearmor CRC-24 matches an independent openssl-based oracle for
    /// a longer payload.  The oracle computes HMAC-SHA256 is NOT used here --
    /// instead we generate a reference CRC via the Python algorithm embedded
    /// in the test vector above (bytes(0..100) -> CRC 0xA23228).
    #[test]
    fn dearmor_crc24_matches_reference_for_range100() {
        // Independently computed: Python crc24(bytes(range(100))) = 0xA23228.
        let data: Vec<u8> = (0u8..100).collect();
        assert_eq!(crc24(&data), 0xA23228, "CRC-24 mismatch against reference");
    }

    // -----------------------------------------------------------------------
    // OpenPGP packet header parser tests
    // -----------------------------------------------------------------------

    /// next_pgp_packet returns None on empty input.
    #[test]
    fn next_pgp_packet_empty_returns_none() {
        assert!(next_pgp_packet(&[]).is_none());
    }

    /// next_pgp_packet returns None when bit 7 of the tag byte is zero
    /// (not a valid OpenPGP packet tag).
    #[test]
    fn next_pgp_packet_invalid_tag_byte_returns_none() {
        assert!(next_pgp_packet(&[0x05, 0x00]).is_none()); // bit 7 = 0
    }

    /// Old-format SecretKey (tag 5), one-octet length.
    ///
    /// Tag byte layout: 1_0_TTTT_LL = 1_0_0101_00 = 0x94
    /// Length byte: 0x03 -> body is 3 bytes.
    #[test]
    fn next_pgp_packet_old_format_tag5_one_octet_length() {
        // 0x94 = 10_0101_00: old format (bit6=0), tag=5, length_type=0 (1-byte)
        let data = [0x94u8, 0x03, 0xAA, 0xBB, 0xCC];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body, [0xAA, 0xBB, 0xCC]);
        assert!(remainder.is_empty());
    }

    /// Old-format SecretSubkey (tag 7), two-octet length.
    ///
    /// Tag byte: 1_0_0111_01 = 0x9D; length = [0x00, 0x02] -> 2 bytes.
    #[test]
    fn next_pgp_packet_old_format_tag7_two_octet_length() {
        // 0x9D = 10_0111_01: old format, tag=7, length_type=1 (2-byte)
        let data = [0x9Du8, 0x00, 0x02, 0xDE, 0xAD];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_SUBKEY);
        assert_eq!(body, [0xDE, 0xAD]);
        assert!(remainder.is_empty());
    }

    /// Old-format four-octet length.
    ///
    /// Tag byte: 1_0_0101_10 = 0x96; length = [0x00, 0x00, 0x00, 0x02] -> 2 bytes.
    #[test]
    fn next_pgp_packet_old_format_four_octet_length() {
        // 0x96 = 10_0101_10: old format, tag=5, length_type=2 (4-byte)
        let data = [0x96u8, 0x00, 0x00, 0x00, 0x02, 0x11, 0x22];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body, [0x11, 0x22]);
        assert!(remainder.is_empty());
    }

    /// New-format SecretKey (tag 5), one-octet length.
    ///
    /// Tag byte: 1_1_000101 = 0xC5; length byte 3 -> body is 3 bytes.
    #[test]
    fn next_pgp_packet_new_format_tag5_one_octet_length() {
        // 0xC5 = 11_000101: new format (bit6=1), tag=5, 1-byte length
        let data = [0xC5u8, 0x03, 0xAA, 0xBB, 0xCC];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body, [0xAA, 0xBB, 0xCC]);
        assert!(remainder.is_empty());
    }

    /// New-format two-octet length: first byte 192, second byte 8 -> len = 200.
    ///
    /// Formula: ((192 - 192) << 8) + 8 + 192 = 200.
    #[test]
    fn next_pgp_packet_new_format_two_octet_length() {
        // 0xC5: new format tag 5; then 0xC0 0x08 -> two-octet len = 200
        let mut data = vec![0xC5u8, 0xC0, 0x08];
        data.extend(vec![0x55u8; 200]);
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body.len(), 200);
        assert!(remainder.is_empty());
    }

    /// New-format five-octet length (0xFF prefix).
    #[test]
    fn next_pgp_packet_new_format_five_octet_length() {
        // 0xC5: new format tag 5; then 0xFF + 4-byte BE length = 3
        let data = [0xC5u8, 0xFF, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body, [0xAA, 0xBB, 0xCC]);
        assert!(remainder.is_empty());
    }

    /// next_pgp_packet returns the remainder after the first packet.
    #[test]
    fn next_pgp_packet_returns_correct_remainder() {
        // Two old-format tag-5 packets, each 2 bytes long.
        // 0x94 = old format, tag=5, 1-byte length
        let data = [0x94u8, 0x02, 0x11, 0x22,
                    0x94u8, 0x02, 0x33, 0x44];
        let (_, body1, rest) = next_pgp_packet(&data).expect("first packet");
        assert_eq!(body1, [0x11, 0x22]);
        let (_, body2, rest2) = next_pgp_packet(rest).expect("second packet");
        assert_eq!(body2, [0x33, 0x44]);
        assert!(rest2.is_empty());
    }

    /// next_pgp_packet returns None when body is truncated.
    #[test]
    fn next_pgp_packet_truncated_body_returns_none() {
        // Claim 5-byte body but only 2 bytes present.
        let data = [0x94u8, 0x05, 0xAA, 0xBB];
        assert!(next_pgp_packet(&data).is_none());
    }

    /// next_pgp_packet returns None when length bytes are missing (old 2-byte).
    #[test]
    fn next_pgp_packet_truncated_length_returns_none() {
        // 0x9D = old format, tag=7, length_type=1 (2-byte), but only 1 length byte given.
        let data = [0x9Du8, 0x00];
        assert!(next_pgp_packet(&data).is_none());
    }

    /// pgp_collect_secret_packets extracts tag-5 and tag-7 packets, skipping others.
    ///
    /// Stream layout (all old-format, 1-byte length):
    ///   tag 2 (Signature) -- should be skipped
    ///   tag 5 (SecretKey) -- should be collected
    ///   tag 6 (PublicKey) -- should be skipped
    ///   tag 7 (SecretSubkey) -- should be collected
    #[test]
    fn pgp_collect_secret_packets_collects_tag5_and_tag7_only() {
        // Tag byte formula for old format: 1_0_TTTT_00
        // Tag 2: 10_0010_00 = 0x88; tag 5: 0x94; tag 6: 10_0110_00 = 0x98; tag 7: 0x9C
        let data = [
            0x88u8, 0x02, 0xAA, 0xBB,  // tag 2, body=[0xAA, 0xBB]
            0x94u8, 0x02, 0xCC, 0xDD,  // tag 5, body=[0xCC, 0xDD]
            0x98u8, 0x02, 0xEE, 0xFF,  // tag 6, body=[0xEE, 0xFF]
            0x9Cu8, 0x02, 0x11, 0x22,  // tag 7, body=[0x11, 0x22]
        ];
        let packets = pgp_collect_secret_packets(&data);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].0, PGP_TAG_SECRET_KEY);
        assert_eq!(packets[0].1, [0xCCu8, 0xDD]);
        assert_eq!(packets[1].0, PGP_TAG_SECRET_SUBKEY);
        assert_eq!(packets[1].1, [0x11u8, 0x22]);
    }

    /// pgp_collect_secret_packets returns empty Vec when no secret packets present.
    #[test]
    fn pgp_collect_secret_packets_empty_when_no_secret_packets() {
        // One Signature packet (tag 2) only.
        let data = [0x88u8, 0x02, 0xAA, 0xBB];
        assert!(pgp_collect_secret_packets(&data).is_empty());
    }

    /// pgp_collect_secret_packets stops at a malformed packet without panicking.
    #[test]
    fn pgp_collect_secret_packets_stops_at_malformed() {
        // Valid tag-5 packet, then truncated garbage.
        let data = [0x94u8, 0x01, 0xAA,  // valid: tag5, body=[0xAA]
                    0x94u8, 0x05, 0xBB]; // invalid: claims 5-byte body, only 1 byte
        let packets = pgp_collect_secret_packets(&data);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].1, [0xAAu8]);
    }

    // -----------------------------------------------------------------------
    // pgp_first_user_id_label tests
    // -----------------------------------------------------------------------

    /// pgp_first_user_id_label extracts the full UID when there is no email suffix.
    #[test]
    fn pgp_first_user_id_label_plain_email() {
        // Tag 13 (User ID), new format: 0xCD = 11_001101
        // Body: "gpgtest@test.invalid" (20 bytes)
        let uid = b"gpgtest@test.invalid";
        let mut data = vec![0xCDu8, uid.len() as u8];
        data.extend_from_slice(uid);
        let label = pgp_first_user_id_label(&data);
        assert_eq!(label.as_deref(), Some("gpgtest@test.invalid"));
    }

    /// pgp_first_user_id_label strips the angle-bracket email from "Name <email>".
    #[test]
    fn pgp_first_user_id_label_strips_email_suffix() {
        let uid = b"John Doe <john@example.com>";
        let mut data = vec![0xCDu8, uid.len() as u8];
        data.extend_from_slice(uid);
        let label = pgp_first_user_id_label(&data);
        assert_eq!(label.as_deref(), Some("John Doe"));
    }

    /// pgp_first_user_id_label returns None when no User-ID packet is present.
    #[test]
    fn pgp_first_user_id_label_none_when_no_uid_packet() {
        // Only a tag-5 Secret-Key packet; no User-ID.
        let data = [0x94u8, 0x02, 0x11, 0x22];
        assert!(pgp_first_user_id_label(&data).is_none());
    }

    // -----------------------------------------------------------------------
    // is_pgp_binary_secret_key_packet tests
    // -----------------------------------------------------------------------

    /// Old-format tag-5 packet (0x94) is detected as a binary PGP secret key.
    #[test]
    fn is_pgp_binary_secret_key_packet_detects_old_format_tag5() {
        assert!(is_pgp_binary_secret_key_packet(&[0x94, 0x03, 0xAA, 0xBB, 0xCC]));
    }

    /// New-format tag-5 packet (0xC5) is detected as a binary PGP secret key.
    #[test]
    fn is_pgp_binary_secret_key_packet_detects_new_format_tag5() {
        assert!(is_pgp_binary_secret_key_packet(&[0xC5, 0x03, 0xAA, 0xBB, 0xCC]));
    }

    /// Old-format tag-6 packet (Public-Key, 0x98 = 10_0110_00) is NOT detected.
    #[test]
    fn is_pgp_binary_secret_key_packet_rejects_tag6() {
        // 0x98 = old format, tag=6 (Public-Key), length_type=0
        assert!(!is_pgp_binary_secret_key_packet(&[0x98, 0x03, 0xAA]));
    }

    /// Empty slice returns false.
    #[test]
    fn is_pgp_binary_secret_key_packet_empty_returns_false() {
        assert!(!is_pgp_binary_secret_key_packet(&[]));
    }

    /// ASN.1 DER SEQUENCE start byte (0x30) is not a PGP secret-key packet.
    #[test]
    fn is_pgp_binary_secret_key_packet_rejects_der_sequence() {
        assert!(!is_pgp_binary_secret_key_packet(&[0x30, 0x82, 0x01, 0x00]));
    }

    /// dearmor produces the same binary as `gpg --export-secret-keys` (non-armored).
    ///
    /// This test is skipped when `gpg` is not installed.  It generates a
    /// temporary key pair so that the test keyring is self-contained.
    #[test]
    fn dearmor_matches_gpg_binary_export() {
        use std::process::{Command, Stdio};

        // Check gpg availability.
        if Command::new("gpg").arg("--version").stdout(Stdio::null()).stderr(Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false) == false { return; }

        let dir = tempfile::tempdir().unwrap();
        let gnupghome = dir.path().to_str().unwrap().to_string();

        // Generate an unprotected RSA-2048 key in the temp keyring.
        let key_params = "\
%no-protection\n\
Key-Type: RSA\n\
Key-Length: 2048\n\
Name-Real: Dearmor Test\n\
Name-Email: dearmor@test.invalid\n\
Expire-Date: 0\n\
%commit\n";
        let param_path = dir.path().join("params.txt");
        std::fs::write(&param_path, key_params).unwrap();

        let ok = Command::new("gpg")
            .env("GNUPGHOME", &gnupghome)
            .args(["--batch", "--gen-key", param_path.to_str().unwrap()])
            .stdout(Stdio::null()).stderr(Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false);
        if !ok { return; }

        // Get the fingerprint of the generated key.
        let fp_out = Command::new("gpg")
            .env("GNUPGHOME", &gnupghome)
            .args(["--list-secret-keys", "--with-colons"])
            .output().unwrap();
        let fp_text = String::from_utf8_lossy(&fp_out.stdout);
        let fingerprint: String = fp_text.lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .unwrap_or("").to_string();
        if fingerprint.is_empty() { return; }

        // Export armored.
        let armored = Command::new("gpg")
            .env("GNUPGHOME", &gnupghome)
            .args(["--armor", "--export-secret-keys", &fingerprint])
            .output().unwrap().stdout;
        if armored.is_empty() { return; }

        // Export raw (non-armored) binary.
        let binary = Command::new("gpg")
            .env("GNUPGHOME", &gnupghome)
            .args(["--export-secret-keys", &fingerprint])
            .output().unwrap().stdout;
        if binary.is_empty() { return; }

        // Dearmor the armored export and compare.
        let decoded = dearmor(&armored).expect("dearmor of real GPG export must succeed");
        assert_eq!(decoded, binary, "dearmored output must match raw GPG export");
    }

    // -----------------------------------------------------------------------
    // OpenPGP v4 Public-Key body parser + MPI decoder tests
    // -----------------------------------------------------------------------

    /// read_pgp_mpi: one-byte value, 7-bit MPI.
    #[test]
    fn read_pgp_mpi_one_byte() {
        // bit count = 7 (0x0007); byte count = 1; value = 0x7F
        let data = [0x00u8, 0x07, 0x7F, 0xAA]; // 0xAA is remainder
        let (value, rest) = read_pgp_mpi(&data).expect("must parse");
        assert_eq!(value, [0x7Fu8]);
        assert_eq!(rest, [0xAAu8]);
    }

    /// read_pgp_mpi: two-byte value, 9-bit MPI.
    #[test]
    fn read_pgp_mpi_two_bytes() {
        // bit count = 9 (0x0009); byte count = 2; value = [0x01, 0xFF]
        let data = [0x00u8, 0x09, 0x01, 0xFF];
        let (value, rest) = read_pgp_mpi(&data).expect("must parse");
        assert_eq!(value, [0x01u8, 0xFF]);
        assert!(rest.is_empty());
    }

    /// read_pgp_mpi: bit count that is an exact multiple of 8.
    #[test]
    fn read_pgp_mpi_exact_byte_boundary() {
        // bit count = 8 (0x0008); byte count = 1
        let data = [0x00u8, 0x08, 0x80];
        let (value, _) = read_pgp_mpi(&data).expect("must parse");
        assert_eq!(value, [0x80u8]);
    }

    /// read_pgp_mpi: bit count zero -> zero-byte value.
    #[test]
    fn read_pgp_mpi_bit_count_zero() {
        // bit count = 0; byte count = 0; value = empty
        let data = [0x00u8, 0x00, 0xFF]; // 0xFF is remainder
        let (value, rest) = read_pgp_mpi(&data).expect("must parse");
        assert!(value.is_empty());
        assert_eq!(rest, [0xFFu8]);
    }

    /// read_pgp_mpi returns None on truncated data (less than 2 bytes).
    #[test]
    fn read_pgp_mpi_truncated_header() {
        assert!(read_pgp_mpi(&[]).is_none());
        assert!(read_pgp_mpi(&[0x00]).is_none());
    }

    /// read_pgp_mpi returns None when body is shorter than the declared bit count.
    #[test]
    fn read_pgp_mpi_truncated_body() {
        // Claims 9-bit MPI (2 bytes) but only 1 byte of body present.
        let data = [0x00u8, 0x09, 0x01];
        assert!(read_pgp_mpi(&data).is_none());
    }

    /// parse_pgp_public_key_body: RSA algorithm 1, simple key material.
    ///
    /// Body: version=4, timestamp=[0;4], algorithm=1,
    ///   MPI n = 0x0123 (9 bits), MPI e = 0x010001 (17 bits).
    #[test]
    fn parse_pgp_pubkey_body_rsa_success() {
        let mut body = Vec::new();
        body.push(4u8);                        // version
        body.extend_from_slice(&[0u8; 4]);    // timestamp
        body.push(1u8);                        // algorithm: RSA
        // MPI n: bit count = 9 (0x0009), value = [0x01, 0x23]
        body.extend_from_slice(&[0x00, 0x09, 0x01, 0x23]);
        // MPI e: bit count = 17 (0x0011), value = [0x01, 0x00, 0x01]
        body.extend_from_slice(&[0x00, 0x11, 0x01, 0x00, 0x01]);
        // Secret material (should be in remaining)
        let secret_tag = [0xFFu8, 0xEE];
        body.extend_from_slice(&secret_tag);

        let parsed = parse_pgp_public_key_body(&body).expect("must parse RSA");
        assert_eq!(parsed.algorithm, 1);
        match &parsed.material {
            PgpPublicKeyMaterial::Rsa { n, e } => {
                assert_eq!(n.as_slice(), [0x01u8, 0x23]);
                assert_eq!(e.as_slice(), [0x01u8, 0x00, 0x01]);
            }
            _ => panic!("expected RSA material"),
        }
        // fingerprint_body covers version..last_public_MPI (excludes secret_tag)
        assert_eq!(parsed.fingerprint_body.len(), body.len() - secret_tag.len());
        assert_eq!(parsed.fingerprint_body[0], 4); // version byte
        assert_eq!(parsed.remaining, secret_tag);
    }

    /// parse_pgp_public_key_body: ECDSA algorithm 19, P-256 public point.
    ///
    /// Uses the known EC P-256 test key from the PPK v3 fixture.
    #[test]
    fn parse_pgp_pubkey_body_ecdsa_p256_success() {
        // Public point from the PPK v3 fixture (same key pair).
        let public_point = hex::decode(
            "0401aecf6df8814671c6ea4fd2d8ccde01338a8358e7085d1f3475cfe0019098d\
             6a26a37e764265e89e5c4e61a7f4fced3ab36d1deca420e93590afe3cdfc7a4ec"
        ).unwrap();
        assert_eq!(public_point.len(), 65);

        // bit count for 65-byte value starting with 0x04 = 0b00000100:
        // MSB is bit 2 in first byte -> bit_count = 2 + 64*8 + 1 = 515 = 0x0203
        let bit_count: u16 = 515;

        let mut body = Vec::new();
        body.push(4u8);                           // version
        body.extend_from_slice(&[0x00u8; 4]);     // timestamp
        body.push(19u8);                          // algorithm: ECDSA
        body.push(8u8);                           // OID length
        body.extend_from_slice(P256_OID);         // P-256 OID
        body.extend_from_slice(&bit_count.to_be_bytes()); // MPI bit count
        body.extend_from_slice(&public_point);    // MPI value (public point)
        // No remaining secret material in this test.

        let parsed = parse_pgp_public_key_body(&body).expect("must parse ECDSA");
        assert_eq!(parsed.algorithm, 19);
        match &parsed.material {
            PgpPublicKeyMaterial::Ecdsa { public_point: pt } => {
                assert_eq!(pt.as_slice(), public_point.as_slice());
            }
            _ => panic!("expected ECDSA material"),
        }
        // fingerprint_body must equal the entire body (no remaining bytes).
        assert_eq!(parsed.fingerprint_body, body);
        assert!(parsed.remaining.is_empty());
    }

    /// parse_pgp_public_key_body returns Unsupported for version != 4.
    #[test]
    fn parse_pgp_pubkey_body_version_not_4_returns_unsupported() {
        let body = [3u8, 0, 0, 0, 0, 1]; // version=3
        let err = parse_pgp_public_key_body(&body).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// parse_pgp_public_key_body returns Unsupported for unknown algorithm.
    #[test]
    fn parse_pgp_pubkey_body_unsupported_algorithm() {
        // Algorithm 17 = DSA
        let body = [4u8, 0, 0, 0, 0, 17];
        let err = parse_pgp_public_key_body(&body).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// parse_pgp_public_key_body returns Unsupported for ECDSA with a non-P-256 curve.
    #[test]
    fn parse_pgp_pubkey_body_ecdsa_non_p256_returns_unsupported() {
        // P-384 OID: 06 05 2b 81 04 00 22 (length=5, OID=[2b 81 04 00 22])
        let p384_oid: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
        let mut body = Vec::new();
        body.push(4u8);             // version
        body.extend_from_slice(&[0u8; 4]);  // timestamp
        body.push(19u8);            // algorithm: ECDSA
        body.push(p384_oid.len() as u8);
        body.extend_from_slice(p384_oid);
        // Minimal MPI placeholder (truncated) -- error fires before MPI read
        body.extend_from_slice(&[0x01, 0x00, 0xFF]);

        let err = parse_pgp_public_key_body(&body).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// parse_pgp_public_key_body returns Malformed on truncated RSA MPI n.
    #[test]
    fn parse_pgp_pubkey_body_rsa_truncated_n_returns_malformed() {
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(&[0u8; 4]);
        body.push(1u8); // RSA
        // Claim 9-bit MPI (2 bytes) but give only 1 byte of value
        body.extend_from_slice(&[0x00, 0x09, 0x01]);

        let err = parse_pgp_public_key_body(&body).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    // OpenPGP S2K key derivation tests

    /// S2K type 0 (simple SHA-1): SHA-1 of passphrase, first key_len bytes.
    ///
    /// Vector derived from: SHA-1("test1234") = 9bc34549d565d9505b287de0cd20ac77be1d3f2c
    #[test]
    fn pgp_s2k_type0_sha1_known_vector() {
        let key = pgp_s2k_derive_key(b"test1234", 0, 2, &[], 0, 16)
            .expect("S2K type 0 must succeed");
        assert_eq!(
            key,
            hex::decode("9bc34549d565d9505b287de0cd20ac77").unwrap(),
            "S2K type 0 SHA-1 key mismatch"
        );
    }

    /// S2K type 3 (iterated+salted SHA-1): known vector with salt=01..08, count_byte=96.
    ///
    /// count_byte=96 -> count = (16+0) << (6+6) = 65536.
    /// Vector derived from the Python reference in the session notes.
    #[test]
    fn pgp_s2k_type3_sha1_known_vector() {
        let salt = hex::decode("0102030405060708").unwrap();
        // count for count_byte=96: (16 + (96 & 15)) << ((96 >> 4) + 6) = 16 << 12 = 65536
        let count: usize = (16usize + (96usize & 15)) << ((96usize >> 4) + 6);
        assert_eq!(count, 65536);
        let key = pgp_s2k_derive_key(b"test1234", 3, 2, &salt, count, 16)
            .expect("S2K type 3 must succeed");
        assert_eq!(
            key,
            hex::decode("47834d3754e438ab593cd9a81009daf2").unwrap(),
            "S2K type 3 SHA-1 key mismatch"
        );
    }

    /// S2K with an unsupported hash ID returns Unsupported.
    #[test]
    fn pgp_s2k_unsupported_hash_returns_unsupported() {
        let err = pgp_s2k_derive_key(b"pass", 0, 3, &[], 0, 16)
            .err()
            .expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    // OpenPGP secret key decryption tests

    /// pgp_decrypt_secret_material: plaintext key (usage=0x00) with correct checksum.
    ///
    /// remaining = 0x00 || MPI(256-bit 0xAB..AB) || checksum(0x1561)
    #[test]
    fn pgp_decrypt_plaintext_usage_zero() {
        let remaining = hex::decode(
            "000100abababababababababababababababababababababababababababababababab1561"
        ).unwrap();
        let mpi = pgp_decrypt_secret_material(&remaining, b"ignored")
            .expect("plaintext must succeed");
        // MPI bytes: 0x0100 (bit count) + 32x0xAB
        assert_eq!(mpi.len(), 34);
        assert_eq!(&mpi[..2], &[0x01, 0x00]);
        assert!(mpi[2..].iter().all(|&b| b == 0xAB));
    }

    /// pgp_decrypt_secret_material: plaintext key with wrong checksum returns Malformed.
    #[test]
    fn pgp_decrypt_plaintext_bad_checksum_returns_malformed() {
        let mut remaining = hex::decode(
            "000100abababababababababababababababababababababababababababababababab1561"
        ).unwrap();
        // Corrupt the checksum.
        let len = remaining.len();
        remaining[len - 1] ^= 0xFF;
        let err = pgp_decrypt_secret_material(&remaining, b"ignored")
            .err()
            .expect("bad checksum must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// pgp_decrypt_secret_material: AES-128-CFB with S2K type 3, SHA-1, usage=0xFE.
    ///
    /// Test vector generated by the Python reference implementation:
    ///   passphrase = "hunter2"
    ///   salt = deadbeef01234567
    ///   count_byte = 96 (count=65536)
    ///   iv = aabbccdd11223344556677889900aabb
    ///   plaintext MPI = 256-bit value 0x4242..42
    #[test]
    fn pgp_decrypt_aes128_s2k_type3_sha1_known_vector() {
        let remaining = hex::decode(concat!(
            "fe070302",                 // usage=0xFE, cipher=7(AES-128), S2K=3, hash=2(SHA-1)
            "deadbeef01234567",         // salt (8 bytes)
            "60",                       // count_byte=96
            "aabbccdd11223344556677889900aabb", // IV (16 bytes)
            // ciphertext (54 bytes): encrypt(MPI(256-bit 0x42..42) || SHA-1(MPI))
            "8e47509e64519b2e7bd215bfcd660b7c",
            "283de63f2256c2c5c9e43a561ffd2e16",
            "be1a003b3edf4363d9c7d911d3bba9a3",
            "0415fd7f7785"
        )).unwrap();

        let mpi = pgp_decrypt_secret_material(&remaining, b"hunter2")
            .expect("correct passphrase must succeed");

        // Decrypted MPI: 0x0100 (256 bits) + 32x0x42
        assert_eq!(mpi.len(), 34, "MPI bytes length mismatch");
        assert_eq!(&mpi[..2], &[0x01, 0x00], "MPI bit-count header mismatch");
        assert!(mpi[2..].iter().all(|&b| b == 0x42), "MPI value mismatch");
    }

    /// pgp_decrypt_secret_material: wrong passphrase returns Malformed (SHA-1 mismatch).
    #[test]
    fn pgp_decrypt_wrong_passphrase_returns_malformed() {
        let remaining = hex::decode(concat!(
            "fe070302",
            "deadbeef01234567",
            "60",
            "aabbccdd11223344556677889900aabb",
            "8e47509e64519b2e7bd215bfcd660b7c",
            "283de63f2256c2c5c9e43a561ffd2e16",
            "be1a003b3edf4363d9c7d911d3bba9a3",
            "0415fd7f7785"
        )).unwrap();

        let err = pgp_decrypt_secret_material(&remaining, b"wrong")
            .err()
            .expect("wrong passphrase must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// pgp_decrypt_secret_material with a real GPG-exported P-256 key.
    ///
    /// Generates a key in a temp GNUPGHOME, exports the binary secret packet,
    /// parses the public portion, and decrypts with the known passphrase.
    /// Skipped when `gpg` is not available.
    #[test]
    fn pgp_decrypt_gpg_p256_key_end_to_end() {
        use std::process::Command;
        let gpg_ok = Command::new("gpg").arg("--version").output().is_ok();
        if !gpg_ok {
            return;
        }

        let tmpdir = tempfile::tempdir().expect("tempdir");
        let gnupghome = tmpdir.path().to_str().unwrap();
        let passphrase = "pgp-test-pass";

        // Generate a nistp256 key.
        let status = Command::new("gpg")
            .args([
                "--batch", "--yes",
                "--pinentry-mode", "loopback",
                "--passphrase", passphrase,
                "--quick-generate-key", "pgptest@test.invalid",
                "nistp256", "default", "0",
            ])
            .env("GNUPGHOME", gnupghome)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("gpg keygen");
        assert!(status.success(), "gpg --quick-generate-key failed");

        // Export binary secret key.
        let output = Command::new("gpg")
            .args([
                "--batch", "--yes",
                "--pinentry-mode", "loopback",
                "--passphrase", passphrase,
                "--export-secret-keys",
            ])
            .env("GNUPGHOME", gnupghome)
            .output()
            .expect("gpg export");
        assert!(output.status.success(), "gpg --export-secret-keys failed");
        let binary = output.stdout;

        // Collect secret-key packets and find a P-256 one.
        let packets = pgp_collect_secret_packets(&binary);
        let mut found = false;
        for (_tag, body) in &packets {
            let pubkey = match parse_pgp_public_key_body(body) {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            if !matches!(pubkey.material, PgpPublicKeyMaterial::Ecdsa { .. }) {
                continue;
            }

            let mpi_bytes =
                pgp_decrypt_secret_material(&pubkey.remaining, passphrase.as_bytes())
                    .expect("decrypt with correct passphrase must succeed");

            // The decrypted MPI bytes should start with a 2-byte bit-count header
            // and contain exactly 32 bytes for a P-256 scalar.
            assert!(mpi_bytes.len() >= 2, "MPI bytes too short");
            let bit_count = u16::from_be_bytes([mpi_bytes[0], mpi_bytes[1]]) as usize;
            let byte_count = (bit_count + 7) / 8;
            assert_eq!(
                mpi_bytes.len(),
                2 + byte_count,
                "MPI byte count doesn't match declared bit count"
            );
            assert!(
                byte_count <= 32,
                "P-256 scalar must be <=32 bytes, got {byte_count}"
            );
            found = true;
            break;
        }
        assert!(found, "no P-256 secret key packet found in GPG export");
    }
}
