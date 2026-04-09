/// Private key parser library for usb-hsm.
///
/// Parses binary key material and returns key bytes in the format expected by
/// [`crate::keystore::KeyEntry`]:
///   - RSA: PKCS#1 DER (the raw `RSAPrivateKey` structure)
///   - EC P-256: raw 32-byte big-endian private key scalar
///
/// Supported PEM types:
///   "RSA PRIVATE KEY"  -- PKCS#1 directly
///   "EC PRIVATE KEY"   -- RFC 5915 `ECPrivateKey`; P-256 only
///   "PRIVATE KEY"      -- PKCS#8 `PrivateKeyInfo`; RSA or EC P-256
///
/// DER files are auto-detected by content rather than extension.
use std::io;
use std::path::Path;

use crate::keystore::KeyType;

mod encrypted_pkcs8;
mod openssh;
mod jks;
mod pkcs12;
mod ppk;
mod openpgp;

pub use encrypted_pkcs8::parse_encrypted_pkcs8;
pub use openssh::{parse_openssh_binary, OpensshFrame};
pub use pkcs12::{verify_pfx_mac, parse_pfx_structure, extract_keys_from_pfx_bags};
pub use openpgp::{
    pgp_collect_secret_packets, pgp_first_user_id_label, is_pgp_armor, dearmor,
    is_pgp_binary_secret_key_packet, next_pgp_packet, parse_pgp_public_key_body,
    pgp_decrypt_secret_material, read_pgp_mpi, PGP_TAG_SECRET_KEY, PGP_TAG_SECRET_SUBKEY,
    PgpPublicKeyMaterial, ParsedPublicKey,
};
pub use ppk::{
    is_ppk, parse_ppk, ppk_v2_derive_key, ppk_v2_decrypt_private_blob, ppk_v2_verify_mac,
    ppk_v3_decrypt_private_blob, ppk_v3_verify_mac,
};
pub use jks::{is_jks_or_jceks, parse_jks_structure, verify_jks_integrity};
#[cfg(test)]
pub(crate) use openssh::{OPENSSH_MAGIC, decrypt_openssh_blob, verify_openssh_check_words};
#[cfg(test)]
pub(crate) use openpgp::{crc24, P256_OID, pgp_s2k_derive_key};
#[cfg(test)]
pub(crate) use ppk::{
    ppk_extract_key, ppk_extract_rsa, ppk_extract_ec_p256,
    ppk_v3_derive_key_iv_mac, ppk_v2_derive_mac_key, ppk_v2_mac_input, PPK_MAC_KEY_PREFIX,
};
#[cfg(test)]
pub(crate) use jks::decrypt_jks_private_key_entry;

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
/// use the Vec to return multiple keys from a single input.
///
/// `passphrase_fn` is called (at most once per encrypted format) with a prompt
/// string and must return the passphrase. Callers that do not handle encrypted
/// keys may pass `|_| Ok(String::new())`. The `path_hint` is used only to
/// derive a fallback alias/label from the filename stem; pass `None` when
/// parsing in-memory bytes with no associated path.
pub fn parse_key_bytes(
    data: &[u8],
    passphrase_fn: &dyn Fn(&str) -> io::Result<String>,
    path_hint: Option<&Path>,
) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let id = random_id()?;
    let stem = || -> String {
        path_hint
            .and_then(|p| p.file_stem())
            .and_then(|s| s.to_str())
            .unwrap_or("key")
            .to_string()
    };

    // GCP service account JSON: check before PEM/DER paths since a JSON file
    // starts with '{', not '-----BEGIN', but we want a clear detection path.
    if let Some(gcp) = detect_gcp_json(data) {
        let alias = stem();

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
        // the random ID generated at the top of parse_key_bytes.
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

    let parsed = if is_pgp_armor(data) {
        let binary = dearmor(data)?;
        return openpgp::parse_pgp_binary(&binary, passphrase_fn);
    } else if openpgp::is_pgp_binary_secret_key_packet(data) {
        return openpgp::parse_pgp_binary(data, passphrase_fn);
    } else if data.starts_with(b"-----BEGIN") {
        let pem_block = pem::parse(data)
            .map_err(|e| KeyParseError::Malformed(format!("PEM parse error: {e}")))?;
        match pem_block.tag() {
            "RSA PRIVATE KEY" => parse_rsa_pkcs1(pem_block.contents(), id),
            "EC PRIVATE KEY" => parse_ec_sec1(pem_block.contents(), id),
            "PRIVATE KEY" => parse_pkcs8(pem_block.contents(), id),
            "ENCRYPTED PRIVATE KEY" => {
                let passphrase = passphrase_fn("Passphrase for encrypted key: ")
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
                    passphrase_fn("Passphrase for OpenSSH key: ")
                        .map_err(KeyParseError::Io)?
                };

                // Decrypt (or pass through) the private blob, then verify check words.
                let blob = openssh::decrypt_openssh_blob(&frame, &passphrase)?;
                let key_data = openssh::verify_openssh_check_words(&blob)?;
                openssh::parse_openssh_key_data(key_data, id)
            }
            tag => Err(KeyParseError::Unsupported(format!(
                "PEM type \"{tag}\" is not supported (expected \
                 \"RSA PRIVATE KEY\", \"EC PRIVATE KEY\", or \"PRIVATE KEY\")"
            ))),
        }
    } else if is_ppk(data) {
        return ppk::parse_ppk_file_data(data, passphrase_fn);
    } else if is_jks_or_jceks(data) {
        return parse_jks_file_data(data, passphrase_fn);
    } else if !data.starts_with(openssh::OPENSSH_MAGIC) && is_pfx_der(data) {
        // PKCS#12 PFX: can contain multiple keys; handled separately.
        return parse_pfx_file_data(data, passphrase_fn);
    } else {
        // Bare DER: probe for PKCS#8 or PKCS#1 / SEC1 by structure.
        parse_der_auto(data, id, passphrase_fn)
    };

    match parsed {
        Ok(key) => Ok((vec![key], vec![])),
        Err(e) => {
            // For single-key formats a parse error on the one key is treated as
            // a per-entry failure (the outer file structure was readable), not a
            // fatal error. The alias is the filename stem.
            Ok((vec![], vec![(stem(), e)]))
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
    passphrase_fn: &dyn Fn(&str) -> io::Result<String>,
) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let passphrase = passphrase_fn("Passphrase for PKCS#12 file: ")
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
    passphrase_fn: &dyn Fn(&str) -> io::Result<String>,
) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let passphrase = passphrase_fn("Passphrase for JKS/JCEKS keystore: ")
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
        match jks::decrypt_jks_private_key_entry(&entry.encrypted_key, &passphrase, entry_id) {
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
fn parse_der_auto(der: &[u8], id: [u8; 16], passphrase_fn: &dyn Fn(&str) -> io::Result<String>) -> Result<ParsedKey, KeyParseError> {
    // OpenSSH new-format binary file (no PEM wrapper): detect before SEQUENCE check.
    if der.starts_with(openssh::OPENSSH_MAGIC) {
        let frame = parse_openssh_binary(der)?;
        let passphrase = if frame.ciphername == "none" {
            String::new()
        } else {
            passphrase_fn("Passphrase for OpenSSH key: ")
                .map_err(KeyParseError::Io)?
        };
        let blob = openssh::decrypt_openssh_blob(&frame, &passphrase)?;
        let key_data = openssh::verify_openssh_check_words(&blob)?;
        return openssh::parse_openssh_key_data(key_data, id);
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
                    let passphrase = passphrase_fn("Passphrase for encrypted key: ")
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

/// Constant-time byte-slice equality.  Returns true iff `a == b` with no
/// early exit on the first differing byte, preventing timing side-channels
/// in MAC/hash comparisons.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
    let mut half1: [u8; 4] = salt_bytes[4..].try_into().expect("len checked above");
    // OpenJDK PBECipherCore: apply per-half inversion when a half consists of
    // two repeated 2-byte pairs — [A,B,A,B] → [B,A,B,A] is the internal
    // repetition check; the transformation is [a,b,c,d] → [d,a,b,d].
    // Applied independently to each half; half1 requires `mut` too.
    if half0[0] == half0[2] && half0[1] == half0[3] {
        half0 = [half0[3], half0[0], half0[1], half0[3]];
    }
    if half1[0] == half1[2] && half1[1] == half1[3] {
        half1 = [half1[3], half1[0], half1[1], half1[3]];
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
    // Reject negative integers (high bit set with no leading 0x00).
    if int_bytes.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        return None;
    }
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
// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
