use super::*;

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
        let (tag, attr_seq_body, rest) = match super::next_tlv(cur) {
            Some(x) => x,
            None => break,
        };
        cur = rest;
        if tag != 0x30 {
            continue;
        }
        let (_, oid, attr_rest) = match super::tlv(attr_seq_body, 0x06) {
            Some(x) => x,
            None => continue,
        };
        let (_, value_set, _) = match super::tlv(attr_rest, 0x31) {
            Some(x) => x,
            None => continue,
        };
        if oid == OID_PKCS9_LOCAL_KEY_ID {
            if let Some((_, val, _)) = super::tlv(value_set, 0x04) {
                let id_bytes = val.to_vec();
                if !id_bytes.is_empty() {
                    local_key_id = Some(id_bytes);
                }
            }
        } else if oid == OID_PKCS9_FRIENDLY_NAME {
            if let Some((_, val, _)) = super::tlv(value_set, 0x1e) {
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
    let (_, seq_body, _) = super::tlv(der, 0x30)
        .ok_or_else(|| super::malformed("PFX SafeContents: expected SEQUENCE"))?;

    let mut cur = seq_body;
    let mut bag_count = 0usize;
    while !cur.is_empty() {
        // Cap SafeBag count to bound memory use from a crafted PKCS#12 file.
        // Each bag_value is .to_vec()-allocated; unbounded growth would allow
        // OOM via many bags. 1,000 bags is far beyond any legitimate keystore.
        // (soft_PKCS11-la8f)
        bag_count += 1;
        if bag_count > 1_000 {
            return Err(super::malformed("PFX SafeContents: SafeBag count exceeds maximum (1000)"));
        }
        let (tag, safe_bag_body, rest) = super::next_tlv(cur)
            .ok_or_else(|| super::malformed("PFX SafeContents: truncated SafeBag"))?;
        cur = rest;
        if tag != 0x30 {
            continue;
        }

        // bagId OID
        let (_, bag_id, sb_rest) = match super::tlv(safe_bag_body, 0x06) {
            Some(x) => x,
            None => continue,
        };

        // bagValue [0] EXPLICIT
        let (_, bag_value_body, sb_rest2) = match super::tlv(sb_rest, 0xa0) {
            Some(x) => x,
            None => continue,
        };

        // bagAttributes SET (tag 0x31, optional)
        let (local_key_id, friendly_name) = if sb_rest2.first() == Some(&0x31) {
            match super::tlv(sb_rest2, 0x31) {
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
    let (_, a0, _) = super::tlv(ci_rest, 0xa0)
        .ok_or_else(|| super::malformed("PKCS#12 encryptedData: [0] EXPLICIT wrapper missing"))?;

    // EncryptedData SEQUENCE
    let (_, ed_body, _) = super::tlv(a0, 0x30)
        .ok_or_else(|| super::malformed("PKCS#12 encryptedData: EncryptedData SEQUENCE missing"))?;

    // Skip version INTEGER
    let (_, _, eci_der) = super::tlv(ed_body, 0x02)
        .ok_or_else(|| super::malformed("PKCS#12 encryptedData: version INTEGER missing"))?;

    // EncryptedContentInfo SEQUENCE
    let (_, eci_body, _) = super::tlv(eci_der, 0x30)
        .ok_or_else(|| super::malformed("PKCS#12 encryptedData: EncryptedContentInfo SEQUENCE missing"))?;

    // Skip contentType OID (typically id-data)
    let (_, _, alg_and_content) = super::tlv(eci_body, 0x06)
        .ok_or_else(|| super::malformed("PKCS#12 encryptedData: contentType OID missing"))?;

    // AlgorithmIdentifier SEQUENCE: encryption OID + params
    let (_, alg_id, content_rest) = super::tlv(alg_and_content, 0x30)
        .ok_or_else(|| super::malformed("PKCS#12 encryptedData: AlgorithmIdentifier missing"))?;

    let (_, enc_oid, alg_params) = super::tlv(alg_id, 0x06)
        .ok_or_else(|| super::malformed("PKCS#12 encryptedData: encryption OID missing"))?;

    // encryptedContent [0] IMPLICIT OCTET STRING (tag 0x80) or bare OCTET STRING (0x04)
    let ciphertext = match content_rest.first() {
        Some(&0x80) => {
            super::next_tlv(content_rest)
                .ok_or_else(|| super::malformed("PKCS#12 encryptedData: encryptedContent truncated"))?.1
        }
        Some(&0x04) => {
            super::tlv(content_rest, 0x04)
                .ok_or_else(|| super::malformed("PKCS#12 encryptedData: encryptedContent OCTET STRING missing"))?.1
        }
        _ => return Err(super::malformed("PKCS#12 encryptedData: encryptedContent missing")),
    };

    if enc_oid == OID_PBES2 {
        use sec1::der::Decode as _;
        let params = pkcs5::pbes2::Parameters::from_der(alg_params)
            .map_err(|e| KeyParseError::Unsupported(
                format!("PBES2: unsupported parameters ({e}); {conversion_msg}")
            ))?;
        params.decrypt(passphrase.as_bytes(), ciphertext)
            .map_err(|_| super::malformed("PBES2 decrypt failed (wrong passphrase?)"))
            .map(|pt| pt.to_vec())
    } else if enc_oid == OID_PKCS12_SHA1_3DES {
        super::pkcs12_pbe_sha1_3des_decrypt(alg_params, passphrase, ciphertext)
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
    let (_, seq_body, _) = super::tlv(der, 0x30)
        .ok_or_else(|| super::malformed("PFX AuthenticatedSafe: expected SEQUENCE"))?;

    let mut cur = seq_body;
    let mut ci_count = 0usize;
    while !cur.is_empty() {
        // Cap ContentInfo count; a legitimate PKCS#12 has 1–3 ContentInfos.
        // (soft_PKCS11-la8f)
        ci_count += 1;
        if ci_count > 100 {
            return Err(super::malformed("PFX AuthenticatedSafe: ContentInfo count exceeds maximum (100)"));
        }
        let (tag, ci_body, rest) = super::next_tlv(cur)
            .ok_or_else(|| super::malformed("PFX AuthenticatedSafe: truncated ContentInfo"))?;
        cur = rest;
        if tag != 0x30 {
            continue;
        }

        let (_, ci_oid, ci_rest) = match super::tlv(ci_body, 0x06) {
            Some(x) => x,
            None => continue,
        };

        if ci_oid == OID_PKCS7_DATA {
            // content [0] EXPLICIT OCTET STRING -> SafeContents DER
            let a0 = match super::tlv(ci_rest, 0xa0) {
                Some((_, v, _)) => v,
                None => continue,
            };
            let safe_contents_der = match super::tlv(a0, 0x04) {
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
    .map_err(|_| super::malformed("PFX: MAC key derivation failed"))?;

    let computed = if hash_type == WC_HASH_TYPE_SHA1 {
        super::hmac_sha1(&mac_key, mac_input).to_vec()
    } else {
        super::hmac_sha256(&mac_key, mac_input).to_vec()
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
    let (_, pfx_body, _) = super::tlv(der, 0x30)
        .ok_or_else(|| super::malformed("PFX: expected outer SEQUENCE"))?;
    let (_, _version, pfx_rest) = super::tlv(pfx_body, 0x02)
        .ok_or_else(|| super::malformed("PFX: version INTEGER missing"))?;

    // authSafe ContentInfo: extract the AuthenticatedSafe bytes (MAC input).
    let (_, auth_safe_body, pfx_rest2) = super::tlv(pfx_rest, 0x30)
        .ok_or_else(|| super::malformed("PFX: authSafe ContentInfo missing"))?;
    let (_, ct_oid, auth_safe_rest) = super::tlv(auth_safe_body, 0x06)
        .ok_or_else(|| super::malformed("PFX: authSafe contentType OID missing"))?;
    if ct_oid != OID_PKCS7_DATA {
        return Err(super::malformed("PFX: authSafe contentType is not id-data"));
    }
    let a0 = super::tlv(auth_safe_rest, 0xa0)
        .ok_or_else(|| super::malformed("PFX: authSafe content [0] missing"))?.1;
    let mac_input = super::tlv(a0, 0x04)
        .ok_or_else(|| super::malformed("PFX: authSafe OCTET STRING missing"))?.1;

    // macData SEQUENCE (required for integrity verification).
    let (_, mac_data_body, _) = super::tlv(pfx_rest2, 0x30)
        .ok_or_else(|| super::malformed("PFX: macData missing; cannot verify integrity"))?;

    // mac DigestInfo: { AlgorithmIdentifier, OCTET STRING }
    let (_, digest_info_body, mac_data_rest) = super::tlv(mac_data_body, 0x30)
        .ok_or_else(|| super::malformed("PFX: macData DigestInfo missing"))?;
    let (_, alg_id_body, digest_rest) = super::tlv(digest_info_body, 0x30)
        .ok_or_else(|| super::malformed("PFX: DigestInfo AlgorithmIdentifier missing"))?;
    let (_, hash_oid, _) = super::tlv(alg_id_body, 0x06)
        .ok_or_else(|| super::malformed("PFX: DigestInfo hash OID missing"))?;
    let (_, mac_value, _) = super::tlv(digest_rest, 0x04)
        .ok_or_else(|| super::malformed("PFX: DigestInfo macValue missing"))?;

    // macSalt OCTET STRING
    let (_, mac_salt, mac_data_rest2) = super::tlv(mac_data_rest, 0x04)
        .ok_or_else(|| super::malformed("PFX: macData macSalt missing"))?;
    if mac_salt.is_empty() {
        return Err(super::malformed("PFX: macData macSalt must not be empty"));
    }

    // iterations INTEGER (DEFAULT 1)
    // Cap to prevent a crafted PFX from triggering a multi-hour KDF hang; absent
    // field defaults to 1 per RFC 7292. The v as i32 cast is safe because
    // v <= 10_000_000 < i32::MAX. (soft_PKCS11-9r05)
    let iterations = match super::parse_der_uint(mac_data_rest2).map(|(v, _)| v) {
        None => 1i32,
        Some(v) if v == 0 || v > 10_000_000 => {
            return Err(super::malformed(
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
    let primary_pass = super::passphrase_to_utf16be(passphrase);

    let computed = compute_pfx_mac(&primary_pass, mac_salt, iterations, hash_type, mac_key_len, mac_input)?;
    if super::ct_eq(&computed, mac_value) {
        return Ok(());
    }

    // Fallback for empty passphrase: some tools use a truly empty byte string
    // (RFC 7292 s.B.3 alternative interpretation) instead of [0x00, 0x00].
    if passphrase.is_empty() {
        if let Ok(computed2) = compute_pfx_mac(&[], mac_salt, iterations, hash_type, mac_key_len, mac_input) {
            if super::ct_eq(&computed2, mac_value) {
                return Ok(());
            }
        }
    }

    Err(super::malformed("PFX: MAC verification failed (wrong passphrase or corrupted file)"))
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
    let (_, pfx_body, _) = super::tlv(der, 0x30)
        .ok_or_else(|| super::malformed("PFX: expected outer SEQUENCE"))?;

    // version INTEGER (expected value 3, but we don't enforce it)
    let (_, _version, pfx_rest) = super::tlv(pfx_body, 0x02)
        .ok_or_else(|| super::malformed("PFX: version INTEGER missing"))?;

    // authSafe ContentInfo SEQUENCE
    let (_, auth_safe_body, _) = super::tlv(pfx_rest, 0x30)
        .ok_or_else(|| super::malformed("PFX: authSafe ContentInfo SEQUENCE missing"))?;

    // contentType OID -- must be id-data
    let (_, ct_oid, auth_safe_rest) = super::tlv(auth_safe_body, 0x06)
        .ok_or_else(|| super::malformed("PFX: authSafe contentType OID missing"))?;

    if ct_oid != OID_PKCS7_DATA {
        return Err(KeyParseError::Malformed(format!(
            "PFX: authSafe contentType is not id-data ({:02x?})",
            ct_oid
        )));
    }

    // content [0] EXPLICIT OCTET STRING -> AuthenticatedSafe DER
    let a0 = super::tlv(auth_safe_rest, 0xa0)
        .ok_or_else(|| super::malformed("PFX: authSafe content [0] missing"))?
        .1;
    let auth_safe_der = super::tlv(a0, 0x04)
        .ok_or_else(|| super::malformed("PFX: authSafe OCTET STRING missing"))?
        .1;

    let mut bags = PfxBags { shrouded_key_bags: Vec::new(), cert_bags: Vec::new() };
    parse_authenticated_safe(auth_safe_der, &mut bags, passphrase)?;
    Ok(bags)
}

/// Extract the DER-encoded X.509 certificate from a CertBag value.
///
/// `CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }`
fn cert_der_from_cert_bag(bag_value: &[u8]) -> Option<Vec<u8>> {
    let (_, cert_bag_body, _) = super::tlv(bag_value, 0x30)?;
    let (_, cert_id, cb_rest) = super::tlv(cert_bag_body, 0x06)?;
    if cert_id != OID_X509_CERTIFICATE {
        return None;
    }
    // certValue [0] EXPLICIT OCTET STRING
    let (_, a0, _) = super::tlv(cb_rest, 0xa0)?;
    let (_, cert_der, _) = super::tlv(a0, 0x04)?;
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
/// If the key has a `localKeyID`, only a cert with a matching `localKeyID` is
/// returned; an unmatched ID yields `None` rather than an unrelated cert.
/// If the key has no `localKeyID`, falls back to the first cert in the list.
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
        None
    } else {
        certs.first().map(|(_, d)| d.clone())
    }
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
        let fallback_id = match super::random_id() {
            Ok(id) => id,
            Err(e) => {
                failures.push((label, e));
                continue;
            }
        };

        match super::parse_encrypted_pkcs8(&key_bag.bag_value, passphrase, fallback_id) {
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
