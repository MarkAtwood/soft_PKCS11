use super::*;

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
    let (_, outer, _) = super::tlv(der, 0x30)
        .ok_or_else(|| super::malformed("EPKI: outer SEQUENCE missing"))?;

    let (_, alg_id, rest) = super::tlv(outer, 0x30)
        .ok_or_else(|| super::malformed("EPKI: AlgorithmIdentifier SEQUENCE missing"))?;

    let (_, enc_oid, alg_params) = super::tlv(alg_id, 0x06)
        .ok_or_else(|| super::malformed("EPKI: encryption OID missing"))?;

    let (_, ciphertext, _) = super::tlv(rest, 0x04)
        .ok_or_else(|| super::malformed("EPKI: encryptedData OCTET STRING missing"))?;

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
            .map_err(|_| super::malformed("PBES2 decrypt failed (wrong passphrase?)"))?;
        return super::parse_pkcs8(&pt, id);
    }

    let plaintext = if enc_oid == OID_PKCS12_SHA1_3DES {
        super::pkcs12_pbe_sha1_3des_decrypt(alg_params, passphrase, ciphertext)?
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

    super::parse_pkcs8(&plaintext, id)
}
