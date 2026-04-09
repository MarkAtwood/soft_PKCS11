use super::*;

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
pub(crate) fn crc24(data: &[u8]) -> u32 {
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
        .map_err(|_| super::malformed("PGP armor: non-UTF-8 input"))?;
    let mut lines = text.lines();

    // First non-empty line must be the armor header.
    let first = lines.next().ok_or_else(|| super::malformed("PGP armor: empty input"))?;
    if !first.starts_with("-----BEGIN PGP") {
        return Err(super::malformed("PGP armor: missing BEGIN PGP armor header"));
    }

    // Skip armor header fields ("Key: Value") up to and including the blank
    // separator line that precedes the base64 body.
    loop {
        let line = lines
            .next()
            .ok_or_else(|| super::malformed("PGP armor: unterminated header section"))?;
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
                return Err(super::malformed(
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
        .map_err(|e| super::malformed(&format!("PGP armor: base64 decode error: {e}")))?;

    // Verify CRC-24 if a checksum line was present.
    if let Some(csum_b64) = checksum_b64 {
        let csum_bytes = base64::engine::general_purpose::STANDARD
            .decode(&csum_b64)
            .map_err(|e| super::malformed(&format!("PGP armor: checksum base64 decode error: {e}")))?;
        if csum_bytes.len() != 3 {
            return Err(super::malformed(
                "PGP armor: checksum must decode to exactly 3 bytes (24 bits)",
            ));
        }
        let expected_crc = ((csum_bytes[0] as u32) << 16)
            | ((csum_bytes[1] as u32) << 8)
            | (csum_bytes[2] as u32);
        let computed_crc = crc24(&decoded);
        if expected_crc != computed_crc {
            return Err(super::malformed(&format!(
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
                    let uid_str = match String::from_utf8(body.to_vec()) {
                        Ok(s) if !s.trim().is_empty() => s,
                        _ => { remaining = rest; continue; }
                    };
                    let uid = uid_str.trim();
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
pub(super) fn parse_pgp_binary(
    data: &[u8],
    passphrase_fn: &dyn Fn(&str) -> io::Result<String>,
) -> Result<(Vec<ParsedKey>, Vec<(String, KeyParseError)>), KeyParseError> {
    let packets = pgp_collect_secret_packets(data);
    if packets.is_empty() {
        return Err(super::malformed("PGP: no secret-key packets found"));
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
        passphrase_fn("Passphrase for OpenPGP key: ").map_err(KeyParseError::Io)?
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
pub(crate) const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

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
        return Err(super::malformed("PGP Public-Key: empty packet body"));
    }
    let version = data[0];
    if version != 4 {
        return Err(KeyParseError::Unsupported(format!(
            "PGP Public-Key version {version} is not supported (only v4 is implemented)"
        )));
    }
    // bytes [1..5]: 4-byte creation timestamp (we read but do not validate)
    if data.len() < 6 {
        return Err(super::malformed("PGP Public-Key: truncated header (need version + timestamp + algorithm)"));
    }
    let algorithm = data[5];

    // `cur` is a moving cursor through the remaining bytes (algorithm-specific material).
    let mut cur: &[u8] = &data[6..];

    let material: PgpPublicKeyMaterial = match algorithm {
        1 => {
            // RSA: MPIs n, e.
            let (n, rest) = read_pgp_mpi(cur)
                .ok_or_else(|| super::malformed("PGP RSA Public-Key: truncated MPI n"))?;
            let n_bytes = n.to_vec();
            cur = rest;
            let (e, rest) = read_pgp_mpi(cur)
                .ok_or_else(|| super::malformed("PGP RSA Public-Key: truncated MPI e"))?;
            let e_bytes = e.to_vec();
            cur = rest;
            PgpPublicKeyMaterial::Rsa { n: n_bytes, e: e_bytes }
        }
        19 => {
            // ECDSA: OID length + OID + public-point MPI.
            let &oid_len_byte = cur.first()
                .ok_or_else(|| super::malformed("PGP ECDSA Public-Key: truncated OID length"))?;
            let oid_len = oid_len_byte as usize;
            cur = &cur[1..];
            if cur.len() < oid_len {
                return Err(super::malformed("PGP ECDSA Public-Key: truncated OID"));
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
                .ok_or_else(|| super::malformed("PGP ECDSA Public-Key: truncated public-point MPI"))?;
            if point.len() != 65 || point[0] != 0x04 {
                return Err(super::malformed(
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
pub(crate) fn pgp_s2k_derive_key(
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
        return Err(super::malformed("PGP secret key: empty S2K/usage region"));
    }
    let usage = remaining[0];
    let cur = &remaining[1..];

    match usage {
        0x00 => {
            // Plaintext secret key: MPI bytes followed by a 2-byte simple checksum.
            if cur.len() < 2 {
                return Err(super::malformed(
                    "PGP secret key: plaintext region too short for checksum",
                ));
            }
            let (mpi_bytes, chk) = cur.split_at(cur.len() - 2);
            let stored = u16::from_be_bytes([chk[0], chk[1]]);
            let computed = mpi_bytes
                .iter()
                .fold(0u16, |acc, &b| acc.wrapping_add(b as u16));
            if computed != stored {
                return Err(super::malformed(
                    "PGP secret key: plaintext checksum mismatch \
                     (corrupted key material)",
                ));
            }
            Ok(mpi_bytes.to_vec())
        }

        0xFE | 0xFF => {
            // Encrypted: cipher_id(1) || S2K-type(1) || hash_id(1) || [salt+count] || IV(16) || ciphertext
            if cur.len() < 3 {
                return Err(super::malformed(
                    "PGP secret key: truncated before cipher/S2K fields",
                ));
            }
            let cipher_id = cur[0];
            let s2k_type = cur[1];
            let hash_id = cur[2];
            let mut cur = &cur[3..];

            let (key_len, iv_len): (usize, usize) = match cipher_id {
                7 => (16usize, 16usize),   // AES-128-CFB
                8 => (24usize, 16usize),   // AES-192-CFB
                9 => (32usize, 16usize),   // AES-256-CFB
                other => {
                    return Err(KeyParseError::Unsupported(format!(
                        "PGP: symmetric cipher ID {other} is not supported"
                    )));
                }
            };

            let (salt, count): (&[u8], usize) = match s2k_type {
                0 => (&[], 0),
                1 => {
                    if cur.len() < 8 {
                        return Err(super::malformed("PGP S2K type 1: truncated salt"));
                    }
                    let s = &cur[..8];
                    cur = &cur[8..];
                    (s, 0)
                }
                3 => {
                    if cur.len() < 9 {
                        return Err(super::malformed("PGP S2K type 3: truncated salt+count"));
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

            if cur.len() < iv_len {
                return Err(super::malformed("PGP secret key: truncated IV"));
            }
            let iv: [u8; 16] = cur[..iv_len].try_into().unwrap();
            cur = &cur[iv_len..];

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
                    return Err(super::malformed(
                        "PGP secret key: decrypted data too short for SHA-1 checksum",
                    ));
                }
                let (mpi_bytes, sha1_stored) = plaintext.split_at(plaintext.len() - 20);
                use wolfcrypt::digest::digest_trait::Digest as _;
                let mut h = wolfcrypt::Sha1::new();
                wolfcrypt::digest::digest_trait::Update::update(&mut h, mpi_bytes);
                let sha1_computed = h.finalize();
                if sha1_computed.as_slice() != sha1_stored {
                    return Err(super::malformed(
                        "PGP secret key: SHA-1 integrity check failed \
                         (wrong passphrase or corrupted key)",
                    ));
                }
                Ok(mpi_bytes.to_vec())
            } else {
                // usage == 0xFF: 2-byte simple checksum.
                if plaintext.len() < 2 {
                    return Err(super::malformed(
                        "PGP secret key: decrypted data too short for checksum",
                    ));
                }
                let (mpi_bytes, chk) = plaintext.split_at(plaintext.len() - 2);
                let stored = u16::from_be_bytes([chk[0], chk[1]]);
                let computed = mpi_bytes
                    .iter()
                    .fold(0u16, |acc, &b| acc.wrapping_add(b as u16));
                if computed != stored {
                    return Err(super::malformed(
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

    // Reject zero modulus — division by zero in the Euclidean algorithm.
    if m == zero {
        return None;
    }
    if a == zero {
        return None;
    }

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
        .ok_or_else(|| super::malformed("PGP RSA secret: truncated MPI d"))?;
    cur = rest;
    let (p, rest) = read_pgp_mpi(cur)
        .ok_or_else(|| super::malformed("PGP RSA secret: truncated MPI p"))?;
    cur = rest;
    let (q, rest) = read_pgp_mpi(cur)
        .ok_or_else(|| super::malformed("PGP RSA secret: truncated MPI q"))?;
    cur = rest;
    // u = p^-1 mod q (OpenPGP convention); we discard it and recompute
    // iqmp = q^-1 mod p (PKCS#1 / wolfCrypt convention).
    let _u = read_pgp_mpi(cur)
        .ok_or_else(|| super::malformed("PGP RSA secret: truncated MPI u"))?;

    // Compute PKCS#1 iqmp = q^-1 mod p.
    let iqmp = modinv_bytes(q, p).ok_or_else(|| {
        super::malformed("PGP RSA: could not compute CRT coefficient (p, q not coprime?)")
    })?;

    let key = wolfcrypt::NativeRsaKey::from_raw_components(n, e, d, p, q, &iqmp)
        .map_err(|err| super::malformed(&format!("PGP RSA: wolfCrypt key load failed: {err:?}")))?;
    let pkcs1_der = key
        .to_pkcs1_der()
        .map_err(|err| super::malformed(&format!("PGP RSA: wolfCrypt DER export failed: {err:?}")))?;

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
        .ok_or_else(|| super::malformed("PGP ECDSA P-256 secret: truncated scalar MPI"))?;

    if scalar_raw.len() > 32 {
        return Err(super::malformed(&format!(
            "PGP ECDSA P-256: scalar is {} bytes, expected <=32",
            scalar_raw.len()
        )));
    }

    if scalar_raw.iter().all(|&b| b == 0) {
        return Err(super::malformed("PGP ECDSA P-256: zero scalar is not a valid private key"));
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
