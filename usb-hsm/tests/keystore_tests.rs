// Keystore integration tests.
//
// Test integrity rules:
// - Framing vector tests (1-3) use externally-produced .p11k blobs from
//   test-vectors/p11k_framing.json (Python cryptography + cbor2).
// - Round-trip test (4) uses Keystore::create then Keystore::load; acceptable
//   because it tests framing + CBOR plumbing, not the crypto primitives.
// - Zeroize test (5) scans /proc/self/mem for a canary after Keystore drop.

use std::fs;
use hex;
use serde::Deserialize;
use tempfile::NamedTempFile;
use std::io::Write;
use usb_hsm::keystore::{KeyEntry, KeyType, Keystore, KeystoreError};

// ---------------------------------------------------------------------------
// Test vector loader
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct FramingVector {
    description: String,
    pin: String,
    p11k_hex: String,
    expected_entry_count: Option<usize>,
    expected_label: Option<String>,
    expected_error: Option<String>,
}

fn load_framing_vectors() -> Vec<FramingVector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/p11k_framing.json");
    let json = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let vectors: Vec<FramingVector> = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));
    assert!(!vectors.is_empty(), "test vector file is empty -- refusing to pass vacuously");
    vectors
}

fn tmpfile(bytes: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmpfile");
    f.write_all(bytes).expect("write tmpfile");
    f
}

// ---------------------------------------------------------------------------
// Test 1-3: externally-produced framing vectors
// ---------------------------------------------------------------------------

#[test]
fn framing_vectors() {
    let vectors = load_framing_vectors();

    for v in &vectors {
        let p11k_bytes = hex::decode(&v.p11k_hex)
            .unwrap_or_else(|e| panic!("hex decode failed for '{}': {e}", v.description));
        let pin = hex::decode(&v.pin)
            .unwrap_or_else(|e| panic!("pin hex decode failed for '{}': {e}", v.description));
        let f = tmpfile(&p11k_bytes);

        match (Keystore::load(f.path(), &pin), &v.expected_error) {
            (Ok(ks), None) => {
                let count: usize = v.expected_entry_count
                    .unwrap_or_else(|| panic!("expected_entry_count missing for '{}'", v.description));
                assert_eq!(
                    ks.entries().len(), count,
                    "entry count mismatch for '{}'", v.description
                );
                if let Some(label) = &v.expected_label {
                    assert_eq!(
                        ks.entries()[0].label, *label,
                        "label mismatch for '{}'", v.description
                    );
                }
            }
            (Err(e), Some(expected)) => {
                let got: &str = match &e {
                    KeystoreError::BadMagic    => "BadMagic",
                    KeystoreError::Truncated(_) => "Truncated",
                    KeystoreError::BadPin      => "BadPin",
                    _                          => "other",
                };
                assert_eq!(got, expected.as_str(),
                    "error kind mismatch for '{}': got {:?}", v.description, e);
            }
            (Ok(_), Some(expected)) => {
                panic!("expected error '{}' but load succeeded for '{}'", expected, v.description);
            }
            (Err(e), None) => {
                panic!("expected success but got error for '{}': {:?}", v.description, e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 4a: truncated file with correct magic returns Truncated, not BadMagic
// ---------------------------------------------------------------------------

#[test]
fn truncated_file_returns_truncated_error() {
    // A file that starts with the correct P11K magic but is too short to hold
    // a complete header must return Truncated, not BadMagic, so operators can
    // distinguish filesystem corruption from a wrong-format file.
    let truncated = b"P11K\x01short";  // valid magic, only 10 bytes total
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(truncated).unwrap();
    let result = Keystore::load(tmp.path(), b"anypin");
    match result {
        Err(KeystoreError::Truncated(n)) => assert_eq!(n, 10),
        Err(e) => panic!("expected Truncated(9), got Err({e:?})"),
        Ok(_) => panic!("expected Truncated(9), got Ok"),
    }
}

// ---------------------------------------------------------------------------
// Test 4: round-trip (tests framing + CBOR, not crypto primitives)
// ---------------------------------------------------------------------------

#[test]
fn round_trip_create_load() {
    let id: [u8; 16] = [0xCA, 0xFE, 0xBA, 0xBE, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    // P-256 scalar must be exactly 32 bytes; pad with 0x00 to reach required length.
    // The round-trip test verifies CBOR framing and key byte preservation -- key type
    // validation now enforces the length, so the fixture must comply.
    let der = {
        let mut v = vec![0x11, 0x22, 0x33, 0x44, 0x55];
        v.resize(32, 0x00);
        v
    };
    let label = "round-trip-key";
    let pin = b"hunter2";

    let entry = KeyEntry {
        id,
        label: label.to_owned(),
        key_type: KeyType::Ec,
        der_bytes: der.clone(),
        cert_der: None,
        pub_bytes: None,
    };

    let blob = Keystore::create(vec![entry], pin, 1).expect("create");
    let f = tmpfile(&blob);
    let ks = Keystore::load(f.path(), pin).expect("load");

    assert_eq!(ks.entries().len(), 1, "entry count");
    let e = &ks.entries()[0];
    assert_eq!(e.id, id, "id");
    assert_eq!(e.label, label, "label");
    assert_eq!(e.key_type, KeyType::Ec, "key_type");
    assert_eq!(e.der_bytes, der, "der_bytes");
}

// ---------------------------------------------------------------------------
// Test 5: zeroize -- key bytes must not appear in process heap after drop
// ---------------------------------------------------------------------------

// 16-byte canary: long enough to be unique; lives in .rodata as a const,
// never in a live heap Vec during the scan.
const CANARY: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
];

/// Scan the [heap] region in /proc/self/mem for `needle`. Returns true if found.
fn needle_in_heap(needle: &[u8]) -> bool {
    use std::io::{Read, Seek, SeekFrom};

    let maps = fs::read_to_string("/proc/self/maps").expect("read maps");
    let mut mem = fs::File::open("/proc/self/mem").expect("open mem");

    for line in maps.lines() {
        if !line.contains("[heap]") { continue; }

        let range = line.split_whitespace().next().unwrap_or("");
        let mut parts = range.split('-');
        let start = u64::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let end   = u64::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        if end <= start { continue; }

        let mut buf = vec![0u8; (end - start) as usize];
        if mem.seek(SeekFrom::Start(start)).is_err() { continue; }
        if mem.read_exact(&mut buf).is_err() { continue; }

        if buf.windows(needle.len()).any(|w| w == needle) {
            return true;
        }
    }
    false
}

#[test]
fn key_bytes_zeroized_after_drop() {
    // CANARY is a const -- lives in .rodata, not on heap.
    // The only heap copy is inside the Keystore; it must be gone after drop.
    let pin = b"zeroize-test-pin";

    let f = {
        let blob = {
            let entry = KeyEntry {
                id: [0u8; 16],
                label: "z".to_owned(),
                // Use KeyType::Ec so the canary bytes are not parsed as PKCS#1 DER.
                // The zeroize test only cares that the bytes are wiped -- key type
                // is irrelevant to the drop-time zeroing path.
                // EC validation requires exactly 32 bytes (P-256 scalar size), so
                // pad CANARY (16 bytes) with zeros to reach the required length.
                // needle_in_heap searches for the 16-byte CANARY pattern, which is
                // still present in the first half of der_bytes.
                key_type: KeyType::Ec,
                der_bytes: {
                    let mut v = CANARY.to_vec();
                    v.extend_from_slice(&[0u8; 16]);
                    v
                },
                cert_der: None,
                pub_bytes: None,
            };
            // entry moved into create(); ZeroizeOnDrop fires when create() returns
            Keystore::create(vec![entry], pin, 1).expect("create for zeroize test")
        };
        // blob: encrypted .p11k -- canary bytes are AES-GCM encrypted (differ from CANARY)
        let tmp = tmpfile(&blob);
        tmp // blob dropped here
    };

    {
        let ks = Keystore::load(f.path(), pin).expect("load for zeroize test");
        // der_bytes is 32 bytes: CANARY (16) + 16 zero padding bytes.
        // Verify the CANARY portion survived the CBOR round-trip.
        assert_eq!(&ks.entries()[0].der_bytes[..16], &CANARY[..],
            "canary must be present before drop");
        // ks dropped here -- Keystore::drop() munlocks, ZeroizeOnDrop fires
    }

    // No live heap Vec holds CANARY; the const itself is in .rodata.
    assert!(
        !needle_in_heap(&CANARY),
        "canary bytes found in [heap] after Keystore drop -- zeroize failed"
    );
}

// ---------------------------------------------------------------------------
// RSA key size validation tests (6-8)
// ---------------------------------------------------------------------------

/// Build a minimal PKCS#1 DER `RSAPrivateKey` with the given modulus byte count.
///
/// This is NOT a valid RSA key (private exponent etc. are absent); it is sized
/// solely to exercise the modulus-length validation in `Keystore::load`.
/// The leading modulus byte is 0x01 (high bit clear) so no DER leading-zero
/// padding is inserted -- the INTEGER value is exactly `modulus_bytes` bytes.
fn make_fake_rsa_pkcs1_der(modulus_bytes: usize) -> Vec<u8> {
    // version INTEGER: 02 01 00
    let version = [0x02u8, 0x01, 0x00];

    // Modulus value: 0x01 followed by zeros. Leading byte 0x01 has the high bit
    // clear, so DER does not insert a leading 0x00 padding byte. The modulus
    // INTEGER value is therefore exactly modulus_bytes bytes.
    let mut modulus_value = vec![0u8; modulus_bytes];
    if !modulus_value.is_empty() {
        modulus_value[0] = 0x01;
    }

    // Encode modulus as a DER INTEGER (tag 0x02).
    let mut modulus_int = vec![0x02u8];
    push_der_len(&mut modulus_int, modulus_bytes);
    modulus_int.extend_from_slice(&modulus_value);

    // Outer SEQUENCE: SEQUENCE { version INTEGER, modulus INTEGER }.
    // (Other RSAPrivateKey fields are omitted -- rsa_modulus_bytes() stops after
    // reading the modulus and never looks further.)
    let inner_len = version.len() + modulus_int.len();
    let mut der = vec![0x30u8]; // SEQUENCE tag
    push_der_len(&mut der, inner_len);
    der.extend_from_slice(&version);
    der.extend_from_slice(&modulus_int);
    der
}

/// X.690 s.8.1.3 definite-length encoding, appended to `buf`.
fn push_der_len(buf: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        buf.push(n as u8);
    } else if n < 0x100 {
        buf.extend_from_slice(&[0x81, n as u8]);
    } else {
        // Two-byte length covers up to 65535 bytes -- more than enough for any RSA key.
        buf.extend_from_slice(&[0x82, (n >> 8) as u8, (n & 0xFF) as u8]);
    }
}

// Test 6: An RSA key with exactly a 512-byte modulus (4096 bits) is accepted.
#[test]
fn rsa_key_exactly_4096_bits_accepted() {
    let pin = b"test-pin-rsa-sz";
    let entry = KeyEntry {
        id: [0u8; 16],
        label: "rsa-4096".to_owned(),
        key_type: KeyType::Rsa,
        der_bytes: make_fake_rsa_pkcs1_der(512),
        cert_der: None,
        pub_bytes: None,
    };
    let blob = Keystore::create(vec![entry], pin, 1).expect("create 4096-bit key");
    let f = tmpfile(&blob);
    Keystore::load(f.path(), pin).expect("4096-bit RSA key (512-byte modulus) must be accepted");
}

// Test 7: An RSA key one byte over the limit (513-byte modulus = 4104 bits) is rejected.
#[test]
fn rsa_key_over_4096_bits_rejected() {
    let pin = b"test-pin-rsa-ov";
    let entry = KeyEntry {
        id: [0u8; 16],
        label: "rsa-over".to_owned(),
        key_type: KeyType::Rsa,
        der_bytes: make_fake_rsa_pkcs1_der(513), // 513 bytes = 4104 bits
        cert_der: None,
        pub_bytes: None,
    };
    let blob = Keystore::create(vec![entry], pin, 1).expect("create oversized key");
    let f = tmpfile(&blob);
    match Keystore::load(f.path(), pin) {
        Err(KeystoreError::UnsupportedFormat(msg)) => {
            // Error must mention both the actual size and the limit.
            assert!(msg.contains("4104"), "error should cite actual bits: {msg}");
            assert!(msg.contains("4096"), "error should cite limit bits: {msg}");
        }
        Ok(_) => panic!("expected UnsupportedFormat for oversized RSA key, got Ok"),
        Err(e) => panic!("expected UnsupportedFormat for oversized RSA key, got: {e}"),
    }
}

// Test 8: An RSA key entry with completely invalid DER bytes is rejected.
#[test]
fn rsa_invalid_der_rejected() {
    let pin = b"test-pin-rsa-ba";
    let entry = KeyEntry {
        id: [0u8; 16],
        label: "bad-der".to_owned(),
        key_type: KeyType::Rsa,
        der_bytes: vec![0xFF, 0xFF, 0xFF, 0xFF], // not PKCS#1 DER
        cert_der: None,
        pub_bytes: None,
    };
    let blob = Keystore::create(vec![entry], pin, 1).expect("create bad-der key");
    let f = tmpfile(&blob);
    assert!(
        matches!(Keystore::load(f.path(), pin), Err(KeystoreError::UnsupportedFormat(_))),
        "invalid RSA DER must return UnsupportedFormat"
    );
}

// ---------------------------------------------------------------------------
// Test: EC key validation rejects wrong-length scalars
// ---------------------------------------------------------------------------

/// EC keys must be exactly 32 bytes (P-256 scalar). An EC key with a different
/// length is either a wrong curve or corrupt data; load must return
/// UnsupportedFormat rather than silently passing malformed key material to
/// wolfcrypt (which has unspecified behavior for wrong-length inputs).
#[test]
fn ec_key_wrong_length_returns_unsupported_format() {
    let pin = b"ec-validate-pin";

    for bad_len in [0_usize, 1, 16, 31, 33, 64] {
        let entry = KeyEntry {
            id: [0u8; 16],
            label: format!("ec-{bad_len}-bytes"),
            key_type: KeyType::Ec,
            der_bytes: vec![0xEC; bad_len],
            cert_der: None,
            pub_bytes: None,
        };
        let blob = Keystore::create(vec![entry], pin, 1).expect("create");
        let f = tmpfile(&blob);
        assert!(
            matches!(Keystore::load(f.path(), pin), Err(KeystoreError::UnsupportedFormat(_))),
            "EC key with {bad_len} bytes must return UnsupportedFormat (expected 32)"
        );
    }
}

/// EC key with exactly 32 bytes must load successfully.
#[test]
fn ec_key_correct_length_loads_ok() {
    let pin = b"ec-ok-pin";
    let entry = KeyEntry {
        id: [0u8; 16],
        label: "ec-valid".to_owned(),
        key_type: KeyType::Ec,
        der_bytes: vec![0x42; 32],
        cert_der: None,
        pub_bytes: None,
    };
    let blob = Keystore::create(vec![entry], pin, 1).expect("create");
    let f = tmpfile(&blob);
    let ks = Keystore::load(f.path(), pin).expect("32-byte EC key must load");
    assert_eq!(ks.entries()[0].der_bytes.len(), 32);
}
