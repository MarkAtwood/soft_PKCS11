#![no_main]

use libfuzzer_sys::fuzz_target;
use usb_hsm::key_parser;

const FIXED_ID: [u8; 16] = [0u8; 16];

// Exercise PBES2/PBES1 encrypted PKCS#8 parsing: AlgorithmIdentifier OID
// dispatch (PBES2, PKCS12-PBE-3DES, PBES1 variants), PBKDF2 iteration parsing,
// PBES2 inner AlgId (AES-128-CBC / AES-256-CBC / 3DES-CBC), and DER length
// validation.  Empty passphrase — all decryptions fail gracefully.
fuzz_target!(|data: &[u8]| {
    let _ = key_parser::parse_encrypted_pkcs8(data, "", FIXED_ID);
});
