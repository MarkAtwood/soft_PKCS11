#![no_main]

use libfuzzer_sys::fuzz_target;
use usb_hsm::key_parser;

// Exercise PuTTY PPK parsing: header/footer detection, field tokenisation,
// base64 block decoding, v2 SHA-1 KDF (with ppk_v2_derive_key), v3 Argon2 KDF
// parameter parsing, and MAC verification.  No decryption attempted.
fuzz_target!(|data: &[u8]| {
    let _ = key_parser::is_ppk(data);
    let _ = key_parser::parse_ppk(data);
});
