#![no_main]

use libfuzzer_sys::fuzz_target;
use usb_hsm::key_parser;

// Exercise JKS/JCEKS parsing: magic detection, entry-count loop, tag dispatch
// (PrivateKeyEntry / TrustedCertEntry / SecretKeyEntry), certificate chain
// parsing, and JKS proprietary SHA-1 integrity verification.
fuzz_target!(|data: &[u8]| {
    let _ = key_parser::is_jks_or_jceks(data);
    let _ = key_parser::parse_jks_structure(data);
    let _ = key_parser::verify_jks_integrity(data, "");
});
