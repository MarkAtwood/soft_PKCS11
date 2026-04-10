#![no_main]

use libfuzzer_sys::fuzz_target;
use usb_hsm::key_parser;

// Exercise the full format dispatcher with arbitrary bytes and no passphrase.
// Covers: GCP JSON, PGP armored/binary, PEM variants, PPK, JKS/JCEKS,
// PKCS#12 PFX, bare DER (PKCS#8/PKCS#1/SEC1/EncryptedPrivateKeyInfo).
fuzz_target!(|data: &[u8]| {
    let _ = key_parser::parse_key_bytes(data, &|_| Ok(String::new()), None);
});
