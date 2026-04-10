#![no_main]

use libfuzzer_sys::fuzz_target;
use usb_hsm::key_parser;

// Exercise PKCS#12 PFX parsing: MAC verification (HMAC-SHA1 over AuthSafe),
// outer DER structure (AuthenticatedSafe, ContentInfo loop), SafeContents bag
// parsing (ShroudedKeyBag, CertBag, SafeBag), and PKCS12-PBE decryption.
// Empty passphrase — all decryptions will fail gracefully.
fuzz_target!(|data: &[u8]| {
    let _ = key_parser::verify_pfx_mac(data, "");
    let _ = key_parser::parse_pfx_structure(data, "");
});
