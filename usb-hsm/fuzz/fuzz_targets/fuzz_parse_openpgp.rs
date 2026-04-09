#![no_main]

use libfuzzer_sys::fuzz_target;
use usb_hsm::key_parser;

// Exercise OpenPGP parsing: packet framing (old/new format length headers),
// secret-key packet collection, User ID extraction, and ASCII armor decoding.
// Uses parse_key_bytes for armored input so the full pipeline is exercised.
fuzz_target!(|data: &[u8]| {
    let _ = key_parser::pgp_collect_secret_packets(data);
    let _ = key_parser::pgp_first_user_id_label(data);
    if key_parser::is_pgp_armor(data) {
        if let Ok(binary) = key_parser::dearmor(data) {
            let _ = key_parser::pgp_collect_secret_packets(&binary);
        }
    }
    // Drive the full pipeline (dearmor + parse) via the dispatcher.
    let _ = key_parser::parse_key_bytes(data, &|_| Ok(String::new()), None);
});
