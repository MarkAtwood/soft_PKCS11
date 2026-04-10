#![no_main]

use libfuzzer_sys::fuzz_target;
use usb_hsm::key_parser;

// Exercise the OpenSSH new-format binary frame parser directly.
// Parses the sshkey blob: magic, cipher, kdf, kdf options, public-key count,
// and encrypted private blob.  Does not attempt decryption.
fuzz_target!(|data: &[u8]| {
    let _ = key_parser::parse_openssh_binary(data);
});
