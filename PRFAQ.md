# PR/FAQ: usb-hsm

---

## Press Release

**FOR IMMEDIATE RELEASE**

### Any USB Drive Is Now a Hardware Security Token -- No Expensive HSM Required

#### `usb-hsm` brings possession-based key protection to every Linux developer and operator, using a standard PKCS#11 interface and a thumb drive they already own

**SEATTLE, WA -- 2026** -- Today we are releasing `usb-hsm`, an open-source PKCS#11 soft-token module for Linux that turns any USB flash drive into a hardware-enforced key possession factor. With `usb-hsm`, cryptographic private keys are encrypted at rest on the USB drive, decrypted into locked memory only when the drive is inserted and a PIN is entered, and permanently zeroized from RAM the moment the drive is removed. No key material ever touches the host disk. The library exposes a standard PKCS#11 C ABI, so it works immediately with OpenSSH, OpenSSL, GPG, Firefox, and every other PKCS#11-aware application -- no code changes required.

Hardware Security Modules protect the most sensitive private keys in the world: root certificate authorities, code-signing pipelines, payment systems. But a certified HSM costs between $1,000 and $30,000, requires rack space and specialized administration, and is engineered for threat models that most teams will never face. The result is a gap: teams that would benefit from physical key possession -- developers signing releases, operators managing TLS certificates, small organizations storing authentication credentials -- have no practical option between "key on disk" (unprotected) and "buy an HSM" (impractical). Most choose to leave keys on disk.

`usb-hsm` fills that gap. The threat model is explicit: a $10 USB drive provides meaningful protection against the most common real-world attacks -- theft of the laptop without the drive, compromise of a backup or disk image, unauthorized server access in the operator's absence. It does not provide tamper-resistant hardware enclaves. It does not protect against a root-level attacker on a running machine. That is the same threat model as any soft token, including SoftHSM2 and most cloud KMS client libraries, and it is sufficient for the majority of use cases that do not justify a physical HSM.

Because `usb-hsm` speaks PKCS#11, there is nothing to integrate. Configure it once via `p11-kit` and every application on the system that already speaks PKCS#11 -- `ssh-agent`, `openssl pkcs11`, `gpg-pkcs11`, Firefox, Chrome, and curl -- immediately uses USB-backed keys.

"I want my SSH and code-signing keys to require physical presence of something I carry," said a developer during early testing. "With `usb-hsm` I pull the drive, the keys are gone from memory. That's the behavior I've wanted from a smart card without buying a smart card reader and a smart card."

`usb-hsm` is written in Rust, targets any Linux distribution with udev support, and is released under the GPL-3.0 license. Cryptographic operations are backed by wolfCrypt via the `wolfcrypt` Rust crate from the `wolfssl-rs` workspace -- a safe, RustCrypto-trait-compatible wrapper that has its own NIST CAVP conformance suite. The keystore format (`.p11k`) is documented and open: keys are encrypted with AES-256-GCM, derived from a PIN via PBKDF2-HMAC-SHA256 with 100,000 iterations, and the format is designed to be readable by any compliant implementation. The project ships with a keystore creation tool, a `p11-kit` module configuration, and a test suite validated against externally-produced reference vectors -- not self-referential round-trips.

`usb-hsm` is available now at [repository URL]. Installation requires copying one `.so` file and adding three lines to a `p11-kit` module config.

---

## Frequently Asked Questions

### External FAQ

**Q: What do I actually put on the USB drive?**

A: A single file -- the keystore, with a `.p11k` extension. You create it with the `usb-hsm-keygen` tool bundled with the project. You give it a PIN during creation. That file is encrypted; the USB drive can be lost, stolen, or cloned and the keys are still protected as long as the PIN is not known.

**Q: What PIN policy is enforced?**

A: `usb-hsm` enforces a minimum PIN length of 6 characters at keystore creation time. There is no maximum. The tool does not enforce complexity rules -- that is a policy decision for the operator. There is currently no lockout after failed attempts; PIN brute-force resistance comes entirely from the PBKDF2 key derivation cost (100,000 iterations of HMAC-SHA256), which makes online brute-force slow and offline brute-force expensive.

**Q: Does it work with SSH?**

A: Yes. Configure `ssh-agent` or your SSH client to use the PKCS#11 module. The standard invocation is:

```bash
ssh -I /usr/local/lib/usb-hsm/libusb_hsm.so user@host
# or permanently in ~/.ssh/config:
PKCS11Provider /usr/local/lib/usb-hsm/libusb_hsm.so
```

**Q: Does it work with code signing (GPG, sigstore, etc.)?**

A: It works with any tool that accepts a PKCS#11 provider. GPG via `gpg-pkcs11-scd`, `cosign` via `--key pkcs11:...` URI, and `openssl` via the `pkcs11` engine all work. Tools that speak only their own key format (raw GPG keyring, raw PEM file) require a shim or do not apply.

**Q: What algorithms are supported?**

A: RSA 2048/4096 (PSS sign, OAEP encrypt/decrypt), ECDSA P-256 (raw r||s signature output, with SHA-256 prehash or pre-hashed input), ML-DSA-65 (signatures, via `CKM_ML_DSA` / `CKM_HASH_ML_DSA`), and ML-KEM-768 (key encapsulation, via `CKM_ML_KEM`). ECC P-384, Ed25519, and X25519 are on the roadmap but not in v1.

**Q: What happens if I pull the USB drive out mid-operation?**

A: In-flight PKCS#11 calls return `CKR_DEVICE_REMOVED`. All key bytes in RAM are zeroized immediately. Open sessions are invalidated. Applications that handle `CKR_DEVICE_REMOVED` gracefully (most PKCS#11-aware tools do) will prompt the user to reinsert; applications that do not will receive an error and exit.

**Q: Can I have multiple keys on one USB drive?**

A: Yes. The keystore is a list of key entries, each with a label and key ID. PKCS#11 object enumeration (`C_FindObjects`) returns all of them. You select which key to use via the standard PKCS#11 object attribute filter -- most tools let you specify a label or key ID.

**Q: Can I use the same keystore on multiple USB drives?**

A: Yes -- copy the `.p11k` file to as many drives as you want. The keystore file is self-contained. This is a deliberate design choice: it allows backup copies. The security model depends on the PIN, not on the physical uniqueness of the drive.

**Q: What happens if I forget my PIN?**

A: The keys are unrecoverable. There is no backdoor, no recovery key, no master password. This is intentional. If you need PIN recovery, store a backup keystore somewhere secure and know the PIN for that copy.

**Q: Does this work on macOS or Windows?**

A: No. v1 targets Linux only. The USB mount detection uses Linux udev. A macOS port would use IOKit disk arbitration; a Windows port would use volume arrival notifications. Pull requests are welcome; they are not in the current roadmap.

**Q: Is this a replacement for a hardware HSM or a smart card?**

A: No. A hardware HSM performs cryptographic operations inside tamper-resistant hardware -- the private key never exists outside the device. `usb-hsm` loads the key into RAM. A root-level attacker on a running machine can read process memory. If your threat model includes a sophisticated, privileged attacker targeting a live system, you need a hardware HSM or a smart card. `usb-hsm` is for the much more common threat: an attacker who gets the disk but not the running machine, or an attacker who gets the machine but not the USB.

---

### Internal FAQ

**Q: Why PKCS#11 and not something simpler like a custom SSH agent?**

A: PKCS#11 is the only interface that is already supported by all of the target applications simultaneously -- OpenSSH, OpenSSL, GPG, browsers, and the wolfHSM test suite. A custom SSH agent would solve exactly one problem. PKCS#11 solves ten. The additional complexity of implementing the C ABI is front-loaded into this project and permanently amortized across all consumers.

**Q: Why Rust instead of C?**

A: Three reasons. First, memory safety: key material handling is exactly the class of code where C buffer overflows and use-after-free bugs have historically caused catastrophic security failures. Rust eliminates that class of bug at compile time. Second, the `zeroize` crate provides a guaranteed, compiler-fence-protected zeroing primitive that C cannot reliably provide without volatile writes. Third, the `cryptoki` crate provides type-safe PKCS#11 bindings that make the ABI surface auditable.

**Q: Why wolfCrypt as the crypto backend rather than pure-Rust RustCrypto crates?**

A: Two reasons. First, consistency with the broader wolfHSM ecosystem -- this project lives alongside wolfHSM and using the same crypto library means one set of FIPS certification concerns, one set of CVE watches, and a shared conformance posture. Second, the `wolfssl-rs` workspace ships a `wolfcrypt-conformance` crate that already validates every primitive we use (AES-GCM, PBKDF2, RSA-PSS, ECDSA P-256) against NIST CAVP and Wycheproof test vectors. We get that coverage for free; `usb-hsm`'s test suite only needs to validate its own framing and plumbing code.

**Q: Why not just use SoftHSM2?**

A: SoftHSM2 has no concept of key presence tied to a physical device. Keys are always available to any process that can read the token directory. `usb-hsm` adds the physical possession factor: keys are only available while the USB is inserted. That is the core value proposition and it does not exist in SoftHSM2.

**Q: Why not just use a real smart card (YubiKey, etc.)?**

A: A YubiKey costs $50-$80, requires a separate driver or middleware stack (OpenSC, pcsc-daemon), performs operations inside hardware (which `usb-hsm` does not), and stores keys in a purpose-built secure element that cannot be extracted. `usb-hsm` costs $0 beyond a $5 USB drive the user already has. The use case is the user who wants physical possession semantics, uses Linux, and cannot or will not acquire dedicated hardware. These are different products with different threat models; `usb-hsm` does not claim to replace a YubiKey.

**Q: What is the key derivation cost at 100,000 PBKDF2 iterations and is it tunable?**

A: On a modern CPU, 100,000 PBKDF2-HMAC-SHA256 iterations takes approximately 0.2-0.5 seconds. This is the deliberately-slow path: it runs once at login, not at every crypto operation. The iteration count is stored in the keystore header so it can be increased for newly-created keystores as hardware speeds up. The minimum enforced by the creation tool is 100,000 (the NIST SP 800-132 floor for PBKDF2-SHA256); there is no maximum. Tests use 1 iteration to keep the test suite fast.

**Q: What is the `.p11k` format and is it stable?**

A: The format is versioned (current version: 1). The header encodes magic bytes, version, KDF parameters, and AES-GCM parameters. The payload is CBOR-encoded. A version bump allows backward-compatible format evolution. The format spec is in `BUILD.md` and in the module-level documentation of `src/keystore.rs`. It is intended to be stable across minor versions; breaking changes require a version bump and a migration tool.

**Q: How do we prevent the test suite from being self-referential?**

A: All cryptographic primitive tests use NIST CAVP known-answer test vectors loaded from JSON files in `test-vectors/`. Tests assert that `vectors.is_empty()` is false before running -- an empty vector file causes a test failure, not a vacuous pass. Integration tests verify signatures using `openssl dgst -verify` as an external oracle subprocess. The codebase's CI configuration explicitly prohibits the patterns: sign-then-verify with same code, encrypt-then-decrypt with same code, and hardcoded expected values derived from the function under test.

**Q: What is the intended upgrade path to a real HSM later?**

A: Because `usb-hsm` speaks standard PKCS#11, migration to a hardware HSM or smart card is a one-line configuration change in `p11-kit`: replace the module path. Applications do not change. Keys must be re-generated in the hardware token (they cannot be exported from the hardware HSM back to a file format for obvious reasons), but the operational integration is identical.

**Q: What is the memory footprint at runtime?**

A: The loaded `.so` is approximately 2MB. Per-key memory is proportional to key size: an RSA-2048 key is approximately 1.2KB of DER, a P-256 key is approximately 120 bytes, an ML-DSA-65 key pair is approximately 3.9KB (2560-byte private key + 1312-byte public key), and an ML-KEM-768 key pair is approximately 3.6KB (2400-byte private key + 1184-byte public key). All key memory is mlock'd. A keystore with 10 RSA-2048 keys uses approximately 12KB of locked memory. The Linux default `mlock` limit (`RLIMIT_MEMLOCK`) is typically 64KB per process, which supports approximately 50 RSA-2048 keys or 15 ML-DSA-65 key pairs before hitting system limits. Operators with large keystores should raise `RLIMIT_MEMLOCK` or run as root (where mlock is unlimited).
