# usb-hsm

A PKCS#11 soft token that uses an ordinary USB flash drive as a cryptographic
key possession factor. Insert the USB drive, provide your PIN, and any
PKCS#11-aware application (OpenSSH, OpenVPN, Firefox, pkcs11-tool, p11-kit,
...) can sign, verify, encrypt, or decrypt with the keys stored on it -- without
the keys ever appearing on disk unencrypted.

**License:** GPL-3.0

---

## What it does

`usb-hsm` builds as a shared library (`.so` / `.dylib`) that exposes the
standard PKCS#11 v2.40 C ABI. Applications load it with p11-kit or a direct
`dlopen` call just like a hardware HSM driver.

Keys are stored on the USB drive in a `.p11k` file -- a compact binary format
that encrypts key material with AES-256-GCM. The AES key is derived from your
PIN with PBKDF2-HMAC-SHA256 (>= 100 000 iterations, NIST SP 800-132 floor).
Decrypted key bytes are `mlock(2)`'d to prevent paging to swap and zeroized
on drop.

When the USB drive is inserted, a background udev monitor detects the mount
and makes the token available. When the drive is removed, the token disappears
and all key material is immediately zeroized.

---

## Supported mechanisms

| Mechanism | Sign | Verify | Encrypt | Decrypt |
|---|---|---|---|---|
| `CKM_RSA_PKCS_PSS` | y | y | | |
| `CKM_RSA_PKCS_OAEP` | | | y | y |
| `CKM_ECDSA` (pre-hashed) | y | y | | |
| `CKM_ECDSA_SHA256` | y | y | | |
| `CKM_ML_DSA` (pure ML-DSA.Sign, §5.3) | y | y | | |
| `CKM_ML_KEM` | | | y | y |

RSA keys: PKCS#1 DER format. EC keys: P-256, raw 32-byte private scalar.
ECDSA signatures are raw r||s per PKCS#11 s.2.3.1 (64 bytes for P-256).
ML-DSA-65 and ML-KEM-768 use PKCS#11 v3.0 mechanism IDs while reporting
PKCS#11 v2.40 compatibility. `CKM_ML_KEM` `C_Encrypt` returns ciphertext ||
shared\_secret (1120 bytes); `C_Decrypt` returns the 32-byte shared secret.

---

## Threat model

| Threat | Protected? |
|---|---|
| Stolen laptop (USB drive absent) | Yes -- no keys on disk |
| Stolen USB drive (PIN unknown) | Yes -- AES-256-GCM + PBKDF2 |
| Physical theft of both laptop and USB | PIN required to decrypt |
| Root-level memory attack on running machine | No -- keys are in RAM |
| Multiple USB drives with `.p11k` files | First found wins (use udev rules to restrict) |

---

## Requirements

- Linux (udev required for USB detection)
- Rust 1.75 or later
- `libudev-dev` (Debian/Ubuntu) or `systemd-devel` (Fedora/RHEL) -- required by the build script
- wolfCrypt Rust wrapper (`wolfssl-rs`) -- **not on crates.io**; must be checked out adjacent
  to this directory:

  ```
  <parent>/
    usb-hsm/        <- this repo
    wolfssl-rs/     <- https://github.com/wolfSSL/wolfssl-rs
      wolfcrypt/
  ```

  Clone wolfssl-rs into the same parent directory before building. See `Cargo.toml` for
  the exact relative path.

---

## Building

```bash
# Debug build (produces target/debug/libusb_hsm.so)
cargo build

# Release build
cargo build --release
```

The library is a `cdylib` that exports the standard `C_GetFunctionList` entry
point. All other PKCS#11 functions are reached through the function table it
returns, matching how p11-kit and real-world PKCS#11 consumers work.

---

## Running the tests

```bash
# Full test suite (recommended; enables test-helpers feature)
cargo t

# Unit tests only (no USB simulation, no keystore needed)
cargo test --lib

# Individual test binary
cargo test --features test-helpers --test integration
cargo test --features test-helpers --test pkcs11_conformance
```

The `test-helpers` Cargo feature exposes `test_mount`, `test_unmount`, and
`test_reset` functions that simulate USB insertion/removal in tests without
requiring a real USB drive or udev daemon.

---

## Preparing a USB drive

Use `usb-hsm-keygen create` to write a `.p11k` keystore file to the USB drive.
The tool also creates or updates a `.usb-hsm` manifest in the same directory
automatically:

```
/media/usb/token.p11k
/media/usb/.usb-hsm
```

The `.usb-hsm` manifest is a plain-text file listing the `.p11k` files on the
drive, one per line (`<filename> <label>`). The library reads the manifest
instead of scanning the directory, so inserting any USB drive without a
`.usb-hsm` file is a no-op (single `stat(2)` call, no enumeration).

To register a `.p11k` file that was placed on the drive manually:

```bash
usb-hsm-keygen manifest-add /media/usb/token.p11k --label "My Token"
```

To deregister a keystore without deleting it:

```bash
usb-hsm-keygen manifest-remove /media/usb/token.p11k
```

**Key format inside `.p11k`:**

```
[0..4]   magic: b"P11K"
[4]      version: 0x01
[5..37]  PBKDF2 salt (32 bytes, random)
[37..41] PBKDF2 iterations (u32 big-endian, >= 100 000)
[41..53] AES-GCM nonce (12 bytes, random)
[53..57] ciphertext length (u32 big-endian)
[57..]   AES-256-GCM ciphertext + 16-byte authentication tag
```

The ciphertext decrypts to a CBOR-encoded array of key entries. Each entry
contains: a 16-byte ID, a label string, a key type (`Rsa`, `Ec`, `MlDsa65`,
`MlKem768`, or other PQC variants), raw private key bytes, and optionally raw
public key bytes (required for PQC keys) and a certificate DER blob.

---

## PIN-based encryption

The PIN is never used directly as a key. It is fed into PBKDF2 to derive the
AES key:

```
PIN  +  random 32-byte salt
         |
         v
PBKDF2-HMAC-SHA256 (>= 100 000 iterations)
         |
         v
    32-byte AES-256 key
         |
         v
   AES-256-GCM  <---- random 12-byte nonce
```

**Encryption** (`usb-hsm-keygen create` / `key-add` / `pin-change`):

1. CBOR-encode all `KeyEntry` structs into a plaintext buffer.
2. Generate a fresh random 32-byte salt and 12-byte nonce.
3. Derive a 32-byte AES key: `PBKDF2-HMAC-SHA256(PIN, salt, iterations)`.
4. Encrypt the buffer in place with AES-256-GCM; keep the detached 16-byte auth tag.
5. Zeroize the AES key immediately.
6. Write the wire format (header + ciphertext + tag).

**Decryption** (`C_Login`):

1. Parse salt, iteration count, and nonce from the file header.
2. Reject files with `iterations < 100 000` (tamper guard; see Security considerations).
3. Re-derive the AES key from the presented PIN.
4. Attempt AES-256-GCM decryption. **If the PIN was wrong, the authentication tag
   will not verify** -- the library returns `CKR_PIN_INCORRECT` at this point, without
   any separate password-check step.
5. Zeroize the AES key regardless of success or failure.
6. CBOR-decode the plaintext into key entries; zeroize the plaintext buffer.
7. `mlock(2)` each key-material buffer to prevent the OS from paging it to swap.

**What is cleartext in the file:** the magic bytes, version, PBKDF2 salt, iteration
count, AES-GCM nonce, and ciphertext length are all unencrypted. An attacker
who has the file knows exactly how expensive a brute-force attempt would be (the
iteration count is at bytes `[37..41]`). The key material itself -- and the key
labels -- are inside the authenticated ciphertext and are never visible without
the PIN.

---

## Integrating with p11-kit

Add the module to `/etc/pkcs11/modules/usb-hsm.module`:

```ini
module: /usr/local/lib/libusb_hsm.so
```

Then use standard p11-kit commands:

```bash
p11-kit list-modules
pkcs11-tool --module /usr/local/lib/libusb_hsm.so --list-slots
pkcs11-tool --module /usr/local/lib/libusb_hsm.so --login --list-objects
```

---

## Integrating with OpenSSH

Add to `~/.ssh/config` or `/etc/ssh/ssh_config`:

```
PKCS11Provider /usr/local/lib/libusb_hsm.so
```

Or pass directly:

```bash
ssh -I /usr/local/lib/libusb_hsm.so user@host
```

---

## PKCS#11 conformance notes

- **One slot, slot ID 0.** The token is always in slot 0.
- **No Security Officer role.** `C_Login(CKU_SO)` returns
  `CKR_USER_TYPE_INVALID`. This is a user-PIN-only token.
- **Minimum PIN length: 6 characters** (`ulMinPinLen = 6` per NIST guidance).
- **ECDSA signatures** are raw r||s per PKCS#11 s.2.3.1: 32 bytes r followed
  by 32 bytes s for P-256 (64 bytes total). Not DER-encoded.
- **USB detection timing.** udev emits block device events before the
  automounter (udisks2) completes the mount. The library retries
  `/proc/mounts` every 100 ms for up to 10 seconds after a block device
  event, so there is no configuration required for standard udisks2 setups.

---

## Architecture

```
C_GetFunctionList
       |
  lib.rs  -- PKCS#11 C ABI, session management, op dispatch
       |
   +---+------------------------+
   |                            |
token.rs                    ops.rs
Token state machine          Crypto operations
Absent->Present->LoggedIn->Removed   sign / verify / encrypt / decrypt
       |
keystore.rs              usb_watch.rs
.p11k format              udev monitor
AES-256-GCM + PBKDF2      /proc/mounts retry loop
mlock + zeroize           UsbEvent channel
```

**Token states:**

- `Absent` -- no USB drive mounted
- `Present { p11k_path }` -- drive mounted, keystore path known, PIN not yet provided
- `LoggedIn { p11k_path, keystore }` -- PIN verified, key material in mlock'd RAM
- `Removed` -- drive was removed while sessions were active; returns `CKR_DEVICE_REMOVED`

---

## Security considerations

- Key bytes are `mlock(2)`'d on load and zeroized (`zeroize` crate) on drop
  before `munlock`. This order (zeroize-then-munlock) is intentional: it
  ensures the zeroing happens while the page is still pinned in RAM, before
  the OS can swap it.
- PBKDF2 iteration count in the `.p11k` file is validated on load. An
  attacker who controls the file cannot set iterations to 0 to eliminate
  brute-force resistance -- the library rejects files below the minimum.
- The udev monitor watches for any `.p11k` file on any mounted filesystem.
  In multi-device environments, restrict which devices are accepted with udev
  rules (e.g., match by USB vendor/product ID or filesystem UUID).

---

## Post-quantum cryptography

ML-DSA-65 (`CKM_ML_DSA`, FIPS 204 §5.3 ML-DSA.Sign) and ML-KEM-768 (`CKM_ML_KEM`)
are supported. The `KeyType` enum and `.p11k` format also accommodate all three
ML-DSA levels (44, 65, 87) and all three ML-KEM levels (512, 768, 1024)
without a format version bump.

**Not in scope:**

- **LMS/HSS** (stateful hash-based signatures): correct use requires a
  persistent one-time-key counter that survives process restart. This needs
  a write-back path to the `.p11k` file that does not currently exist. Adding
  LMS without it would silently allow key-slot reuse, which breaks security.
- **Hybrid schemes** (e.g. X25519+ML-KEM-768): hybrid composition belongs in
  the TLS or SSH stack, not in the token. Use each mechanism independently
  and compose at the protocol layer.

---

## Future plans

### Key import formats

`usb-hsm-keygen` auto-detects the following formats and normalizes them to
the same internal `KeyEntry` representation:

| Format | Detected by |
|---|---|
| PEM (`RSA PRIVATE KEY`, `EC PRIVATE KEY`, `PRIVATE KEY`) | PEM header |
| Bare DER (PKCS#1 RSA, SEC1 EC, PKCS#8 unencrypted) | ASN.1 structure |
| PKCS#8 encrypted (PBES2: PBKDF2-SHA1/SHA256 + AES-CBC) | `-----BEGIN ENCRYPTED PRIVATE KEY-----` / OID |
| PKCS#12 (`.pfx` / `.p12`, multi-key) | ASN.1 SEQUENCE + PKCS#12 OID |
| OpenSSH new-format (passphrase-protected or unencrypted) | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| OpenSSH binary private key | `openssh-key-v1\0` magic |
| OpenPGP armored / binary secret key | PEM header / packet tag |
| PuTTY PPK v2 / v3 | `PuTTY-User-Key-File-` prefix |
| JKS / JCEKS Java KeyStore | `FEEDFEED` / `CECECECE` magic |
| GCP Service Account JSON | JSON object with `private_key` field |

### Key types

ECC P-384, Ed25519, and X25519 are planned but not in v1.

### Platforms

macOS (IOKit disk arbitration) and Windows (volume arrival notifications)
are community-contribution candidates; they are not on the current roadmap.

---

## License

GPL-3.0. See `LICENSE` for the full text.
