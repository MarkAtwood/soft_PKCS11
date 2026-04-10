# BUILD.md -- Agentic Build Prompt: `usb-hsm`

> **Purpose:** This file is a complete agentic build prompt. An autonomous agent
> reading this file should be able to build, test, and validate the `usb-hsm`
> project from scratch with no additional human input for the core workflow.
> Read this entire file before writing a single line of code.

---

## What You Are Building

A PKCS#11 soft-token shared library (`libusb_hsm.so`) written in Rust that:

1. Watches for USB storage devices being mounted (Linux udev/inotify)
2. Scans the mount point for a keystore file (`.p11k` format defined below)
3. Decrypts the keystore into memory-locked pages (mlock, never swapped)
4. Exposes a fully-conformant PKCS#11 C ABI so that standard tools (`ssh`,
   `openssl`, `p11-kit`, `pkcs11-tool`) can use it transparently
5. Zeroizes all key material in memory the moment the USB is unmounted

**Security threat model (encode this in comments and docs):**
- Protects against: casual theft of the machine without the USB, offline disk
  attacks, loss of the USB without the PIN
- Does NOT protect against: root-level attacker on a running machine (same as
  any soft token), hardware USB bus sniffing
- The USB is a possession factor, not a tamper-resistant element

**Language:** Rust (edition 2021, MSRV 1.75)
**Target OS:** Linux (any distro with udev; glibc or musl)
**Output:** `target/release/libusb_hsm.so` (cdylib)

---

## Pre-Flight: Session Setup

Before doing anything else, run these checks:

```bash
bd status 2>/dev/null || (bd init --quiet && bd setup claude)
cargo --version        # must be >= 1.75
rustc --version
pkg-config --exists libudev && echo "udev ok" || echo "MISSING: libudev-dev"
```

If `libudev-dev` is missing, file a blocker issue and stop -- do not proceed
without it. The correct install command is:

```bash
# Debian/Ubuntu
sudo apt-get install -y libudev-dev pkg-config

# Fedora/RHEL
sudo dnf install -y systemd-devel pkgconf
```

---

## Beads Issue Decomposition

**Run this block FIRST, before any code.** Create the epic and all child issues.
Use parallel subagents to create issues simultaneously -- do not create them
sequentially.

### Epic

```bash
bd create \
  --title="usb-hsm: PKCS#11 soft token sourcing keys from USB" \
  --description="Build a cdylib PKCS#11 module in Rust that detects USB mount events via udev, loads an encrypted keystore from the USB, serves PKCS#11 crypto ops, and zeroizes on unmount. This is the top-level epic." \
  --type=feature \
  --priority=1
```

Save the epic ID (e.g., `beads-001`). All child issues must depend on this epic.

### Child Issues

Spawn **7 parallel subagents**, each creating one issue:

**Subagent 1 -- Crate scaffold:**
```bash
bd create \
  --title="Scaffold Rust crate and Cargo.toml" \
  --description="Create the usb-hsm Rust crate with cdylib target, all required dependencies pinned, workspace layout, and build.rs for pkg-config udev linkage. Acceptance: cargo build --release produces a .so with no warnings." \
  --type=task --priority=1 \
  --acceptance="cargo build --release succeeds; file target/release/libusb_hsm.so shows ELF shared object; no compiler warnings"
```

**Subagent 2 -- USB watcher:**
```bash
bd create \
  --title="Implement usb_watch: udev mount detection" \
  --description="Watch udev for block device add/remove events and correlate with /proc/mounts to find the USB mount point. Emit typed events: Mounted(PathBuf) and Unmounted(PathBuf). Must be cancellation-safe (tokio CancellationToken or std thread with channel). Acceptance: unit tests with a mock udev event stream prove Mounted and Unmounted fire correctly." \
  --type=task --priority=1 \
  --acceptance="unit tests pass using mock event source; no panics on rapid mount/unmount cycles"
```

**Subagent 3 -- Keystore format:**
```bash
bd create \
  --title="Implement keystore: encrypted key container" \
  --description="Define and implement the .p11k binary format: [magic(4) | version(1) | kdf_salt(32) | kdf_iterations(4) | aes_gcm_nonce(12) | ciphertext(var) | tag(16)]. Key derivation: PBKDF2-HMAC-SHA256. Encryption: AES-256-GCM. The plaintext payload is a CBOR-encoded list of KeyEntry structs (id, label, key_type, raw_key_bytes). Implement mlock on the decrypted buffer. Implement Zeroize on all types holding key bytes. Acceptance: round-trip test using an independent reference implementation or known test vector." \
  --type=task --priority=1 \
  --acceptance="round-trip encode/decode test using known NIST PBKDF2 test vectors for KDF; known AES-GCM test vectors for encryption; no key bytes appear in process memory after Zeroize (verified by /proc/self/mem scan in test)"
```

**Subagent 4 -- PKCS#11 token state machine:**
```bash
bd create \
  --title="Implement token: PKCS#11 slot/token state machine" \
  --description="Model the PKCS#11 slot and token lifecycle: slot always present, token present iff USB is mounted. Implement C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_OpenSession, C_CloseSession, C_CloseAllSessions, C_Login, C_Logout. Token state transitions: TokenAbsent -> TokenPresent(keystore loaded) -> LoggedIn -> (unmount) -> Zeroized -> TokenAbsent. Thread-safe using Arc<Mutex<TokenState>>. Acceptance: state machine unit tests covering all transitions including mid-session unmount." \
  --type=task --priority=1 \
  --acceptance="all state transitions tested; concurrent session test with two threads; mid-session unmount triggers zeroize and returns CKR_DEVICE_REMOVED to in-flight calls"
```

**Subagent 5 -- Crypto ops:**
```bash
bd create \
  --title="Implement ops: sign, verify, encrypt, decrypt" \
  --description="Implement PKCS#11 crypto operations against loaded key material: C_Sign/C_SignInit (RSA PKCS1v15 + PSS, ECDSA P-256), C_Verify/C_VerifyInit, C_Encrypt/C_EncryptInit (RSA OAEP), C_Decrypt/C_DecryptInit. Use the RustCrypto crates (rsa, p256, aes-gcm). Never copy key bytes outside the mlock'd region. Acceptance: each operation tested with NIST CAVP test vectors, never with self-referential round-trips." \
  --type=task --priority=1 \
  --acceptance="RSA-PSS sign tested against NIST CAVP vectors; ECDSA P-256 sign tested against NIST vectors; all tests use known-answer format: (key, message, expected_signature) -- no test encrypts then decrypts with the same function"
```

**Subagent 6 -- C ABI / PKCS#11 exports:**
```bash
bd create \
  --title="Implement lib.rs: PKCS#11 C ABI entry points" \
  --description="Export all required PKCS#11 v2.40 functions via #[no_mangle] extern C. Implement C_GetFunctionList as the mandatory bootstrap. Map Rust errors to CKR_* codes exhaustively -- no catch-all CKR_GENERAL_ERROR except for truly unexpected paths. Acceptance: pkcs11-tool --module target/release/libusb_hsm.so --list-mechanisms runs without crashing; p11-kit list-modules loads the module." \
  --type=task --priority=1 \
  --acceptance="pkcs11-tool --module ./target/release/libusb_hsm.so --list-slots exits 0; C_GetFunctionList returns non-null; all exported symbols present (nm -D check)"
```

**Subagent 7 -- Integration tests:**
```bash
bd create \
  --title="Integration test suite: end-to-end PKCS#11 flows" \
  --description="Write integration tests that: (1) create a temp dir simulating a USB mount, (2) write a valid .p11k keystore to it, (3) trigger the usb_watch Mounted event, (4) call C_Login, (5) perform sign/verify using pkcs11-tool as the external oracle, (6) simulate unmount and verify zeroize. Use a separate test binary in tests/. All assertions must use an external oracle (pkcs11-tool output, openssl verification). Never assert correctness by re-running the function under test." \
  --type=task --priority=1 \
  --acceptance="full flow test passes; unmount-during-operation test proves CKR_DEVICE_REMOVED; pkcs11-tool --sign output verified by openssl dgst -verify using the public key extracted independently"
```

After creating all issues, add dependencies:

```bash
# All implementation issues depend on scaffold
bd dep add <usb_watch_id>  <scaffold_id>
bd dep add <keystore_id>   <scaffold_id>
bd dep add <token_id>      <scaffold_id>
bd dep add <ops_id>        <scaffold_id>
bd dep add <lib_id>        <scaffold_id>

# Integration tests depend on all implementation issues
bd dep add <integration_id> <usb_watch_id>
bd dep add <integration_id> <keystore_id>
bd dep add <integration_id> <token_id>
bd dep add <integration_id> <ops_id>
bd dep add <integration_id> <lib_id>
```

---

## Repository Layout

Create this exact layout. Do not create any files not listed here unless they
are generated artifacts (target/, *.lock).

```
soft_PKCS11/           # repo root
+-- Cargo.toml
+-- build.rs
+-- src/
|   +-- lib.rs          # #[no_mangle] PKCS#11 C ABI entry points
|   +-- token.rs        # Slot/token state machine
|   +-- usb_watch.rs    # udev watcher, Mounted/Unmounted events
|   +-- keystore.rs     # .p11k format: parse, decrypt, mlock, zeroize
|   +-- ops.rs          # sign, verify, encrypt, decrypt implementations
+-- tests/
|   +-- integration.rs  # end-to-end PKCS#11 flow tests
|   +-- pkcs11_conformance.rs  # C_GetFunctionList, slot/token info tests
+-- test-vectors/
|   +-- p11k_framing.json     # externally-produced .p11k parse/error test cases
+-- p11kit/
    +-- usb-hsm.module         # p11-kit module config
```

---

## Cargo.toml Specification

```toml
[package]
name = "usb-hsm"
version = "0.1.0"
edition = "2021"
rust-version = "1.75"

[lib]
crate-type = ["cdylib"]

[dependencies]
# PKCS#11 C ABI types and constants
cryptoki = "0.7"

# Crypto primitives -- wolfCrypt Rust wrapper (safe, RustCrypto-trait-compatible)
# Path points to the wolfssl-rs workspace sibling; adjust if the repo is elsewhere.
# wolfcrypt provides: Aes256Gcm, pbkdf2_hmac_sha256, RsaPrivateKey, RsaPublicKey,
# P256SigningKey, P256VerifyingKey, WolfRng -- all backed by wolfSSL C library.
wolfcrypt = { path = "../wolfssl-rs/wolfcrypt" }

# Key material safety -- wolfcrypt key types implement ZeroizeOnDrop internally,
# but we still use zeroize directly for intermediate buffers we own.
zeroize = { version = "1.7", features = ["derive", "zeroize_derive"] }

# Serialization for .p11k payload
ciborium = "0.2"     # CBOR encode/decode
serde = { version = "1", features = ["derive"] }

# USB / mount detection
udev = "0.8"
inotify = "0.10"

# Concurrency
parking_lot = "0.12"
crossbeam-channel = "0.5"

# Low-level
libc = "0.2"

[dev-dependencies]
tempfile = "3"
assert_cmd = "2"
hex = "0.4"
serde_json = "1"    # for loading test vectors

[build-dependencies]
pkg-config = "0.3"
```

---

## build.rs Specification

```rust
// build.rs
// Link libudev via pkg-config. Fail fast with a clear error if not found.
fn main() {
    pkg_config::Config::new()
        .atleast_version("204")
        .probe("libudev")
        .expect("libudev not found. Install libudev-dev (Debian) or systemd-devel (Fedora).");
}
```

---

## Module Specifications

### `src/usb_watch.rs`

**Purpose:** Detect USB storage mount/unmount events.

**Approach:** Use the `udev` crate to open a monitor socket on the `block`
subsystem. For each `add` event, check `/proc/mounts` to find the mount point
of the new device. For `remove`, emit `Unmounted` for the previously seen mount
point. Run the monitor in a background thread; send events over a
`crossbeam_channel`.

**Public API:**
```rust
pub enum UsbEvent {
    Mounted(PathBuf),
    Unmounted(PathBuf),
}

pub struct UsbWatcher {
    rx: crossbeam_channel::Receiver<UsbEvent>,
    // private: thread handle, stop channel
}

impl UsbWatcher {
    pub fn start() -> Result<Self, Error>;
    pub fn events(&self) -> &crossbeam_channel::Receiver<UsbEvent>;
    pub fn stop(self);  // signals thread to exit, joins
}
```

**Testing requirement:** Do NOT test against a real USB device. Instead,
provide a `MockUsbSource` that accepts a sequence of `(action: &str,
devnode: &str)` events and drives the same parsing logic. The test must assert:

1. A `block` `add` event where the device appears in `/proc/mounts` produces
   exactly one `Mounted` event with the correct path.
2. A `block` `remove` event produces exactly one `Unmounted` event.
3. An `add` event for a device NOT in `/proc/mounts` produces no event (it
   might be a partition not yet mounted -- retry logic is out of scope).
4. Rapid add/remove cycles (100 iterations) produce exactly 100 Mounted and
   100 Unmounted events in order.

Tests must inject `/proc/mounts` content as a string, not read the real file.

---

### `src/keystore.rs`

**Purpose:** Define `.p11k` format; load, decrypt, mlock, and zeroize key material.

**Wire format (big-endian):**
```
[0..4]   magic:           0x50 0x31 0x31 0x4B  ("P11K")
[4]      version:         0x01
[5..37]  kdf_salt:        32 random bytes
[37..41] kdf_iterations:  u32 (minimum 200_000 in production; 1 in tests)
[41..53] aes_gcm_nonce:   12 random bytes
[53..57] ciphertext_len:  u32
[57..57+ciphertext_len] ciphertext: AES-256-GCM encrypted CBOR payload
[57+ciphertext_len .. +16] aes_gcm_tag: 16 bytes
```

**CBOR payload** (list of KeyEntry):
```rust
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyEntry {
    pub id: [u8; 16],       // CKA_ID -- random bytes
    pub label: String,      // CKA_LABEL
    pub key_type: KeyType,  // RSA | EC
    pub der_bytes: Vec<u8>, // DER-encoded private key; zeroized on drop
}
```

**Decryption flow:**
1. Parse and validate magic + version; return `Err(BadMagic)` on mismatch
2. Derive 32-byte AES key: `PBKDF2-HMAC-SHA256(pin, kdf_salt, kdf_iterations, 32)`
3. Decrypt with `AES-256-GCM`; return `Err(BadPin)` on tag verification failure
4. CBOR-decode to `Vec<KeyEntry>`
5. Call `libc::mlock` on the backing allocation of each `der_bytes` Vec
6. Zeroize the intermediate AES key immediately after use

**Public API:**
```rust
pub struct Keystore {
    entries: Vec<KeyEntry>,  // mlock'd
}

impl Keystore {
    pub fn load(path: &Path, pin: &[u8]) -> Result<Self, KeystoreError>;
    pub fn entries(&self) -> &[KeyEntry];
    pub fn create(entries: Vec<KeyEntry>, pin: &[u8], iterations: u32) -> Result<Vec<u8>, KeystoreError>;
}

impl Drop for Keystore {
    // zeroize all key bytes and munlock
}
```

**Future: Additional Keystore Formats**

Several additional input formats are planned for future milestones. Do not
implement any of them now. Do make the design decisions below so that adding
them later requires only changes to `src/keystore.rs` and `Cargo.toml` --
nothing in `token.rs`, `ops.rs`, or `lib.rs` should ever need to change for a
new format.

**Design rules that must hold from day one:**

- `Keystore::load` dispatches on the file header before committing to a parse
  strategy. Peek at the first ~16 bytes and route to the appropriate parser.
  Add a `// FUTURE: format dispatch point` comment here.
- `KeyEntry` is the internal normalized representation. Every format reduces
  to `Vec<KeyEntry>` before returning from `load`. No format-specific fields
  on `KeyEntry`.
- `KeystoreError` must include an `UnsupportedFormat(String)` variant from day
  one so unimplemented format paths return a clean error immediately.

**Format detection table** (implement the dispatch table even if only the
first row is wired up):

| Header bytes / pattern | Format |
|------------------------------------------------|------------------------------------------------|
| `50 31 31 4B` ("P11K") | .p11k native (v1, current) |
| `30 82 ...` (ASN.1 SEQUENCE + try PKCS#12 OID) | PKCS#12 (.pfx/.p12) -- future |
| `30 82 ...` (ASN.1 SEQUENCE + PKCS#8 OID) | Raw DER PKCS#8 (encrypted or not) -- future |
| `-----BEGIN ENCRYPTED PRIVATE KEY-----` | PKCS#8 EncryptedPrivateKeyInfo PEM -- future |
| `-----BEGIN PRIVATE KEY-----` | PKCS#8 unencrypted PEM -- future |
| `-----BEGIN RSA PRIVATE KEY-----` | Traditional OpenSSL RSA PEM (PKCS#1) -- future |
| `-----BEGIN EC PRIVATE KEY-----` | Traditional OpenSSL EC PEM (SEC1) -- future |
| `-----BEGIN OPENSSH PRIVATE KEY-----` | OpenSSH new-format private key -- future |
| `6F 70 65 6E 73 73 68 2D 6B 65 79 2D 76 31 00` | OpenSSH binary private key -- future |
| `-----BEGIN PGP PRIVATE KEY BLOCK-----` | OpenPGP armored secret key -- future |
| `C5 xx / C7 xx` (OpenPGP secret key packet tag) | OpenPGP binary secret key -- future |
| `PuTTY-User-Key-File-2:` / `-3:` | PuTTY PPK v2/v3 -- future |
| `FE ED FE ED` (big-endian u32) | JKS Java KeyStore -- future |
| `CE CE CE CE` (big-endian u32) | JCEKS Java KeyStore -- future |
| `7B 22 ...` with `"private_key"` field (JSON) | GCP Service Account JSON -- future |

Note on ASN.1 disambiguation: both PKCS#12 and DER PKCS#8 start with `0x30`.
Distinguish them by inspecting the OID in the first SEQUENCE: PKCS#12 uses
`1.2.840.113549.1.12.10.1.x`; PKCS#8 EncryptedPrivateKeyInfo uses
`1.2.840.113549.1.5.13` (PBES2); unencrypted PKCS#8 uses `1.2.840.113549.1.1.1`
(rsaEncryption) or `1.2.840.10045.2.1` (ecPublicKey). Do not distinguish by
file extension -- extensions are unreliable.

**Per-format notes:**

*PKCS#12* -- bundles cert + private key + chain. When loaded, the private key
is extracted into `KeyEntry.der_bytes`; the certificate is ignored by
`usb-hsm` (PKCS#11 object model can expose it separately if needed later).

*Raw DER PKCS#8* -- the binary (non-PEM) form of the same content as the PEM
variants below. Common output of Java and .NET crypto APIs. Same parse path
as the PEM variants after stripping the base64 armor.

*Encrypted PKCS#8 PEM* -- the format `openssl genpkey` produces. Uses PBES2
(PBKDF2 + AES-CBC or AES-GCM) as the outer encryption. No custom parsing
needed beyond standard ASN.1 -- wolfCrypt handles it. This is the most natural
"I already have an OpenSSL key" import path.

*OpenSSH private key* -- the `-----BEGIN OPENSSH PRIVATE KEY-----` format
(used by default since OpenSSH 7.8). Uses bcrypt as the KDF and
chacha20-poly1305 or AES-256-CTR as the cipher. **Important:** SSH keys
commonly include Ed25519 and Ed448 types, which are not in the v1 `ops.rs`
implementation. Adding OpenSSH format support will require also adding
Ed25519/Ed448 support in `ops.rs`. Flag this dependency in the future issue.

*OpenPGP / GPG* -- OpenPGP secret key packets (RFC 4880). GPG keys have
richer metadata (user IDs, binding signatures) that PKCS#11 has no model for;
only the raw key material is extracted into `KeyEntry`. Like SSH, GPG keys
commonly use Ed25519 which requires the same `ops.rs` extension noted above.
The PIN maps to the OpenPGP key passphrase for decryption.

*PuTTY PPK* -- PuTTY's native private key format. v2 uses SHA-1 HMAC + AES-256-CBC;
v3 (PuTTY 0.75+) uses Argon2 KDF + AES-256-CBC. Very common on Windows.
Like OpenSSH, PPK files frequently carry Ed25519 keys -- same `ops.rs` dependency.
The `putty-key` crate or manual parsing handles the text-based format.

*JKS / JCEKS* -- Java KeyStore formats. JKS uses a proprietary Sun algorithm
(weak; SHA-1 + DES3); JCEKS uses Triple-DES with stronger integrity. Both are
common in Java enterprise, Tomcat, Spring Boot, and Android. The `keystore`
crate or manual parsing handles these. Note: JKS is deprecated as of Java 9
in favour of PKCS#12, but remains widespread in legacy systems.

*GCP Service Account JSON* -- Google Cloud service account credentials contain
a PKCS#8 PEM private key embedded as the `"private_key"` field in a JSON
object. Detection: file starts with `{` and contains the string `"private_key"`.
Parse path: extract the `private_key` string, then follow the PKCS#8 PEM path.
No new crypto needed -- just a JSON unwrap layer.

**When any of these formats is added later:**
1. Add a detection arm to the dispatch table in `Keystore::load`
2. Implement a `parse_<format>(bytes: &[u8], pin: &[u8]) -> Result<Vec<KeyEntry>>` function
3. Add any required dep to `Cargo.toml`
4. If new key types are needed (Ed25519, Ed448), open a separate issue for `ops.rs`
5. No other files change

**Test integrity rules (CRITICAL):**

The `wolfcrypt` crate's own conformance suite (`wolfcrypt-conformance`) already
validates `Aes256Gcm` and `pbkdf2_hmac_sha256` against NIST CAVP and Wycheproof
vectors. **Do not re-test the primitives** -- that is `wolfssl-rs`'s job and
duplicating it adds noise without signal.

`usb-hsm` keystore tests must instead validate the **framing layer**: the
binary header layout, the CBOR payload, and the plumbing that calls into
wolfcrypt. Use NIST vectors only where usb-hsm code owns the logic (i.e., the
header parsing and the wire-format byte order). Use `wolfcrypt` as the trusted
oracle for the crypto itself.

1. **Header parse test:** Construct a `.p11k` byte sequence by hand (magic,
   version, salt, iterations, nonce, a known ciphertext produced by a
   reference tool such as `openssl enc -aes-256-gcm`). Call `Keystore::load`
   and assert the parsed fields match what was written. This tests the header
   parser, not AES-GCM.

2. **Wrong PIN test:** Call `Keystore::load` with an incorrect PIN and assert
   it returns `Err(KeystoreError::BadPin)`. This tests that AES-GCM tag
   rejection propagates correctly through the framing layer.

3. **Bad magic test:** Corrupt the first byte and assert `Err(BadMagic)`.

4. **Round-trip test:** Create a keystore with `Keystore::create`, then load
   it with `Keystore::load` and assert the `KeyEntry` fields round-trip intact.
   This is acceptable because it tests framing + CBOR, not the crypto primitives.

5. **Zeroize test:** After a `Keystore` is dropped, scan the process heap
   (via `/proc/self/mem`) for the known key bytes. Assert they are not found.
   Use a recognizable canary pattern (e.g., `0xDE 0xAD 0xBE 0xEF` repeated)
   as part of the test key so you can reliably detect non-zeroization.

---

### `src/token.rs`

**Purpose:** PKCS#11 slot and token state machine.

**State enum:**
```rust
enum TokenState {
    Absent,
    Present { keystore: Keystore },
    LoggedIn { keystore: Keystore, sessions: HashMap<CK_SESSION_HANDLE, SessionInfo> },
}
```

**Required transitions:**
```
Absent  --(USB mounted + keystore found)-->  Present
Present --(C_Login with correct PIN)--------> LoggedIn
LoggedIn --(C_Logout)-----------------------> Present
Present/LoggedIn --(USB unmounted)----------> Absent (+ zeroize)
LoggedIn --(C_OpenSession)------------------> LoggedIn (session added)
LoggedIn --(C_CloseSession)-----------------> LoggedIn (session removed)
LoggedIn --(C_CloseAllSessions)-------------> Present (sessions cleared)
```

Any operation attempted in wrong state returns the correct CKR_* error:
- `CKR_TOKEN_NOT_PRESENT` -- operations against `Absent`
- `CKR_USER_NOT_LOGGED_IN` -- object/crypto ops against `Present`
- `CKR_USER_ALREADY_LOGGED_IN` -- C_Login against `LoggedIn`

**Thread safety:** Wrap in `Arc<parking_lot::RwLock<TokenState>>`. Read ops
(C_GetTokenInfo, C_GetSlotInfo) take a read lock. Write ops (C_Login, C_Logout,
mount/unmount transitions) take a write lock.

**Testing:** State machine tests must exercise every transition. Concurrent
test: spin up 4 threads each calling C_OpenSession in a loop while the main
thread triggers an unmount transition; assert no panics and all in-flight calls
return either `CKR_OK` or `CKR_DEVICE_REMOVED`, never UB.

---

### `src/ops.rs`

**Purpose:** Execute crypto operations against key material in the token.

**Operations to implement:**

| PKCS#11 Mechanism  | Underlying primitive                  |
|--------------------|---------------------------------------|
| CKM_RSA_PKCS       | RSA PKCS#1 v1.5 sign/verify           |
| CKM_RSA_PKCS_PSS   | RSA-PSS sign/verify                   |
| CKM_RSA_PKCS_OAEP  | RSA-OAEP encrypt/decrypt              |
| CKM_ECDSA          | ECDSA P-256 sign/verify (raw r\|\|s)  |
| CKM_ECDSA_SHA256   | ECDSA P-256 with SHA-256 prehash      |

**Key constraint:** Key bytes must never leave the mlock'd `KeyEntry.der_bytes`
allocation. Operations borrow it; they do not copy. Use
`wolfcrypt::rsa::RsaPrivateKey::from_pkcs8_der` and
`wolfcrypt::ecdsa::P256SigningKey::from_pkcs8_der` with the slice in place.

**Test integrity rules (CRITICAL):**

`wolfcrypt-conformance` in the `wolfssl-rs` workspace already validates
`RsaPrivateKey`, `P256SigningKey`, and their verify counterparts against NIST
CAVP and Wycheproof vectors. **Do not re-test primitive correctness here.**

`usb-hsm` ops tests must validate the **PKCS#11 plumbing layer**: that the
right wolfcrypt type is selected for the right `CKM_*` mechanism, that DER
bytes are parsed from `KeyEntry` correctly, and that error codes map properly.

Use `openssl` as the external oracle for integration-level correctness:

1. **Sign -> openssl verify (RSA-PSS):** Call `C_Sign` with `CKM_RSA_PKCS_PSS`
   against a test key. Write the signature to a temp file. Invoke:
   `openssl dgst -sha256 -sigopt rsa_padding_mode:pss -verify pubkey.pem -signature sig.bin msg.bin`
   Assert exit code 0. The public key must be extracted from the DER
   independently of the sign path (e.g., via `openssl rsa -pubout`).

2. **Sign -> openssl verify (ECDSA P-256):** Same pattern with
   `openssl dgst -sha256 -verify`.

3. **Wrong mechanism test:** Attempt `C_SignInit` with a mechanism not in
   `C_GetMechanismList` and assert `CKR_MECHANISM_INVALID`.

4. **Key type mismatch test:** Attempt RSA sign with an EC key object and
   assert `CKR_KEY_TYPE_INCONSISTENT`.

**Prohibited test patterns:**
- Do NOT sign a message and verify with wolfcrypt's own verify function.
- Do NOT generate a keypair in-test and use it as the oracle.
- These prove nothing about correctness. They only prove the code runs without crashing.

---

### `src/lib.rs`

**Purpose:** Export the PKCS#11 2.40 C ABI.

**Mandatory exports** (minimum viable set for `pkcs11-tool` and `p11-kit`):

```c
C_GetFunctionList
C_Initialize / C_Finalize
C_GetInfo
C_GetSlotList
C_GetSlotInfo
C_GetTokenInfo
C_GetMechanismList
C_GetMechanismInfo
C_OpenSession
C_CloseSession
C_CloseAllSessions
C_GetSessionInfo
C_Login
C_Logout
C_GetObjectCount         (stub: return CKR_FUNCTION_NOT_SUPPORTED if not implemented)
C_FindObjectsInit
C_FindObjects
C_FindObjectsFinal
C_GetAttributeValue
C_SignInit
C_Sign
C_SignUpdate             (stub: CKR_FUNCTION_NOT_SUPPORTED)
C_SignFinal             (stub: CKR_FUNCTION_NOT_SUPPORTED)
C_VerifyInit
C_Verify
C_EncryptInit
C_Encrypt
C_DecryptInit
C_Decrypt
C_GenerateRandom
C_SeedRandom            (stub: CKR_OK, ignore)
```

**Error mapping discipline:** Every `match` on `TokenError` or `KeystoreError`
must map to a specific `CKR_*` code. Catch-all `_ => CKR_GENERAL_ERROR` is
forbidden except as a final fallback for truly unknown errors, and must be
accompanied by a `// UNREACHABLE: explain why` comment. CI will grep for
unadorned `CKR_GENERAL_ERROR` and fail.

---

## Test Vector Policy

`usb-hsm` uses `wolfcrypt` as its crypto backend. The `wolfcrypt-conformance`
crate in the `wolfssl-rs` workspace already validates every primitive (AES-GCM,
PBKDF2, RSA-PSS, ECDSA P-256) against NIST CAVP and Wycheproof test vectors.

**`usb-hsm` does not maintain its own NIST CAVP vector files.** Doing so would
duplicate coverage that is already authoritative in `wolfssl-rs` and create a
maintenance burden with no benefit.

Instead, the `test-vectors/` directory holds only vectors that test
**usb-hsm's own logic** -- the `.p11k` binary framing and header parsing:

### `test-vectors/p11k_framing.json`

Hand-constructed framing test cases. Each entry provides a pre-built `.p11k`
byte sequence (hex-encoded) produced by an external reference (e.g., `openssl`
or a Python script using `cryptography` library) and the expected parsed fields.
These test the header parser, not the crypto.

Format:
```json
[
  {
    "description": "minimal valid keystore, 1 RSA key",
    "pin": "74657374",
    "p11k_hex": "...",
    "expected_entry_count": 1,
    "expected_label": "test-key"
  },
  {
    "description": "wrong PIN returns BadPin",
    "pin": "77726f6e67",
    "p11k_hex": "...",
    "expected_error": "BadPin"
  },
  {
    "description": "corrupted magic returns BadMagic",
    "pin": "74657374",
    "p11k_hex": "...",
    "expected_error": "BadMagic"
  }
]
```

**Do not fabricate these vectors.** Produce each `p11k_hex` from an external
tool (openssl, Python cryptography library, or a standalone Rust binary that
is separate from the code under test) and record the expected result. If you
cannot produce reference vectors externally, file a `bd human` issue:

```bash
bd human <keystore_issue_id> \
  --message="Need externally-produced .p11k framing vectors for test-vectors/p11k_framing.json. See BUILD.md s.Test Vector Policy."
```

---

## Build Order and Subagent Strategy

Execute in this order, using subagents as indicated:

### Phase 1: Scaffold (sequential -- everything depends on this)

1. Claim scaffold issue: `bd update <scaffold_id> --claim`
2. Create `Cargo.toml`, `build.rs`, empty `src/lib.rs` (with a single
   `#[no_mangle] pub extern "C" fn C_GetFunctionList() -> *const () { std::ptr::null() }`)
3. Verify: `cargo build --release 2>&1` -- must exit 0
4. Close scaffold issue: `bd close <scaffold_id>`

### Phase 2: Core modules (spawn 3 parallel subagents)

**Subagent A -- keystore + test vectors:**
- Implement `src/keystore.rs`
- Embed PBKDF2 and AES-GCM test vectors
- Write `tests/keystore_tests.rs`
- Run `cargo test keystore` -- must pass
- Run `cargo test --test keystore_tests` -- must pass
- Update keystore issue in-progress then close

**Subagent B -- usb_watch:**
- Implement `src/usb_watch.rs` with `MockUsbSource` for testing
- Write unit tests inline in the module
- Run `cargo test usb_watch` -- must pass
- Close usb_watch issue

**Subagent C -- token state machine:**
- Implement `src/token.rs`
- Write unit tests for all transitions
- Run `cargo test token` -- must pass
- Close token issue

Wait for all 3 subagents to complete before proceeding.

### Phase 3: Ops (one subagent, depends on keystore and token)

- Implement `src/ops.rs`
- Embed NIST CAVP vectors or file `bd human` if unavailable
- Write ops tests using only KAT (known-answer tests)
- Run `cargo test ops` -- must pass
- Close ops issue

### Phase 4: PKCS#11 ABI (depends on all of Phase 2 + Phase 3)

- Implement `src/lib.rs` -- wire up all C exports to token/ops
- Run `cargo build --release`
- Verify exports: `nm -D target/release/libusb_hsm.so | grep -c 'T C_'` must be >= 20
- Verify with pkcs11-tool: `pkcs11-tool --module target/release/libusb_hsm.so --list-mechanisms`
- Close lib issue

### Phase 5: Integration tests (spawn 2 parallel subagents)

**Subagent D -- PKCS#11 conformance:**
- Write `tests/pkcs11_conformance.rs`
- Tests: C_GetFunctionList returns non-null, C_Initialize returns CKR_OK,
  C_GetSlotList returns at least one slot, C_GetSlotInfo on slot 0 succeeds
- No USB required; just the module loaded cold

**Subagent E -- Full USB flow:**
- Write `tests/integration.rs`
- Use `tempfile::TempDir` as simulated USB mount
- Drive `UsbWatcher` with mock events
- Full flow: create keystore -> mount -> login -> sign -> verify (openssl) -> unmount -> assert zeroize
- The sign output MUST be verified by invoking `openssl dgst -verify` as an
  external subprocess using the public key extracted from the DER independently

Wait for both, then: `cargo test` -- full suite must pass.

---

## Quality Gates

Run these in order. Do not proceed past a failing gate.

```bash
# 1. No compiler warnings
cargo build --release 2>&1 | grep -c "^warning" && echo "FAIL: warnings found" || echo "OK"

# 2. All tests pass
cargo test 2>&1 | tail -5

# 3. No unsafe without comment
grep -rn "unsafe" src/ | grep -v "// SAFETY:" && echo "FAIL: undocumented unsafe" || echo "OK"

# 4. No CKR_GENERAL_ERROR catch-all without comment
grep -n "CKR_GENERAL_ERROR" src/ | grep -v "UNREACHABLE" && echo "FAIL: unadorned CKR_GENERAL_ERROR" || echo "OK"

# 5. PKCS#11 module loads
pkcs11-tool --module target/release/libusb_hsm.so --list-slots

# 6. No key bytes in memory after drop (zeroize test)
cargo test zeroize -- --nocapture

# 7. Address sanitizer clean
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu 2>&1 | tail -10
```

Gate 7 requires nightly. If nightly is not installed, file a `bd human` issue
rather than skipping it.

---

## Test Integrity Enforcement Rules

These rules apply to every test in this project, no exceptions:

### Prohibited patterns

1. **Self-referential round-trip as correctness proof:**
   ```rust
   // FORBIDDEN:
   let ct = encrypt(key, msg);
   let pt = decrypt(key, ct);
   assert_eq!(pt, msg);  // proves nothing about correctness
   ```

2. **Using the code under test as its own oracle:**
   ```rust
   // FORBIDDEN:
   let sig = sign(key, msg);
   let ok = verify(pubkey, msg, &sig);
   assert!(ok);  // only proves internal consistency, not correctness
   ```

3. **Hardcoded expected values computed by the same function:**
   ```rust
   // FORBIDDEN: running the function once, pasting output as expected
   let result = my_pbkdf2(pass, salt, 1000, 32);
   assert_eq!(result, hex!("a1b2c3..."));  // if a1b2c3 was generated by this function, it's circular
   ```

### Required patterns

1. **Known-answer tests against external vectors:**
   ```rust
   // REQUIRED:
   let vectors: Vec<Pbkdf2Vector> = serde_json::from_str(include_str!("../test-vectors/pbkdf2_sha256.json")).unwrap();
   for v in &vectors {
       let dk = pbkdf2_hmac_sha256(&v.password, &v.salt, v.iterations, v.dklen);
       assert_eq!(dk, v.dk, "vector {} failed", v.id);
   }
   ```

2. **Cross-validation with an independent implementation:**
   ```rust
   // REQUIRED for integration sign test:
   let sig = my_sign(key, msg);
   // Verify with openssl as external oracle:
   let status = Command::new("openssl")
       .args(["dgst", "-sha256", "-verify", "pubkey.pem", "-signature", "sig.bin", "msg.bin"])
       .status().unwrap();
   assert!(status.success());
   ```

3. **Halting on missing vectors:**
   If a test vector file is missing or empty, the test must **fail with a clear
   error message**, not pass vacuously. Use:
   ```rust
   let vectors: Vec<_> = load_vectors();
   assert!(!vectors.is_empty(), "test vector file is empty -- refusing to pass vacuously");
   ```

---

## p11-kit Module Config

Create `p11kit/usb-hsm.module`:

```ini
[p11-kit-module]
module: /usr/local/lib/usb-hsm/libusb_hsm.so
description: USB HSM soft token
managed: yes
priority: 5
```

---

## Security Notes to Encode as Comments

Add these as module-level doc comments in the relevant files:

**`src/keystore.rs`:**
```
/// # Security Model
/// The .p11k keystore is encrypted at rest on the USB with AES-256-GCM.
/// The key is derived from a user PIN via PBKDF2-HMAC-SHA256 with at least
/// 200,000 iterations (production) to resist brute-force.
/// Decrypted key bytes are mlock(2)'d to prevent paging to swap.
/// On drop, all key bytes are zeroized via the `zeroize` crate.
///
/// # Threat Model
/// Protects against: theft of machine (without USB), theft of USB (without PIN),
/// offline disk forensics.
/// Does NOT protect against: root-level in-memory attack on a running machine.
/// The USB is a possession factor only.
```

**`src/usb_watch.rs`:**
```
/// # Security Note
/// This module watches udev for block device events. It does NOT verify that
/// the mounted filesystem belongs to a specific USB device -- any filesystem
/// containing a .p11k file at its root will be treated as a token.
/// In environments with multiple USB devices, only the first .p11k found
/// is used. Administrators should use udev rules to restrict which devices
/// are accepted.
```

---

## Acceptance Criteria (Final Checklist)

Before closing the last issue, every item below must be true:

- [ ] `cargo build --release` exits 0 with zero warnings
- [ ] `cargo test` exits 0; all tests pass
- [ ] `test-vectors/p11k_framing.json` is non-empty and all framing tests run against it
- [ ] Framing tests include: valid load, wrong PIN -> BadPin, corrupted magic -> BadMagic
- [ ] `pkcs11-tool --module target/release/libusb_hsm.so --list-slots` exits 0
- [ ] `nm -D target/release/libusb_hsm.so | grep 'T C_'` shows >= 20 exported symbols
- [ ] Zeroize test confirms key bytes absent from memory after drop
- [ ] No undocumented `unsafe` blocks in `src/`
- [ ] No unadorned `CKR_GENERAL_ERROR` in `src/`
- [ ] Integration test: sign output verified by `openssl dgst -verify` as external oracle
- [ ] ops tests include: wrong mechanism -> CKR_MECHANISM_INVALID; key type mismatch -> CKR_KEY_TYPE_INCONSISTENT
- [ ] `bd stats` shows 0 open issues OR only `bd human` issues awaiting operator input
- [ ] All completed issues are closed with `bd close`

---

## Beads Session Close Protocol

When all work is done, run:

```bash
bd close <id1> <id2> ...   # close all completed issues in one command
bd stats                    # verify 0 open non-human issues
```

Do not say "done" until `bd stats` confirms this.
