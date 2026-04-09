/// PKCS#11 C ABI entry points for the usb-hsm soft token.
///
/// C_GetFunctionList is the sole entry point needed by p11-kit and pkcs11-tool.
/// All other functions are reached through the CK_FUNCTION_LIST it returns.
pub mod key_parser;
pub mod keystore;
pub mod manifest;
pub mod ops;
pub mod token;
pub mod usb_watch;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;

use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_PTR, CK_BBOOL, CK_BYTE_PTR, CK_C_INITIALIZE_ARGS,
    CK_C_INITIALIZE_ARGS_PTR, CK_FLAGS, CK_FUNCTION_LIST,
    CK_INFO, CK_MECHANISM_INFO, CK_MECHANISM_PTR, CK_MECHANISM_TYPE,
    CK_NOTIFY, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV,
    CK_RSA_PKCS_OAEP_PARAMS, CK_RSA_PKCS_PSS_PARAMS,
    CK_SESSION_HANDLE, CK_SESSION_INFO, CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG,
    CK_ULONG_PTR, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VERSION, CK_VOID_PTR,
    CKA_CLASS, CKA_DECRYPT, CKA_ENCRYPT, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE,
    CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_VERIFY,
    CKF_DECRYPT, CKF_ENCRYPT, CKF_LOGIN_REQUIRED, CKF_OS_LOCKING_OK, CKF_REMOVABLE_DEVICE,
    CKF_RNG, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKF_SIGN, CKF_TOKEN_INITIALIZED,
    CKF_TOKEN_PRESENT, CKF_USER_PIN_INITIALIZED, CKF_VERIFY, CKF_WRITE_PROTECTED,
    CKG_MGF1_SHA256,
    CKK_EC, CKK_ML_DSA, CKK_ML_KEM, CKK_RSA,
    CKM_EC_KEY_PAIR_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ML_DSA, CKM_ML_KEM,
    CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS,
    CKM_SHA256,
    CKC_X_509, CKO_CERTIFICATE, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
    CKA_CERTIFICATE_TYPE, CKA_VALUE,
    CKA_EC_PARAMS, CKA_EC_POINT, CKA_MODULUS, CKA_PUBLIC_EXPONENT,
    CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL,
    CKR_CANT_LOCK, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED, CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID, CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK,
    CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID,
    CKR_SLOT_ID_INVALID, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_NOT_PRESENT, CKR_USER_TYPE_INVALID,
    CKS_RO_PUBLIC_SESSION, CKS_RO_USER_FUNCTIONS, CKS_RW_PUBLIC_SESSION, CKS_RW_USER_FUNCTIONS,
    CKU_USER,
    CK_FALSE, CK_TRUE, CK_UNAVAILABLE_INFORMATION,
    CKZ_DATA_SPECIFIED,
};

use keystore::KeyType;
use ops::OpsError;
use token::Token;
use usb_watch::{UsbEvent, UsbWatcher};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// All token slots, indexed by `CK_SLOT_ID` (i.e. `slots[slot_id]`).
///
/// Starts with a single slot in `Absent` state so that `C_GetSlotList(FALSE)`
/// always returns at least one slot.  The USB dispatcher replaces the entire
/// Vec on each mount event -- one `Arc<Token>` per `.p11k` file found on the
/// drive, sorted alphabetically so slot IDs are deterministic.
///
/// Protected by a `RwLock` because mount/unmount events (write-lock, rare)
/// must not race with concurrent PKCS#11 calls (read-lock, frequent).
fn slots() -> &'static parking_lot::RwLock<Vec<Arc<Token>>> {
    static SLOTS: OnceLock<parking_lot::RwLock<Vec<Arc<Token>>>> = OnceLock::new();
    SLOTS.get_or_init(|| parking_lot::RwLock::new(vec![Arc::new(Token::new())]))
}

/// Return the `Arc<Token>` for `slot_id`, or `None` if the slot ID is out of range.
fn get_slot(slot_id: CK_SLOT_ID) -> Option<Arc<Token>> {
    let guard = slots().read();
    guard.get(slot_id as usize).cloned()
}


struct SessionEntry {
    /// The slot that owns this session (set at C_OpenSession time).
    /// Required so that session-scoped operations (C_Login, C_Sign, ...) can
    /// dispatch to the correct Token without searching all slots.
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    op: Option<OpCtx>,
}

enum OpCtx {
    FindObjects { results: Vec<CK_OBJECT_HANDLE>, pos: usize },
    Sign { key_handle: CK_OBJECT_HANDLE, mechanism: CK_MECHANISM_TYPE },
    Verify { key_handle: CK_OBJECT_HANDLE, mechanism: CK_MECHANISM_TYPE },
    Encrypt { key_handle: CK_OBJECT_HANDLE, mechanism: CK_MECHANISM_TYPE },
    Decrypt { key_handle: CK_OBJECT_HANDLE, mechanism: CK_MECHANISM_TYPE },
}

// ---------------------------------------------------------------------------
// Session state split: WHY THERE ARE TWO MAPS
//
// Sessions appear in TWO places:
//
//   1. token().state -> Present/LoggedIn { sessions: HashMap<CK_SESSION_HANDLE, SessionInfo> }
//      Authority for: is this handle open at all? what flags does it have?
//      Manipulated by: on_mount, on_unmount, open_session, close_session,
//                      close_all_sessions, login, logout.
//
//   2. op_state() -> HashMap<CK_SESSION_HANDLE, SessionEntry>
//      Authority for: is there an active operation (FindObjects, Sign, etc.)?
//      Manipulated by: c_open_session, c_close_session, c_close_all_sessions,
//                      c_find_objects_init, c_sign_init, c_sign, etc.
//
// INVARIANT: under normal operation a valid session handle appears in BOTH maps.
//
// EXCEPTION: after on_unmount(), token().state is Removed (sessions cleared).
// op_state may still contain stale entries. They return CKR_DEVICE_REMOVED via
// token().with_keystore() on any access attempt; they are cleared lazily.
//
// PROTOCOL for open/close:
//   Open:  alloc_session_handle() -> get_slot(slot_id).open_session(flags, handle)
//          -> op_state().lock().insert(handle, SessionEntry { slot_id, ... }).
//          If the insert is interrupted by a concurrent close, the handle is in the
//          token's map but not op_state -- a theoretical TOCTOU (bead soft_PKCS11-9m5).
//   Close: op_state().lock().remove(handle) first (reads slot_id), then
//          get_slot(slot_id).close_session(handle).
//   CloseAll: collect handles for slot from op_state, remove them, then
//             get_slot(slot_id).close_all_sessions().
//
// WHY THE SPLIT: token.rs owns the keystore and USB state machine. lib.rs is the
// PKCS#11 dispatch layer. Mixing operation context into token.rs would couple two
// independent concerns. The split is intentional; new PKCS#11 functions MUST update
// both maps in the correct order above.
// ---------------------------------------------------------------------------
fn op_state() -> &'static parking_lot::Mutex<HashMap<CK_SESSION_HANDLE, SessionEntry>> {
    static OP_STATE: OnceLock<parking_lot::Mutex<HashMap<CK_SESSION_HANDLE, SessionEntry>>> =
        OnceLock::new();
    OP_STATE.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Session objects -- ephemeral key pairs generated by C_GenerateKeyPair.
//
// Handle range: >= SESSION_OBJ_ORIGIN (0x30_0000).
// SESSION_OBJ_NEXT is a monotonically-increasing counter allocating handles.
// Objects are scoped to the creating session and destroyed on C_CloseSession.
// ---------------------------------------------------------------------------

const SESSION_OBJ_ORIGIN: CK_OBJECT_HANDLE = 0x30_0000;
static SESSION_OBJ_NEXT: AtomicU64 = AtomicU64::new(0x30_0000);

// ---------------------------------------------------------------------------
// Session handle allocator -- global so handles are unique across all slots.
// ---------------------------------------------------------------------------

/// Monotonically-increasing session handle counter, shared across all slots.
///
/// Session handles must be unique within `op_state()` regardless of which slot
/// opened them; per-Token counters would risk collisions if two slots both
/// allocate handle 1.  This global counter eliminates that risk.
///
/// Starts at 1 (0 is the PKCS#11 invalid handle sentinel).
/// Wraparound at u64::MAX takes ~584,000 years at 1M sessions/sec.
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// Allocate a globally unique session handle.
fn alloc_session_handle() -> CK_SESSION_HANDLE {
    let h = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
    // Skip 0 -- reserved as the invalid handle in PKCS#11.
    if h == 0 { NEXT_SESSION.fetch_add(1, Ordering::Relaxed) } else { h }
}

// ---------------------------------------------------------------------------
// Session object handle allocator.
// ---------------------------------------------------------------------------

/// Allocate a unique handle for a new session object (ephemeral key pair).
///
/// Handles are allocated from a monotonically-increasing u64 counter starting
/// at `SESSION_OBJ_ORIGIN` (0x30_0000).  Session objects are ephemeral -- they
/// are destroyed when the creating session closes -- so the working set at any
/// instant is bounded by the number of live sessions x keys per session.
///
/// **Wraparound:** the counter wraps at u64::MAX ~= 1.8 x 10^19.  At one million
/// `C_GenerateKeyPair` calls per second, overflow takes ~584,000 years.  A
/// wrapped handle that collides with a live session object would be inserted
/// over the existing entry in `session_objs()`, destroying the older key --
/// no undefined behaviour, but data loss.  If this ever becomes a realistic
/// concern, replace the counter with a freelist allocator that reuses evicted
/// handles.
fn alloc_obj_handle() -> CK_OBJECT_HANDLE {
    SESSION_OBJ_NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Private half of a generated key pair -- held in RAM, zeroized on drop.
struct SessionPrivKey {
    session: CK_SESSION_HANDLE,
    key_type: keystore::KeyType,
    /// EC: raw 32-byte P-256 scalar; RSA: PKCS#1 DER.
    der_bytes: Zeroizing<Vec<u8>>,
    id: [u8; 16],
    label: String,
}

/// Public half of a generated key pair.
struct SessionPubKey {
    session: CK_SESSION_HANDLE,
    key_type: keystore::KeyType,
    /// EC: 65-byte X9.63 uncompressed (0x04 || x || y); RSA: n_len(4) || n || e encoding.
    pub_bytes: Vec<u8>,
    id: [u8; 16],
    label: String,
}

enum SessionObj {
    PrivKey(SessionPrivKey),
    PubKey(SessionPubKey),
}

fn session_objs() -> &'static parking_lot::Mutex<HashMap<CK_OBJECT_HANDLE, SessionObj>> {
    static SESSION_OBJS: OnceLock<parking_lot::Mutex<HashMap<CK_OBJECT_HANDLE, SessionObj>>> =
        OnceLock::new();
    SESSION_OBJS.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// USB watcher state -- started by C_Initialize, stopped by C_Finalize.
// ---------------------------------------------------------------------------

/// Owns the UsbWatcher (udev monitor thread) and the dispatcher thread that
/// translates UsbEvents into token().on_mount() / on_unmount() calls.
struct WatcherState {
    watcher: UsbWatcher,
    dispatcher: Option<std::thread::JoinHandle<()>>,
}

// SAFETY: UsbWatcher is Send (all fields -- crossbeam Receiver/Sender and
// JoinHandle -- are Send). WatcherState is therefore also Send.
// The Mutex below ensures only one thread accesses WatcherState at a time.
unsafe impl Send for WatcherState {}

fn watcher_state() -> &'static parking_lot::Mutex<Option<WatcherState>> {
    static WATCHER_STATE: OnceLock<parking_lot::Mutex<Option<WatcherState>>> = OnceLock::new();
    WATCHER_STATE.get_or_init(|| parking_lot::Mutex::new(None))
}

// ---------------------------------------------------------------------------
// Object handle encoding
// ---------------------------------------------------------------------------

/// PKCS#11 s.6.7.3: a handle of 0 is `CK_INVALID_HANDLE` (never assigned to
/// any object). We encode a key-list index as `index + HANDLE_ORIGIN` so that
/// index 0 maps to handle 1, ensuring handle 0 is never issued. Every decode
/// site subtracts `HANDLE_ORIGIN` to recover the original index. Changing this
/// value without updating every encode and decode site silently breaks all
/// handle lookups.
const HANDLE_ORIGIN: CK_OBJECT_HANDLE = 1;

/// Certificate object handles start at `CERT_HANDLE_ORIGIN` to avoid colliding
/// with key handles (which occupy `1..CERT_HANDLE_ORIGIN - 1`). The gap is large
/// enough for any realistic keystore. A handle `>= CERT_HANDLE_ORIGIN` is a
/// `CKO_CERTIFICATE` object; `< CERT_HANDLE_ORIGIN` (and non-zero) is a
/// `CKO_PRIVATE_KEY` object. Passing a cert handle to `C_SignInit` or similar
/// correctly returns `CKR_KEY_HANDLE_INVALID` because the derived index exceeds
/// `entries.len()`.
const CERT_HANDLE_ORIGIN: CK_OBJECT_HANDLE = 0x10_0000;

/// Token `CKO_PUBLIC_KEY` handles for PQC key types (ML-DSA, ML-KEM).  Only
/// emitted for keystore entries that carry a `pub_bytes` field.  The index
/// encoded by this handle is the same as the private key index so that both
/// handle ranges address the same `KeyEntry`.
const PUB_KEY_HANDLE_ORIGIN: CK_OBJECT_HANDLE = 0x20_0000;

// Handle space layout -- required ordering for all dispatch correctness:
//   [HANDLE_ORIGIN,         CERT_HANDLE_ORIGIN)     -- CKO_PRIVATE_KEY  (keystore entries)
//   [CERT_HANDLE_ORIGIN,    PUB_KEY_HANDLE_ORIGIN)  -- CKO_CERTIFICATE  (keystore entries with cert_der)
//   [PUB_KEY_HANDLE_ORIGIN, SESSION_OBJ_ORIGIN)     -- CKO_PUBLIC_KEY   (PQC keystore entries with pub_bytes)
//   [SESSION_OBJ_ORIGIN,    u64::MAX)               -- session objects   (C_GenerateKeyPair output)
//
// Every handle-range dispatch site checks in DESCENDING order (session first,
// then pub key, then cert, then key) so that the highest range is matched first.
// Changing any of these constants requires auditing ALL dispatch sites:
//   c_get_attribute_value, init_op, c_sign, c_verify, c_encrypt, c_decrypt,
//   c_find_objects_init.
const _: () = assert!(
    HANDLE_ORIGIN < CERT_HANDLE_ORIGIN,
    "handle range invariant violated: key handles must lie below cert handles",
);
const _: () = assert!(
    CERT_HANDLE_ORIGIN < PUB_KEY_HANDLE_ORIGIN,
    "handle range invariant violated: cert handles must lie below pub-key handles",
);
const _: () = assert!(
    PUB_KEY_HANDLE_ORIGIN < SESSION_OBJ_ORIGIN,
    "handle range invariant violated: pub-key handles must lie below session-object handles",
);

// ---------------------------------------------------------------------------
// Mechanisms
// ---------------------------------------------------------------------------

// CKM_RSA_PKCS is intentionally absent from both lists below.
//
// wolfcrypt's sign_pkcs1v15_with_digest hashes the input internally before
// applying PKCS#1 v1.5 padding. PKCS#11 callers are required (spec s.11.11)
// to pre-hash and DER-encode a DigestInfo block before calling C_Sign; if we
// advertise CKM_RSA_PKCS, those callers will pass a pre-formed DigestInfo and
// wolfcrypt will hash it again -- producing a silent wrong signature that
// verifies under no standard key. CKR_MECHANISM_INVALID is better than a
// silent malformation.
//
// To restore CKM_RSA_PKCS: wolfssl-rs must expose wc_RsaSSL_Sign (or
// equivalent) -- a path that pads the caller-supplied DigestInfo block without
// hashing it. Any test for this mechanism must verify against an independent
// oracle (e.g. openssl rsautl -raw), never a round-trip through this token.
const MECHANISMS: &[CK_MECHANISM_TYPE] = &[
    CKM_RSA_PKCS_PSS,
    CKM_RSA_PKCS_OAEP,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_ML_DSA,
    // CKM_HASH_ML_DSA (FIPS 204 §5.4 HashML-DSA.Sign) is intentionally absent.
    // The wolfcrypt high-level Rust API (`MlDsa65SigningKey`) only exposes
    // `wc_dilithium_sign_msg` (ML-DSA.Sign, FIPS 204 §5.3 -- message hashed
    // internally with SHAKE256). The HashML-DSA variant (`sign_ctx_hash` /
    // `wc_dilithium_sign_ctx_hash`) exists in wolfcrypt-wrapper but is not
    // exposed in the type-safe `wolfcrypt` crate. Advertising a mechanism that
    // returns CKR_MECHANISM_INVALID is a direct PKCS#11 conformance violation.
    // Track re-adding this in a future wolfssl-rs update (soft_PKCS11-alk6).
    CKM_ML_KEM,
];

// PKCS#11 s.11.13/s.11.14: CKM_RSA_PKCS_OAEP and CKM_ML_KEM are
// encryption-only mechanisms (CKF_ENCRYPT|CKF_DECRYPT). They must NOT appear
// in the allowed-mechanism list for C_SignInit or C_VerifyInit; attempting to
// sign with OAEP or ML_KEM is always CKR_MECHANISM_INVALID per spec.
// CKM_RSA_PKCS is absent for the same reason described above MECHANISMS.
const SIGN_VERIFY_MECHANISMS: &[CK_MECHANISM_TYPE] =
    &[CKM_RSA_PKCS_PSS, CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ML_DSA];

fn mechanism_info(mech: CK_MECHANISM_TYPE) -> Option<CK_MECHANISM_INFO> {
    match mech {
        CKM_RSA_PKCS_PSS => Some(CK_MECHANISM_INFO {
            ulMinKeySize: 512,
            ulMaxKeySize: 4096,
            flags: CKF_SIGN | CKF_VERIFY,
        }),
        CKM_RSA_PKCS_OAEP => Some(CK_MECHANISM_INFO {
            ulMinKeySize: 512,
            ulMaxKeySize: 4096,
            flags: CKF_ENCRYPT | CKF_DECRYPT,
        }),
        CKM_ECDSA | CKM_ECDSA_SHA256 => Some(CK_MECHANISM_INFO {
            ulMinKeySize: 256,
            ulMaxKeySize: 521,
            flags: CKF_SIGN | CKF_VERIFY,
        }),
        CKM_ML_DSA => Some(CK_MECHANISM_INFO {
            ulMinKeySize: 44,
            ulMaxKeySize: 87,
            flags: CKF_SIGN | CKF_VERIFY,
        }),
        CKM_ML_KEM => Some(CK_MECHANISM_INFO {
            ulMinKeySize: 512,
            ulMaxKeySize: 1024,
            flags: CKF_ENCRYPT | CKF_DECRYPT,
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fill_padded(buf: &mut [u8], s: &str) {
    buf.iter_mut().for_each(|b| *b = b' ');
    let src = s.as_bytes();
    let n = src.len().min(buf.len());
    buf[..n].copy_from_slice(&src[..n]);
}

/// PKCS#11 two-call pattern: fill `attr` with `data`.
/// NULL pValue -> set length only (returns CKR_OK).
/// Non-null but undersized pValue -> sets ulValueLen to the *required* length and
/// returns CKR_BUFFER_TOO_SMALL (s.11.7: callers rely on this to resize and retry;
/// CK_UNAVAILABLE_INFORMATION would break the two-call pattern).
unsafe fn write_attr(attr: &mut CK_ATTRIBUTE, data: &[u8]) -> CK_RV {
    if attr.pValue.is_null() {
        attr.ulValueLen = data.len() as CK_ULONG;
        return CKR_OK;
    }
    let buf_len = attr.ulValueLen as usize;
    // Always write the required length before the size check so the caller can
    // resize its buffer on CKR_BUFFER_TOO_SMALL.
    attr.ulValueLen = data.len() as CK_ULONG;
    if buf_len < data.len() {
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), attr.pValue as *mut u8, data.len());
    CKR_OK
}

fn ops_err(e: OpsError) -> CK_RV {
    match e {
        OpsError::MechanismInvalid => CKR_MECHANISM_INVALID,
        OpsError::KeyTypeInconsistent => CKR_KEY_TYPE_INCONSISTENT,
        // CKM_ECDSA prehash must be exactly 32 bytes for P-256 (SHA-256 output).
        // Wrong-length input from the caller maps to CKR_DATA_LEN_RANGE per s.11.11.
        OpsError::DataLenRange => CKR_DATA_LEN_RANGE,
        // UNREACHABLE: wolfcrypt internal failures propagate as Crypto; map to general error.
        OpsError::Crypto(_) => CKR_GENERAL_ERROR,
    }
}

/// Max output size for the NULL-pointer length-query case.
///
/// Every mechanism in `SIGN_VERIFY_MECHANISMS` must have an explicit arm.
/// The `_ => 512` fallback exists only for defence-in-depth: callers that
/// somehow reach it get a conservatively large buffer rather than a silent
/// under-allocation. Adding a new mechanism without a matching arm here is
/// tracked in bead soft_PKCS11-xuc; an exhaustive match or compile-time
/// assertion should enforce this invariant in the future.
fn sign_max_output(mechanism: CK_MECHANISM_TYPE) -> CK_ULONG {
    match mechanism {
        CKM_RSA_PKCS_PSS => 512, // RSA-4096 max
        // PKCS#11 s.2.3.1: raw r||s, each exactly 32 bytes for P-256 -> 64 bytes fixed.
        CKM_ECDSA | CKM_ECDSA_SHA256 => 64,
        // ML-DSA-65 (FIPS 204): fixed 3309-byte signature.
        // required_key_type constrains CKM_ML_DSA to MlDsa65 so 3309 is exact.
        CKM_ML_DSA => 3309,
        // Fallback: 512 bytes covers RSA-4096, the largest key type this library
        // supports. New mechanisms with signatures larger than 512 bytes MUST add
        // an explicit arm above -- the fallback silently over-allocates for small
        // signatures and under-allocates for hypothetical large ones.
        //
        // debug_assert! panics in debug/test builds if this arm is reached, catching
        // a missing explicit arm during development. In release builds it is a no-op
        // and 512 is returned as a conservative safe maximum.
        // This branch is unreachable in practice: init_op validates the mechanism
        // against SIGN_VERIFY_MECHANISMS before any OpCtx::Sign is stored, so all
        // reaching mechanisms are in {CKM_RSA_PKCS_PSS, CKM_ECDSA,
        // CKM_ECDSA_SHA256} -- all covered above.
        _ => {
            debug_assert!(
                false,
                "sign_max_output called with unrecognized mechanism {mechanism:#x}; \
                 add an explicit arm for this mechanism in sign_max_output()"
            );
            512
        }
    }
}

// ---------------------------------------------------------------------------
// USB watcher helpers
// ---------------------------------------------------------------------------

/// Look up the `.p11k` keystore files listed in the manifest at
/// `<mount_point>/<manifest_name>`.
///
/// This replaces the old directory-scan approach: a single `stat(2)` on the
/// manifest file is sufficient to determine whether the drive is a token drive.
/// Drives without the manifest file are silently ignored (strict-mode opt-in).
///
/// The manifest lists one `<filename> <label>` per line; line order determines
/// slot assignment. Each listed file is validated to exist before being returned.
/// Filenames containing path separators are rejected to prevent path traversal.
///
/// Returns an empty Vec if the manifest is absent, unreadable, or lists no
/// valid `.p11k` files.
fn find_p11k_from_manifest(mount_point: &std::path::Path, manifest_name: &str) -> Vec<std::path::PathBuf> {
    let manifest_path = mount_point.join(manifest_name);
    let content = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            // The file exists but could not be read (permissions, I/O error, etc.).
            // Log a warning so the user knows why the drive was silently ignored.
            // (soft_PKCS11-zrxe)
            log::warn!(
                "usb-hsm: could not read manifest at {}: {e}; ignoring drive",
                manifest_path.display()
            );
            return Vec::new();
        }
    };
    let entries = crate::manifest::parse_manifest(&content);
    if entries.is_empty() {
        log::warn!(
            "usb-hsm: manifest at {} is empty or has no valid entries; ignoring drive",
            manifest_path.display()
        );
        return Vec::new();
    }
    let mut result = Vec::new();
    for entry in &entries {
        // Accept only a plain filename with no path components. Checking
        // Path::file_name() == Some(filename) rejects "..", ".", and any
        // name containing "/" or "\\" in a single idiomatic test. The
        // previous check for '/' and '\\' did not catch "..". (soft_PKCS11-o7ph)
        if std::path::Path::new(&entry.filename).file_name()
            != Some(std::ffi::OsStr::new(&entry.filename))
        {
            log::warn!(
                "usb-hsm: manifest entry '{}' is not a plain filename; skipping",
                entry.filename
            );
            continue;
        }
        let p11k_path = mount_point.join(&entry.filename);
        if p11k_path.exists() {
            result.push(p11k_path);
        } else {
            log::warn!(
                "usb-hsm: manifest entry '{}' not found at {}; skipping",
                entry.filename,
                p11k_path.display()
            );
        }
    }
    result
}

/// Start the USB watcher background system: a udev monitor thread and a
/// dispatcher thread. Both threads run until `stop_usb_watcher` is called.
///
/// Failure is non-fatal: if udev is not available (container environments,
/// CI, test hosts), hotplug detection is simply disabled. Developers can
/// still use `test_mount`/`test_unmount` to load keystores explicitly.
///
/// # Timing note
/// The udev 'block' subsystem 'add' event fires when the kernel creates the
/// block device node, which may precede the filesystem being mounted in
/// /proc/mounts. UsbWatcher handles this race with a pending-retry loop: it
/// keeps a map of unresolved block devices and re-checks /proc/mounts every
/// poll tick (100 ms) for up to PENDING_TIMEOUT (10 s) before giving up.
/// No inotify watch on /proc/mounts is needed.
fn start_usb_watcher() {
    let watcher = match UsbWatcher::start() {
        Ok(w) => w,
        Err(e) => {
            // Not fatal: log and continue without hotplug support.
            log::warn!("usb-hsm: USB watcher failed to start: {e}; hotplug detection disabled");
            return;
        }
    };

    // Clone the receiver so the dispatcher thread can own it.
    // UsbWatcher retains the original; both sides share the same channel.
    let rx = watcher.events().clone();

    let dispatcher = std::thread::Builder::new()
        .name("usb-hsm-hotplug".into())
        .spawn(move || {
            // Iterate until the channel closes (UsbWatcher::stop() drops the
            // sender, which terminates this iterator cleanly).
            for event in rx.iter() {
                match event {
                    UsbEvent::Mounted { mount_point, manifest_name } => {
                        // Read the .usb-hsm manifest to find the listed .p11k files.
                        // If the manifest is absent this is not a token drive; ignore it.
                        let p11k_paths = find_p11k_from_manifest(&mount_point, &manifest_name);
                        if !p11k_paths.is_empty() {
                            // Transition any existing slots for this mount to Removed
                            // (handles the re-plug case: a mount event can arrive
                            // before the corresponding unmount fires).
                            {
                                let guard = slots().read();
                                for t in guard.iter() {
                                    if t.is_at_mount(&mount_point) {
                                        t.on_unmount();
                                    }
                                }
                            }
                            // One slot per .p11k file, alphabetically ordered.
                            // Slot 0 = first file, slot 1 = second, etc.
                            let new_slots: Vec<Arc<Token>> = p11k_paths
                                .iter()
                                .map(|p11k_path| {
                                    let t = Arc::new(Token::new());
                                    t.on_mount(&mount_point, p11k_path);
                                    t
                                })
                                .collect();
                            *slots().write() = new_slots;
                        }
                    }
                    UsbEvent::Unmounted(mount_point) => {
                        // Only zeroize slots whose mount_point matches the removed
                        // drive. is_at_mount() prevents an unrelated USB device
                        // removal from destroying active key material (soft_PKCS11-3hh).
                        let guard = slots().read();
                        for t in guard.iter() {
                            if t.is_at_mount(&mount_point) {
                                t.on_unmount();
                            }
                        }
                    }
                }
            }
        })
        .ok(); // spawn failure leaves hotplug disabled but is not fatal

    *watcher_state().lock() = Some(WatcherState { watcher, dispatcher });
}

/// Stop the USB watcher. Signals the udev monitor thread, which drops the
/// channel sender, causing the dispatcher thread to exit its iterator and
/// terminate. Joins both threads before returning.
///
/// Called from C_Finalize; safe to call if start_usb_watcher() was never
/// called or failed silently.
fn stop_usb_watcher() {
    if let Some(state) = watcher_state().lock().take() {
        // Stop the udev monitor thread first; it will drop the channel sender,
        // which signals the dispatcher thread to exit.
        state.watcher.stop();
        // Join the dispatcher thread for a clean shutdown.
        if let Some(handle) = state.dispatcher {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// C_Initialize / C_Finalize / C_GetInfo
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_initialize(p_init_args: CK_VOID_PTR) -> CK_RV {
    // Validate CK_C_INITIALIZE_ARGS before touching global state (PKCS#11 §11.4).
    if !p_init_args.is_null() {
        let args: &CK_C_INITIALIZE_ARGS = &*(p_init_args as CK_C_INITIALIZE_ARGS_PTR);
        // pReserved must be NULL per spec; any other value is an error.
        if !args.pReserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // Mutex callbacks must be either all-NULL or all-non-NULL.
        let cb_null = [
            args.CreateMutex.is_none(),
            args.DestroyMutex.is_none(),
            args.LockMutex.is_none(),
            args.UnlockMutex.is_none(),
        ];
        let all_null = cb_null.iter().all(|&n| n);
        let all_set = cb_null.iter().all(|&n| !n);
        if !all_null && !all_set {
            return CKR_ARGUMENTS_BAD;
        }
        // This library always uses OS-level locking (parking_lot). If the caller
        // supplies custom mutex functions without also setting CKF_OS_LOCKING_OK,
        // we cannot honour the contract and must reject.
        if all_set && (args.flags & CKF_OS_LOCKING_OK == 0) {
            return CKR_CANT_LOCK;
        }
        // If CKF_OS_LOCKING_OK is set (with or without callbacks), or if no
        // callbacks are supplied, our internal OS locking satisfies the contract.
    }
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    let _ = slots();
    let _ = op_state();
    // Start USB hotplug detection. Non-fatal if udev is unavailable.
    start_usb_watcher();
    CKR_OK
}

unsafe extern "C" fn c_finalize(_p_reserved: CK_VOID_PTR) -> CK_RV {
    if !INITIALIZED.swap(false, Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    op_state().lock().clear();
    stop_usb_watcher();
    CKR_OK
}

unsafe extern "C" fn c_get_info(p_info: *mut CK_INFO) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let info = &mut *p_info;
    info.cryptokiVersion = CK_VERSION { major: 2, minor: 40 };
    fill_padded(&mut info.manufacturerID, "usb-hsm");
    info.flags = 0;
    fill_padded(&mut info.libraryDescription, "USB HSM PKCS#11 soft token");
    info.libraryVersion = CK_VERSION { major: 0, minor: 1 };
    CKR_OK
}

// ---------------------------------------------------------------------------
// C_GetSlotList / C_GetSlotInfo / C_GetTokenInfo
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_get_slot_list(
    token_present: CK_BBOOL,
    p_slot_list: *mut CK_SLOT_ID,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // Collect the slot IDs that satisfy the token_present filter.
    // token_present=CK_FALSE -> all slots regardless of state.
    // token_present=CK_TRUE  -> only slots with a token present (Present or LoggedIn).
    let matching: Vec<CK_SLOT_ID> = {
        let guard = slots().read();
        guard
            .iter()
            .enumerate()
            .filter(|(_, t)| token_present != CK_TRUE || t.get_token_present())
            .map(|(i, _)| i as CK_SLOT_ID)
            .collect()
    };
    let count = matching.len() as CK_ULONG;
    if p_slot_list.is_null() {
        // Query mode: just report how many slots match.
        *pul_count = count;
    } else {
        if *pul_count < count {
            *pul_count = count;
            return CKR_BUFFER_TOO_SMALL;
        }
        for (i, &sid) in matching.iter().enumerate() {
            *p_slot_list.add(i) = sid;
        }
        *pul_count = count;
    }
    CKR_OK
}

unsafe extern "C" fn c_get_slot_info(slot_id: CK_SLOT_ID, p_info: *mut CK_SLOT_INFO) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SLOT_ID_INVALID,
    };
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let info = &mut *p_info;
    // Slot description includes the slot number so multi-slot drives are distinguishable.
    fill_padded(&mut info.slotDescription, &format!("USB HSM slot {slot_id}"));
    fill_padded(&mut info.manufacturerID, "usb-hsm");
    info.flags = CKF_REMOVABLE_DEVICE
        | if tok.get_token_present() { CKF_TOKEN_PRESENT } else { 0 };
    info.hardwareVersion = CK_VERSION { major: 0, minor: 0 };
    info.firmwareVersion = CK_VERSION { major: 0, minor: 0 };
    CKR_OK
}

unsafe extern "C" fn c_get_token_info(slot_id: CK_SLOT_ID, p_info: *mut CK_TOKEN_INFO) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SLOT_ID_INVALID,
    };
    if !tok.get_token_present() {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let info = &mut *p_info;
    // Token label includes slot number so multi-slot drives are distinguishable.
    fill_padded(&mut info.label, &format!("USB HSM Token {slot_id}"));
    fill_padded(&mut info.manufacturerID, "usb-hsm");
    fill_padded(&mut info.model, "soft-token");
    fill_padded(&mut info.serialNumber, "00000001");
    // CKF_WRITE_PROTECTED (PKCS#11 s.6.7): keys cannot be created or modified.
    // This flag does NOT restrict crypto operations (sign/verify/encrypt/decrypt);
    // those are read-only uses of existing key material and are permitted on both
    // read-only and read-write sessions regardless of this flag.
    //
    // CKF_LOGIN_REQUIRED: all private key operations require prior C_Login.
    // This is enforced by tok.with_keystore() which fails in Present state.
    info.flags = CKF_RNG
        | CKF_WRITE_PROTECTED
        | CKF_LOGIN_REQUIRED
        | CKF_USER_PIN_INITIALIZED
        | CKF_TOKEN_INITIALIZED;
    info.ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
    info.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    info.ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    info.ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    info.ulMaxPinLen = 255;
    // Min PIN length matches the 6-character minimum enforced at keystore creation
    // time by usb-hsm-keygen. The PKCS#11 layer does not re-validate PIN length
    // at C_Login time (the keystore's AES-GCM authentication tag is the actual
    // PIN validator). This value informs PKCS#11 middleware when it prompts
    // users for a new PIN; it must match the creation-time policy.
    info.ulMinPinLen = 6;
    info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    info.hardwareVersion = CK_VERSION { major: 0, minor: 0 };
    info.firmwareVersion = CK_VERSION { major: 0, minor: 0 };
    fill_padded(&mut info.utcTime, "0000000000000000");
    CKR_OK
}

// ---------------------------------------------------------------------------
// C_GetMechanismList / C_GetMechanismInfo
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    p_mechanism_list: *mut CK_MECHANISM_TYPE,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if get_slot(slot_id).is_none() {
        return CKR_SLOT_ID_INVALID;
    }
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if p_mechanism_list.is_null() {
        *pul_count = MECHANISMS.len() as CK_ULONG;
    } else {
        if (*pul_count as usize) < MECHANISMS.len() {
            *pul_count = MECHANISMS.len() as CK_ULONG;
            return CKR_BUFFER_TOO_SMALL;
        }
        for (i, &m) in MECHANISMS.iter().enumerate() {
            *p_mechanism_list.add(i) = m;
        }
        *pul_count = MECHANISMS.len() as CK_ULONG;
    }
    CKR_OK
}

unsafe extern "C" fn c_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    mech_type: CK_MECHANISM_TYPE,
    p_info: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if get_slot(slot_id).is_none() {
        return CKR_SLOT_ID_INVALID;
    }
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    match mechanism_info(mech_type) {
        Some(info) => {
            *p_info = info;
            CKR_OK
        }
        None => CKR_MECHANISM_INVALID,
    }
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _p_application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SLOT_ID_INVALID,
    };
    if ph_session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // Allocate a handle that is unique across ALL slots (global counter).
    // This is necessary because op_state() is a single map keyed by handle:
    // two per-Token counters starting at 1 would collide immediately.
    let handle = alloc_session_handle();
    let rv = tok.open_session(flags, handle);
    if rv == CKR_OK {
        // NOTE: There is a theoretical TOCTOU here (bead soft_PKCS11-9m5): another
        // thread could call C_CloseSession(handle) in the window between
        // tok.open_session() releasing its write lock and this insert. That
        // would put an orphaned entry in op_state. In practice PKCS#11 callers do
        // not race open/close on the same unknown handle, and PKCS#11 s.6.7.2
        // permits single-threaded access assumptions unless CKF_OS_LOCKING_OK is
        // set (which we do not yet advertise). Tracked for future resolution.
        op_state().lock().insert(
            handle,
            SessionEntry { slot_id, flags: flags | CKF_SERIAL_SESSION, op: None },
        );
        *ph_session = handle;
    }
    rv
}

unsafe extern "C" fn c_close_session(h_session: CK_SESSION_HANDLE) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // Remove from op_state first (Close protocol: op_state before token map).
    // The slot_id tells us which token's sessions map to update.
    let slot_id = match op_state().lock().remove(&h_session) {
        Some(entry) => entry.slot_id,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    // Zeroize and remove all ephemeral keys owned by this session.
    session_objs().lock().retain(|_, obj| {
        let sess = match obj {
            SessionObj::PrivKey(pk) => pk.session,
            SessionObj::PubKey(pk) => pk.session,
        };
        sess != h_session
    });
    match get_slot(slot_id) {
        Some(tok) => tok.close_session(h_session),
        // Slot was removed (drive ejected) after the session was opened.
        // op_state and session_objs are already cleaned up above.
        None => CKR_SESSION_HANDLE_INVALID,
    }
}

unsafe extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SLOT_ID_INVALID,
    };
    // Collect the handles for this slot, then remove them from op_state.
    // Only this slot's sessions are affected; other slots are untouched.
    let closed: Vec<CK_SESSION_HANDLE> = {
        let mut guard = op_state().lock();
        let handles: Vec<_> = guard
            .iter()
            .filter(|(_, e)| e.slot_id == slot_id)
            .map(|(h, _)| *h)
            .collect();
        for h in &handles {
            guard.remove(h);
        }
        handles
    };
    // Zeroize ephemeral keys for the closed sessions.
    session_objs().lock().retain(|_, obj| {
        let sess = match obj {
            SessionObj::PrivKey(pk) => pk.session,
            SessionObj::PubKey(pk) => pk.session,
        };
        !closed.contains(&sess)
    });
    tok.close_all_sessions()
}

unsafe extern "C" fn c_get_session_info(
    h_session: CK_SESSION_HANDLE,
    p_info: *mut CK_SESSION_INFO,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let (session_flags, slot_id) = {
        match op_state().lock().get(&h_session) {
            Some(e) => (e.flags, e.slot_id),
            None => return CKR_SESSION_HANDLE_INVALID,
        }
    };
    let is_logged_in = match get_slot(slot_id) {
        Some(tok) => tok.with_keystore(|_| ()).is_ok(),
        None => false, // slot removed after session opened
    };
    let state = if is_logged_in {
        if session_flags & CKF_RW_SESSION != 0 {
            CKS_RW_USER_FUNCTIONS
        } else {
            CKS_RO_USER_FUNCTIONS
        }
    } else if session_flags & CKF_RW_SESSION != 0 {
        CKS_RW_PUBLIC_SESSION
    } else {
        CKS_RO_PUBLIC_SESSION
    };
    let info = &mut *p_info;
    info.slotID = slot_id;
    info.state = state;
    info.flags = session_flags;
    info.ulDeviceError = 0;
    CKR_OK
}

unsafe extern "C" fn c_login(
    h_session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: CK_UTF8CHAR_PTR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // This token has no Security Officer role; only CKU_USER is supported.
    if user_type != CKU_USER {
        return CKR_USER_TYPE_INVALID;
    }
    // h_session identifies which token to log into.
    //
    // h_session == 0 (CK_INVALID_HANDLE) is accepted as a slot-0 shortcut.
    // Firefox NSS calls C_Login without guarding against slot->session being
    // CK_INVALID_HANDLE in two code paths:
    //   - PK11_CheckUserPassword (lib/pk11wrap/pk11auth.c): calls C_Logout then
    //     C_Login on slot->session without an INVALID_HANDLE check.
    //   - PK11_InitPin (lib/pk11wrap/pk11auth.c): silently ignores the return
    //     value of PK11_InitToken; if C_OpenSession failed inside that call,
    //     slot->session is still 0 when C_Login is reached.
    //
    // OpenSSH (ssh-pkcs11.c) and pkcs11-tool (OpenSC) never pass h_session=0:
    // both call C_OpenSession first and only proceed to C_Login on success.
    //
    // Any non-zero handle must be present in op_state; 0 goes to slot 0.
    let slot_id: CK_SLOT_ID = if h_session == 0 {
        0
    } else {
        match op_state().lock().get(&h_session) {
            Some(e) => e.slot_id,
            None => return CKR_SESSION_HANDLE_INVALID,
        }
    };
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let pin: &[u8] = if p_pin.is_null() || ul_pin_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p_pin, ul_pin_len as usize)
    };
    tok.login(pin)
}

unsafe extern "C" fn c_logout(h_session: CK_SESSION_HANDLE) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // Use h_session to identify the target slot (same reasoning as c_login).
    let slot_id = match op_state().lock().get(&h_session) {
        Some(e) => e.slot_id,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    match get_slot(slot_id) {
        Some(tok) => tok.logout(),
        None => CKR_SESSION_HANDLE_INVALID,
    }
}

// ---------------------------------------------------------------------------
// Object enumeration
// ---------------------------------------------------------------------------

unsafe fn matches_template(
    entry: &keystore::KeyEntry,
    template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> bool {
    for i in 0..count as usize {
        let attr = &*template.add(i);
        if attr.pValue.is_null() || attr.ulValueLen == 0 {
            continue;
        }
        let val = std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
        let ok = match attr.type_ {
            CKA_CLASS => {
                if val.len() != std::mem::size_of::<CK_OBJECT_CLASS>() {
                    return false;
                }
                (val.as_ptr() as *const CK_OBJECT_CLASS).read_unaligned() == CKO_PRIVATE_KEY
            }
            CKA_KEY_TYPE => {
                if val.len() != std::mem::size_of::<CK_ULONG>() {
                    return false;
                }
                let kt = (val.as_ptr() as *const CK_ULONG).read_unaligned();
                match entry.key_type {
                    KeyType::Rsa => kt == CKK_RSA,
                    KeyType::Ec => kt == CKK_EC,
                    KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => kt == CKK_ML_DSA,
                    KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => kt == CKK_ML_KEM,
                }
            }
            CKA_LABEL => val == entry.label.as_bytes(),
            CKA_ID => val == &entry.id[..],
            CKA_TOKEN | CKA_PRIVATE | CKA_SENSITIVE | CKA_SIGN | CKA_VERIFY => {
                // CKA_VERIFY is included: private-key objects in this implementation
                // support C_VerifyInit by deriving the public key from the private key.
                val.len() == 1 && val[0] == CK_TRUE
            }
            CKA_DECRYPT => {
                // Only RSA private keys support OAEP decryption.
                let expected = if entry.key_type == KeyType::Rsa { CK_TRUE } else { CK_FALSE };
                val.len() == 1 && val[0] == expected
            }
            CKA_ENCRYPT => {
                // PKCS#11 v2.40 s.4.8 defines CKA_ENCRYPT on public key objects.
                // s.4.9 (private key common attributes) lists CKA_DECRYPT, CKA_SIGN,
                // CKA_UNWRAP -- CKA_ENCRYPT is absent. Returning FALSE is spec-conformant.
                //
                // This library stores only private key objects (no CKO_PUBLIC_KEY objects).
                // OAEP encryption works by extracting the public component from the private
                // key DER at C_EncryptInit time. An alternative -- setting CKA_ENCRYPT=TRUE
                // on private keys so that attribute-first callers find them -- is used by
                // YubiKey YKCS11 (a similar private-key-only token) but is a deliberate
                // spec deviation. We stay conformant: encrypt-capable callers locate the key
                // by label/ID (not by CKA_ENCRYPT) and let the token validate at init time.
                // (Research: soft_PKCS11-7k4; SoftHSM2 #257/#259; PKCS#11 base v2.40 s.4.8/4.9)
                val.len() == 1 && val[0] == CK_FALSE
            }
            _ => return false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Template-matching for `CKO_CERTIFICATE` objects.
///
/// Only called for entries that have `cert_der.is_some()`. Supports the
/// attributes that callers typically filter on: `CKA_CLASS`, `CKA_LABEL`,
/// `CKA_ID`, `CKA_TOKEN`, and `CKA_CERTIFICATE_TYPE`.
unsafe fn matches_cert_template(
    entry: &keystore::KeyEntry,
    template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> bool {
    for i in 0..count as usize {
        let attr = &*template.add(i);
        if attr.pValue.is_null() || attr.ulValueLen == 0 {
            continue;
        }
        let val = std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
        let ok = match attr.type_ {
            CKA_CLASS => {
                if val.len() != std::mem::size_of::<CK_OBJECT_CLASS>() {
                    return false;
                }
                (val.as_ptr() as *const CK_OBJECT_CLASS).read_unaligned() == CKO_CERTIFICATE
            }
            CKA_CERTIFICATE_TYPE => {
                if val.len() != std::mem::size_of::<CK_ULONG>() {
                    return false;
                }
                (val.as_ptr() as *const CK_ULONG).read_unaligned() == CKC_X_509
            }
            CKA_LABEL => val == entry.label.as_bytes(),
            CKA_ID => val == &entry.id[..],
            CKA_TOKEN => val.len() == 1 && val[0] == CK_TRUE,
            _ => return false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Template-matching for token `CKO_PUBLIC_KEY` objects (ML-DSA / ML-KEM).
///
/// Only called for keystore entries that have `pub_bytes.is_some()`.
/// Supports `CKA_CLASS` (must be `CKO_PUBLIC_KEY`), `CKA_KEY_TYPE`, `CKA_TOKEN`
/// (must be `CK_TRUE`), `CKA_ID`, `CKA_LABEL`, `CKA_VERIFY`, and `CKA_ENCRYPT`.
unsafe fn matches_token_pub_template(
    entry: &keystore::KeyEntry,
    template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> bool {
    for i in 0..count as usize {
        let attr = &*template.add(i);
        if attr.pValue.is_null() || attr.ulValueLen == 0 {
            continue;
        }
        let val = std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
        let ok = match attr.type_ {
            CKA_CLASS => {
                if val.len() != std::mem::size_of::<CK_OBJECT_CLASS>() {
                    return false;
                }
                (val.as_ptr() as *const CK_OBJECT_CLASS).read_unaligned() == CKO_PUBLIC_KEY
            }
            CKA_KEY_TYPE => {
                if val.len() != std::mem::size_of::<CK_ULONG>() {
                    return false;
                }
                let kt = (val.as_ptr() as *const CK_ULONG).read_unaligned();
                match entry.key_type {
                    KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => kt == CKK_ML_DSA,
                    KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => kt == CKK_ML_KEM,
                    KeyType::Rsa | KeyType::Ec => false, // no token pub-key objects for RSA/EC
                }
            }
            CKA_LABEL => val == entry.label.as_bytes(),
            CKA_ID => val == &entry.id[..],
            CKA_TOKEN => val.len() == 1 && val[0] == CK_TRUE,
            CKA_VERIFY | CKA_ENCRYPT => val.len() == 1 && val[0] == CK_TRUE,
            _ => return false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Template-matching for session `CKO_PRIVATE_KEY` objects.
///
/// Matches `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_TOKEN` (must be `CK_FALSE`),
/// `CKA_ID`, and `CKA_LABEL`.  Rejects any unrecognised attribute.
unsafe fn matches_session_priv_template(
    obj: &SessionPrivKey,
    template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> bool {
    for i in 0..count as usize {
        let attr = &*template.add(i);
        if attr.pValue.is_null() || attr.ulValueLen == 0 {
            continue;
        }
        let val =
            std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
        let ok = match attr.type_ {
            CKA_CLASS => {
                if val.len() != std::mem::size_of::<CK_OBJECT_CLASS>() {
                    return false;
                }
                (val.as_ptr() as *const CK_OBJECT_CLASS).read_unaligned() == CKO_PRIVATE_KEY
            }
            CKA_KEY_TYPE => {
                if val.len() != std::mem::size_of::<CK_ULONG>() {
                    return false;
                }
                let expected: CK_ULONG = match obj.key_type {
                    keystore::KeyType::Rsa => CKK_RSA,
                    keystore::KeyType::Ec => CKK_EC,
                    keystore::KeyType::MlDsa44
                    | keystore::KeyType::MlDsa65
                    | keystore::KeyType::MlDsa87 => CKK_ML_DSA,
                    keystore::KeyType::MlKem512
                    | keystore::KeyType::MlKem768
                    | keystore::KeyType::MlKem1024 => CKK_ML_KEM,
                };
                (val.as_ptr() as *const CK_ULONG).read_unaligned() == expected
            }
            CKA_TOKEN => val.len() == 1 && val[0] == CK_FALSE,
            CKA_ID => val == &obj.id[..],
            CKA_LABEL => val == obj.label.as_bytes(),
            _ => return false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Template-matching for session `CKO_PUBLIC_KEY` objects.
unsafe fn matches_session_pub_template(
    obj: &SessionPubKey,
    template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> bool {
    for i in 0..count as usize {
        let attr = &*template.add(i);
        if attr.pValue.is_null() || attr.ulValueLen == 0 {
            continue;
        }
        let val =
            std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
        let ok = match attr.type_ {
            CKA_CLASS => {
                if val.len() != std::mem::size_of::<CK_OBJECT_CLASS>() {
                    return false;
                }
                (val.as_ptr() as *const CK_OBJECT_CLASS).read_unaligned() == CKO_PUBLIC_KEY
            }
            CKA_KEY_TYPE => {
                if val.len() != std::mem::size_of::<CK_ULONG>() {
                    return false;
                }
                let expected: CK_ULONG = match obj.key_type {
                    keystore::KeyType::Rsa => CKK_RSA,
                    keystore::KeyType::Ec => CKK_EC,
                    keystore::KeyType::MlDsa44
                    | keystore::KeyType::MlDsa65
                    | keystore::KeyType::MlDsa87 => CKK_ML_DSA,
                    keystore::KeyType::MlKem512
                    | keystore::KeyType::MlKem768
                    | keystore::KeyType::MlKem1024 => CKK_ML_KEM,
                };
                (val.as_ptr() as *const CK_ULONG).read_unaligned() == expected
            }
            CKA_TOKEN => val.len() == 1 && val[0] == CK_FALSE,
            CKA_ID => val == &obj.id[..],
            CKA_LABEL => val == obj.label.as_bytes(),
            _ => return false,
        };
        if !ok {
            return false;
        }
    }
    true
}

unsafe extern "C" fn c_find_objects_init(
    h_session: CK_SESSION_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let slot_id = {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) if e.op.is_some() => return CKR_OPERATION_ACTIVE,
            Some(e) => e.slot_id,
        }
    };
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let mut results = match tok.with_keystore(|ks| {
        let no_filter = p_template.is_null() || ul_count == 0;
        let mut handles: Vec<CK_OBJECT_HANDLE> = Vec::new();
        for (i, e) in ks.entries().iter().enumerate() {
            // Private key object
            if no_filter || matches_template(e, p_template, ul_count) {
                handles.push((i as CK_OBJECT_HANDLE) + HANDLE_ORIGIN);
            }
            // Certificate object (only for entries that carry a cert)
            if e.cert_der.is_some()
                && (no_filter || matches_cert_template(e, p_template, ul_count))
            {
                handles.push((i as CK_OBJECT_HANDLE) + CERT_HANDLE_ORIGIN);
            }
            // Token public key object (PQC entries that carry pub_bytes)
            if e.pub_bytes.is_some()
                && matches!(
                    e.key_type,
                    KeyType::MlDsa44
                        | KeyType::MlDsa65
                        | KeyType::MlDsa87
                        | KeyType::MlKem512
                        | KeyType::MlKem768
                        | KeyType::MlKem1024
                )
                && (no_filter || matches_token_pub_template(e, p_template, ul_count))
            {
                handles.push((i as CK_OBJECT_HANDLE) + PUB_KEY_HANDLE_ORIGIN);
            }
        }
        handles
    }) {
        Ok(v) => v,
        Err(rv) => return rv,
    };
    // Append session objects owned by this session (PKCS#11 s.11.7: session objects
    // are visible only to their creating session).
    {
        let no_filter = p_template.is_null() || ul_count == 0;
        let guard = session_objs().lock();
        for (&h, obj) in guard.iter() {
            let obj_session = match obj {
                SessionObj::PrivKey(pk) => pk.session,
                SessionObj::PubKey(pk) => pk.session,
            };
            if obj_session != h_session {
                continue;
            }
            let include = no_filter
                || match obj {
                    SessionObj::PrivKey(pk) => {
                        matches_session_priv_template(pk, p_template, ul_count)
                    }
                    SessionObj::PubKey(pk) => {
                        matches_session_pub_template(pk, p_template, ul_count)
                    }
                };
            if include {
                results.push(h);
            }
        }
    }
    match op_state().lock().get_mut(&h_session) {
        Some(e) => e.op = Some(OpCtx::FindObjects { results, pos: 0 }),
        None => return CKR_SESSION_HANDLE_INVALID,
    }
    CKR_OK
}

unsafe extern "C" fn c_find_objects(
    h_session: CK_SESSION_HANDLE,
    ph_object: CK_OBJECT_HANDLE_PTR,
    ul_max: CK_ULONG,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if ph_object.is_null() || pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = op_state().lock();
    let entry = match guard.get_mut(&h_session) {
        Some(e) => e,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let (results, pos) = match &mut entry.op {
        Some(OpCtx::FindObjects { results, pos }) => (results, pos),
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };
    let avail = results.len().saturating_sub(*pos);
    let n = avail.min(ul_max as usize);
    for i in 0..n {
        *ph_object.add(i) = results[*pos + i];
    }
    *pos += n;
    *pul_count = n as CK_ULONG;
    CKR_OK
}

unsafe extern "C" fn c_find_objects_final(h_session: CK_SESSION_HANDLE) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let mut guard = op_state().lock();
    match guard.get_mut(&h_session) {
        None => CKR_SESSION_HANDLE_INVALID,
        Some(e) => match &e.op {
            Some(OpCtx::FindObjects { .. }) => {
                e.op = None;
                CKR_OK
            }
            _ => CKR_OPERATION_NOT_INITIALIZED,
        },
    }
}

// ---------------------------------------------------------------------------
// Object attributes
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_get_attribute_value(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: CK_ATTRIBUTE_PTR,
    ul_count: CK_ULONG,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // PKCS#11 v2.40 s.11.7: NULL pTemplate with ul_count=0 is a valid no-op and
    // returns CKR_OK (the zero-iteration loop below handles this naturally).
    // NULL pTemplate with ul_count>0 is invalid (nowhere to write results).
    if p_template.is_null() && ul_count > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    if h_object == 0 {
        return CKR_KEY_HANDLE_INVALID;
    }

    // Session objects occupy handles >= SESSION_OBJ_ORIGIN (highest range, checked first).
    if h_object >= SESSION_OBJ_ORIGIN {
        if op_state().lock().get(&h_session).is_none() {
            return CKR_SESSION_HANDLE_INVALID;
        }
        let guard = session_objs().lock();
        let obj = match guard.get(&h_object) {
            Some(o) => o,
            None => return CKR_KEY_HANDLE_INVALID,
        };
        let mut rv_overall = CKR_OK;
        for i in 0..ul_count as usize {
            let attr = &mut *p_template.add(i);
            let rv_attr = match obj {
                SessionObj::PrivKey(pk) => match attr.type_ {
                    CKA_CLASS => {
                        let v: CK_OBJECT_CLASS = CKO_PRIVATE_KEY;
                        write_attr(attr, &v.to_ne_bytes())
                    }
                    CKA_KEY_TYPE => {
                        let v: CK_ULONG = match pk.key_type {
                            KeyType::Rsa => CKK_RSA,
                            KeyType::Ec => CKK_EC,
                            KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => CKK_ML_DSA,
                            KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => CKK_ML_KEM,
                        };
                        write_attr(attr, &v.to_ne_bytes())
                    }
                    CKA_TOKEN => write_attr(attr, &[CK_FALSE]),
                    CKA_PRIVATE | CKA_SENSITIVE | CKA_SIGN => write_attr(attr, &[CK_TRUE]),
                    CKA_ID => write_attr(attr, &pk.id),
                    CKA_LABEL => write_attr(attr, pk.label.as_bytes()),
                    _ => {
                        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        CKR_ATTRIBUTE_TYPE_INVALID
                    }
                },
                SessionObj::PubKey(pk) => {
                    // P-256 named-curve parameters DER: OID secp256r1 (1.2.840.10045.3.1.7)
                    const P256_PARAMS: &[u8] =
                        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
                    match attr.type_ {
                        CKA_CLASS => {
                            let v: CK_OBJECT_CLASS = CKO_PUBLIC_KEY;
                            write_attr(attr, &v.to_ne_bytes())
                        }
                        CKA_KEY_TYPE => {
                            let v: CK_ULONG = match pk.key_type {
                                KeyType::Rsa => CKK_RSA,
                                KeyType::Ec => CKK_EC,
                                KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => CKK_ML_DSA,
                                KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => CKK_ML_KEM,
                            };
                            write_attr(attr, &v.to_ne_bytes())
                        }
                        CKA_TOKEN => write_attr(attr, &[CK_FALSE]),
                        CKA_VERIFY => write_attr(attr, &[CK_TRUE]),
                        CKA_ID => write_attr(attr, &pk.id),
                        CKA_LABEL => write_attr(attr, pk.label.as_bytes()),
                        CKA_EC_POINT if pk.key_type == KeyType::Ec => {
                            write_attr(attr, &pk.pub_bytes)
                        }
                        CKA_EC_PARAMS if pk.key_type == KeyType::Ec => {
                            write_attr(attr, P256_PARAMS)
                        }
                        CKA_MODULUS if pk.key_type == KeyType::Rsa => {
                            // pub_bytes wire format: n_len(4 BE u32) || n(n_len bytes) || e(rest).
                            // pkcs1_extract_pub_components guarantees this is well-formed at
                            // key-generation time.  The explicit bounds check below prevents a
                            // panic if that invariant is ever violated by a future refactor.
                            if pk.pub_bytes.len() < 4 {
                                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                CKR_GENERAL_ERROR
                            } else {
                                let n_len = u32::from_be_bytes(
                                    pk.pub_bytes[..4].try_into().unwrap(),
                                ) as usize;
                                if 4 + n_len > pk.pub_bytes.len() {
                                    // n_len is corrupt -- would produce OOB slice.
                                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                    CKR_GENERAL_ERROR
                                } else {
                                    write_attr(attr, &pk.pub_bytes[4..4 + n_len])
                                }
                            }
                        }
                        CKA_PUBLIC_EXPONENT if pk.key_type == KeyType::Rsa => {
                            // Same pub_bytes format as CKA_MODULUS above.  n_len bounds check
                            // prevents OOB slice; see comment there for the format contract.
                            if pk.pub_bytes.len() < 4 {
                                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                CKR_GENERAL_ERROR
                            } else {
                                let n_len = u32::from_be_bytes(
                                    pk.pub_bytes[..4].try_into().unwrap(),
                                ) as usize;
                                if 4 + n_len > pk.pub_bytes.len() {
                                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                                    CKR_GENERAL_ERROR
                                } else {
                                    write_attr(attr, &pk.pub_bytes[4 + n_len..])
                                }
                            }
                        }
                        _ => {
                            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            CKR_ATTRIBUTE_TYPE_INVALID
                        }
                    }
                }
            };
            if rv_attr != CKR_OK && rv_overall == CKR_OK {
                rv_overall = rv_attr;
            }
        }
        return rv_overall;
    }

    // Token CKO_PUBLIC_KEY objects (ML-DSA / ML-KEM) -- checked before cert range.
    if h_object >= PUB_KEY_HANDLE_ORIGIN {
        let pub_idx = (h_object - PUB_KEY_HANDLE_ORIGIN) as usize;
        let slot_id = match op_state().lock().get(&h_session) {
            Some(e) => e.slot_id,
            None => return CKR_SESSION_HANDLE_INVALID,
        };
        let tok = match get_slot(slot_id) {
            Some(t) => t,
            None => return CKR_SESSION_HANDLE_INVALID,
        };
        return match tok.with_keystore(|ks| {
            let entry = match ks.entries().get(pub_idx) {
                Some(e) => e,
                None => return CKR_KEY_HANDLE_INVALID,
            };
            if entry.pub_bytes.is_none() {
                return CKR_KEY_HANDLE_INVALID;
            }
            let pub_bytes = entry.pub_bytes.as_deref().unwrap();
            let key_type_ckk: CK_ULONG = match entry.key_type {
                KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => CKK_ML_DSA,
                KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => CKK_ML_KEM,
                KeyType::Rsa | KeyType::Ec => return CKR_KEY_HANDLE_INVALID,
            };
            let supports_verify = matches!(
                entry.key_type,
                KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87
            );
            let supports_encrypt = matches!(
                entry.key_type,
                KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024
            );
            let mut rv_overall = CKR_OK;
            for i in 0..ul_count as usize {
                let attr = &mut *p_template.add(i);
                let rv_attr = match attr.type_ {
                    CKA_CLASS => {
                        let v: CK_OBJECT_CLASS = CKO_PUBLIC_KEY;
                        write_attr(attr, &v.to_ne_bytes())
                    }
                    CKA_KEY_TYPE => write_attr(attr, &key_type_ckk.to_ne_bytes()),
                    CKA_TOKEN => write_attr(attr, &[CK_TRUE]),
                    CKA_LABEL => write_attr(attr, entry.label.as_bytes()),
                    CKA_ID => write_attr(attr, &entry.id),
                    CKA_VERIFY => write_attr(attr, &[if supports_verify { CK_TRUE } else { CK_FALSE }]),
                    CKA_ENCRYPT => write_attr(attr, &[if supports_encrypt { CK_TRUE } else { CK_FALSE }]),
                    // CKA_VALUE: raw public key bytes (PKCS#11 v3.0 s.2.3.7 / s.2.3.9)
                    CKA_VALUE => write_attr(attr, pub_bytes),
                    _ => {
                        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        CKR_ATTRIBUTE_TYPE_INVALID
                    }
                };
                if rv_attr != CKR_OK && rv_overall == CKR_OK {
                    rv_overall = rv_attr;
                }
            }
            rv_overall
        }) {
            Ok(rv) => rv,
            Err(rv) => rv,
        };
    }

    // Dispatch on object type: cert handles use a separate high-range origin.
    if h_object >= CERT_HANDLE_ORIGIN {
        let cert_idx = (h_object - CERT_HANDLE_ORIGIN) as usize;
        let slot_id = match op_state().lock().get(&h_session) {
            Some(e) => e.slot_id,
            None => return CKR_SESSION_HANDLE_INVALID,
        };
        let tok = match get_slot(slot_id) {
            Some(t) => t,
            None => return CKR_SESSION_HANDLE_INVALID,
        };
        return match tok.with_keystore(|ks| {
            let entry = match ks.entries().get(cert_idx) {
                Some(e) => e,
                None => return CKR_KEY_HANDLE_INVALID,
            };
            let cert_bytes = match entry.cert_der.as_deref() {
                Some(b) => b,
                None => return CKR_KEY_HANDLE_INVALID,
            };
            let mut rv_overall = CKR_OK;
            for i in 0..ul_count as usize {
                let attr = &mut *p_template.add(i);
                let rv_attr = match attr.type_ {
                    CKA_CLASS => {
                        let v: CK_OBJECT_CLASS = CKO_CERTIFICATE;
                        write_attr(attr, &v.to_ne_bytes())
                    }
                    CKA_CERTIFICATE_TYPE => {
                        let v: CK_ULONG = CKC_X_509;
                        write_attr(attr, &v.to_ne_bytes())
                    }
                    CKA_VALUE => write_attr(attr, cert_bytes),
                    CKA_LABEL => write_attr(attr, entry.label.as_bytes()),
                    CKA_ID => write_attr(attr, &entry.id),
                    CKA_TOKEN => write_attr(attr, &[CK_TRUE]),
                    _ => {
                        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        CKR_ATTRIBUTE_TYPE_INVALID
                    }
                };
                if rv_attr != CKR_OK && rv_overall == CKR_OK {
                    rv_overall = rv_attr;
                }
            }
            rv_overall
        }) {
            Ok(rv) => rv,
            Err(rv) => rv,
        };
    }

    let key_idx = (h_object - HANDLE_ORIGIN) as usize;
    let slot_id = match op_state().lock().get(&h_session) {
        Some(e) => e.slot_id,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    match tok.with_keystore(|ks| {
        let entry = match ks.entries().get(key_idx) {
            Some(e) => e,
            None => return CKR_KEY_HANDLE_INVALID,
        };
        let mut rv_overall = CKR_OK;
        for i in 0..ul_count as usize {
            let attr = &mut *p_template.add(i);
            let rv_attr = match attr.type_ {
                CKA_CLASS => {
                    let v: CK_OBJECT_CLASS = CKO_PRIVATE_KEY;
                    write_attr(attr, &v.to_ne_bytes())
                }
                CKA_KEY_TYPE => {
                    let v: CK_ULONG = match entry.key_type {
                        KeyType::Rsa => CKK_RSA,
                        KeyType::Ec => CKK_EC,
                        KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => CKK_ML_DSA,
                        KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => CKK_ML_KEM,
                    };
                    write_attr(attr, &v.to_ne_bytes())
                }
                CKA_LABEL => write_attr(attr, entry.label.as_bytes()),
                CKA_ID => write_attr(attr, &entry.id),
                CKA_TOKEN | CKA_PRIVATE | CKA_SENSITIVE | CKA_SIGN | CKA_VERIFY => {
                    // CKA_VERIFY is supported: C_VerifyInit derives the public key
                    // from the private key, so private-key objects support verify.
                    write_attr(attr, &[CK_TRUE])
                }
                CKA_DECRYPT => {
                    // Only RSA private keys support OAEP decryption (CKM_RSA_PKCS_OAEP).
                    let v = if entry.key_type == KeyType::Rsa { CK_TRUE } else { CK_FALSE };
                    write_attr(attr, &[v])
                }
                CKA_ENCRYPT => {
                    // CKA_ENCRYPT belongs to public key objects (PKCS#11 v2.40 s.4.8).
                    // Private keys (s.4.9) carry CKA_DECRYPT, not CKA_ENCRYPT. Returning
                    // FALSE is spec-conformant and matches SoftHSM2/OpenSC behaviour.
                    // See the CKA_ENCRYPT arm in matches_template for the full rationale
                    // and the YKCS11 precedent for the alternative approach.
                    write_attr(attr, &[CK_FALSE])
                }
                _ => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
            };
            if rv_attr != CKR_OK && rv_overall == CKR_OK {
                rv_overall = rv_attr;
            }
        }
        rv_overall
    }) {
        Ok(rv) => rv,
        Err(rv) => rv,
    }
}

// ---------------------------------------------------------------------------
// Shared *_init scaffolding
// ---------------------------------------------------------------------------

/// Maps a PKCS#11 mechanism type to the `KeyType` it requires.
///
/// PKCS#11 s.11.11 mandates `CKR_KEY_TYPE_INCONSISTENT` from `C_SignInit` when
/// the key type is incompatible with the mechanism -- the error must come from
/// the init function, not from the subsequent `C_Sign`. This function provides
/// the mechanism->key-type mapping used by `init_op` to enforce that invariant.
///
/// Returns `None` only for mechanisms not in the supported set; in practice all
/// mechanisms in `SIGN_VERIFY_MECHANISMS` and the encrypt/decrypt set are covered.
fn required_key_type(mech: CK_MECHANISM_TYPE) -> Option<KeyType> {
    match mech {
        CKM_RSA_PKCS_PSS | CKM_RSA_PKCS_OAEP => Some(KeyType::Rsa),
        CKM_ECDSA | CKM_ECDSA_SHA256 => Some(KeyType::Ec),
        CKM_ML_DSA => Some(KeyType::MlDsa65),
        CKM_ML_KEM => Some(KeyType::MlKem768),
        // Unknown mechanism: no key-type constraint. This branch is unreachable
        // in practice because init_op checks allowed_mechs before calling this.
        _ => None,
    }
}

/// Validate mechanism-specific parameters for mechanisms that carry a parameter struct.
///
/// PKCS#11 s.11.14: `CKM_RSA_PKCS_PSS` and `CKM_RSA_PKCS_OAEP` require the caller
/// to pass a parameter struct that names the hash algorithm and MGF. Ignoring these
/// parameters would silently accept requests asking for SHA-1 or SHA-384 while
/// performing SHA-256 -- a correctness bug and potential interoperability failure.
///
/// This function is called AFTER the mechanism-type check (allowed_mechs) inside
/// `init_op`. This ordering matters: if an OAEP mechanism is passed to C_SignInit
/// (where OAEP is not allowed), `init_op` must return `CKR_MECHANISM_INVALID` rather
/// than `CKR_MECHANISM_PARAM_INVALID`. Spec s.11.11 lists `CKR_MECHANISM_INVALID` as
/// the correct error for an unsupported mechanism, regardless of parameter validity.
///
/// Mechanisms with no parameters (e.g. `CKM_ECDSA`) are accepted
/// unconditionally -- PKCS#11 does not mandate `pParameter == NULL` for parameterless
/// mechanisms and some callers leave it non-null.
///
/// # Safety
/// `mech.pParameter` is dereferenced as a typed struct pointer when non-null.
/// Callers must ensure the pointer is valid for at least `mech.ulParameterLen` bytes.
/// In practice this is always satisfied: the pointer comes from a C caller following
/// the PKCS#11 ABI which allocates the struct on its stack or heap.
unsafe fn validate_mechanism_params(mech: &cryptoki_sys::CK_MECHANISM) -> CK_RV {
    match mech.mechanism {
        CKM_RSA_PKCS_PSS => {
            // pParameter must be non-null and large enough to hold the params struct.
            if mech.pParameter.is_null()
                || mech.ulParameterLen
                    < std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG
            {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            // SAFETY: pParameter is non-null and ulParameterLen >= sizeof the struct
            // (checked above).  Alignment is provided by the C caller: PKCS#11 callers
            // allocate CK_RSA_PKCS_PSS_PARAMS on the stack or heap, which the platform
            // ABI aligns to at least sizeof(CK_ULONG).  cryptoki-sys matches the C ABI
            // struct layout.  Misaligned pointers from non-conforming callers are
            // undefined behaviour under the PKCS#11 ABI, not a defect in this code.
            let params = &*(mech.pParameter as *const CK_RSA_PKCS_PSS_PARAMS);
            // Reject any combination other than SHA-256 + MGF1-SHA256 so that a
            // caller requesting SHA-1 doesn't silently get SHA-256 instead.
            if params.hashAlg != CKM_SHA256 || params.mgf != CKG_MGF1_SHA256 {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            CKR_OK
        }
        CKM_RSA_PKCS_OAEP => {
            // pParameter must be non-null and large enough to hold the params struct.
            if mech.pParameter.is_null()
                || mech.ulParameterLen
                    < std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG
            {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            // SAFETY: same alignment argument as the PSS branch above -- C callers
            // allocate on stack/heap with platform-ABI alignment; cryptoki-sys layout
            // matches the C ABI struct.
            let params = &*(mech.pParameter as *const CK_RSA_PKCS_OAEP_PARAMS);
            // SHA-256 + MGF1-SHA256 only.
            if params.hashAlg != CKM_SHA256 || params.mgf != CKG_MGF1_SHA256 {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            // source must be CKZ_DATA_SPECIFIED (label embedded in the params struct).
            if params.source != CKZ_DATA_SPECIFIED {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            // wolfcrypt's OAEP implementation uses an empty label; reject non-empty
            // labels so callers discover the mismatch at init time rather than
            // getting incorrect decryption results.
            if !params.pSourceData.is_null() && params.ulSourceDataLen > 0 {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            CKR_OK
        }
        // All other mechanisms carry no required parameters; accept unconditionally.
        _ => CKR_OK,
    }
}

/// Shared body for C_SignInit / C_VerifyInit / C_EncryptInit / C_DecryptInit.
///
/// Validates the session, checks for an active operation, validates the
/// mechanism type against `allowed_mechs`, validates mechanism-specific parameters
/// (e.g. hash algorithm for PSS/OAEP), confirms the key exists in the keystore,
/// then writes the `OpCtx` produced by `make_ctx`. Returns CKR_OK or the first
/// error encountered.
///
/// Mechanism-type check happens BEFORE parameter validation. This matches the
/// PKCS#11 s.11.11 requirement that `CKR_MECHANISM_INVALID` is returned for an
/// unsupported mechanism, regardless of parameter validity. If OAEP is passed to
/// C_SignInit (where it is not allowed), the result must be `CKR_MECHANISM_INVALID`,
/// not `CKR_MECHANISM_PARAM_INVALID`.
///
/// ## Key type validation
///
/// This function retrieves the `KeyEntry` (not just its existence) and checks that
/// the key type is compatible with the mechanism via `required_key_type()`. A
/// `CKM_RSA_PKCS_PSS` init with an EC key returns `CKR_KEY_TYPE_INCONSISTENT`
/// here, satisfying PKCS#11 s.11.11 which lists this error as a valid `C_SignInit`
/// return code. The error must come from the init call, not from `C_Sign`.
///
/// ## Two-lock pattern
///
/// `init_op` acquires `op_state()` twice: once to check the session and
/// OPERATION_ACTIVE (lines below), releases the lock to call `with_keystore`
/// (which may block on the token RwLock), then re-acquires to write the op context.
/// In the window between the two acquisitions another thread could close or modify
/// the same session. However, PKCS#11 s.6.7 requires that callers serialise access
/// to a single session unless `CKF_OS_LOCKING_OK` is advertised (which this library
/// does not). The re-check at the second acquisition (`None => return CKR_SESSION_HANDLE_INVALID`)
/// correctly handles the close-in-window case. Concurrent `*Init` on the same session
/// without serialisation is a caller violation. Tracked in bead soft_PKCS11-9m5.
fn init_op(
    h_session: CK_SESSION_HANDLE,
    mech: &cryptoki_sys::CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
    allowed_mechs: &[CK_MECHANISM_TYPE],
    // When true, token public key handles (PUB_KEY_HANDLE_ORIGIN range) are
    // accepted in addition to private key handles.  Pass true for
    // C_VerifyInit and C_EncryptInit; false for C_SignInit and C_DecryptInit.
    allow_pub_key_handle: bool,
    make_ctx: impl FnOnce() -> OpCtx,
) -> CK_RV {
    // Check ordering: (1) mechanism type, (2) mechanism params, (3) session state.
    //
    // This ordering is deliberate and must not be changed.  PKCS#11 conformance
    // test suites (e.g. pkcs11-compliance) probe specific error codes and depend
    // on stateless checks (mechanism validity, parameter validity) preceding
    // stateful checks (session validity, operation-active state).  Reversing
    // the order -- e.g. checking the session first -- would cause a call with an
    // invalid mechanism to return CKR_SESSION_HANDLE_INVALID instead of
    // CKR_MECHANISM_INVALID, breaking callers that use error codes to distinguish
    // "wrong call" from "wrong session".
    //
    // PKCS#11 s.11.11 lists both CKR_MECHANISM_INVALID and CKR_SESSION_HANDLE_INVALID
    // as valid returns but does not mandate an ordering; we choose the order that
    // gives the most actionable error first and is consistent across all *Init functions.
    if !allowed_mechs.contains(&mech.mechanism) {
        return CKR_MECHANISM_INVALID;
    }
    // (2) Parameter validation: checked after mechanism-type (only valid mechanisms have
    // parameters worth checking) and before session state (allows parameter errors to be
    // surfaced without a valid token, useful for testing and client-side validation).
    // SAFETY: pParameter is a C-owned pointer; validated inside validate_mechanism_params.
    let params_rv = unsafe { validate_mechanism_params(mech) };
    if params_rv != CKR_OK {
        return params_rv;
    }
    // (3) Session check last among the stateless validations: acquires a lock on op_state.
    let slot_id = {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) if e.op.is_some() => return CKR_OPERATION_ACTIVE,
            Some(e) => e.slot_id,
        }
    };
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    // Validate the key handle and check key type compatibility.
    if h_key >= SESSION_OBJ_ORIGIN {
        // Session object key.
        let guard = session_objs().lock();
        match guard.get(&h_key) {
            None => return CKR_KEY_HANDLE_INVALID,
            Some(SessionObj::PubKey(_)) => {
                // Public key objects cannot be used for signing or decryption.
                return CKR_KEY_HANDLE_INVALID;
            }
            Some(SessionObj::PrivKey(pk)) => {
                if let Some(required) = required_key_type(mech.mechanism) {
                    if pk.key_type != required {
                        return CKR_KEY_TYPE_INCONSISTENT;
                    }
                }
            }
        }
    } else if h_key >= PUB_KEY_HANDLE_ORIGIN {
        // Token public key handle (ML-DSA / ML-KEM).  Only valid when the caller
        // explicitly allows public key handles (C_VerifyInit, C_EncryptInit).
        if !allow_pub_key_handle {
            return CKR_KEY_HANDLE_INVALID;
        }
        let pub_idx = (h_key - PUB_KEY_HANDLE_ORIGIN) as usize;
        match tok.with_keystore(|ks| {
            let entry = match ks.entries().get(pub_idx) {
                Some(e) => e,
                None => return Err(CKR_KEY_HANDLE_INVALID),
            };
            if entry.pub_bytes.is_none() {
                return Err(CKR_KEY_HANDLE_INVALID);
            }
            if let Some(required) = required_key_type(mech.mechanism) {
                if entry.key_type != required {
                    return Err(CKR_KEY_TYPE_INCONSISTENT);
                }
            }
            Ok(())
        }) {
            Ok(Ok(())) => {}
            Ok(Err(rv)) | Err(rv) => return rv,
        }
    } else if h_key >= CERT_HANDLE_ORIGIN {
        return CKR_KEY_HANDLE_INVALID;
    } else {
        let key_idx = (h_key - HANDLE_ORIGIN) as usize;
        // Look up the key entry and validate key type against mechanism in one keystore
        // access, avoiding a second with_keystore call for the type check.
        // Returns Err(CKR_KEY_HANDLE_INVALID) if the index is out of range, or
        // Err(CKR_KEY_TYPE_INCONSISTENT) if the key type is wrong for the mechanism.
        // The outer Err from with_keystore itself propagates CKR_USER_NOT_LOGGED_IN etc.
        match tok.with_keystore(|ks| {
            let entry = match ks.entries().get(key_idx) {
                Some(e) => e,
                None => return Err(CKR_KEY_HANDLE_INVALID),
            };
            if let Some(required) = required_key_type(mech.mechanism) {
                if entry.key_type != required {
                    return Err(CKR_KEY_TYPE_INCONSISTENT);
                }
            }
            Ok(())
        }) {
            Ok(Ok(())) => {}
            Ok(Err(rv)) | Err(rv) => return rv,
        }
    }
    match op_state().lock().get_mut(&h_session) {
        Some(e) => e.op = Some(make_ctx()),
        None => return CKR_SESSION_HANDLE_INVALID,
    }
    CKR_OK
}

// ---------------------------------------------------------------------------
// Sign
//
// PKCS#11 s.11.11: signing uses existing key material and does not modify the
// token. It is therefore permitted from both read-only and read-write sessions
// even on a CKF_WRITE_PROTECTED token. No session-type check is required.
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_sign_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_mechanism.is_null() || h_key == 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*p_mechanism;
    init_op(h_session, mech, h_key, SIGN_VERIFY_MECHANISMS, false, || OpCtx::Sign { key_handle: h_key, mechanism: mech.mechanism })
}

unsafe extern "C" fn c_sign(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_data.is_null() || pul_signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let (key_handle, mechanism, slot_id) = {
        let guard = op_state().lock();
        match guard.get(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => match &e.op {
                Some(OpCtx::Sign { key_handle, mechanism }) => (*key_handle, *mechanism, e.slot_id),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            },
        }
    };
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    // NULL pSignature -> length query, return conservative max without signing.
    if p_signature.is_null() {
        *pul_signature_len = sign_max_output(mechanism);
        return CKR_OK;
    }
    let data = std::slice::from_raw_parts(p_data, ul_data_len as usize);
    // Compute the signature. If this fails, clear the op context before returning --
    // PKCS#11 s.11.11: C_Sign terminates the active operation on any return code
    // other than CKR_BUFFER_TOO_SMALL. Without clearing, the session is wedged:
    // a subsequent C_SignInit returns CKR_OPERATION_ACTIVE.
    let sig_result: Result<Vec<u8>, CK_RV> = if key_handle >= SESSION_OBJ_ORIGIN {
        let guard = session_objs().lock();
        match guard.get(&key_handle) {
            Some(SessionObj::PrivKey(pk)) => {
                ops::sign_raw(pk.key_type, &pk.der_bytes, mechanism, data).map_err(ops_err)
            }
            _ => Err(CKR_KEY_HANDLE_INVALID),
        }
    } else {
        let key_idx = (key_handle - HANDLE_ORIGIN) as usize;
        match tok.with_keystore(|ks| {
            let entry = ks.entries().get(key_idx).ok_or(CKR_KEY_HANDLE_INVALID)?;
            ops::sign(entry, mechanism, data).map_err(ops_err)
        }) {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(rv)) | Err(rv) => Err(rv),
        }
    };
    let sig = match sig_result {
        Ok(s) => s,
        Err(rv) => {
            // s.11.11: any error other than CKR_BUFFER_TOO_SMALL terminates the
            // active operation. All errors reaching this arm are crypto/key
            // failures, not buffer-sizing issues -- clear the op context.
            if let Some(e) = op_state().lock().get_mut(&h_session) {
                e.op = None;
            }
            return rv;
        }
    };
    let buf_len = *pul_signature_len as usize;
    *pul_signature_len = sig.len() as CK_ULONG;
    if buf_len < sig.len() {
        // s.11.11 exception: CKR_BUFFER_TOO_SMALL does NOT terminate the active
        // operation. Leave op context intact so the caller can retry C_Sign with
        // a correctly sized buffer (it must NOT call C_SignInit again first).
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(sig.as_ptr(), p_signature, sig.len());
    // Session may have been closed concurrently; a missing entry is not an
    // error at this point -- the signature was produced successfully.
    if let Some(e) = op_state().lock().get_mut(&h_session) {
        e.op = None;
    }
    CKR_OK
}

unsafe extern "C" fn c_sign_update(
    h_session: CK_SESSION_HANDLE,
    _p_data: CK_BYTE_PTR,
    _ul_data_len: CK_ULONG,
) -> CK_RV {
    // PKCS#11 s.11.11: all functions must return CKR_CRYPTOKI_NOT_INITIALIZED
    // if C_Initialize has not been called. Check before touching any shared state.
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // Multi-part signing is not implemented. PKCS#11 s.11.11: returning any error
    // from C_SignUpdate MUST terminate the active operation. Clear op context here
    // so a subsequent C_SignInit does not get CKR_OPERATION_ACTIVE (session wedge).
    //
    // PKCS#11 s.11.1: session handle validity must be checked before other errors.
    // Return CKR_SESSION_HANDLE_INVALID for unknown handles, not CKR_FUNCTION_NOT_SUPPORTED.
    {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => e.op = None,
        }
    }
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn c_sign_final(
    h_session: CK_SESSION_HANDLE,
    _p_signature: CK_BYTE_PTR,
    _pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    // PKCS#11 s.11.11: all functions must return CKR_CRYPTOKI_NOT_INITIALIZED
    // if C_Initialize has not been called. Check before touching any shared state.
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // Multi-part signing is not implemented. PKCS#11 s.11.11: returning any error
    // from C_SignFinal MUST terminate the active operation. Clear op context here
    // so a subsequent C_SignInit does not get CKR_OPERATION_ACTIVE (session wedge).
    //
    // PKCS#11 s.11.1: session handle validity must be checked before other errors.
    {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => e.op = None,
        }
    }
    CKR_FUNCTION_NOT_SUPPORTED
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_verify_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_mechanism.is_null() || h_key == 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*p_mechanism;
    init_op(h_session, mech, h_key, SIGN_VERIFY_MECHANISMS, true, || OpCtx::Verify { key_handle: h_key, mechanism: mech.mechanism })
}

unsafe extern "C" fn c_verify(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    ul_signature_len: CK_ULONG,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_data.is_null() || p_signature.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let (key_handle, mechanism, slot_id) = {
        let guard = op_state().lock();
        match guard.get(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => match &e.op {
                Some(OpCtx::Verify { key_handle, mechanism }) => (*key_handle, *mechanism, e.slot_id),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            },
        }
    };
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let data = std::slice::from_raw_parts(p_data, ul_data_len as usize);
    let sig = std::slice::from_raw_parts(p_signature, ul_signature_len as usize);
    let result = if key_handle >= SESSION_OBJ_ORIGIN {
        // Session key verify is not supported yet.
        CKR_KEY_HANDLE_INVALID
    } else if key_handle >= PUB_KEY_HANDLE_ORIGIN {
        let pub_idx = (key_handle - PUB_KEY_HANDLE_ORIGIN) as usize;
        match tok.with_keystore(|ks| {
            let entry = ks.entries().get(pub_idx).ok_or(CKR_KEY_HANDLE_INVALID)?;
            ops::verify(entry, mechanism, data, sig).map_err(ops_err)
        }) {
            Ok(Ok(())) => CKR_OK,
            Ok(Err(rv)) => rv,
            Err(rv) => rv,
        }
    } else {
        let key_idx = (key_handle - HANDLE_ORIGIN) as usize;
        match tok.with_keystore(|ks| {
            let entry = ks.entries().get(key_idx).ok_or(CKR_KEY_HANDLE_INVALID)?;
            ops::verify(entry, mechanism, data, sig).map_err(ops_err)
        }) {
            Ok(Ok(())) => CKR_OK,
            Ok(Err(rv)) => rv,
            Err(rv) => rv,
        }
    };
    // C_Verify terminates the operation regardless of outcome (PKCS#11 s.11.11).
    if let Some(e) = op_state().lock().get_mut(&h_session) {
        e.op = None;
    }
    result
}

unsafe extern "C" fn c_verify_update(
    h_session: CK_SESSION_HANDLE,
    _p_part: CK_BYTE_PTR,
    _ul_part_len: CK_ULONG,
) -> CK_RV {
    // PKCS#11 s.11.11: all functions must return CKR_CRYPTOKI_NOT_INITIALIZED
    // if C_Initialize has not been called. Check before touching any shared state.
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // Multi-part verification is not implemented. PKCS#11 s.11.11: returning any
    // error from C_VerifyUpdate MUST terminate the active operation. Clear the op
    // context here so a subsequent C_VerifyInit does not get CKR_OPERATION_ACTIVE
    // (session wedge).
    //
    // WHY this stub exists even though C_VerifyUpdate returns an error: without a
    // non-null function pointer a caller that detects null cannot clean up the op
    // context it set up in C_VerifyInit. With a stub, the caller calls it, receives
    // CKR_FUNCTION_NOT_SUPPORTED, and the spec-mandated termination clears the
    // context -- no wedge. This mirrors c_sign_update for the same reason.
    //
    // PKCS#11 s.11.1: session handle validity must be checked before other errors.
    {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => e.op = None,
        }
    }
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn c_verify_final(
    h_session: CK_SESSION_HANDLE,
    _p_signature: CK_BYTE_PTR,
    _ul_signature_len: CK_ULONG,
) -> CK_RV {
    // PKCS#11 s.11.11: all functions must return CKR_CRYPTOKI_NOT_INITIALIZED
    // if C_Initialize has not been called. Check before touching any shared state.
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // Multi-part verification is not implemented. PKCS#11 s.11.11: returning any
    // error from C_VerifyFinal MUST terminate the active operation. Clear the op
    // context so the session is not permanently wedged. See c_verify_update for
    // the full rationale for why these stubs exist.
    //
    // PKCS#11 s.11.1: session handle validity must be checked before other errors.
    {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => e.op = None,
        }
    }
    CKR_FUNCTION_NOT_SUPPORTED
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_encrypt_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_mechanism.is_null() || h_key == 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*p_mechanism;
    init_op(h_session, mech, h_key, &[CKM_RSA_PKCS_OAEP, CKM_ML_KEM], true, || OpCtx::Encrypt { key_handle: h_key, mechanism: mech.mechanism })
}

unsafe extern "C" fn c_encrypt(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_encrypted: CK_BYTE_PTR,
    pul_encrypted_len: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_data.is_null() || pul_encrypted_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let (key_handle, mechanism, slot_id) = {
        let guard = op_state().lock();
        match guard.get(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => match &e.op {
                Some(OpCtx::Encrypt { key_handle, mechanism }) => (*key_handle, *mechanism, e.slot_id),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            },
        }
    };
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    // NULL output pointer: return the maximum ciphertext length without encrypting.
    // The op context is NOT cleared so the caller can retry with a real buffer.
    if p_encrypted.is_null() {
        *pul_encrypted_len = match mechanism {
            CKM_RSA_PKCS_OAEP => 512, // RSA-4096 max
            // ML-KEM-768: 1088-byte ciphertext || 32-byte shared secret.
            CKM_ML_KEM => 1120,
            _ => 512,
        };
        return CKR_OK;
    }
    let data = std::slice::from_raw_parts(p_data, ul_data_len as usize);
    let encrypt_result: Result<Vec<u8>, CK_RV> = if key_handle >= SESSION_OBJ_ORIGIN {
        // Session key encrypt is not supported yet.
        Err(CKR_KEY_HANDLE_INVALID)
    } else if key_handle >= PUB_KEY_HANDLE_ORIGIN {
        let pub_idx = (key_handle - PUB_KEY_HANDLE_ORIGIN) as usize;
        match tok.with_keystore(|ks| {
            let entry = ks.entries().get(pub_idx).ok_or(CKR_KEY_HANDLE_INVALID)?;
            ops::encrypt(entry, mechanism, data).map_err(ops_err)
        }) {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(rv)) | Err(rv) => Err(rv),
        }
    } else {
        let key_idx = (key_handle - HANDLE_ORIGIN) as usize;
        match tok.with_keystore(|ks| {
            let entry = ks.entries().get(key_idx).ok_or(CKR_KEY_HANDLE_INVALID)?;
            ops::encrypt(entry, mechanism, data).map_err(ops_err)
        }) {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(rv)) | Err(rv) => Err(rv),
        }
    };
    let ciphertext = match encrypt_result {
        Ok(c) => c,
        Err(rv) => {
            // PKCS#11 s.11.13: C_Encrypt terminates the active operation on error.
            // Clear op context so caller can call C_EncryptInit again.
            if let Some(e) = op_state().lock().get_mut(&h_session) {
                e.op = None;
            }
            return rv;
        }
    };
    let buf_len = *pul_encrypted_len as usize;
    *pul_encrypted_len = ciphertext.len() as CK_ULONG;
    if buf_len < ciphertext.len() {
        // s.11.13: CKR_BUFFER_TOO_SMALL does NOT terminate the active operation.
        // Leave op context intact so the caller can retry C_Encrypt with a
        // correctly sized buffer without first calling C_EncryptInit again.
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(ciphertext.as_ptr(), p_encrypted, ciphertext.len());
    if let Some(e) = op_state().lock().get_mut(&h_session) {
        e.op = None;
    }
    CKR_OK
}

unsafe extern "C" fn c_decrypt_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_mechanism.is_null() || h_key == 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*p_mechanism;
    init_op(h_session, mech, h_key, &[CKM_RSA_PKCS_OAEP, CKM_ML_KEM], false, || OpCtx::Decrypt { key_handle: h_key, mechanism: mech.mechanism })
}

unsafe extern "C" fn c_decrypt(
    h_session: CK_SESSION_HANDLE,
    p_encrypted: CK_BYTE_PTR,
    ul_encrypted_len: CK_ULONG,
    p_data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_encrypted.is_null() || pul_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let (key_handle, mechanism, slot_id) = {
        let guard = op_state().lock();
        match guard.get(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => match &e.op {
                Some(OpCtx::Decrypt { key_handle, mechanism }) => (*key_handle, *mechanism, e.slot_id),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            },
        }
    };
    let tok = match get_slot(slot_id) {
        Some(t) => t,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    // NULL output pointer: return a conservative upper bound without decrypting.
    // The op context is NOT cleared so the caller can retry with a real buffer.
    if p_data.is_null() {
        *pul_data_len = match mechanism {
            // ML-KEM decapsulation always produces a 32-byte shared secret.
            CKM_ML_KEM => 32,
            // OAEP: plaintext <= ciphertext size (OAEP padding is never negative).
            _ => ul_encrypted_len,
        };
        return CKR_OK;
    }
    let ciphertext = std::slice::from_raw_parts(p_encrypted, ul_encrypted_len as usize);
    let decrypt_result: Result<Vec<u8>, CK_RV> = if key_handle >= SESSION_OBJ_ORIGIN {
        // Session key decrypt is not supported yet.
        Err(CKR_KEY_HANDLE_INVALID)
    } else {
        let key_idx = (key_handle - HANDLE_ORIGIN) as usize;
        match tok.with_keystore(|ks| {
            let entry = ks.entries().get(key_idx).ok_or(CKR_KEY_HANDLE_INVALID)?;
            ops::decrypt(entry, mechanism, ciphertext).map_err(ops_err)
        }) {
            Ok(Ok(p)) => Ok(p),
            Ok(Err(rv)) | Err(rv) => Err(rv),
        }
    };
    let plaintext = match decrypt_result {
        Ok(p) => p,
        Err(rv) => {
            // PKCS#11 s.11.14: C_Decrypt terminates the active operation on error.
            // Clear op context so caller can call C_DecryptInit again.
            if let Some(e) = op_state().lock().get_mut(&h_session) {
                e.op = None;
            }
            return rv;
        }
    };
    let buf_len = *pul_data_len as usize;
    *pul_data_len = plaintext.len() as CK_ULONG;
    if buf_len < plaintext.len() {
        // SECURITY: The decrypted value may be key material (e.g., a wrapped AES
        // key being unwrapped via OAEP). Zeroize before returning so it does not
        // linger on the heap. *pul_data_len is already set above so the caller
        // can allocate a correct-size buffer and retry (op context is kept alive
        // per s.11.14 -- CKR_BUFFER_TOO_SMALL is the one case where retry is valid).
        let mut p = plaintext;
        p.zeroize();
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(plaintext.as_ptr(), p_data, plaintext.len());
    if let Some(e) = op_state().lock().get_mut(&h_session) {
        e.op = None;
    }
    CKR_OK
}

// Multi-part encrypt/decrypt stubs -- same session-wedge rationale as sign/verify stubs.
// PKCS#11 s.11.13/s.11.14: any error from C_EncryptUpdate/Final or C_DecryptUpdate/Final
// MUST terminate the active operation. These stubs clear the op context and return
// CKR_FUNCTION_NOT_SUPPORTED, matching the exact pattern of c_sign_update/c_sign_final.
// Without non-null pointers here, a caller that called C_EncryptInit successfully and
// then tried C_EncryptUpdate (receiving NULL) cannot release the op context, permanently
// wedging the session with CKR_OPERATION_ACTIVE on the next C_EncryptInit.

unsafe extern "C" fn c_encrypt_update(
    h_session: CK_SESSION_HANDLE,
    _p_part: CK_BYTE_PTR,
    _ul_part_len: CK_ULONG,
    _p_encrypted_part: CK_BYTE_PTR,
    _pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // PKCS#11 s.11.1: session handle validity precedes function-specific errors.
    {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => e.op = None,
        }
    }
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn c_encrypt_final(
    h_session: CK_SESSION_HANDLE,
    _p_last_encrypted_part: CK_BYTE_PTR,
    _pul_last_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => e.op = None,
        }
    }
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn c_decrypt_update(
    h_session: CK_SESSION_HANDLE,
    _p_encrypted_part: CK_BYTE_PTR,
    _ul_encrypted_part_len: CK_ULONG,
    _p_part: CK_BYTE_PTR,
    _pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => e.op = None,
        }
    }
    CKR_FUNCTION_NOT_SUPPORTED
}

unsafe extern "C" fn c_decrypt_final(
    h_session: CK_SESSION_HANDLE,
    _p_last_part: CK_BYTE_PTR,
    _pul_last_part_len: CK_ULONG_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    {
        let mut guard = op_state().lock();
        match guard.get_mut(&h_session) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(e) => e.op = None,
        }
    }
    CKR_FUNCTION_NOT_SUPPORTED
}

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_generate_random(
    h_session: CK_SESSION_HANDLE,
    random_data: CK_BYTE_PTR,
    ul_random_len: CK_ULONG,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // PKCS#11 v2.40 s.11.15: a valid open session handle is required.
    if op_state().lock().get(&h_session).is_none() {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if random_data.is_null() || ul_random_len == 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let ret = libc::getrandom(random_data as *mut libc::c_void, ul_random_len as usize, 0);
    if ret < 0 || ret as CK_ULONG != ul_random_len {
        // getrandom(2) returns fewer bytes than requested only if interrupted by a
        // signal (EINTR) or if the request exceeds 33 MiB (Linux implementation limit).
        // It can also fail with ENOSYS on kernels < 3.17, EPERM under seccomp profiles
        // that block the syscall, or EFAULT on bad pointer (prevented above).
        // These are real failure modes in containerised / minimal environments.
        CKR_GENERAL_ERROR
    } else {
        CKR_OK
    }
}

unsafe extern "C" fn c_seed_random(
    h_session: CK_SESSION_HANDLE,
    _p_seed: CK_BYTE_PTR,
    _ul_seed_len: CK_ULONG,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    // PKCS#11 s.11.15: C_SeedRandom requires a valid open session handle.
    // Validated for consistency with C_GenerateRandom even though the seed
    // is discarded (getrandom(2) draws from the kernel CSPRNG; it does not
    // accept external entropy injection).
    if op_state().lock().get(&h_session).is_none() {
        return CKR_SESSION_HANDLE_INVALID;
    }
    CKR_OK
}

// ---------------------------------------------------------------------------
// C_GenerateKeyPair
//
// PKCS#11 s.11.14: generates an ephemeral key pair.  Both objects are session
// objects (CKA_TOKEN=false); CKA_TOKEN=true in either template is rejected with
// CKR_TEMPLATE_INCONSISTENT.  Generated keys are stored in session_objs() and
// destroyed when the session is closed.
//
// Supported mechanisms:
//   CKM_EC_KEY_PAIR_GEN  -- P-256 only (curve must not be explicitly specified
//                           in the template, or must match P-256 OID)
//   CKM_RSA_PKCS_KEY_PAIR_GEN -- 2048-bit minimum
// ---------------------------------------------------------------------------

unsafe extern "C" fn c_generate_key_pair(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    _p_public_key_template: CK_ATTRIBUTE_PTR,
    ul_public_key_attribute_count: CK_ULONG,
    p_private_key_template: CK_ATTRIBUTE_PTR,
    ul_private_key_attribute_count: CK_ULONG,
    ph_public_key: CK_OBJECT_HANDLE_PTR,
    ph_private_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_mechanism.is_null() || ph_public_key.is_null() || ph_private_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*p_mechanism;
    if mech.mechanism != CKM_EC_KEY_PAIR_GEN && mech.mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN {
        return CKR_MECHANISM_INVALID;
    }

    // Session must exist.
    if op_state().lock().get(&h_session).is_none() {
        return CKR_SESSION_HANDLE_INVALID;
    }

    // Reject CKA_TOKEN=true in either template -- this token is read-only.
    for (tmpl_ptr, count) in [
        (_p_public_key_template, ul_public_key_attribute_count),
        (p_private_key_template, ul_private_key_attribute_count),
    ] {
        if tmpl_ptr.is_null() || count == 0 {
            continue;
        }
        for i in 0..count as usize {
            let attr = &*tmpl_ptr.add(i);
            if attr.type_ == CKA_TOKEN
                && attr.ulValueLen as usize == std::mem::size_of::<CK_BBOOL>()
                && *(attr.pValue as *const CK_BBOOL) == CK_TRUE
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
        }
    }

    // Generate the key pair.
    let (priv_der, pub_bytes, key_type) = match mech.mechanism {
        CKM_EC_KEY_PAIR_GEN => {
            let mut rng = match wolfcrypt::rand::WolfRng::new() {
                Ok(r) => r,
                Err(_) => return CKR_GENERAL_ERROR,
            };
            let key = match wolfcrypt::ecc::EccKey::generate(
                wolfcrypt::ecc::EccCurveId::SecP256R1,
                &mut rng,
            ) {
                Ok(k) => k,
                Err(_) => return CKR_GENERAL_ERROR,
            };
            let scalar = match key.export_private() {
                Ok(s) => s,
                Err(_) => return CKR_GENERAL_ERROR,
            };
            let pub_x963 = match key.export_public_x963() {
                Ok(p) => p,
                Err(_) => return CKR_GENERAL_ERROR,
            };
            (scalar, pub_x963, keystore::KeyType::Ec)
        }
        CKM_RSA_PKCS_KEY_PAIR_GEN => {
            let key = match wolfcrypt::rsa::RsaPrivateKey::generate(2048) {
                Ok(k) => k,
                Err(_) => return CKR_GENERAL_ERROR,
            };
            let pkcs1 = match key.to_pkcs1_der() {
                Ok(d) => d,
                Err(_) => return CKR_GENERAL_ERROR,
            };
            // Extract n and e from the PKCS#1 DER to build the public key encoding.
            // Format: 4 bytes n_len (big-endian u32) || n || e
            let pub_bytes = match pkcs1_extract_pub_components(&pkcs1) {
                Some(b) => b,
                None => return CKR_GENERAL_ERROR,
            };
            (pkcs1, pub_bytes, keystore::KeyType::Rsa)
        }
        _ => return CKR_MECHANISM_INVALID,
    };

    // Allocate object handles for the key pair.
    let priv_h = alloc_obj_handle();
    let pub_h = alloc_obj_handle();

    // Random 16-byte ID shared between the pair.
    let mut id = [0u8; 16];
    if getrandom_id(&mut id).is_err() {
        return CKR_GENERAL_ERROR;
    }

    {
        let mut guard = session_objs().lock();
        guard.insert(priv_h, SessionObj::PrivKey(SessionPrivKey {
            session: h_session,
            key_type,
            der_bytes: Zeroizing::new(priv_der),
            id,
            label: String::new(),
        }));
        guard.insert(pub_h, SessionObj::PubKey(SessionPubKey {
            session: h_session,
            key_type,
            pub_bytes,
            id,
            label: String::new(),
        }));
    }

    *ph_private_key = priv_h;
    *ph_public_key = pub_h;
    CKR_OK
}

/// Extract modulus (n) and public exponent (e) from a PKCS#1 RSAPrivateKey DER blob.
///
/// Returns a `Vec<u8>` encoded as:
///   `n_len(4 BE u32) || n(n_len bytes) || e(remaining bytes)`
///
/// where `n` and `e` are the raw unsigned big-endian integer values with any
/// leading DER zero-padding byte stripped (i.e. the 0x00 byte DER adds when the
/// high bit is set is removed, yielding the minimal unsigned representation).
///
/// For a 2048-bit key: n_len = 256, total buf = 4 + 256 + e_len (typically 3).
///
/// Returns `None` if the DER is malformed.
///
/// DECODE SITES MUST validate `4 + n_len <= buf.len()` before slicing -- this
/// encodes an invariant, not a guarantee robust to arbitrary input.  See the
/// bounds checks in `c_get_attribute_value` (CKA_MODULUS / CKA_PUBLIC_EXPONENT).
///
/// PKCS#1 RSAPrivateKey structure (RFC 8017 s.A.1.2):
///   SEQUENCE { version INTEGER, n INTEGER, e INTEGER, d INTEGER, ... }
fn pkcs1_extract_pub_components(der: &[u8]) -> Option<Vec<u8>> {
    // Parse a DER TLV, returning (tag, value_slice, rest).
    fn parse_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        if buf.len() < 2 {
            return None;
        }
        let tag = buf[0];
        let (len, header_len) = if buf[1] & 0x80 == 0 {
            (buf[1] as usize, 2)
        } else {
            let num_len_bytes = (buf[1] & 0x7f) as usize;
            if buf.len() < 2 + num_len_bytes {
                return None;
            }
            let mut len: usize = 0;
            for &b in &buf[2..2 + num_len_bytes] {
                len = len.checked_shl(8)?.checked_add(b as usize)?;
            }
            (len, 2 + num_len_bytes)
        };
        if buf.len() < header_len + len {
            return None;
        }
        Some((tag, &buf[header_len..header_len + len], &buf[header_len + len..]))
    }

    // Skip leading 0x00 padding byte in DER INTEGER encoding.
    fn strip_int_padding(v: &[u8]) -> &[u8] {
        if v.len() > 1 && v[0] == 0x00 {
            &v[1..]
        } else {
            v
        }
    }

    // Unwrap outer SEQUENCE.
    let (tag, seq_body, _) = parse_tlv(der)?;
    if tag != 0x30 {
        return None;
    }

    // version INTEGER (must be 0).
    let (tag, version_val, rest) = parse_tlv(seq_body)?;
    if tag != 0x02 || version_val != [0u8] {
        return None;
    }

    // n INTEGER (modulus).
    let (tag, n_val, rest) = parse_tlv(rest)?;
    if tag != 0x02 {
        return None;
    }
    let n = strip_int_padding(n_val);

    // e INTEGER (public exponent).
    let (tag, e_val, _) = parse_tlv(rest)?;
    if tag != 0x02 {
        return None;
    }
    let e = strip_int_padding(e_val);

    // Encode as: n_len (4 bytes BE) || n || e
    let n_len = n.len() as u32;
    let mut out = Vec::with_capacity(4 + n.len() + e.len());
    out.extend_from_slice(&n_len.to_be_bytes());
    out.extend_from_slice(n);
    out.extend_from_slice(e);
    Some(out)
}

fn getrandom_id(buf: &mut [u8; 16]) -> Result<(), ()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|_| ())
}

// ---------------------------------------------------------------------------
// CK_FUNCTION_LIST -- the table returned by C_GetFunctionList
// ---------------------------------------------------------------------------

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 40 },
    C_Initialize:          Some(c_initialize),
    C_Finalize:            Some(c_finalize),
    C_GetInfo:             Some(c_get_info),
    C_GetFunctionList:     Some(C_GetFunctionList),
    C_GetSlotList:         Some(c_get_slot_list),
    C_GetSlotInfo:         Some(c_get_slot_info),
    C_GetTokenInfo:        Some(c_get_token_info),
    C_GetMechanismList:    Some(c_get_mechanism_list),
    C_GetMechanismInfo:    Some(c_get_mechanism_info),
    C_InitToken:           None,
    C_InitPIN:             None,
    C_SetPIN:              None,
    C_OpenSession:         Some(c_open_session),
    C_CloseSession:        Some(c_close_session),
    C_CloseAllSessions:    Some(c_close_all_sessions),
    C_GetSessionInfo:      Some(c_get_session_info),
    C_GetOperationState:   None,
    C_SetOperationState:   None,
    C_Login:               Some(c_login),
    C_Logout:              Some(c_logout),
    C_CreateObject:        None,
    C_CopyObject:          None,
    C_DestroyObject:       None,
    C_GetObjectSize:       None,
    C_GetAttributeValue:   Some(c_get_attribute_value),
    C_SetAttributeValue:   None,
    C_FindObjectsInit:     Some(c_find_objects_init),
    C_FindObjects:         Some(c_find_objects),
    C_FindObjectsFinal:    Some(c_find_objects_final),
    C_EncryptInit:         Some(c_encrypt_init),
    C_Encrypt:             Some(c_encrypt),
    C_EncryptUpdate:       Some(c_encrypt_update),
    C_EncryptFinal:        Some(c_encrypt_final),
    C_DecryptInit:         Some(c_decrypt_init),
    C_Decrypt:             Some(c_decrypt),
    C_DecryptUpdate:       Some(c_decrypt_update),
    C_DecryptFinal:        Some(c_decrypt_final),
    C_DigestInit:          None,
    C_Digest:              None,
    C_DigestUpdate:        None,
    C_DigestKey:           None,
    C_DigestFinal:         None,
    C_SignInit:            Some(c_sign_init),
    C_Sign:                Some(c_sign),
    C_SignUpdate:          Some(c_sign_update),
    C_SignFinal:           Some(c_sign_final),
    C_SignRecoverInit:     None,
    C_SignRecover:         None,
    C_VerifyInit:          Some(c_verify_init),
    C_Verify:              Some(c_verify),
    C_VerifyUpdate:        Some(c_verify_update),
    C_VerifyFinal:         Some(c_verify_final),
    C_VerifyRecoverInit:   None,
    C_VerifyRecover:       None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate:   None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey:         None,
    C_GenerateKeyPair:     Some(c_generate_key_pair),
    C_WrapKey:             None,
    C_UnwrapKey:           None,
    C_DeriveKey:           None,
    C_SeedRandom:          Some(c_seed_random),
    C_GenerateRandom:      Some(c_generate_random),
    C_GetFunctionStatus:   None,
    C_CancelFunction:      None,
    C_WaitForSlotEvent:    None,
};

// ---------------------------------------------------------------------------
// Test helpers -- gated behind the "test-helpers" Cargo feature.
//
// cfg(test) cannot be used here: integration tests compile usb_hsm as a normal
// library dep, so cfg(test) is not active in this compilation unit.  The feature
// gate achieves the same isolation: production builds omit these symbols entirely;
// tests enable the feature via .cargo/config.toml (see there for the alias).
// ---------------------------------------------------------------------------

#[cfg(feature = "test-helpers")]
/// Simulate a USB mount by recording the .p11k path.
/// The keystore is NOT decrypted here; call C_Login (or token().login()) with the PIN.
///
/// The mount_point is derived from `p11k_path.parent()` -- real USB mounts always
/// place the .p11k file at the root of the mount, so the parent IS the mount point.
/// This preserves the test API signature (single argument) while satisfying
/// `Token::on_mount`'s requirement for an explicit mount_point (bead soft_PKCS11-3hh).
/// Enabled only when the `test-helpers` Cargo feature is active.
pub fn test_mount(p11k_path: &std::path::Path) {
    let _ = op_state();
    let mount_point = p11k_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    // Replace the slot list with a single slot for this path, mirroring
    // what the real USB dispatcher does for a single-.p11k drive.
    let t = Arc::new(Token::new());
    t.on_mount(mount_point, p11k_path);
    *slots().write() = vec![t];
}

#[cfg(feature = "test-helpers")]
/// Simulate mounting multiple .p11k files as independent slots (one per file).
/// `p11k_paths[0]` becomes slot 0, `p11k_paths[1]` becomes slot 1, and so on.
/// The mount point for each slot is derived from its file's parent directory.
/// Enabled only when the `test-helpers` Cargo feature is active.
pub fn test_mount_multi(p11k_paths: &[&std::path::Path]) {
    let _ = op_state();
    let new_slots: Vec<Arc<Token>> = p11k_paths
        .iter()
        .map(|p11k_path| {
            let mount_point = p11k_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let t = Arc::new(Token::new());
            t.on_mount(mount_point, p11k_path);
            t
        })
        .collect();
    *slots().write() = new_slots;
}

#[cfg(feature = "test-helpers")]
/// Simulate a USB unmount, zeroizing all key material.
/// Enabled only when the `test-helpers` Cargo feature is active.
pub fn test_unmount() {
    let guard = slots().read();
    for t in guard.iter() {
        t.on_unmount();
    }
}

#[cfg(feature = "test-helpers")]
/// Reset initialized flag and clear all session state between tests.
/// Enabled only when the `test-helpers` Cargo feature is active.
pub fn test_reset() {
    INITIALIZED.store(false, Ordering::SeqCst);
    op_state().lock().clear();
    {
        let guard = slots().read();
        for t in guard.iter() {
            t.on_unmount();
        }
    }
    stop_usb_watcher();
}

// ---------------------------------------------------------------------------

/// PKCS#11 bootstrap entry point. The only symbol that callers (p11-kit,
/// pkcs11-tool) need to resolve directly from the shared library.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(
    pp_function_list: *mut *mut CK_FUNCTION_LIST,
) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *pp_function_list = &FUNCTION_LIST as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST;
    CKR_OK
}
