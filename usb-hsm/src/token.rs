use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use cryptoki_sys::{
    CK_FLAGS, CK_RV, CK_SESSION_HANDLE,
    CKF_SERIAL_SESSION,
    CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED, CKR_GENERAL_ERROR, CKR_OK,
    CKR_PIN_INCORRECT, CKR_SESSION_COUNT, CKR_SESSION_HANDLE_INVALID, CKR_TOKEN_NOT_PRESENT,
    CKR_TOKEN_NOT_RECOGNIZED, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_NOT_LOGGED_IN,
};

/// Maximum number of concurrent open sessions.
///
/// PKCS#11 does not mandate a specific limit, but hardware tokens typically
/// enforce one; we mirror that practice. 1024 is far beyond any realistic
/// application need while preventing unbounded HashMap growth and the
/// theoretical u64 handle-counter wraparound collision (which would require
/// ~2^64 session open/close cycles -- impossible in practice, but the limit
/// makes the invariant true by construction).
pub const MAX_SESSIONS: usize = 1024;

use crate::keystore::{Keystore, KeystoreError};

// ---------------------------------------------------------------------------
// Public session-info type
// ---------------------------------------------------------------------------

pub struct SessionInfo {
    pub flags: CK_FLAGS,
}

// ---------------------------------------------------------------------------
// Internal state machine
// ---------------------------------------------------------------------------

enum TokenState {
    /// No USB drive mounted; token is completely absent.
    Absent,
    /// USB drive is mounted and a .p11k keystore file was found. The keystore
    /// is NOT yet decrypted -- the PIN has not been provided. The PIN comes
    /// via C_Login, not at mount time.
    Present {
        /// The filesystem root of the USB drive (e.g. /media/user/USB).
        /// Stored alongside p11k_path so on_unmount() can verify that the
        /// unmount event is for THIS drive and not an unrelated USB device.
        /// See bead soft_PKCS11-3hh for the original bug description.
        mount_point: PathBuf,
        p11k_path: PathBuf,
        sessions: HashMap<CK_SESSION_HANDLE, SessionInfo>,
    },
    /// User has called C_Login; keystore is decrypted into mlock'd RAM.
    /// mount_point and p11k_path are retained so logout() can return to Present
    /// state without losing track of which file to reload on the next login, and
    /// so on_unmount() can correctly filter unmount events by drive.
    LoggedIn {
        mount_point: PathBuf,
        p11k_path: PathBuf,
        keystore: Keystore,
        sessions: HashMap<CK_SESSION_HANDLE, SessionInfo>,
    },
    /// USB was removed while sessions were active; key material has been
    /// zeroized. Stale handles return CKR_DEVICE_REMOVED.
    Removed,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Map a KeystoreError to the most specific PKCS#11 error code.
fn map_keystore_err(e: KeystoreError) -> CK_RV {
    match e {
        // Wrong PIN: AES-GCM authentication tag mismatch.
        KeystoreError::BadPin => CKR_PIN_INCORRECT,
        // File not readable or USB removed during read.
        KeystoreError::Io(_) => CKR_DEVICE_ERROR,
        // File exists but is not a .p11k file, is truncated, or is an unsupported version.
        KeystoreError::BadMagic | KeystoreError::Truncated(_) | KeystoreError::UnsupportedFormat(_) => CKR_TOKEN_NOT_RECOGNIZED,
        // Should not happen in normal use; indicates internal crypto or parse error.
        KeystoreError::CborDecode(_) | KeystoreError::Crypto(_) => CKR_GENERAL_ERROR,
    }
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

pub struct Token {
    state: Arc<parking_lot::RwLock<TokenState>>,
}

impl Token {
    pub fn new() -> Self {
        Token {
            state: Arc::new(parking_lot::RwLock::new(TokenState::Absent)),
        }
    }

    // -----------------------------------------------------------------------
    // USB-watcher callbacks
    // -----------------------------------------------------------------------

    /// Called by the USB watcher when a drive containing a .p11k file is mounted.
    /// Stores the mount point and keystore path for later use by login();
    /// does NOT decrypt the keystore.
    ///
    /// `mount_point` is the filesystem root of the USB drive (e.g. `/media/u/USB`).
    /// `p11k_path` is the full path to the `.p11k` file found at the mount root.
    /// Both are stored so `on_unmount` can correctly identify which drive's removal
    /// should trigger token zeroization (see `is_at_mount` / `on_unmount`).
    ///
    /// The PIN is NOT provided here -- it comes from the application via C_Login.
    /// This is the correct PKCS#11 model: the library discovers the token's presence,
    /// and the application supplies credentials when it calls C_Login.
    pub fn on_mount(&self, mount_point: &std::path::Path, p11k_path: &std::path::Path) {
        let mut guard = self.state.write();
        match &*guard {
            TokenState::Absent | TokenState::Removed => {
                *guard = TokenState::Present {
                    mount_point: mount_point.to_path_buf(),
                    p11k_path: p11k_path.to_path_buf(),
                    sessions: HashMap::new(),
                };
            }
            TokenState::Present { .. } | TokenState::LoggedIn { .. } => {
                // Already mounted; ignore duplicate mount event. The keystore path
                // from the first mount remains authoritative.
                //
                // IMPORTANT: this means that if the USB drive is physically moved to a
                // different mount point (without calling on_unmount first), the stored
                // p11k_path will be stale.  A subsequent C_Login will fail with
                // CKR_DEVICE_ERROR (file not found).
                //
                // Applications that re-mount a drive at a new path MUST call C_Finalize
                // followed by C_Initialize to reset the token to Absent state before the
                // new on_mount event will be accepted.  This is consistent with the
                // PKCS#11 model: a token removal event always precedes a re-insertion,
                // and the removal event resets state to Removed/Absent.
            }
        }
    }

    /// Returns `true` if the current token's mount point matches `candidate`.
    ///
    /// Used by the USB dispatcher to determine whether a USB removal event
    /// is for the active token drive or an unrelated USB device. Comparing by
    /// mount point (not p11k_path) is correct because the unmount event carries
    /// the mount point, not the path to a specific file.
    ///
    /// Returns `false` in `Absent` and `Removed` states (no active mount to match).
    pub fn is_at_mount(&self, candidate: &std::path::Path) -> bool {
        let guard = self.state.read();
        match &*guard {
            TokenState::Present { mount_point, .. }
            | TokenState::LoggedIn { mount_point, .. } => mount_point == candidate,
            TokenState::Absent | TokenState::Removed => false,
        }
    }

    /// Called by the USB watcher when the active token drive is unmounted.
    /// Zeroizes all key material immediately. Any live sessions subsequently
    /// return `CKR_DEVICE_REMOVED`.
    ///
    /// Callers MUST pre-filter using `is_at_mount()` before calling this function.
    /// The dispatcher in lib.rs only calls `on_unmount` when `is_at_mount(mount_point)`
    /// returns `true`, preventing an unrelated USB device removal from destroying
    /// the active token's key material (the bug fixed by bead soft_PKCS11-3hh).
    pub fn on_unmount(&self) {
        let mut guard = self.state.write();
        *guard = TokenState::Removed;
    }

    // -----------------------------------------------------------------------
    // PKCS#11 operations
    // -----------------------------------------------------------------------

    /// Returns `true` if a keystore path is known (Present or LoggedIn).
    pub fn get_token_present(&self) -> bool {
        let guard = self.state.read();
        matches!(*guard, TokenState::Present { .. } | TokenState::LoggedIn { .. })
    }

    /// C_Login: loads and decrypts the keystore using the provided PIN.
    /// Transitions Present -> LoggedIn on success.
    ///
    /// If the PIN is wrong the state returns to Present so the caller can retry.
    /// This matches standard PKCS#11 behavior: a failed C_Login does not invalidate
    /// the session or require the application to call C_Initialize again.
    pub fn login(&self, pin: &[u8]) -> CK_RV {
        let mut guard = self.state.write();
        match &*guard {
            TokenState::Absent => CKR_TOKEN_NOT_PRESENT,
            TokenState::Removed => CKR_DEVICE_REMOVED,
            TokenState::LoggedIn { .. } => CKR_USER_ALREADY_LOGGED_IN,
            TokenState::Present { .. } => {
                // CONCURRENCY SAFETY (soft_PKCS11-44g): this write lock is held for
                // the entire duration of login(), including the Keystore::load() call.
                // Any concurrent on_unmount() call will block waiting for the write lock
                // and take effect AFTER login() completes -- there is no window where an
                // unmount event can be lost or interleaved with the state transition.
                //
                // Move data out so we can call Keystore::load without holding a
                // borrow on guard. Use Removed as a transient placeholder.
                let old = std::mem::replace(&mut *guard, TokenState::Removed);
                let (mount_point, p11k_path, sessions) = match old {
                    TokenState::Present { mount_point, p11k_path, sessions } => {
                        (mount_point, p11k_path, sessions)
                    }
                    _ => unreachable!(),
                };
                // No failed-PIN attempt counter is maintained here. This is intentional.
                //
                // Rationale (soft_PKCS11-lka): the threat model for usb-hsm is an attacker
                // who obtains the laptop OR the USB drive -- not both. An attacker who can
                // call C_Login repeatedly must already have the running machine AND the
                // physical USB drive inserted. That scenario (attacker at the console with
                // both the machine and the drive) is outside the stated threat model (see
                // PRFAQ.md and README.md s.Threat Model); a soft token provides no defence
                // against a physically-present, privileged attacker regardless.
                //
                // The only form of brute-force resistance offered is PBKDF2-HMAC-SHA256 at
                // >=200,000 iterations (~=0.5 s/attempt), which slows online attacks to
                // ~2 attempts/second. A 6-char alphanumeric PIN (the minimum) has ~56 billion
                // combinations; a 6-digit numeric PIN has 10^6 -- operators who use numeric
                // PINs should be aware of the online-brute-force exposure if an attacker
                // has physical access to both the machine and the drive.
                //
                // A future version could add exponential backoff here if the threat model
                // expands to include unattended machines with the drive permanently inserted.
                let keystore = match Keystore::load(&p11k_path, pin) {
                    Ok(ks) => ks,
                    Err(e) => {
                        // Restore Present state -- the caller may retry with the correct PIN.
                        *guard = TokenState::Present { mount_point, p11k_path, sessions };
                        return map_keystore_err(e);
                    }
                };
                *guard = TokenState::LoggedIn { mount_point, p11k_path, keystore, sessions };
                CKR_OK
            }
        }
    }

    /// C_Logout: drops the decrypted keystore (ZeroizeOnDrop fires), transitions
    /// LoggedIn -> Present so the user can call C_Login again without remounting.
    ///
    /// Per PKCS#11 s.11.6: open sessions survive C_Logout as public sessions.
    pub fn logout(&self) -> CK_RV {
        let mut guard = self.state.write();
        match &*guard {
            TokenState::Absent => CKR_TOKEN_NOT_PRESENT,
            TokenState::Removed => CKR_DEVICE_REMOVED,
            TokenState::Present { .. } => CKR_USER_NOT_LOGGED_IN,
            TokenState::LoggedIn { .. } => {
                let old = std::mem::replace(&mut *guard, TokenState::Removed);
                let (mount_point, p11k_path, sessions) = match old {
                    // keystore is dropped here; ZeroizeOnDrop fires immediately.
                    TokenState::LoggedIn { mount_point, p11k_path, sessions, .. } => {
                        (mount_point, p11k_path, sessions)
                    }
                    _ => unreachable!(),
                };
                *guard = TokenState::Present { mount_point, p11k_path, sessions };
                CKR_OK
            }
        }
    }

    /// C_OpenSession: records a caller-allocated session handle in the token's
    /// sessions map.
    ///
    /// The handle must be allocated externally (by lib.rs's global counter) so
    /// that handles are unique across all slots, not just within one token.
    /// Token only enforces the per-slot session cap and the Absent/Removed guards.
    ///
    /// Standard PKCS#11 flow: `C_OpenSession` before `C_Login` (s.11.5). Sessions
    /// opened in `Present` state are public sessions; `with_keystore` returns
    /// `CKR_USER_NOT_LOGGED_IN` until login.  `login()` carries sessions forward
    /// into `LoggedIn` state (s.11.6) so the handle remains valid after login.
    ///
    /// Returns `CKR_OK` on success.
    pub fn open_session(&self, flags: CK_FLAGS, handle: CK_SESSION_HANDLE) -> CK_RV {
        let mut guard = self.state.write();
        match &mut *guard {
            TokenState::Absent => CKR_TOKEN_NOT_PRESENT,
            TokenState::Removed => CKR_DEVICE_REMOVED,
            TokenState::Present { sessions, .. } | TokenState::LoggedIn { sessions, .. } => {
                if sessions.len() >= MAX_SESSIONS {
                    return CKR_SESSION_COUNT;
                }
                sessions.insert(handle, SessionInfo { flags: flags | CKF_SERIAL_SESSION });
                CKR_OK
            }
        }
    }

    /// C_CloseSession: removes a session by handle.
    /// Valid in both Present and LoggedIn states (PKCS#11 s.11.5).
    pub fn close_session(&self, handle: CK_SESSION_HANDLE) -> CK_RV {
        let mut guard = self.state.write();
        match &mut *guard {
            TokenState::Absent => CKR_TOKEN_NOT_PRESENT,
            TokenState::Removed => CKR_DEVICE_REMOVED,
            TokenState::Present { sessions, .. } | TokenState::LoggedIn { sessions, .. } => {
                if sessions.remove(&handle).is_some() {
                    CKR_OK
                } else {
                    CKR_SESSION_HANDLE_INVALID
                }
            }
        }
    }

    /// C_CloseAllSessions: closes all sessions and transitions to `Present`.
    pub fn close_all_sessions(&self) -> CK_RV {
        let mut guard = self.state.write();
        match &*guard {
            TokenState::Absent => CKR_TOKEN_NOT_PRESENT,
            TokenState::Removed => CKR_DEVICE_REMOVED,
            TokenState::Present { .. } => {
                // Clear any residual public sessions; retain mount_point + p11k_path
                // so a subsequent C_Login can still find the keystore.
                let old = std::mem::replace(&mut *guard, TokenState::Removed);
                let (mount_point, p11k_path) = match old {
                    TokenState::Present { mount_point, p11k_path, .. } => (mount_point, p11k_path),
                    _ => unreachable!(),
                };
                *guard = TokenState::Present { mount_point, p11k_path, sessions: HashMap::new() };
                CKR_OK
            }
            TokenState::LoggedIn { .. } => {
                let old = std::mem::replace(&mut *guard, TokenState::Removed);
                let (mount_point, p11k_path, keystore) = match old {
                    TokenState::LoggedIn { mount_point, p11k_path, keystore, .. } => {
                        (mount_point, p11k_path, keystore)
                    }
                    _ => unreachable!(),
                };
                // Explicitly drop keystore (ZeroizeOnDrop fires) before going back to Present.
                drop(keystore);
                *guard = TokenState::Present { mount_point, p11k_path, sessions: HashMap::new() };
                CKR_OK
            }
        }
    }

    /// Runs `f` with a reference to the `Keystore`. Only succeeds in the
    /// `LoggedIn` state; returns `Err(CK_RV)` otherwise.
    pub fn with_keystore<F, R>(&self, f: F) -> Result<R, CK_RV>
    where
        F: FnOnce(&Keystore) -> R,
    {
        let guard = self.state.read();
        match &*guard {
            TokenState::Absent => Err(CKR_TOKEN_NOT_PRESENT),
            TokenState::Removed => Err(CKR_DEVICE_REMOVED),
            TokenState::Present { .. } => Err(CKR_USER_NOT_LOGGED_IN),
            TokenState::LoggedIn { keystore, .. } => Ok(f(keystore)),
        }
    }
}

impl Default for Token {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // 1. new() -> state is Absent (no keystore needed; always runs)
    #[test]
    fn test_new_is_absent() {
        let token = Token::new();
        assert!(!token.get_token_present());
    }

    // login() from Absent -> CKR_TOKEN_NOT_PRESENT (no keystore needed; always runs)
    #[test]
    fn test_login_from_absent() {
        let token = Token::new();
        assert_eq!(token.login(b"anypin"), CKR_TOKEN_NOT_PRESENT);
    }

    // The remaining tests create a keystore with 1 PBKDF2 iteration so they run fast.
    // Without `test-helpers`, MIN_KDF_ITERATIONS=100_000 and Keystore::load rejects
    // the 1-iteration file -- these tests are therefore gated on `test-helpers`.
    #[cfg(feature = "test-helpers")]
    mod with_keystore {
        use super::super::*;
        use crate::keystore::{KeyEntry, KeyType};
        use cryptoki_sys::{CKF_RW_SESSION, CKR_SESSION_COUNT};
        use tempfile::NamedTempFile;

        /// Mount helper for unit tests: derives mount_point from the temp file's
        /// parent directory. Real USB mounts place the .p11k at the filesystem
        /// root, so parent() IS the mount point. Tests use temp files in the
        /// system tmp dir, so parent() is always Some(...).
        fn do_mount(token: &Token, file: &NamedTempFile) {
            let path = file.path();
            let mount_point = path.parent().expect("tempfile must have a parent directory");
            token.on_mount(mount_point, path);
        }

        /// Write a minimal keystore to a temp file and return the file handle.
        /// Uses 1 PBKDF2 iteration so tests are fast; only valid when test-helpers
        /// relaxes MIN_KDF_ITERATIONS to 1.
        fn make_keystore_file(pin: &[u8]) -> NamedTempFile {
            let entries = vec![KeyEntry {
                id: [0u8; 16],
                label: "test-key".to_string(),
                key_type: KeyType::Ec,
                // P-256 scalar must be exactly 32 bytes (EC_P256_SCALAR_BYTES).
                // These tests exercise token state transitions, not cryptographic
                // operations, so the value is arbitrary as long as length is correct.
                der_bytes: vec![0xde; 32],
                cert_der: None,
                pub_bytes: None,
            }];
            let blob = Keystore::create(entries, pin, 1).expect("create keystore");
            let file = NamedTempFile::new().expect("tempfile");
            std::fs::write(file.path(), &blob).expect("write keystore");
            file
        }

        // 2. on_mount() records the path and transitions to Present (no PIN required)
        #[test]
        fn test_on_mount_makes_present() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert!(token.get_token_present());
        }

        // 3. login() from Present decrypts the keystore -> LoggedIn
        #[test]
        fn test_login_from_present() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            let rv = token.login(pin);
            assert_eq!(rv, CKR_OK);
            token.with_keystore(|ks| assert!(!ks.entries().is_empty())).expect("with_keystore");
        }

        // 4. logout() from LoggedIn -> Present
        #[test]
        fn test_logout_from_logged_in() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            assert_eq!(token.logout(), CKR_OK);
            assert!(token.get_token_present());
            assert_eq!(token.with_keystore(|_| ()).unwrap_err(), CKR_USER_NOT_LOGGED_IN);
        }

        // 5. on_unmount() from Present -> Removed state
        #[test]
        fn test_on_unmount_from_present() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            token.on_unmount();
            assert!(!token.get_token_present());
        }

        // 6. on_unmount() from LoggedIn -> Removed, key material zeroized
        #[test]
        fn test_on_unmount_from_logged_in() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            token.on_unmount();
            assert!(!token.get_token_present());
            assert_eq!(token.with_keystore(|_| ()).unwrap_err(), CKR_DEVICE_REMOVED);
        }

        // 8. open_session() from Present (not logged in) -> CKR_OK (public session)
        //
        // PKCS#11 s.11.5 does NOT list CKR_USER_NOT_LOGGED_IN as a valid return code
        // for C_OpenSession. Standard apps open sessions *before* calling C_Login.
        // A session opened in Present state is a public session; keystore-requiring
        // operations will return CKR_USER_NOT_LOGGED_IN until the caller logs in.
        #[test]
        fn test_open_session_before_login() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            // Handle is caller-provided since Token::open_session no longer allocates.
            let rv = token.open_session(CKF_RW_SESSION | CKF_SERIAL_SESSION, 1);
            assert_eq!(rv, CKR_OK, "open_session in Present state must succeed (public session)");
        }

        // 9. open_session() from LoggedIn -> CKR_OK + valid handle
        #[test]
        fn test_open_session_logged_in() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            let rv = token.open_session(CKF_RW_SESSION | CKF_SERIAL_SESSION, 1);
            assert_eq!(rv, CKR_OK);
        }

        // 10. close_session() with valid handle -> CKR_OK
        #[test]
        fn test_close_session_valid_handle() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            assert_eq!(token.open_session(CKF_RW_SESSION | CKF_SERIAL_SESSION, 1), CKR_OK);
            assert_eq!(token.close_session(1), CKR_OK);
        }

        // 11. close_session() with invalid handle -> CKR_SESSION_HANDLE_INVALID
        #[test]
        fn test_close_session_invalid_handle() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            assert_eq!(token.close_session(9999), CKR_SESSION_HANDLE_INVALID);
        }

        // 12. login() when already LoggedIn -> CKR_USER_ALREADY_LOGGED_IN
        #[test]
        fn test_login_already_logged_in() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            assert_eq!(token.login(pin), CKR_USER_ALREADY_LOGGED_IN);
        }

        // 13. close_all_sessions() -> key material zeroized, state back to Present
        #[test]
        fn test_close_all_sessions() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            let rv1 = token.open_session(CKF_RW_SESSION | CKF_SERIAL_SESSION, 1);
            let rv2 = token.open_session(CKF_SERIAL_SESSION, 2);
            assert_eq!(rv1, CKR_OK);
            assert_eq!(rv2, CKR_OK);
            assert_eq!(token.close_all_sessions(), CKR_OK);
            assert!(token.get_token_present());
            assert_eq!(token.with_keystore(|_| ()).unwrap_err(), CKR_USER_NOT_LOGGED_IN);
        }

        // on_unmount with open sessions -> CKR_DEVICE_REMOVED on stale handles
        #[test]
        fn test_stale_handle_after_unmount() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            assert_eq!(token.open_session(CKF_RW_SESSION | CKF_SERIAL_SESSION, 1), CKR_OK);
            token.on_unmount();
            assert_eq!(token.close_session(1), CKR_DEVICE_REMOVED);
        }

        // Sessions opened before C_Logout survive into Present state (PKCS#11 s.11.6).
        #[test]
        fn test_close_session_survives_logout() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            assert_eq!(token.open_session(CKF_RW_SESSION | CKF_SERIAL_SESSION, 1), CKR_OK);
            // Logout transitions to Present; session handle must remain valid.
            assert_eq!(token.logout(), CKR_OK);
            assert_eq!(token.close_session(1), CKR_OK, "pre-logout session must be closeable after logout");
        }

        // Unknown session handle after logout returns CKR_SESSION_HANDLE_INVALID.
        #[test]
        fn test_close_unknown_session_after_logout() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);
            assert_eq!(token.logout(), CKR_OK);
            assert_eq!(token.close_session(9999), CKR_SESSION_HANDLE_INVALID);
        }

        // MAX_SESSIONS cap is enforced; exceeding it returns CKR_SESSION_COUNT
        // and re-opens successfully after one session is closed (soft_PKCS11-8ex).
        #[test]
        fn test_session_count_limit() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            assert_eq!(token.login(pin), CKR_OK);

            // Open MAX_SESSIONS sessions with handles 1..=MAX_SESSIONS.
            let mut handles: Vec<CK_SESSION_HANDLE> = Vec::with_capacity(MAX_SESSIONS);
            for i in 0..MAX_SESSIONS {
                let h = (i + 1) as CK_SESSION_HANDLE;
                let rv = token.open_session(CKF_SERIAL_SESSION, h);
                assert_eq!(rv, CKR_OK, "session {i} of {MAX_SESSIONS} should open successfully");
                handles.push(h);
            }

            // One past the cap must fail (handle is not stored since rv != CKR_OK).
            let rv = token.open_session(CKF_SERIAL_SESSION, (MAX_SESSIONS + 1) as CK_SESSION_HANDLE);
            assert_eq!(rv, CKR_SESSION_COUNT, "session at cap+1 must return CKR_SESSION_COUNT");

            // After closing one, the next open must succeed.
            assert_eq!(token.close_session(handles[0]), CKR_OK);
            let rv = token.open_session(CKF_SERIAL_SESSION, (MAX_SESSIONS + 1) as CK_SESSION_HANDLE);
            assert_eq!(rv, CKR_OK, "open after freeing a slot must succeed");
        }

        // is_at_mount() returns true for the active drive, false for others (soft_PKCS11-3hh).
        // This test verifies that an unrelated path does not match and that on_unmount()
        // called via is_at_mount() guard correctly protects the token.
        #[test]
        fn test_is_at_mount_matches_only_active_drive() {
            let pin = b"testpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            // Mount using the file's parent directory as the mount point (via do_mount).
            do_mount(&token, &file);
            let active_mount = file.path().parent().expect("tempfile has parent");

            // The active mount must match.
            assert!(token.is_at_mount(active_mount), "active mount point must match");

            // An unrelated path must not match.
            let unrelated = std::path::Path::new("/mnt/other_usb");
            assert!(!token.is_at_mount(unrelated), "unrelated path must not match");

            // Simulating the dispatcher: only unmount if is_at_mount returns true.
            // An unrelated unmount must leave the token intact.
            if token.is_at_mount(unrelated) {
                token.on_unmount(); // should NOT be called
            }
            assert!(token.get_token_present(), "token must survive unrelated unmount event");

            // The real drive's unmount must go through.
            if token.is_at_mount(active_mount) {
                token.on_unmount();
            }
            assert!(!token.get_token_present(), "token must be removed after correct unmount");
        }

        // login() with wrong PIN -> CKR_PIN_INCORRECT, state reverts to Present
        #[test]
        fn test_login_wrong_pin() {
            let pin = b"correctpin";
            let file = make_keystore_file(pin);
            let token = Token::new();
            do_mount(&token, &file);
            let rv = token.login(b"wrongpin");
            assert_eq!(rv, CKR_PIN_INCORRECT, "wrong PIN must return CKR_PIN_INCORRECT");
            // State must revert to Present so the caller can retry.
            assert!(token.get_token_present(), "token must still be present after wrong PIN");
            // Retry with correct PIN must succeed.
            assert_eq!(token.login(pin), CKR_OK, "correct PIN must succeed after wrong PIN retry");
        }
    }
}
