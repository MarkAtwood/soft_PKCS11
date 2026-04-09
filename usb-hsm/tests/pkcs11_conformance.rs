// pkcs11_conformance.rs -- structural conformance tests for the PKCS#11 C ABI.
//
// Test integrity rules:
// - Tests use an external oracle (inspecting struct fields against PKCS#11 v2.40
//   specification constants) rather than checking round-trips through our own code.
// - No test depends on token-present state; these tests work without a USB device.
// - C_GetFunctionList is the only directly-linked symbol; everything else is called
//   through the returned function list, matching how real PKCS#11 callers behave.

use cryptoki_sys::{
    CK_ATTRIBUTE, CK_FLAGS, CK_FUNCTION_LIST, CK_INFO, CK_MECHANISM, CK_MECHANISM_INFO,
    CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_RSA_PKCS_OAEP_PARAMS, CK_RSA_PKCS_PSS_PARAMS,
    CK_SESSION_HANDLE, CK_SLOT_ID, CK_SLOT_INFO, CK_ULONG,
    CKA_KEY_TYPE,
    CKF_DECRYPT, CKF_ENCRYPT, CKF_REMOVABLE_DEVICE, CKF_RW_SESSION, CKF_SERIAL_SESSION,
    CKF_SIGN, CKF_VERIFY,
    CKG_MGF1_SHA256,
    CKK_EC, CKK_RSA,
    CKM_AES_CBC, CKM_ECDSA, CKM_ECDSA_SHA256,
    CKM_ML_DSA, CKM_ML_KEM,
    CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS,
    CKM_SHA_1, CKM_SHA256,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_FUNCTION_NOT_SUPPORTED, CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE,
    CKR_SESSION_HANDLE_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_USER_TYPE_INVALID,
    CKU_USER, CKU_SO,
    CKZ_DATA_SPECIFIED,
};
use cryptoki_sys::CK_BYTE_PTR;
use std::io::Write as _;
use std::sync::Mutex;
use tempfile::NamedTempFile;
use usb_hsm::keystore::{KeyEntry, KeyType, Keystore};

// Serialize conformance tests: they share global INITIALIZED state.
static LOCK: Mutex<()> = Mutex::new(());

/// Get and validate the function list; returns a static reference.
unsafe fn function_list() -> &'static CK_FUNCTION_LIST {
    let mut pp: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let rv = usb_hsm::C_GetFunctionList(&mut pp);
    assert_eq!(rv, CKR_OK, "C_GetFunctionList returned {rv}");
    assert!(!pp.is_null(), "C_GetFunctionList set null pointer");
    &*pp
}

// ---------------------------------------------------------------------------
// Test 1: C_GetFunctionList returns non-null, version 2.40
// ---------------------------------------------------------------------------

#[test]
fn c_get_function_list_version() {
    let _g = LOCK.lock().unwrap();
    unsafe {
        let fl = function_list();
        assert_eq!(fl.version.major, 2, "cryptoki major version");
        assert_eq!(fl.version.minor, 40, "cryptoki minor version");
        assert!(fl.C_Initialize.is_some(), "C_Initialize must be present");
        assert!(fl.C_GetSlotList.is_some(), "C_GetSlotList must be present");
        assert!(fl.C_Login.is_some(), "C_Login must be present");
    }
}

// ---------------------------------------------------------------------------
// Test 2: C_GetInfo returns library information
// ---------------------------------------------------------------------------

#[test]
fn c_get_info_library_fields() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        let rv = fl.C_Initialize.unwrap()(std::ptr::null_mut());
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize: {rv}"
        );

        let mut info: CK_INFO = std::mem::zeroed();
        let rv = fl.C_GetInfo.unwrap()(&mut info);
        assert_eq!(rv, CKR_OK, "C_GetInfo");
        assert_eq!(info.cryptokiVersion.major, 2, "PKCS#11 major");
        assert_eq!(info.cryptokiVersion.minor, 40, "PKCS#11 minor");
        // manufacturerID is space-padded -- must not be all zeros.
        assert!(info.manufacturerID.iter().any(|&b| b != 0), "manufacturerID empty");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 3: C_GetSlotList always returns exactly 1 slot (slot 0)
// ---------------------------------------------------------------------------

#[test]
fn c_get_slot_list_one_slot() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        // Query count.
        let mut count: CK_ULONG = 0;
        let rv = fl.C_GetSlotList.unwrap()(0, std::ptr::null_mut(), &mut count);
        assert_eq!(rv, CKR_OK, "C_GetSlotList count");
        assert_eq!(count, 1, "must report exactly 1 slot");

        // Retrieve slot IDs.
        let mut slot_id: CK_SLOT_ID = 0xFF;
        let mut count2: CK_ULONG = 1;
        let rv = fl.C_GetSlotList.unwrap()(0, &mut slot_id, &mut count2);
        assert_eq!(rv, CKR_OK, "C_GetSlotList fill");
        assert_eq!(slot_id, 0, "slot ID must be 0");
        assert_eq!(count2, 1);

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 4: C_GetSlotInfo returns well-formed slot descriptor
// ---------------------------------------------------------------------------

#[test]
fn c_get_slot_info_fields() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let mut info: CK_SLOT_INFO = std::mem::zeroed();
        let rv = fl.C_GetSlotInfo.unwrap()(0, &mut info);
        assert_eq!(rv, CKR_OK, "C_GetSlotInfo");

        // Slot description must be space-padded (non-zero).
        assert!(info.slotDescription.iter().any(|&b| b != 0), "slotDescription empty");
        // CKF_REMOVABLE_DEVICE must be set (this is a USB device).
        assert!(info.flags & CKF_REMOVABLE_DEVICE != 0, "CKF_REMOVABLE_DEVICE must be set");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 5: C_GetTokenInfo without a mounted token returns CKR_TOKEN_NOT_PRESENT
// ---------------------------------------------------------------------------

#[test]
fn c_get_token_info_no_token() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let rv = fl.C_GetTokenInfo.unwrap()(0, std::ptr::null_mut());
        assert_eq!(rv, CKR_TOKEN_NOT_PRESENT, "no USB -> CKR_TOKEN_NOT_PRESENT");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 6: C_GetMechanismList returns all 7 supported mechanisms.
//
// CKM_RSA_PKCS is intentionally absent: wolfcrypt hashes the input internally,
// double-hashing conformant callers that pre-hash and wrap DigestInfo.
// Absent is better than silently wrong. See bead soft_PKCS11-t72.
// ---------------------------------------------------------------------------

#[test]
fn c_get_mechanism_list_expected() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let mut count: CK_ULONG = 0;
        let rv = fl.C_GetMechanismList.unwrap()(0, std::ptr::null_mut(), &mut count);
        assert_eq!(rv, CKR_OK, "C_GetMechanismList count");
        assert_eq!(count, 6, "expected 6 mechanisms");

        let mut mechs = vec![0u64; count as usize];
        let rv = fl.C_GetMechanismList.unwrap()(0, mechs.as_mut_ptr(), &mut count);
        assert_eq!(rv, CKR_OK, "C_GetMechanismList fill");

        let expected: &[CK_MECHANISM_TYPE] = &[
            CKM_RSA_PKCS_PSS,
            CKM_RSA_PKCS_OAEP,
            CKM_ECDSA,
            CKM_ECDSA_SHA256,
            CKM_ML_DSA,
            CKM_ML_KEM,
        ];
        for &exp in expected {
            assert!(mechs.contains(&exp), "mechanism {exp:#x} missing from list");
        }

        // CKM_RSA_PKCS must NOT appear -- it is removed until wolfssl-rs exposes
        // a raw padding path that does not hash the input internally.
        assert!(!mechs.contains(&CKM_RSA_PKCS), "CKM_RSA_PKCS must not be advertised");

        // Verify sign-capable mechanisms report CKF_SIGN.
        for &mech in &[CKM_RSA_PKCS_PSS, CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ML_DSA] {
            let mut info: CK_MECHANISM_INFO = std::mem::zeroed();
            let rv = fl.C_GetMechanismInfo.unwrap()(0, mech, &mut info);
            assert_eq!(rv, CKR_OK, "C_GetMechanismInfo({mech:#x})");
            assert!(info.flags & CKF_SIGN != 0, "mech {mech:#x} must have CKF_SIGN");
            assert!(info.flags & CKF_VERIFY != 0, "mech {mech:#x} must have CKF_VERIFY");
        }

        // ML-KEM is encrypt/decrypt only -- must report CKF_ENCRYPT | CKF_DECRYPT.
        {
            let mut info: CK_MECHANISM_INFO = std::mem::zeroed();
            let rv = fl.C_GetMechanismInfo.unwrap()(0, CKM_ML_KEM, &mut info);
            assert_eq!(rv, CKR_OK, "C_GetMechanismInfo(CKM_ML_KEM)");
            assert!(info.flags & CKF_ENCRYPT != 0, "CKM_ML_KEM must have CKF_ENCRYPT");
            assert!(info.flags & CKF_DECRYPT != 0, "CKM_ML_KEM must have CKF_DECRYPT");
            assert_eq!(info.flags & CKF_SIGN, 0, "CKM_ML_KEM must not have CKF_SIGN");
        }

        // CKM_RSA_PKCS must return CKR_MECHANISM_INVALID from C_GetMechanismInfo.
        let mut info: CK_MECHANISM_INFO = std::mem::zeroed();
        let rv = fl.C_GetMechanismInfo.unwrap()(0, CKM_RSA_PKCS, &mut info);
        assert_eq!(rv, CKR_MECHANISM_INVALID, "C_GetMechanismInfo(CKM_RSA_PKCS) must return CKR_MECHANISM_INVALID");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 7: C_Login rejects CKU_SO (no Security Officer role on this token)
// ---------------------------------------------------------------------------

#[test]
fn c_login_rejects_cku_so() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        // The session handle is ignored by this implementation; use a dummy value.
        // The user-type check fires before any session or token access.
        let dummy_session: CK_SESSION_HANDLE = 1;
        let rv = fl.C_Login.unwrap()(dummy_session, CKU_SO, std::ptr::null_mut(), 0);
        assert_eq!(rv, CKR_USER_TYPE_INVALID, "CKU_SO must be rejected with CKR_USER_TYPE_INVALID");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 8: C_GenerateRandom requires a valid session handle (PKCS#11 s.11.15)
// ---------------------------------------------------------------------------

#[test]
fn c_generate_random_requires_valid_session() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let mut buf = [0u8; 16];
        let bogus_session: CK_SESSION_HANDLE = 0xDEAD;
        let rv = fl.C_GenerateRandom.unwrap()(bogus_session, buf.as_mut_ptr(), buf.len() as CK_ULONG);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "bogus session handle must return CKR_SESSION_HANDLE_INVALID");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 9: C_SeedRandom requires a valid session handle (PKCS#11 s.11.15)
// ---------------------------------------------------------------------------

#[test]
fn c_seed_random_requires_valid_session() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let bogus_session: CK_SESSION_HANDLE = 0xBEEF;
        let seed = [0u8; 32];
        let rv = fl.C_SeedRandom.unwrap()(bogus_session, seed.as_ptr() as CK_BYTE_PTR, seed.len() as CK_ULONG);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "bogus session must return CKR_SESSION_HANDLE_INVALID");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 10: CKM_RSA_PKCS_PSS parameter validation (soft_PKCS11-km3)
//
// validate_mechanism_params() fires before session/key lookup, so these tests
// work without a USB device or a real key -- the parameter check returns before
// reaching C_SignInit's session validation.
// ---------------------------------------------------------------------------

#[test]
fn c_sign_init_pss_null_params_rejected() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        // pParameter is null -> CKR_MECHANISM_PARAM_INVALID before session check.
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = fl.C_SignInit.unwrap()(99, &mut mech, 1);
        assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID, "null PSS params must be rejected");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

#[test]
fn c_sign_init_pss_wrong_hash_rejected() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        // SHA-1 hash algorithm is not supported (SHA-256 only).
        let mut params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA_1,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_SignInit.unwrap()(99, &mut mech, 1);
        assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID, "SHA-1 PSS must be rejected");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

#[test]
fn c_sign_init_pss_correct_params_passes_param_check() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        // Correct SHA-256 + MGF1-SHA256 params must pass param validation and
        // reach session lookup (session 99 is bogus -> CKR_SESSION_HANDLE_INVALID,
        // not CKR_MECHANISM_PARAM_INVALID).
        let mut params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_SignInit.unwrap()(99, &mut mech, 1);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID,
            "correct PSS params must pass param check and reach session lookup");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 11: CKM_RSA_PKCS_OAEP parameter validation (soft_PKCS11-km3)
// ---------------------------------------------------------------------------

#[test]
fn c_encrypt_init_oaep_null_params_rejected() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = fl.C_EncryptInit.unwrap()(99, &mut mech, 1);
        assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID, "null OAEP params must be rejected");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

#[test]
fn c_encrypt_init_oaep_wrong_hash_rejected() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let mut params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA_1,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: std::ptr::null_mut(),
            ulSourceDataLen: 0,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_EncryptInit.unwrap()(99, &mut mech, 1);
        assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID, "SHA-1 OAEP must be rejected");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

#[test]
fn c_encrypt_init_oaep_correct_params_passes_param_check() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        // Correct SHA-256 + MGF1-SHA256 params must pass param validation and
        // reach session lookup (session 99 is bogus -> CKR_SESSION_HANDLE_INVALID).
        let mut params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: std::ptr::null_mut(),
            ulSourceDataLen: 0,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_EncryptInit.unwrap()(99, &mut mech, 1);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID,
            "correct OAEP params must pass param check and reach session lookup");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 16: C_GetMechanismInfo -- CKM_RSA_PKCS_OAEP flags and key sizes
//          (soft_PKCS11-17n)
// ---------------------------------------------------------------------------

#[test]
fn c_get_mechanism_info_oaep_has_encrypt_decrypt_not_sign() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let mut info: CK_MECHANISM_INFO = std::mem::zeroed();
        let rv = fl.C_GetMechanismInfo.unwrap()(0, CKM_RSA_PKCS_OAEP, &mut info);
        assert_eq!(rv, CKR_OK, "C_GetMechanismInfo(CKM_RSA_PKCS_OAEP)");

        // PKCS#11 s.12.1.7: OAEP is an encrypt/decrypt mechanism, not a sign mechanism.
        // Verifying both the positive and negative flags prevents a "flags = 0xFFFFFFFF"
        // bug from passing (the CKF_SIGN check alone would catch that but not the inverse).
        assert!(info.flags & CKF_ENCRYPT != 0, "CKM_RSA_PKCS_OAEP must have CKF_ENCRYPT");
        assert!(info.flags & CKF_DECRYPT != 0, "CKM_RSA_PKCS_OAEP must have CKF_DECRYPT");
        assert!(info.flags & CKF_SIGN == 0,    "CKM_RSA_PKCS_OAEP must NOT have CKF_SIGN");
        assert!(info.flags & CKF_VERIFY == 0,  "CKM_RSA_PKCS_OAEP must NOT have CKF_VERIFY");

        // Key size limits for RSA OAEP: minimum 512 bits, maximum 4096 bits.
        assert_eq!(info.ulMinKeySize, 512,  "CKM_RSA_PKCS_OAEP min key size must be 512 bits");
        assert_eq!(info.ulMaxKeySize, 4096, "CKM_RSA_PKCS_OAEP max key size must be 4096 bits");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Test 17: C_GetMechanismInfo returns CKR_MECHANISM_INVALID for unsupported
//          mechanisms (soft_PKCS11-17n)
// ---------------------------------------------------------------------------

#[test]
fn c_get_mechanism_info_unsupported_returns_mechanism_invalid() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let mut info: CK_MECHANISM_INFO = std::mem::zeroed();
        // CKM_AES_CBC is a real PKCS#11 mechanism that this library does not support.
        // Using a named constant rather than a raw number makes the intent clear and
        // ensures the test would catch a regression if AES-CBC were accidentally added.
        let rv = fl.C_GetMechanismInfo.unwrap()(0, CKM_AES_CBC, &mut info);
        assert_eq!(rv, CKR_MECHANISM_INVALID,
            "unsupported mechanism must return CKR_MECHANISM_INVALID, got {rv}");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Helpers for tests that need a logged-in token (tests 18+)
//
// These helpers set up a keystore with one RSA key and one EC key. The tests
// then exercise PKCS#11 init functions with mismatched key types to verify
// CKR_KEY_TYPE_INCONSISTENT is returned at init time per PKCS#11 s.11.11.
// ---------------------------------------------------------------------------

/// X.690 s.8.1.3 definite-length encoding, appended to `buf`.
/// Duplicated from keystore_tests.rs -- shared logic for building minimal DER.
fn conformance_push_der_len(buf: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        buf.push(n as u8);
    } else if n < 0x100 {
        buf.extend_from_slice(&[0x81, n as u8]);
    } else {
        buf.extend_from_slice(&[0x82, (n >> 8) as u8, (n & 0xFF) as u8]);
    }
}

/// Build a minimal PKCS#1 RSAPrivateKey DER with a 512-byte (4096-bit) modulus.
///
/// The private exponent and other RSA fields are omitted -- Keystore::load stops
/// after reading the modulus length during RSA size validation and never parses
/// further. The leading modulus byte is 0x01 (high bit clear) so DER does not
/// insert a leading 0x00 padding byte -- the modulus value is exactly 512 bytes.
fn minimal_rsa_der_4096() -> Vec<u8> {
    const MODULUS_BYTES: usize = 512; // 4096 bits
    let version = [0x02u8, 0x01, 0x00]; // version INTEGER 0
    let mut modulus_value = vec![0u8; MODULUS_BYTES];
    modulus_value[0] = 0x01; // high bit clear -> no DER leading-zero padding
    let mut modulus_int = vec![0x02u8]; // INTEGER tag
    conformance_push_der_len(&mut modulus_int, MODULUS_BYTES);
    modulus_int.extend_from_slice(&modulus_value);

    let inner_len = version.len() + modulus_int.len();
    let mut der = vec![0x30u8]; // SEQUENCE tag
    conformance_push_der_len(&mut der, inner_len);
    der.extend_from_slice(&version);
    der.extend_from_slice(&modulus_int);
    der
}

/// Write a keystore with one RSA key (handle 1) and one EC key (handle 2) to a
/// temp file. Returns the file handle (the file persists until the handle is dropped).
///
/// Keys are stored in creation order, which matches handle assignment order:
///   handle 1 = entries[0] = RSA key
///   handle 2 = entries[1] = EC key
/// This ordering is stable because the keystore preserves insertion order (Vec).
fn two_key_keystore(pin: &[u8]) -> NamedTempFile {
    let entries = vec![
        KeyEntry {
            id: [0x01u8; 16],
            label: "rsa-key".to_owned(),
            key_type: KeyType::Rsa,
            der_bytes: minimal_rsa_der_4096(),
            cert_der: None,
            pub_bytes: None,
        },
        KeyEntry {
            id: [0x02u8; 16],
            label: "ec-key".to_owned(),
            key_type: KeyType::Ec,
            // EC keys have no DER validation on load -- any non-empty bytes work
            // for the key-type mismatch tests, which never reach actual signing.
            der_bytes: vec![0xEC; 32],
            cert_der: None,
            pub_bytes: None,
        },
    ];
    let blob = Keystore::create(entries, pin, 1).expect("create two-key keystore");
    let mut f = NamedTempFile::new().expect("tmpfile");
    f.write_all(&blob).expect("write keystore");
    f
}

/// Open a session and log in using `test_mount`. Returns the session handle.
///
/// Caller is responsible for calling C_Finalize and test_reset after the test.
unsafe fn login_session(
    fl: &CK_FUNCTION_LIST,
    p11k_path: &std::path::Path,
    pin: &[u8],
) -> CK_SESSION_HANDLE {
    usb_hsm::test_mount(p11k_path);

    let mut h: CK_SESSION_HANDLE = 0;
    let flags: CK_FLAGS = CKF_RW_SESSION | CKF_SERIAL_SESSION;
    let rv = fl.C_OpenSession.unwrap()(0, flags, std::ptr::null_mut(), None, &mut h);
    assert_eq!(rv, CKR_OK, "C_OpenSession");

    let rv = fl.C_Login.unwrap()(h, CKU_USER, pin.as_ptr() as *mut _, pin.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK, "C_Login");

    h
}

/// Find the first object handle matching the given CKK_* key type. Panics if none found.
unsafe fn find_key_handle(
    fl: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    ckk_type: CK_ULONG,
) -> CK_OBJECT_HANDLE {
    let mut key_type_val: CK_ULONG = ckk_type;
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_KEY_TYPE,
        pValue: &mut key_type_val as *mut _ as *mut _,
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let rv = fl.C_FindObjectsInit.unwrap()(session, template.as_mut_ptr(), 1);
    assert_eq!(rv, CKR_OK, "C_FindObjectsInit(CKA_KEY_TYPE={ckk_type:#x})");

    let mut handle: CK_OBJECT_HANDLE = 0;
    let mut found: CK_ULONG = 0;
    let rv = fl.C_FindObjects.unwrap()(session, &mut handle, 1, &mut found);
    assert_eq!(rv, CKR_OK, "C_FindObjects");
    assert_eq!(found, 1, "expected exactly one key with CKA_KEY_TYPE={ckk_type:#x}");

    fl.C_FindObjectsFinal.unwrap()(session);
    handle
}

// ---------------------------------------------------------------------------
// Tests 18-22: Key type validation at *Init time (soft_PKCS11-2rb)
// ---------------------------------------------------------------------------

/// C_SignInit with an RSA mechanism and an EC key must return CKR_KEY_TYPE_INCONSISTENT.
/// PKCS#11 s.11.11: the error must come from the init function, not from C_Sign.
#[test]
fn c_sign_init_rsa_mech_with_ec_key_returns_key_type_inconsistent() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-kt";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let ec_handle = find_key_handle(fl, session, CKK_EC);

        // CKM_RSA_PKCS_PSS requires KeyType::Rsa; presenting an EC key must fail at init.
        let mut params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut params as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_SignInit.unwrap()(session, &mut mech, ec_handle);
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT,
            "C_SignInit(CKM_RSA_PKCS_PSS, EC_key) must return CKR_KEY_TYPE_INCONSISTENT");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

/// C_SignInit with an ECDSA mechanism and an RSA key must return CKR_KEY_TYPE_INCONSISTENT.
#[test]
fn c_sign_init_ecdsa_mech_with_rsa_key_returns_key_type_inconsistent() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-kt2";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let rsa_handle = find_key_handle(fl, session, CKK_RSA);

        // CKM_ECDSA requires KeyType::Ec; presenting an RSA key must fail at init.
        let mut mech = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = fl.C_SignInit.unwrap()(session, &mut mech, rsa_handle);
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT,
            "C_SignInit(CKM_ECDSA, RSA_key) must return CKR_KEY_TYPE_INCONSISTENT");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

/// C_EncryptInit(CKM_RSA_PKCS_OAEP) with an EC key must return CKR_KEY_TYPE_INCONSISTENT.
#[test]
fn c_encrypt_init_oaep_with_ec_key_returns_key_type_inconsistent() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-kt3";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let ec_handle = find_key_handle(fl, session, CKK_EC);

        // OAEP requires an RSA key; EC key must be rejected at C_EncryptInit.
        let mut params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: std::ptr::null_mut(),
            ulSourceDataLen: 0,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut params as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_EncryptInit.unwrap()(session, &mut mech, ec_handle);
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT,
            "C_EncryptInit(CKM_RSA_PKCS_OAEP, EC_key) must return CKR_KEY_TYPE_INCONSISTENT");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

/// C_VerifyInit with CKM_RSA_PKCS_PSS and an EC key must return CKR_KEY_TYPE_INCONSISTENT.
#[test]
fn c_verify_init_pss_with_ec_key_returns_key_type_inconsistent() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-kt4";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let ec_handle = find_key_handle(fl, session, CKK_EC);

        // PSS requires an RSA key; EC key must be rejected at C_VerifyInit.
        let mut params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut params as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_VerifyInit.unwrap()(session, &mut mech, ec_handle);
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT,
            "C_VerifyInit(CKM_RSA_PKCS_PSS, EC_key) must return CKR_KEY_TYPE_INCONSISTENT");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Tests 23-24: CKM_ECDSA prehash data length validation (soft_PKCS11-91z)
//
// CKM_ECDSA requires exactly 32 bytes of prehash (SHA-256 output for P-256).
// Passing any other length must return CKR_DATA_LEN_RANGE from C_Sign --
// wolfcrypt accepts wrong-length input silently but produces invalid signatures.
// ---------------------------------------------------------------------------

use cryptoki_sys::CKR_DATA_LEN_RANGE;

/// C_Sign(CKM_ECDSA) with a 20-byte (SHA-1) prehash must return CKR_DATA_LEN_RANGE.
/// The EC key DER bytes in the test keystore are not a valid P-256 key, but the
/// length check fires before key parsing so the test is independent of key validity.
#[test]
fn c_sign_ecdsa_short_prehash_returns_data_len_range() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-dl1";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let ec_handle = find_key_handle(fl, session, CKK_EC);

        let mut mech = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = fl.C_SignInit.unwrap()(session, &mut mech, ec_handle);
        assert_eq!(rv, CKR_OK, "C_SignInit(CKM_ECDSA, EC) must succeed");

        // 20 bytes = SHA-1 output. CKM_ECDSA with P-256 requires exactly 32 bytes.
        let bad_hash = [0xAAu8; 20];
        let mut sig_buf = [0u8; 72];
        let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;
        let rv = fl.C_Sign.unwrap()(
            session,
            bad_hash.as_ptr() as *mut _,
            bad_hash.len() as CK_ULONG,
            sig_buf.as_mut_ptr(),
            &mut sig_len,
        );
        assert_eq!(rv, CKR_DATA_LEN_RANGE,
            "C_Sign(CKM_ECDSA, 20-byte hash) must return CKR_DATA_LEN_RANGE");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

/// C_Sign(CKM_ECDSA) with a 48-byte (SHA-384) prehash must return CKR_DATA_LEN_RANGE.
#[test]
fn c_sign_ecdsa_long_prehash_returns_data_len_range() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-dl2";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let ec_handle = find_key_handle(fl, session, CKK_EC);

        let mut mech = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = fl.C_SignInit.unwrap()(session, &mut mech, ec_handle);
        assert_eq!(rv, CKR_OK, "C_SignInit(CKM_ECDSA, EC) must succeed");

        // 48 bytes = SHA-384 output. Still wrong for P-256.
        let bad_hash = [0xBBu8; 48];
        let mut sig_buf = [0u8; 72];
        let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;
        let rv = fl.C_Sign.unwrap()(
            session,
            bad_hash.as_ptr() as *mut _,
            bad_hash.len() as CK_ULONG,
            sig_buf.as_mut_ptr(),
            &mut sig_len,
        );
        assert_eq!(rv, CKR_DATA_LEN_RANGE,
            "C_Sign(CKM_ECDSA, 48-byte hash) must return CKR_DATA_LEN_RANGE");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Tests: C_VerifyUpdate / C_VerifyFinal stubs (soft_PKCS11-6mk)
//
// PKCS#11 s.11.11 mandates that any error returned by C_VerifyUpdate or
// C_VerifyFinal terminates the active verification operation. Callers rely on
// this to avoid a "session wedge" where the op context from C_VerifyInit stays
// active and blocks the next C_VerifyInit with CKR_OPERATION_ACTIVE.
//
// Both functions are non-null in the function table even though multi-part
// verification is not implemented. Null function pointers give callers no way
// to trigger the cleanup; stubs with CKR_FUNCTION_NOT_SUPPORTED do. This is
// the same design used for C_SignUpdate / C_SignFinal.
// ---------------------------------------------------------------------------

/// C_VerifyUpdate and C_VerifyFinal must be non-null in the function list.
///
/// Both functions are stubs that return CKR_FUNCTION_NOT_SUPPORTED, but they
/// MUST be non-null so that callers can call them to trigger the mandatory
/// s.11.11 op-context cleanup.
#[test]
fn c_verify_update_and_final_function_pointers_are_non_null() {
    let _g = LOCK.lock().unwrap();
    unsafe {
        let fl = function_list();
        assert!(
            fl.C_VerifyUpdate.is_some(),
            "C_VerifyUpdate must be non-null: callers need to call it for s.11.11 cleanup"
        );
        assert!(
            fl.C_VerifyFinal.is_some(),
            "C_VerifyFinal must be non-null: callers need to call it for s.11.11 cleanup"
        );
    }
}

/// C_VerifyUpdate returns CKR_FUNCTION_NOT_SUPPORTED AND clears the active
/// verify op context. Without the clear, a subsequent C_VerifyInit on the same
/// session returns CKR_OPERATION_ACTIVE -- a session wedge that cannot be
/// resolved without closing the session.
///
/// Uses CKM_RSA_PKCS_PSS to keep the test minimal. The RSA key in two_key_keystore
/// has a valid 4096-bit DER so C_VerifyInit succeeds at the mechanism/type check stage.
#[test]
fn c_verify_update_clears_op_context_prevents_session_wedge() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-vu1";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let rsa_handle = find_key_handle(fl, session, CKK_RSA);

        let mut params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut params as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };

        // First C_VerifyInit: stores an OpCtx::Verify in op_state for this session.
        let rv = fl.C_VerifyInit.unwrap()(session, &mut mech, rsa_handle);
        assert_eq!(rv, CKR_OK, "first C_VerifyInit");

        // C_VerifyUpdate: must return CKR_FUNCTION_NOT_SUPPORTED and terminate the
        // operation (s.11.11: any error from C_VerifyUpdate terminates the op).
        let dummy = [0xAAu8; 4];
        let rv =
            fl.C_VerifyUpdate.unwrap()(session, dummy.as_ptr() as *mut _, dummy.len() as CK_ULONG);
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyUpdate return code");

        // Second C_VerifyInit on the same session: must return CKR_OK because the
        // op context was cleared. CKR_OPERATION_ACTIVE is the specific failure mode
        // if the stub forgot to clear -- the session is then permanently wedged.
        let rv = fl.C_VerifyInit.unwrap()(session, &mut mech, rsa_handle);
        assert_ne!(
            rv, CKR_OPERATION_ACTIVE,
            "C_VerifyUpdate must clear the op context; CKR_OPERATION_ACTIVE means it did not"
        );
        assert_eq!(rv, CKR_OK, "second C_VerifyInit after C_VerifyUpdate");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

/// C_VerifyFinal returns CKR_FUNCTION_NOT_SUPPORTED AND clears the active
/// verify op context. Same s.11.11 termination requirement as C_VerifyUpdate.
#[test]
fn c_verify_final_clears_op_context_prevents_session_wedge() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-vf1";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let rsa_handle = find_key_handle(fl, session, CKK_RSA);

        let mut params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut params as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };

        // Establish an active verify operation.
        let rv = fl.C_VerifyInit.unwrap()(session, &mut mech, rsa_handle);
        assert_eq!(rv, CKR_OK, "first C_VerifyInit");

        // C_VerifyFinal: must return CKR_FUNCTION_NOT_SUPPORTED and terminate the op.
        let rv = fl.C_VerifyFinal.unwrap()(session, std::ptr::null_mut(), 0);
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED, "C_VerifyFinal return code");

        // Op context must be cleared: next C_VerifyInit must succeed.
        let rv = fl.C_VerifyInit.unwrap()(session, &mut mech, rsa_handle);
        assert_ne!(
            rv, CKR_OPERATION_ACTIVE,
            "C_VerifyFinal must clear the op context; CKR_OPERATION_ACTIVE means it did not"
        );
        assert_eq!(rv, CKR_OK, "second C_VerifyInit after C_VerifyFinal");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

/// C_SignUpdate and C_VerifyUpdate must have consistent non-null behavior.
/// Both are sign/verify multi-part stubs; this symmetry check catches future
/// regressions where one is accidentally set back to None.
#[test]
fn sign_and_verify_multi_part_stubs_are_symmetric() {
    let _g = LOCK.lock().unwrap();
    unsafe {
        let fl = function_list();
        // Sign side (pre-existing stubs).
        assert!(fl.C_SignUpdate.is_some(), "C_SignUpdate must be non-null");
        assert!(fl.C_SignFinal.is_some(), "C_SignFinal must be non-null");
        // Verify side (added in soft_PKCS11-6mk).
        assert!(fl.C_VerifyUpdate.is_some(), "C_VerifyUpdate must be non-null");
        assert!(fl.C_VerifyFinal.is_some(), "C_VerifyFinal must be non-null");
    }
}

// ---------------------------------------------------------------------------

/// C_SignInit with a correct mechanism+key-type pairing must pass the type check
/// and proceed (returns CKR_OK, not a type error). Verifies the positive path.
#[test]
fn c_sign_init_correct_key_type_passes_type_check() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-kt5";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let ec_handle = find_key_handle(fl, session, CKK_EC);

        // CKM_ECDSA with an EC key is the correct pairing; init must succeed.
        // (Actual signing would fail because der_bytes is not a valid EC key,
        // but that is irrelevant -- C_SignInit only validates type, not key material.)
        let mut mech = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = fl.C_SignInit.unwrap()(session, &mut mech, ec_handle);
        assert_eq!(rv, CKR_OK,
            "C_SignInit(CKM_ECDSA, EC_key) with correct pairing must return CKR_OK");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Encrypt/Decrypt multi-part stub tests (soft_PKCS11-jiw, soft_PKCS11-dq2)
// ---------------------------------------------------------------------------

/// C_EncryptUpdate and C_EncryptFinal must be non-null. Without non-null
/// pointers a caller that called C_EncryptInit cannot release the op context
/// (session wedge) when multi-part encrypt is not supported. Same s.11.11
/// rationale as verify stubs added in soft_PKCS11-6mk.
#[test]
fn c_encrypt_and_decrypt_update_final_function_pointers_are_non_null() {
    let _g = LOCK.lock().unwrap();
    unsafe {
        let fl = function_list();
        assert!(fl.C_EncryptUpdate.is_some(), "C_EncryptUpdate must be non-null: needed for s.11.11 op-context cleanup");
        assert!(fl.C_EncryptFinal.is_some(),  "C_EncryptFinal must be non-null: needed for s.11.11 op-context cleanup");
        assert!(fl.C_DecryptUpdate.is_some(), "C_DecryptUpdate must be non-null: needed for s.11.11 op-context cleanup");
        assert!(fl.C_DecryptFinal.is_some(),  "C_DecryptFinal must be non-null: needed for s.11.11 op-context cleanup");
    }
}

/// C_EncryptUpdate returns CKR_FUNCTION_NOT_SUPPORTED AND clears the active
/// encrypt op context. Without the clear, a subsequent C_EncryptInit returns
/// CKR_OPERATION_ACTIVE -- a session wedge.
#[test]
fn c_encrypt_update_clears_op_context_prevents_session_wedge() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-eu1";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let rsa_handle = find_key_handle(fl, session, CKK_RSA);

        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: CKM_SHA256,
                mgf: CKG_MGF1_SHA256,
                source: CKZ_DATA_SPECIFIED,
                pSourceData: std::ptr::null_mut(),
                ulSourceDataLen: 0,
            } as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };

        let rv = fl.C_EncryptInit.unwrap()(session, &mut mech, rsa_handle);
        assert_eq!(rv, CKR_OK, "C_EncryptInit");

        // C_EncryptUpdate must terminate the op (s.11.11) and return not-supported.
        let dummy = [0xABu8; 4];
        let rv = fl.C_EncryptUpdate.unwrap()(
            session,
            dummy.as_ptr() as *mut _,
            dummy.len() as CK_ULONG,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED, "C_EncryptUpdate return code");

        // Op context must be cleared: next C_EncryptInit must not get OPERATION_ACTIVE.
        let rv = fl.C_EncryptInit.unwrap()(session, &mut mech, rsa_handle);
        assert_ne!(
            rv, CKR_OPERATION_ACTIVE,
            "C_EncryptUpdate must clear the op context; CKR_OPERATION_ACTIVE means it did not"
        );
        assert_eq!(rv, CKR_OK, "second C_EncryptInit after C_EncryptUpdate");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

/// C_DecryptUpdate returns CKR_FUNCTION_NOT_SUPPORTED AND clears the active
/// decrypt op context. Same s.11.11 termination requirement.
#[test]
fn c_decrypt_update_clears_op_context_prevents_session_wedge() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    let pin = b"test-pin-du1";
    let ks_file = two_key_keystore(pin);
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let session = login_session(fl, ks_file.path(), pin);
        let rsa_handle = find_key_handle(fl, session, CKK_RSA);

        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: CKM_SHA256,
                mgf: CKG_MGF1_SHA256,
                source: CKZ_DATA_SPECIFIED,
                pSourceData: std::ptr::null_mut(),
                ulSourceDataLen: 0,
            } as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };

        let rv = fl.C_DecryptInit.unwrap()(session, &mut mech, rsa_handle);
        assert_eq!(rv, CKR_OK, "C_DecryptInit");

        // C_DecryptUpdate must terminate the op (s.11.11).
        let dummy = [0xCDu8; 4];
        let rv = fl.C_DecryptUpdate.unwrap()(
            session,
            dummy.as_ptr() as *mut _,
            dummy.len() as CK_ULONG,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED, "C_DecryptUpdate return code");

        let rv = fl.C_DecryptInit.unwrap()(session, &mut mech, rsa_handle);
        assert_ne!(
            rv, CKR_OPERATION_ACTIVE,
            "C_DecryptUpdate must clear the op context; CKR_OPERATION_ACTIVE means it did not"
        );
        assert_eq!(rv, CKR_OK, "second C_DecryptInit after C_DecryptUpdate");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}

/// Multi-part stubs must return CKR_SESSION_HANDLE_INVALID for an invalid session
/// handle, not CKR_FUNCTION_NOT_SUPPORTED. PKCS#11 s.11.1: session validity is
/// checked before function-specific processing.
#[test]
fn multi_part_stubs_return_session_handle_invalid_for_bad_handle() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = function_list();
        fl.C_Initialize.unwrap()(std::ptr::null_mut());

        let bad: CK_SESSION_HANDLE = 0xDEADBEEF;
        let dummy = [0u8; 4];
        let mut out_len: CK_ULONG = 0;

        let rv = fl.C_SignUpdate.unwrap()(bad, dummy.as_ptr() as *mut _, 4);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "C_SignUpdate bad handle");

        let rv = fl.C_SignFinal.unwrap()(bad, std::ptr::null_mut(), &mut out_len);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "C_SignFinal bad handle");

        let rv = fl.C_VerifyUpdate.unwrap()(bad, dummy.as_ptr() as *mut _, 4);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "C_VerifyUpdate bad handle");

        let rv = fl.C_VerifyFinal.unwrap()(bad, std::ptr::null_mut(), 0);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "C_VerifyFinal bad handle");

        let rv = fl.C_EncryptUpdate.unwrap()(
            bad, dummy.as_ptr() as *mut _, 4, std::ptr::null_mut(), std::ptr::null_mut(),
        );
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "C_EncryptUpdate bad handle");

        let rv = fl.C_EncryptFinal.unwrap()(bad, std::ptr::null_mut(), &mut out_len);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "C_EncryptFinal bad handle");

        let rv = fl.C_DecryptUpdate.unwrap()(
            bad, dummy.as_ptr() as *mut _, 4, std::ptr::null_mut(), std::ptr::null_mut(),
        );
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "C_DecryptUpdate bad handle");

        let rv = fl.C_DecryptFinal.unwrap()(bad, std::ptr::null_mut(), &mut out_len);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID, "C_DecryptFinal bad handle");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
}
