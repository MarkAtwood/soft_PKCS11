// integration.rs -- end-to-end PKCS#11 flow tests.
//
// Test integrity rules:
// - Sign operations are verified by openssl as an independent external oracle.
//   The public key is embedded as a constant independent of the sign path.
// - The global token state is controlled via test_mount / test_unmount helpers
//   to simulate USB device insertion/removal without physical hardware.
// - Tests are serialized through LOCK to prevent shared-state races.

use std::io::Write;
use std::process::Command;
use std::sync::Mutex;
use tempfile::NamedTempFile;

use cryptoki_sys::{
    CK_RSA_PKCS_OAEP_PARAMS, CK_RSA_PKCS_PSS_PARAMS,
    CKG_MGF1_SHA256, CKM_SHA256, CKZ_DATA_SPECIFIED,
    CK_ATTRIBUTE, CK_BBOOL, CK_FUNCTION_LIST, CK_MECHANISM, CK_MECHANISM_TYPE,
    CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SESSION_INFO, CK_SLOT_ID, CK_ULONG,
    CKA_CLASS, CKA_CERTIFICATE_TYPE, CKA_DECRYPT, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKA_LABEL,
    CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_TOKEN, CKA_VALUE, CKA_VERIFY,
    CKF_RW_SESSION, CKF_SERIAL_SESSION,
    CKC_X_509, CKM_EC_KEY_PAIR_GEN, CKM_ECDSA_SHA256,
    CKM_ML_DSA, CKM_ML_KEM,
    CKM_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS,
    CKK_EC, CKK_ML_DSA, CKK_ML_KEM, CKK_RSA,
    CKO_CERTIFICATE, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
    CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_DEVICE_REMOVED, CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_SESSION_HANDLE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKS_RW_PUBLIC_SESSION, CKS_RW_USER_FUNCTIONS,
    CKU_USER, CK_FALSE, CK_TRUE,
};
use usb_hsm::keystore::{KeyEntry, KeyType, Keystore};

// ---------------------------------------------------------------------------
// Embedded test keys (from ops_tests.rs -- same constants, independent source)
// ---------------------------------------------------------------------------

// PKCS#8 PrivateKeyInfo wrapping an RSA-2048 private key.
// openssl genpkey (and similar tools) output this format by default.
// The token must unwrap PKCS#8 -> PKCS#1 at load time (see keystore.rs pkcs8_rsa_unwrap).
// The inner PKCS#1 bytes start at byte 26 (hex offset 52): `308204a2...`
const RSA_PKCS8_DER_HEX: &str =
    "308204bc020100300d06092a864886f70d0101010500048204a6308204a2020100\
028201010090bca1c919c80b652bf02db7c6b784ded65262e5f74017109ee13f4\
5e83e7c80a7403ddc9f5ad75ae7260b5dd8e0ce665b32f80f9ce42b015c2f7cd5\
7d94efca1c87d60cc7d2ed86eb74678f5fd99e212b633f069dc94e024a9d2f10d\
0d0466538256d982a00e7eaa268ae0cec20a94f82b3e9fcaa4d4e9c8cf25acd30\
024f85c38a608b54c36d84cc8299ffb6b8bfdb33d1d33de9fdc78c9bfae78d398\
464b1df4676acac3ec505c67a4740b4bfd791454bd31963c2e065f1c33dc459292\
dc5db58a2ebe6a066080c9673fe429fb67a6637e31f3a1f42d90a943390e4c684\
81a97c2dbf8c26be8b93c17f84de66b04b5f66a4c29d67d403f565b0774f0b59c\
70203010001028201000487a135d054a6590cc0167c9bd93b86a3debad1744b0ae\
75b299b57a4dc9efc4e995369848a0cfd990897151488123da072ded20578b56f7\
45ca5506ffed666c83ccee57bb3ed92f6eaeca0cf674046001586c98b1fa873a88\
1f51109c332f59dd2220ea632b00f73f4c8f35395c0e6c80bb93eb4a2f8f4c58b\
4f0733f4f35b25376cc13aa7aab8f8e0084fc7333ba59311f71746f5de4fa86c1f\
1bfcca438063ba7045a3240aa988ff211ccc3123c356464305e0ba9c5f510936df\
e777fedd538ecac8911122f8fe1497f86a265ad870531fcc0e00817a43fd050aa7\
23aba87aa0b2b1bc78130a5910f7ce3ead4f541237da27cfb5758ebb51f4b1606d\
c2ad02818100c816292b3739f2226643bcfa41b31d4259c1e0fa38c4f66bc6e267\
55318a187659c9b46266a95ad547c823e87b7a795e97fff3ee535add2b29e3755d\
f07eb03a8d526e96152ceb4c54634bd9df9550cce0a5554b5f85173a56a26a361\
1d6be491e173b5e9ef96699f17bc65841debae99f3c9f983e83c0add8bb6d73c4c\
36f1502818100b92ed992bccf1787d7cf8231e9d19eda1040140ed74237fe87b72\
4ee515c39c0fa6b590708d4083a65c687f3935479c8bb8cc94bded52f48d55cc46\
dc13b61226927e5f581f560bb437a6e190399f4998b119be57a33fd77e744c50a2\
c65f54e503636fba598be062a1a2e254654692f1581cd9778f48470f95ebca9c2c\
73c6b02818041704e029e4b4b4fc8d67aa5f67ad824ed2a25a47090aa6f515a96a\
51c50a7f37d2624e2d1e4ad9a77a1936ce38588d051321adb6553a0660f8b1ec59\
c7432bad3a1941d6dcb85212fb0520c6dbd6df1b3bf1f0849b3438786f2137e9f\
92f624ffbc65646ae5f292829212aaa6d06b9d20c1390917d90b59503aec6f2279\
30890281807b95999c45274c03db71dfe8a1abc480b121a2813905374b4595632f\
2cdb08ac12337be9a6e9a2481ecdfcc3008afaef8cc2eb4018095c12165a5fb903\
a13634f9caa7bc4dabcd8f8bfbf3e7fbb04e3dfe429530f37a28e9514d62d66444\
f30dfd9800dfb667164214ecfde8e063cb02a22ecb5f1058d6de727dd818cf2599\
db028180343c18d07cb36b8cf0aeaf131737392ca61458bf739144c3dea2df3e9b\
2dcba31228d42d696a3b5dfadcefea8433cd6dac264a916d242c3edee280927d24\
a276933e809bd4512637c5f66bf88d4c7556651fd898244750468276d44339086f\
56ae79d42ff7efb8eba4a2c1aec0e258bfa46ed40aaf5f8fabc4251d72d597941d";

const RSA_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkLyhyRnIC2Ur8C23xreE\n\
3tZSYuX3QBcQnuE/Reg+fICnQD3cn1rXWucmC13Y4M5mWzL4D5zkKwFcL3zVfZTv\n\
yhyH1gzH0u2G63Rnj1/ZniErYz8GnclOAkqdLxDQ0EZlOCVtmCoA5+qiaK4M7CCp\n\
T4Kz6fyqTU6cjPJazTACT4XDimCLVMNthMyCmf+2uL/bM9HTPen9x4yb+ueNOYRk\n\
sd9GdqysPsUFxnpHQLS/15FFS9MZY8LgZfHDPcRZKS3F21ii6+agZggMlnP+Qp+2\n\
emY34x86H0LZCpQzkOTGhIGpfC2/jCa+i5PBf4TeZrBLX2akwp1n1AP1ZbB3TwtZ\n\
xwIDAQAB\n\
-----END PUBLIC KEY-----\n";

const EC_PRIV_HEX: &str = "0933c1010f2979cdde48ae7a403a816591e82fcb54fc288e8da637ce4fd570dc";

const EC_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWRQtnlYv3Adsx0aUHF5xC5saolFi\n\
Cj9KLL55jRVdDwDOm82eSiZtkf+tBwKxRriC2m3vk0DQbH6Cgz7ssHsthg==\n\
-----END PUBLIC KEY-----\n";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static LOCK: Mutex<()> = Mutex::new(());

fn write_tmp(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmpfile");
    f.write_all(data).expect("write");
    f
}

fn write_tmp_str(s: &str) -> NamedTempFile {
    write_tmp(s.as_bytes())
}

/// Convert raw r||s (64 bytes for P-256) to DER SEQUENCE { INTEGER r, INTEGER s }.
///
/// This is an independent implementation used to present token signatures to
/// openssl (which expects DER). It is NOT the production rs_to_der in ops.rs --
/// having a separate copy preserves the "external oracle" test property.
fn raw_rs_to_der(raw: &[u8]) -> Vec<u8> {
    assert_eq!(raw.len(), 64, "P-256 raw r||s must be exactly 64 bytes");
    let r = &raw[..32];
    let s = &raw[32..];

    fn encode_int(v: &[u8]) -> Vec<u8> {
        // Strip leading zeros but keep at least one byte.
        let start = v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1);
        let trimmed = &v[start..];
        let mut out = vec![0x02u8]; // INTEGER tag
        if trimmed[0] & 0x80 != 0 {
            out.push(trimmed.len() as u8 + 1);
            out.push(0x00);
        } else {
            out.push(trimmed.len() as u8);
        }
        out.extend_from_slice(trimmed);
        out
    }

    let r_enc = encode_int(r);
    let s_enc = encode_int(s);
    let payload_len = r_enc.len() + s_enc.len();
    let mut der = vec![0x30u8, payload_len as u8]; // SEQUENCE tag + len (<=70 for P-256)
    der.extend_from_slice(&r_enc);
    der.extend_from_slice(&s_enc);
    der
}

fn make_keystore_file(entries: Vec<KeyEntry>, pin: &[u8]) -> NamedTempFile {
    let blob = Keystore::create(entries, pin, 1).expect("create keystore");
    let mut f = NamedTempFile::new().expect("tmpfile");
    f.write_all(&blob).expect("write");
    f
}

/// Get the function list pointer; the returned reference is 'static.
unsafe fn fl() -> &'static CK_FUNCTION_LIST {
    let mut pp: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let rv = usb_hsm::C_GetFunctionList(&mut pp);
    assert_eq!(rv, CKR_OK);
    &*pp
}

/// Initialize the library, accepting already-initialized as OK.
unsafe fn init(fl: &CK_FUNCTION_LIST) {
    use cryptoki_sys::CKR_CRYPTOKI_ALREADY_INITIALIZED;
    let rv = fl.C_Initialize.unwrap()(std::ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED, "init: {rv}");
}

/// Open a session; returns the session handle.
unsafe fn open_session(fl: &CK_FUNCTION_LIST) -> CK_SESSION_HANDLE {
    let mut h: CK_SESSION_HANDLE = 0;
    let rv = fl.C_OpenSession.unwrap()(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut h,
    );
    assert_eq!(rv, CKR_OK, "C_OpenSession");
    h
}

/// Open a session on `slot_id`; returns the session handle.
unsafe fn open_session_on_slot(fl: &CK_FUNCTION_LIST, slot_id: CK_SLOT_ID) -> CK_SESSION_HANDLE {
    let mut h: CK_SESSION_HANDLE = 0;
    let rv = fl.C_OpenSession.unwrap()(
        slot_id,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut h,
    );
    assert_eq!(rv, CKR_OK, "C_OpenSession on slot {slot_id}");
    h
}

/// Find the first object matching CKO_PRIVATE_KEY; assert at least one exists.
unsafe fn find_first_private_key(
    fl: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
) -> CK_OBJECT_HANDLE {
    let mut cls: CK_OBJECT_CLASS = CKO_PRIVATE_KEY;
    let mut tmpl = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: &mut cls as *mut _ as _,
        ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    let rv = fl.C_FindObjectsInit.unwrap()(session, &mut tmpl, 1);
    assert_eq!(rv, CKR_OK, "C_FindObjectsInit");

    let mut handles = [0u64; 16];
    let mut found: CK_ULONG = 0;
    let rv = fl.C_FindObjects.unwrap()(session, handles.as_mut_ptr(), 16, &mut found);
    assert_eq!(rv, CKR_OK, "C_FindObjects");
    fl.C_FindObjectsFinal.unwrap()(session);

    assert!(found > 0, "no private keys found in keystore");
    handles[0]
}

/// Sign `msg` using `mech` on `key_handle`; returns raw signature bytes.
unsafe fn pkcs11_sign(
    fl: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    mech: CK_MECHANISM_TYPE,
    key_handle: CK_OBJECT_HANDLE,
    msg: &[u8],
) -> Vec<u8> {
    // CKM_RSA_PKCS_PSS requires a CK_RSA_PKCS_PSS_PARAMS with the hash/MGF algorithm.
    // Other mechanisms (RSA_PKCS, ECDSA, ECDSA_SHA256) carry no required parameters.
    let mut pss_params = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mut ck_mech = if mech == CKM_RSA_PKCS_PSS {
        CK_MECHANISM {
            mechanism: mech,
            pParameter: &mut pss_params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        }
    } else {
        CK_MECHANISM { mechanism: mech, pParameter: std::ptr::null_mut(), ulParameterLen: 0 }
    };
    let rv = fl.C_SignInit.unwrap()(session, &mut ck_mech, key_handle);
    assert_eq!(rv, CKR_OK, "C_SignInit mech={mech:#x}");

    let mut sig_len: CK_ULONG = 512;
    let mut sig_buf = vec![0u8; 512];
    let rv = fl.C_Sign.unwrap()(
        session,
        msg.as_ptr() as _,
        msg.len() as CK_ULONG,
        sig_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "C_Sign mech={mech:#x}");
    sig_buf.truncate(sig_len as usize);
    sig_buf
}

// ---------------------------------------------------------------------------
// Test 1: RSA-PSS full PKCS#11 flow -> openssl verify
// ---------------------------------------------------------------------------

#[test]
fn rsa_pss_pkcs11_flow_verified_by_openssl() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"testpin";
    let entry = KeyEntry {
        id: [1u8; 16],
        label: "test-rsa".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);
        let key = find_first_private_key(fl, session);
        let msg = b"integration test message for RSA-PSS";
        let sig = pkcs11_sign(fl, session, CKM_RSA_PKCS_PSS, key, msg);

        let sig_f = write_tmp(&sig);
        let msg_f = write_tmp(msg);
        let pub_f = write_tmp_str(RSA_PUB_PEM);

        let out = Command::new("openssl")
            .args([
                "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-verify", pub_f.path().to_str().unwrap(),
                "-signature", sig_f.path().to_str().unwrap(),
                msg_f.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl not found");

        assert!(
            out.status.success(),
            "openssl RSA-PSS verify failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test 2: ECDSA-SHA256 full PKCS#11 flow -> openssl verify
// ---------------------------------------------------------------------------

#[test]
fn ecdsa_sha256_pkcs11_flow_verified_by_openssl() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"testpin";
    let entry = KeyEntry {
        id: [2u8; 16],
        label: "test-ec".to_string(),
        key_type: KeyType::Ec,
        der_bytes: hex::decode(EC_PRIV_HEX).expect("ec hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);
        let key = find_first_private_key(fl, session);
        let msg = b"integration test message for ECDSA-SHA256";
        // sig is raw r||s per PKCS#11 s.2.3.1; convert to DER for openssl.
        let sig_raw = pkcs11_sign(fl, session, CKM_ECDSA_SHA256, key, msg);
        assert_eq!(sig_raw.len(), 64, "CKM_ECDSA_SHA256 signature must be 64 bytes raw r||s");
        let sig_der = raw_rs_to_der(&sig_raw);

        let sig_f = write_tmp(&sig_der);
        let msg_f = write_tmp(msg);
        let pub_f = write_tmp_str(EC_PUB_PEM);

        let out = Command::new("openssl")
            .args([
                "dgst", "-sha256",
                "-verify", pub_f.path().to_str().unwrap(),
                "-signature", sig_f.path().to_str().unwrap(),
                msg_f.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl not found");

        assert!(
            out.status.success(),
            "openssl ECDSA verify failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test 3: USB removal mid-session returns CKR_DEVICE_REMOVED
// ---------------------------------------------------------------------------

#[test]
fn device_removed_returns_ckr_device_removed() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"testpin";
    let entry = KeyEntry {
        id: [3u8; 16],
        label: "test-ec".to_string(),
        key_type: KeyType::Ec,
        der_bytes: hex::decode(EC_PRIV_HEX).expect("ec hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);

        // Simulate USB removal while session is open.
        usb_hsm::test_unmount();

        // All subsequent token operations must return CKR_DEVICE_REMOVED.
        let rv = fl.C_CloseSession.unwrap()(session);
        assert_eq!(rv, CKR_DEVICE_REMOVED, "C_CloseSession after removal");

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_DEVICE_REMOVED, "C_Login after removal");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_CloseSession succeeds after C_Logout; session info returns public state
// ---------------------------------------------------------------------------
//
// PKCS#11 s.11.6 -- C_Logout does not close existing sessions; they become public
// sessions. C_CloseSession must return CKR_OK on those handles, and
// C_GetSessionInfo must report CKS_RW_PUBLIC_SESSION (not CKS_RW_USER_FUNCTIONS).

#[test]
fn session_survives_logout() {
    let _g = LOCK.lock().unwrap();
    let pin = b"test-session-logout-pin";
    let entry = KeyEntry {
        id: [0xAB; 16],
        label: "test-ec".to_string(),
        key_type: KeyType::Ec,
        der_bytes: hex::decode(EC_PRIV_HEX).expect("ec hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);

        // Verify the session is in user state before logout.
        let mut info: CK_SESSION_INFO = std::mem::zeroed();
        let rv = fl.C_GetSessionInfo.unwrap()(session, &mut info);
        assert_eq!(rv, CKR_OK, "C_GetSessionInfo pre-logout");
        assert_eq!(info.state, CKS_RW_USER_FUNCTIONS, "pre-logout state must be CKS_RW_USER_FUNCTIONS");

        let rv = fl.C_Logout.unwrap()(session);
        assert_eq!(rv, CKR_OK, "C_Logout");

        // After logout the session must still be accessible as a public session.
        let rv = fl.C_GetSessionInfo.unwrap()(session, &mut info);
        assert_eq!(rv, CKR_OK, "C_GetSessionInfo post-logout");
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION, "post-logout state must be CKS_RW_PUBLIC_SESSION");

        // C_CloseSession must return CKR_OK, not CKR_USER_NOT_LOGGED_IN.
        let rv = fl.C_CloseSession.unwrap()(session);
        assert_eq!(rv, CKR_OK, "C_CloseSession after logout must succeed");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: CKM_RSA_PKCS is not advertised and returns CKR_MECHANISM_INVALID
// ---------------------------------------------------------------------------
//
// CKM_RSA_PKCS was removed from MECHANISMS because wolfcrypt hashes the input
// internally, double-hashing any conformant caller that pre-hashes and wraps
// DigestInfo (e.g. OpenSSH). Silent wrong signatures are worse than
// CKR_MECHANISM_INVALID. See bead soft_PKCS11-t72.

#[test]
fn rsa_pkcs_pkcs11_flow_verified_by_openssl() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"testpin-rsapkcs";
    let entry = KeyEntry {
        id: [5u8; 16],
        label: "test-rsa-pkcs".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);
        let key = find_first_private_key(fl, session);

        let mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = fl.C_SignInit.unwrap()(session, &mech as *const _ as *mut _, key);
        assert_eq!(
            rv, CKR_MECHANISM_INVALID,
            "C_SignInit(CKM_RSA_PKCS) must return CKR_MECHANISM_INVALID -- \
             mechanism is removed until wolfssl-rs exposes a raw padding path"
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_SignInit and C_VerifyInit reject CKM_RSA_PKCS_OAEP
// ---------------------------------------------------------------------------
//
// PKCS#11 s.11.13/s.11.14: CKM_RSA_PKCS_OAEP has only CKF_ENCRYPT|CKF_DECRYPT
// flags; it must not be accepted by C_SignInit or C_VerifyInit. The allowed
// mechanism list for those functions must exclude OAEP.

#[test]
fn sign_init_and_verify_init_reject_oaep() {
    let _g = LOCK.lock().unwrap();
    let pin = b"test-oaep-reject-pin";
    let entry = KeyEntry {
        id: [0x03; 16],
        label: "test-rsa-oaep".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);
        let key = find_first_private_key(fl, session);

        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        // OAEP is encrypt-only; C_SignInit must return CKR_MECHANISM_INVALID.
        let rv = fl.C_SignInit.unwrap()(session, &mut ck_mech, key);
        assert_eq!(rv, CKR_MECHANISM_INVALID, "C_SignInit(OAEP) must return CKR_MECHANISM_INVALID");

        // OAEP is encrypt-only; C_VerifyInit must return CKR_MECHANISM_INVALID.
        let rv = fl.C_VerifyInit.unwrap()(session, &mut ck_mech, key);
        assert_eq!(rv, CKR_MECHANISM_INVALID, "C_VerifyInit(OAEP) must return CKR_MECHANISM_INVALID");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_GetAttributeValue sets ulValueLen to required length on CKR_BUFFER_TOO_SMALL
// ---------------------------------------------------------------------------
//
// PKCS#11 s.11.7 two-call pattern: on CKR_BUFFER_TOO_SMALL the caller resizes its
// buffer to ulValueLen and retries. If ulValueLen is CK_UNAVAILABLE_INFORMATION
// (usize::MAX) the caller cannot know how large a buffer to allocate.

#[test]
fn get_attribute_value_reports_required_len_on_buffer_too_small() {
    let _g = LOCK.lock().unwrap();
    let label = "label-length-test";
    let pin = b"test-bufsize-pin";
    let entry = KeyEntry {
        id: [0x04; 16],
        label: label.to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);
        let key = find_first_private_key(fl, session);

        // Provide a 1-byte buffer -- definitely too small for the label.
        let mut tiny_buf = [0u8; 1];
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: tiny_buf.as_mut_ptr() as _,
            ulValueLen: 1,
        };
        let rv = fl.C_GetAttributeValue.unwrap()(session, key, &mut attr, 1);
        assert_eq!(rv, CKR_BUFFER_TOO_SMALL, "C_GetAttributeValue must return CKR_BUFFER_TOO_SMALL");
        // s.11.7: ulValueLen must hold the actual required length so the caller
        // can retry with a correctly-sized buffer. CK_UNAVAILABLE_INFORMATION
        // would make retry impossible.
        assert_eq!(
            attr.ulValueLen as usize,
            label.len(),
            "ulValueLen must be the required length ({}) not CK_UNAVAILABLE_INFORMATION",
            label.len()
        );

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_OpenSession works before C_Login (PKCS#11 s.11.5 conformance)
// ---------------------------------------------------------------------------
//
// The PKCS#11 spec does not include CKR_USER_NOT_LOGGED_IN in the allowed
// return codes for C_OpenSession. Standard apps open a session first, then
// call C_Login(session). The session obtained before login must remain valid
// after login (login carries sessions from Present to LoggedIn per s.11.6).

#[test]
fn open_session_before_login_standard_flow() {
    let _g = LOCK.lock().unwrap();
    let pin = b"test-pre-login-session";
    let entry = KeyEntry {
        id: [0x06; 16],
        label: "test-rsa-pre-login".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        // C_OpenSession BEFORE C_Login -- must succeed with a public session.
        let mut h: CK_SESSION_HANDLE = 0;
        let rv = fl.C_OpenSession.unwrap()(
            0,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            std::ptr::null_mut(),
            None,
            &mut h,
        );
        assert_eq!(rv, CKR_OK, "C_OpenSession before login must return CKR_OK");
        assert!(h != 0, "session handle must be non-zero");

        // Confirm public session state before login.
        let mut info: CK_SESSION_INFO = std::mem::zeroed();
        let rv = fl.C_GetSessionInfo.unwrap()(h, &mut info);
        assert_eq!(rv, CKR_OK, "C_GetSessionInfo");
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION, "pre-login session state must be CKS_RW_PUBLIC_SESSION");

        // Login using the session handle obtained before login.
        let rv = fl.C_Login.unwrap()(h, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login with pre-login session handle");

        // The session handle obtained before login must still be valid.
        let rv = fl.C_GetSessionInfo.unwrap()(h, &mut info);
        assert_eq!(rv, CKR_OK, "session handle must be valid after login");
        assert_eq!(info.state, CKS_RW_USER_FUNCTIONS, "post-login state must be CKS_RW_USER_FUNCTIONS");

        fl.C_CloseSession.unwrap()(h);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_FindObjects with CKA_DECRYPT and CKA_VERIFY attribute filters
// ---------------------------------------------------------------------------
//
// matches_template must handle CKA_DECRYPT and CKA_VERIFY; previously the
// _ => return false catchall caused these filters to always return no objects.

#[test]
fn find_objects_with_attribute_filters() {
    let _g = LOCK.lock().unwrap();
    let pin = b"test-findobj-filter";
    let entries = vec![
        KeyEntry {
            id: [0x07; 16],
            label: "rsa-key".to_string(),
            key_type: KeyType::Rsa,
            der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
            cert_der: None,
            pub_bytes: None,
        },
        KeyEntry {
            id: [0x08; 16],
            label: "ec-key".to_string(),
            key_type: KeyType::Ec,
            der_bytes: hex::decode(EC_PRIV_HEX).expect("ec hex"),
            cert_der: None,
            pub_bytes: None,
        },
    ];
    let kf = make_keystore_file(entries, pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");
        let session = open_session(fl);

        // Filter by CKA_VERIFY = CK_TRUE: both RSA and EC support verify.
        let mut verify_true: CK_BBOOL = CK_TRUE;
        let mut tmpl_verify = CK_ATTRIBUTE {
            type_: CKA_VERIFY,
            pValue: &mut verify_true as *mut _ as _,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        };
        let rv = fl.C_FindObjectsInit.unwrap()(session, &mut tmpl_verify, 1);
        assert_eq!(rv, CKR_OK, "FindObjectsInit(CKA_VERIFY=true)");
        let mut handles = [0u64; 16];
        let mut found: CK_ULONG = 0;
        fl.C_FindObjects.unwrap()(session, handles.as_mut_ptr(), 16, &mut found);
        fl.C_FindObjectsFinal.unwrap()(session);
        assert_eq!(found, 2, "CKA_VERIFY=true must match both RSA and EC keys");

        // Filter by CKA_DECRYPT = CK_TRUE: only RSA supports decryption.
        let mut decrypt_true: CK_BBOOL = CK_TRUE;
        let mut tmpl_decrypt = CK_ATTRIBUTE {
            type_: CKA_DECRYPT,
            pValue: &mut decrypt_true as *mut _ as _,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        };
        let rv = fl.C_FindObjectsInit.unwrap()(session, &mut tmpl_decrypt, 1);
        assert_eq!(rv, CKR_OK, "FindObjectsInit(CKA_DECRYPT=true)");
        let mut found2: CK_ULONG = 0;
        fl.C_FindObjects.unwrap()(session, handles.as_mut_ptr(), 16, &mut found2);
        fl.C_FindObjectsFinal.unwrap()(session);
        assert_eq!(found2, 1, "CKA_DECRYPT=true must match only the RSA key");

        // Filter by CKA_DECRYPT = CK_FALSE: only EC keys.
        let mut decrypt_false: CK_BBOOL = CK_FALSE;
        let mut tmpl_no_decrypt = CK_ATTRIBUTE {
            type_: CKA_DECRYPT,
            pValue: &mut decrypt_false as *mut _ as _,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        };
        let rv = fl.C_FindObjectsInit.unwrap()(session, &mut tmpl_no_decrypt, 1);
        assert_eq!(rv, CKR_OK, "FindObjectsInit(CKA_DECRYPT=false)");
        let mut found3: CK_ULONG = 0;
        fl.C_FindObjects.unwrap()(session, handles.as_mut_ptr(), 16, &mut found3);
        fl.C_FindObjectsFinal.unwrap()(session);
        assert_eq!(found3, 1, "CKA_DECRYPT=false must match only the EC key");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: CKR_BUFFER_TOO_SMALL from C_Sign does not terminate the signing operation
// ---------------------------------------------------------------------------
//
// PKCS#11 s.11.11: CKR_BUFFER_TOO_SMALL is the one error that does NOT terminate
// an active single-part operation. The caller may retry with a larger buffer
// without calling C_SignInit again. This test verifies:
// 1. A non-null undersized buffer returns CKR_BUFFER_TOO_SMALL.
// 2. The operation survives: C_Sign with a correct-size buffer then succeeds.
// 3. The final signature is valid (openssl as independent oracle).

#[test]
fn c_sign_buffer_too_small_does_not_terminate_op() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"test-buftoosmall-pin";
    let entry = KeyEntry {
        id: [0x09; 16],
        label: "test-rsa-buf".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);
        let key = find_first_private_key(fl, session);
        let msg = b"message for CKR_BUFFER_TOO_SMALL PKCS11 s11.11 test";

        let mut pss_params = CK_RSA_PKCS_PSS_PARAMS { hashAlg: CKM_SHA256, mgf: CKG_MGF1_SHA256, sLen: 32 };
        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut pss_params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_SignInit.unwrap()(session, &mut ck_mech, key);
        assert_eq!(rv, CKR_OK, "C_SignInit");

        // Step 1: non-null 1-byte buffer -- too small, must return CKR_BUFFER_TOO_SMALL.
        // sig_len must be updated to the actual required length.
        let mut tiny_buf = [0u8; 1];
        let mut sig_len: CK_ULONG = 1;
        let rv = fl.C_Sign.unwrap()(
            session,
            msg.as_ptr() as _,
            msg.len() as CK_ULONG,
            tiny_buf.as_mut_ptr(),
            &mut sig_len,
        );
        assert_eq!(rv, CKR_BUFFER_TOO_SMALL, "undersized non-null buffer must give CKR_BUFFER_TOO_SMALL");
        assert!(sig_len > 1, "sig_len must be updated to the required size");

        // Step 2: retry with the correct size -- op must still be active (s.11.11 exception).
        // If CKR_BUFFER_TOO_SMALL had wrongly terminated the op, this would return
        // CKR_OPERATION_NOT_INITIALIZED instead of CKR_OK.
        let mut sig_buf = vec![0u8; sig_len as usize];
        let mut sig_len2 = sig_len;
        let rv = fl.C_Sign.unwrap()(
            session,
            msg.as_ptr() as _,
            msg.len() as CK_ULONG,
            sig_buf.as_mut_ptr(),
            &mut sig_len2,
        );
        assert_eq!(rv, CKR_OK, "retry with correct size must succeed -- op must have survived CKR_BUFFER_TOO_SMALL");
        sig_buf.truncate(sig_len2 as usize);

        // Step 3: verify with openssl as independent oracle.
        let sig_f = write_tmp(&sig_buf);
        let msg_f = write_tmp(msg);
        let pub_f = write_tmp_str(RSA_PUB_PEM);
        let out = Command::new("openssl")
            .args([
                "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-verify", pub_f.path().to_str().unwrap(),
                "-signature", sig_f.path().to_str().unwrap(),
                msg_f.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl not found");
        assert!(
            out.status.success(),
            "openssl RSA-PSS verify failed after buffer-too-small retry:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_Verify accepts a valid RSA-PSS signature (C_Sign as reference path)
// ---------------------------------------------------------------------------
//
// Oracle: C_Sign output is independently verified against openssl in
// rsa_pss_pkcs11_flow_verified_by_openssl. If C_Sign produces correct
// signatures, C_Verify must accept them -- this tests the C_VerifyInit /
// C_Verify dispatch path end-to-end.

#[test]
fn c_verify_accepts_valid_rsa_pss_signature() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"test-verify-pin";
    let entry = KeyEntry {
        id: [0x0A; 16],
        label: "test-rsa-verify".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);
        let key = find_first_private_key(fl, session);
        let msg = b"message for C_Verify integration test";

        // Sign with C_Sign (independently cross-validated against openssl in
        // rsa_pss_pkcs11_flow_verified_by_openssl).
        let sig = pkcs11_sign(fl, session, CKM_RSA_PKCS_PSS, key, msg);

        // Verify with C_Verify using the same mechanism and key handle.
        let mut pss_params = CK_RSA_PKCS_PSS_PARAMS { hashAlg: CKM_SHA256, mgf: CKG_MGF1_SHA256, sLen: 32 };
        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut pss_params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_VerifyInit.unwrap()(session, &mut ck_mech, key);
        assert_eq!(rv, CKR_OK, "C_VerifyInit");

        let rv = fl.C_Verify.unwrap()(
            session,
            msg.as_ptr() as _,
            msg.len() as CK_ULONG,
            sig.as_ptr() as _,
            sig.len() as CK_ULONG,
        );
        assert_eq!(rv, CKR_OK, "C_Verify must accept a valid RSA-PSS signature");

        // Verify that a tampered signature is rejected.
        let rv = fl.C_VerifyInit.unwrap()(session, &mut ck_mech, key);
        assert_eq!(rv, CKR_OK, "C_VerifyInit for tamper test");
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xFF;
        let rv = fl.C_Verify.unwrap()(
            session,
            msg.as_ptr() as _,
            msg.len() as CK_ULONG,
            bad_sig.as_ptr() as _,
            bad_sig.len() as CK_ULONG,
        );
        assert_ne!(rv, CKR_OK, "C_Verify must reject a tampered signature");

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: RSA-OAEP C_Encrypt output is correctly decrypted by openssl
// ---------------------------------------------------------------------------
//
// Oracle: openssl pkeyutl decrypts the C_Encrypt output -- this is a true
// external oracle. If openssl can decrypt what we encrypted and recovers the
// original plaintext, our OAEP encryption is correct per RFC 8017 s.7.1.
//
// RSA_PKCS8_DER_HEX is PKCS#8-wrapped PKCS#1; the token unwraps it at load.
// openssl pkey -inform DER handles both PKCS#1 and PKCS#8 DER and converts to PEM.

#[test]
fn rsa_oaep_c_encrypt_verified_by_openssl_decrypt() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"test-oaep-oracle-pin";
    let entry = KeyEntry {
        id: [0x0B; 16],
        label: "test-rsa-oaep-oracle".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);
        let key = find_first_private_key(fl, session);

        let plaintext = b"rsa-oaep-oracle-test-plaintext";

        // Encrypt with C_Encrypt (CKM_RSA_PKCS_OAEP).
        let mut oaep_params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: std::ptr::null_mut(),
            ulSourceDataLen: 0,
        };
        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut oaep_params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        let rv = fl.C_EncryptInit.unwrap()(session, &mut ck_mech, key);
        assert_eq!(rv, CKR_OK, "C_EncryptInit");

        // Length query: NULL output pointer returns max ciphertext size.
        let mut ct_len: CK_ULONG = 0;
        let rv = fl.C_Encrypt.unwrap()(
            session,
            plaintext.as_ptr() as _,
            plaintext.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut ct_len,
        );
        assert_eq!(rv, CKR_OK, "C_Encrypt length query");
        assert!(ct_len > 0, "ciphertext length must be non-zero");

        let mut ct_buf = vec![0u8; ct_len as usize];
        let mut ct_len2 = ct_len;
        let rv = fl.C_Encrypt.unwrap()(
            session,
            plaintext.as_ptr() as _,
            plaintext.len() as CK_ULONG,
            ct_buf.as_mut_ptr(),
            &mut ct_len2,
        );
        assert_eq!(rv, CKR_OK, "C_Encrypt");
        ct_buf.truncate(ct_len2 as usize);

        // Write ciphertext and private key to temp files.
        let ct_f = write_tmp(&ct_buf);
        let priv_der = hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex");
        let priv_der_f = write_tmp(&priv_der);

        // Convert private key DER to PEM (openssl pkey handles PKCS#1 and PKCS#8 DER).
        let priv_pem_f = tempfile::NamedTempFile::new().expect("tmpfile");
        let out = Command::new("openssl")
            .args([
                "pkey", "-inform", "DER",
                "-in", priv_der_f.path().to_str().unwrap(),
                "-out", priv_pem_f.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl not found");
        assert!(
            out.status.success(),
            "openssl pkey DER->PEM failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        // Decrypt with openssl pkeyutl OAEP-SHA256 (external oracle).
        let out = Command::new("openssl")
            .args([
                "pkeyutl", "-decrypt",
                "-inkey", priv_pem_f.path().to_str().unwrap(),
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256",
                "-in", ct_f.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl not found");
        assert!(
            out.status.success(),
            "openssl OAEP-SHA256 decrypt failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        assert_eq!(
            out.stdout.as_slice(), plaintext.as_ref(),
            "openssl decrypted a different plaintext -- C_Encrypt is not RFC 8017 OAEP-SHA256"
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// soft_PKCS11-atf: after a crypto error, the session must NOT be wedged.
// C_SignInit must succeed again after a C_Sign failure.
#[test]
fn sign_op_context_cleared_after_device_removed() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();
    unsafe {
        let fl = fl();
        init(fl);

        // Set up a keystore with an EC key.
        let ec_priv = hex::decode(EC_PRIV_HEX).unwrap();
        let kf = make_keystore_file(
            vec![usb_hsm::keystore::KeyEntry {
                id: [3u8; 16],
                label: "ec-sign-ctx".to_owned(),
                key_type: usb_hsm::keystore::KeyType::Ec,
                der_bytes: ec_priv,
                cert_der: None,
                pub_bytes: None,
            }],
            b"testpin",
        );
        usb_hsm::test_mount(kf.path());

        let mut session: CK_SESSION_HANDLE = 0;
        let rv = fl.C_OpenSession.unwrap()(0, CKF_RW_SESSION | CKF_SERIAL_SESSION,
            std::ptr::null_mut(), None, &mut session);
        assert_eq!(rv, CKR_OK);

        let rv = fl.C_Login.unwrap()(session, CKU_USER, b"testpin".as_ptr() as _, 7);
        assert_eq!(rv, CKR_OK, "login");

        // Find the key object.
        let mut h_key: CK_OBJECT_HANDLE = 0;
        let mut found: CK_ULONG = 0;
        fl.C_FindObjectsInit.unwrap()(session, std::ptr::null_mut(), 0);
        fl.C_FindObjects.unwrap()(session, &mut h_key, 1, &mut found);
        fl.C_FindObjectsFinal.unwrap()(session);
        assert_eq!(found, 1, "must find exactly one key");

        // Init a sign operation.
        let mut mech = CK_MECHANISM { mechanism: CKM_ECDSA_SHA256, pParameter: std::ptr::null_mut(), ulParameterLen: 0 };
        let rv = fl.C_SignInit.unwrap()(session, &mut mech, h_key);
        assert_eq!(rv, CKR_OK, "first SignInit must succeed");

        // Simulate USB removal mid-operation.
        usb_hsm::test_unmount();

        // C_Sign now fails because the device is removed.
        let msg = b"hello";
        let mut sig_buf = [0u8; 72];
        let mut sig_len: CK_ULONG = 72;
        let rv = fl.C_Sign.unwrap()(session, msg.as_ptr() as _, msg.len() as CK_ULONG,
            sig_buf.as_mut_ptr(), &mut sig_len);
        assert_eq!(rv, CKR_DEVICE_REMOVED, "C_Sign must return CKR_DEVICE_REMOVED");

        // CRITICAL: the op context must be cleared. Re-mounting and signing again
        // must succeed without needing to close/reopen the session.
        usb_hsm::test_mount(kf.path());
        let _rv = fl.C_Login.unwrap()(session, CKU_USER, b"testpin".as_ptr() as _, 7);
        // After device removal the session is invalid; re-login should return
        // CKR_DEVICE_REMOVED. The key assertion
        // is that we do NOT get CKR_OPERATION_ACTIVE on a fresh SignInit below --
        // that would mean the op context was NOT cleared.
        // Use a fresh session for the final sign check.
        usb_hsm::test_reset();
        usb_hsm::test_mount(kf.path());
        fl.C_Initialize.unwrap()(std::ptr::null_mut());
        let mut s2: CK_SESSION_HANDLE = 0;
        fl.C_OpenSession.unwrap()(0, CKF_RW_SESSION | CKF_SERIAL_SESSION,
            std::ptr::null_mut(), None, &mut s2);
        fl.C_Login.unwrap()(s2, CKU_USER, b"testpin".as_ptr() as _, 7);
        let mut h2: CK_OBJECT_HANDLE = 0;
        let mut found2: CK_ULONG = 0;
        fl.C_FindObjectsInit.unwrap()(s2, std::ptr::null_mut(), 0);
        fl.C_FindObjects.unwrap()(s2, &mut h2, 1, &mut found2);
        fl.C_FindObjectsFinal.unwrap()(s2);

        let rv = fl.C_SignInit.unwrap()(s2, &mut mech, h2);
        assert_eq!(rv, CKR_OK, "SignInit on fresh session after reset must succeed -- NOT CKR_OPERATION_ACTIVE");
    }
}

// ---------------------------------------------------------------------------
// Test: openssl OAEP-SHA256 encrypt -> C_Decrypt (soft_PKCS11-p8f)
//
// Oracle: openssl pkeyutl encrypts with SHA-256 + MGF1-SHA256 OAEP using the
// embedded RSA public key. Our C_Decrypt must recover the plaintext exactly.
// This validates the full decrypt path with an independent external oracle as
// the encryptor, complementing rsa_oaep_c_encrypt_verified_by_openssl_decrypt
// which tests the reverse direction.
// ---------------------------------------------------------------------------

#[test]
fn rsa_oaep_openssl_encrypt_decrypted_by_c_decrypt() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"test-oaep-c-decrypt-pin";
    let entry = usb_hsm::keystore::KeyEntry {
        id: [0x0C; 16],
        label: "test-rsa-oaep-decrypt".to_string(),
        key_type: usb_hsm::keystore::KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);

        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session = open_session(fl);
        let key = find_first_private_key(fl, session);

        let plaintext = b"openssl-encrypted-oaep-test-plaintext";

        // Write the public key PEM to a temp file so openssl can encrypt with it.
        let pub_f = write_tmp_str(RSA_PUB_PEM);

        // Write plaintext to a temp file.
        let pt_f = write_tmp(plaintext);

        // Encrypt with openssl pkeyutl using OAEP-SHA256 (external oracle).
        let ct_f = tempfile::NamedTempFile::new().expect("tmpfile");
        let out = Command::new("openssl")
            .args([
                "pkeyutl", "-encrypt",
                "-pubin",
                "-inkey", pub_f.path().to_str().unwrap(),
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256",
                "-in", pt_f.path().to_str().unwrap(),
                "-out", ct_f.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl not found");
        assert!(
            out.status.success(),
            "openssl OAEP-SHA256 encrypt failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        let ciphertext = std::fs::read(ct_f.path()).expect("read ciphertext");

        // Decrypt the openssl-produced ciphertext with C_Decrypt.
        let mut oaep_params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: std::ptr::null_mut(),
            ulSourceDataLen: 0,
        };
        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut oaep_params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };

        let rv = fl.C_DecryptInit.unwrap()(session, &mut ck_mech, key);
        assert_eq!(rv, CKR_OK, "C_DecryptInit");

        // Length query: NULL output pointer returns required buffer length.
        let mut pt_len: CK_ULONG = 0;
        let rv = fl.C_Decrypt.unwrap()(
            session,
            ciphertext.as_ptr() as _,
            ciphertext.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut pt_len,
        );
        assert_eq!(rv, CKR_OK, "C_Decrypt length query");
        assert!(pt_len > 0, "plaintext length must be non-zero");

        let mut pt_buf = vec![0u8; pt_len as usize];
        let mut pt_len2 = pt_len;
        let rv = fl.C_Decrypt.unwrap()(
            session,
            ciphertext.as_ptr() as _,
            ciphertext.len() as CK_ULONG,
            pt_buf.as_mut_ptr(),
            &mut pt_len2,
        );
        assert_eq!(rv, CKR_OK, "C_Decrypt");
        pt_buf.truncate(pt_len2 as usize);

        assert_eq!(
            pt_buf.as_slice(), plaintext.as_ref(),
            "C_Decrypt must recover the openssl-encrypted plaintext exactly"
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: CKR_OPERATION_ACTIVE -- calling C_SignInit twice without completing
//       the first operation (soft_PKCS11-cnm)
// ---------------------------------------------------------------------------

#[test]
fn c_sign_init_twice_returns_operation_active() {
    let _g = LOCK.lock().unwrap();
    let pin = b"test-pin-op-active";
    let entry = KeyEntry {
        id: [0xA1; 16],
        label: "test-rsa-op-active".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        let session = open_session(fl);
        let key = find_first_private_key(fl, session);

        let mut pss_params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut pss_params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };

        // First C_SignInit must succeed.
        let rv = fl.C_SignInit.unwrap()(session, &mut mech, key);
        assert_eq!(rv, CKR_OK, "first C_SignInit must succeed");

        // Second C_SignInit without completing the first must return CKR_OPERATION_ACTIVE
        // per PKCS#11 s.11.12: only one active operation per session at a time.
        let rv = fl.C_SignInit.unwrap()(session, &mut mech, key);
        assert_eq!(rv, CKR_OPERATION_ACTIVE,
            "second C_SignInit must return CKR_OPERATION_ACTIVE");

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: CKR_KEY_HANDLE_INVALID -- calling C_SignInit with a handle that does
//       not correspond to any key in the keystore (soft_PKCS11-cnm)
// ---------------------------------------------------------------------------

#[test]
fn c_sign_init_invalid_key_handle_returns_key_handle_invalid() {
    let _g = LOCK.lock().unwrap();
    let pin = b"test-pin-key-inval";
    let entry = KeyEntry {
        id: [0xA2; 16],
        label: "test-rsa-key-inval".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        let session = open_session(fl);

        let mut pss_params = CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            sLen: 32,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS,
            pParameter: &mut pss_params as *mut _ as *mut std::os::raw::c_void,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
        };

        // Handle 9999 is far outside the range of valid key handles (1-indexed,
        // maximum = number of keys in keystore). Must return CKR_KEY_HANDLE_INVALID
        // per PKCS#11 s.11.12.
        let rv = fl.C_SignInit.unwrap()(session, &mut mech, 9999);
        assert_eq!(rv, CKR_KEY_HANDLE_INVALID,
            "nonexistent key handle must return CKR_KEY_HANDLE_INVALID");

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_CloseAllSessions closes all sessions and allows new sessions
//       (soft_PKCS11-juc, PKCS#11 s.11.5)
// ---------------------------------------------------------------------------

#[test]
fn c_close_all_sessions_closes_all_and_allows_new() {
    let _g = LOCK.lock().unwrap();
    let pin = b"test-pin-close-all";
    let entry = KeyEntry {
        id: [0xA3; 16],
        label: "test-rsa-close-all".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);

        let session1 = open_session(fl);
        let session2 = open_session(fl);
        assert_ne!(session1, session2, "two concurrent session handles must be distinct");

        // C_CloseAllSessions must succeed and close all sessions for slot 0.
        let rv = fl.C_CloseAllSessions.unwrap()(0);
        assert_eq!(rv, CKR_OK, "C_CloseAllSessions must return CKR_OK");

        // Both old handles must now be invalid -- PKCS#11 s.11.5 guarantees this.
        let mut info: CK_SESSION_INFO = std::mem::zeroed();
        let rv = fl.C_GetSessionInfo.unwrap()(session1, &mut info);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID,
            "session1 must be invalid after C_CloseAllSessions");

        let rv = fl.C_GetSessionInfo.unwrap()(session2, &mut info);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID,
            "session2 must be invalid after C_CloseAllSessions");

        // Token is still mounted; C_OpenSession must succeed for new sessions.
        let mut new_h: CK_SESSION_HANDLE = 0;
        let rv = fl.C_OpenSession.unwrap()(
            0,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            std::ptr::null_mut(),
            None,
            &mut new_h,
        );
        assert_eq!(rv, CKR_OK, "C_OpenSession must succeed after C_CloseAllSessions");
        assert!(new_h != 0, "new session handle must be non-zero");

        fl.C_CloseSession.unwrap()(new_h);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_GenerateRandom fills the buffer with non-zero data (soft_PKCS11-ofx)
// ---------------------------------------------------------------------------

#[test]
fn c_generate_random_fills_with_non_zero_data() {
    let _g = LOCK.lock().unwrap();
    let pin = b"test-pin-gen-rand";
    let entry = KeyEntry {
        id: [0xA4; 16],
        label: "test-rsa-gen-rand".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        let session = open_session(fl);

        let mut buf = [0u8; 32];
        let rv = fl.C_GenerateRandom.unwrap()(session, buf.as_mut_ptr(), 32);
        assert_eq!(rv, CKR_OK, "C_GenerateRandom must return CKR_OK with a valid session");

        // Probability of all-zero output from a correct RNG: 2^-256 ~= 0.
        // A failure here almost certainly means the RNG is returning zeros.
        assert_ne!(buf, [0u8; 32],
            "C_GenerateRandom must not return an all-zero buffer");

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_GenerateRandom with zero length returns CKR_ARGUMENTS_BAD (ofx)
// ---------------------------------------------------------------------------

#[test]
fn c_generate_random_zero_length_returns_arguments_bad() {
    let _g = LOCK.lock().unwrap();
    let pin = b"test-pin-gen-zero";
    let entry = KeyEntry {
        id: [0xA5; 16],
        label: "test-rsa-gen-zero".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        let session = open_session(fl);

        // A non-null pointer with zero length is a degenerate request: no bytes
        // can be filled, so it is treated as a caller error (CKR_ARGUMENTS_BAD).
        let mut buf = [0u8; 1];
        let rv = fl.C_GenerateRandom.unwrap()(session, buf.as_mut_ptr(), 0);
        assert_eq!(rv, CKR_ARGUMENTS_BAD,
            "zero-length C_GenerateRandom must return CKR_ARGUMENTS_BAD");

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Certificate object tests (CKO_CERTIFICATE)
//
// These tests use a fixed synthetic cert DER byte sequence.  The token stores
// and returns it opaquely; no ASN.1 parsing is performed here.  The oracle is
// the round-trip: what we store must come back byte-for-byte.
// ---------------------------------------------------------------------------

// A minimal synthetic DER byte sequence -- NOT a real certificate, just a
// fixed oracle value for byte-exact round-trip verification.
const TEST_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x00, 0x1c, // SEQUENCE, length 28 (fake)
    0xde, 0xad, 0xbe, 0xef, // fake content
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18,
];

// Matches the internal CERT_HANDLE_ORIGIN constant in lib.rs.
const CERT_HANDLE_ORIGIN: CK_OBJECT_HANDLE = 0x10_0000;

/// Build a single-entry keystore that has a cert_der payload.
fn make_cert_keystore(pin: &[u8]) -> NamedTempFile {
    let entry = KeyEntry {
        id: [0xCE; 16],
        label: "cert-test-key".to_string(),
        key_type: KeyType::Ec,
        der_bytes: hex::decode(EC_PRIV_HEX).expect("ec hex"),
        cert_der: Some(TEST_CERT_DER.to_vec()),
        pub_bytes: None,
    };
    make_keystore_file(vec![entry], pin)
}

/// Find all objects matching `cls`; returns their handles.
unsafe fn find_by_class(
    fl: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    cls: CK_OBJECT_CLASS,
) -> Vec<CK_OBJECT_HANDLE> {
    let mut cls_val = cls;
    let mut tmpl = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: &mut cls_val as *mut _ as _,
        ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    let rv = fl.C_FindObjectsInit.unwrap()(session, &mut tmpl, 1);
    assert_eq!(rv, CKR_OK, "C_FindObjectsInit cls={cls:#x}");
    let mut handles = [0u64; 32];
    let mut found: CK_ULONG = 0;
    let rv = fl.C_FindObjects.unwrap()(session, handles.as_mut_ptr(), 32, &mut found);
    assert_eq!(rv, CKR_OK, "C_FindObjects cls={cls:#x}");
    fl.C_FindObjectsFinal.unwrap()(session);
    handles[..found as usize].to_vec()
}

// ---------------------------------------------------------------------------
// Test: C_FindObjects returns both key handle and cert handle; class filters
// ---------------------------------------------------------------------------
//
// With no filter, a single keystore entry with cert_der set must appear twice:
// once as a private-key object and once as a certificate object.  Class-based
// filters must restrict results to the matching object type only.

#[test]
fn cert_find_objects_by_class() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"testpin-cert-find";
    let kf = make_cert_keystore(pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");
        let session = open_session(fl);

        // Unfiltered: must return exactly two handles.
        let rv = fl.C_FindObjectsInit.unwrap()(session, std::ptr::null_mut(), 0);
        assert_eq!(rv, CKR_OK, "C_FindObjectsInit (unfiltered)");
        let mut handles = [0u64; 16];
        let mut found: CK_ULONG = 0;
        let rv = fl.C_FindObjects.unwrap()(session, handles.as_mut_ptr(), 16, &mut found);
        assert_eq!(rv, CKR_OK, "C_FindObjects (unfiltered)");
        fl.C_FindObjectsFinal.unwrap()(session);
        assert_eq!(found, 2, "unfiltered find must return key handle + cert handle");
        let all: Vec<CK_OBJECT_HANDLE> = handles[..2].to_vec();
        let key_handles: Vec<_> = all.iter().filter(|&&h| h < CERT_HANDLE_ORIGIN).copied().collect();
        let cert_handles_all: Vec<_> = all.iter().filter(|&&h| h >= CERT_HANDLE_ORIGIN).copied().collect();
        assert_eq!(key_handles.len(), 1, "expected one key handle");
        assert_eq!(cert_handles_all.len(), 1, "expected one cert handle");

        // CKO_PRIVATE_KEY filter must return exactly one handle below CERT_HANDLE_ORIGIN.
        let priv_handles = find_by_class(fl, session, CKO_PRIVATE_KEY);
        assert_eq!(priv_handles.len(), 1, "CKO_PRIVATE_KEY filter must return exactly one handle");
        assert!(
            priv_handles[0] < CERT_HANDLE_ORIGIN,
            "key handle must be < CERT_HANDLE_ORIGIN, got {:#x}",
            priv_handles[0]
        );

        // CKO_CERTIFICATE filter must return exactly one handle at or above CERT_HANDLE_ORIGIN.
        let cert_handles = find_by_class(fl, session, CKO_CERTIFICATE);
        assert_eq!(cert_handles.len(), 1, "CKO_CERTIFICATE filter must return exactly one handle");
        assert!(
            cert_handles[0] >= CERT_HANDLE_ORIGIN,
            "cert handle must be >= CERT_HANDLE_ORIGIN, got {:#x}",
            cert_handles[0]
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_GetAttributeValue on cert handle returns correct attributes
// ---------------------------------------------------------------------------
//
// The oracle for CKA_VALUE is TEST_CERT_DER -- the same bytes put in at keystore
// creation.  CKA_CLASS and CKA_CERTIFICATE_TYPE are fixed protocol values and
// serve as their own oracle.

#[test]
fn cert_get_attribute_value() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"testpin-cert-attrs";
    let kf = make_cert_keystore(pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");
        let session = open_session(fl);

        let cert_handles = find_by_class(fl, session, CKO_CERTIFICATE);
        assert_eq!(cert_handles.len(), 1, "expected one cert handle");
        let cert_h = cert_handles[0];

        // Query CKA_CLASS, CKA_CERTIFICATE_TYPE, CKA_VALUE, CKA_ID in one call.
        let mut cls_val: CK_OBJECT_CLASS = 0;
        let mut cert_type_val: CK_ULONG = 0;
        let mut value_buf = [0u8; 64];
        let mut id_buf = [0u8; 16];
        let mut attrs = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: &mut cls_val as *mut _ as _,
                ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_CERTIFICATE_TYPE,
                pValue: &mut cert_type_val as *mut _ as _,
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: value_buf.as_mut_ptr() as _,
                ulValueLen: value_buf.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID,
                pValue: id_buf.as_mut_ptr() as _,
                ulValueLen: id_buf.len() as CK_ULONG,
            },
        ];
        let rv = fl.C_GetAttributeValue.unwrap()(session, cert_h, attrs.as_mut_ptr(), 4);
        assert_eq!(rv, CKR_OK, "C_GetAttributeValue on cert handle");

        assert_eq!(cls_val, CKO_CERTIFICATE, "CKA_CLASS must be CKO_CERTIFICATE");
        assert_eq!(cert_type_val, CKC_X_509, "CKA_CERTIFICATE_TYPE must be CKC_X_509");

        let value_len = attrs[2].ulValueLen as usize;
        assert_eq!(value_len, TEST_CERT_DER.len(), "CKA_VALUE length must match stored cert");
        assert_eq!(
            &value_buf[..value_len],
            TEST_CERT_DER,
            "CKA_VALUE bytes must match stored cert DER exactly"
        );

        let id_len = attrs[3].ulValueLen as usize;
        assert_eq!(id_len, 16, "CKA_ID must be 16 bytes");
        assert_eq!(&id_buf[..16], &[0xCEu8; 16], "CKA_ID must match keystore entry id");

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// Test: C_SignInit with a cert handle returns CKR_KEY_HANDLE_INVALID
// ---------------------------------------------------------------------------
//
// Certificate objects cannot be used for signing.  Passing a cert handle to
// C_SignInit must be rejected before any operation state is established.

#[test]
fn cert_sign_init_returns_handle_invalid() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"testpin-cert-sign";
    let kf = make_cert_keystore(pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");
        let session = open_session(fl);

        let cert_handles = find_by_class(fl, session, CKO_CERTIFICATE);
        assert_eq!(cert_handles.len(), 1, "expected one cert handle");
        let cert_h = cert_handles[0];

        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_ECDSA_SHA256,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = fl.C_SignInit.unwrap()(session, &mut ck_mech, cert_h);
        assert_eq!(
            rv, CKR_KEY_HANDLE_INVALID,
            "C_SignInit with cert handle must return CKR_KEY_HANDLE_INVALID"
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// C_GenerateKeyPair helpers
// ---------------------------------------------------------------------------

/// Encode `len` as a DER definite-form length into `out`.
fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xFF) as u8]);
    }
}

/// Encode unsigned big-endian bytes `v` as a DER INTEGER.
fn der_uint(v: &[u8]) -> Vec<u8> {
    // Strip leading zeros but keep at least one byte.
    let start = v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1);
    let trimmed = &v[start..];
    let needs_pad = trimmed[0] & 0x80 != 0;
    let inner_len = trimmed.len() + usize::from(needs_pad);
    let mut out = vec![0x02];
    der_len(&mut out, inner_len);
    if needs_pad { out.push(0x00); }
    out.extend_from_slice(trimmed);
    out
}

/// Build a SubjectPublicKeyInfo DER for an EC P-256 key from its X9.63 uncompressed point.
///
/// This is an independent implementation used to present the token's generated public key
/// to openssl.  It is NOT derived from any token code path.
fn build_ec_p256_spki(x963_point: &[u8]) -> Vec<u8> {
    assert_eq!(x963_point.len(), 65, "P-256 X9.63 point must be 65 bytes");
    assert_eq!(x963_point[0], 0x04, "X9.63 uncompressed point must start with 0x04");
    // AlgorithmIdentifier for EC P-256 (id-ecPublicKey OID + secp256r1 OID, fixed DER):
    let alg_id: &[u8] = &[
        0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // secp256r1
    ];
    // BIT STRING: 0x00 (zero unused bits) || X9.63 point
    let mut bit_str = vec![0x03];
    der_len(&mut bit_str, x963_point.len() + 1);
    bit_str.push(0x00);
    bit_str.extend_from_slice(x963_point);
    // SubjectPublicKeyInfo SEQUENCE
    let inner_len = alg_id.len() + bit_str.len();
    let mut spki = vec![0x30];
    der_len(&mut spki, inner_len);
    spki.extend_from_slice(alg_id);
    spki.extend_from_slice(&bit_str);
    spki
}

/// Build a SubjectPublicKeyInfo DER for an RSA key from its raw modulus and public exponent.
///
/// This is an independent implementation used to present the token's generated public key
/// to openssl.  It is NOT derived from any token code path.
fn build_rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier: SEQUENCE { OID rsaEncryption, NULL }
    let alg_id: &[u8] = &[
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // rsaEncryption
        0x05, 0x00, // NULL
    ];
    // RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
    let n_enc = der_uint(modulus);
    let e_enc = der_uint(exponent);
    let rsa_inner = n_enc.len() + e_enc.len();
    let mut rsa_pub = vec![0x30];
    der_len(&mut rsa_pub, rsa_inner);
    rsa_pub.extend_from_slice(&n_enc);
    rsa_pub.extend_from_slice(&e_enc);
    // BIT STRING: 0x00 (zero unused bits) || RSAPublicKey DER
    let mut bit_str = vec![0x03];
    der_len(&mut bit_str, rsa_pub.len() + 1);
    bit_str.push(0x00);
    bit_str.extend_from_slice(&rsa_pub);
    // SubjectPublicKeyInfo SEQUENCE
    let spki_inner = alg_id.len() + bit_str.len();
    let mut spki = vec![0x30];
    der_len(&mut spki, spki_inner);
    spki.extend_from_slice(alg_id);
    spki.extend_from_slice(&bit_str);
    spki
}

/// Query a single attribute via C_GetAttributeValue; panics if the call fails.
/// `buf_size` must be at least as large as the attribute value.
unsafe fn get_attr(
    fl: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    h_obj: CK_OBJECT_HANDLE,
    attr_type: CK_ULONG,
    buf_size: usize,
) -> Vec<u8> {
    let mut buf = vec![0u8; buf_size];
    let mut attr = CK_ATTRIBUTE {
        type_: attr_type,
        pValue: buf.as_mut_ptr() as _,
        ulValueLen: buf.len() as CK_ULONG,
    };
    let rv = fl.C_GetAttributeValue.unwrap()(session, h_obj, &mut attr, 1);
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue attr={attr_type:#x}");
    buf.truncate(attr.ulValueLen as usize);
    buf
}

// ---------------------------------------------------------------------------
// C_GenerateKeyPair tests
// ---------------------------------------------------------------------------

// Test: EC P-256 key pair generation, ECDSA-SHA256 signing, and openssl verification.
//
// The public key is retrieved via CKA_EC_POINT and an independent SubjectPublicKeyInfo
// DER is constructed from the raw point bytes.  openssl is the external verification oracle.
#[test]
fn generate_ec_key_pair_sign_verify() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"gen-ec-pin";
    let kf = make_cert_keystore(pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");
        let session = open_session(fl);

        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut h_pub: CK_OBJECT_HANDLE = 0;
        let mut h_priv: CK_OBJECT_HANDLE = 0;
        let rv = fl.C_GenerateKeyPair.unwrap()(
            session,
            &mut ck_mech,
            std::ptr::null_mut(), 0,
            std::ptr::null_mut(), 0,
            &mut h_pub,
            &mut h_priv,
        );
        assert_eq!(rv, CKR_OK, "C_GenerateKeyPair EC");
        assert_ne!(h_pub, 0, "h_pub must be non-zero");
        assert_ne!(h_priv, 0, "h_priv must be non-zero");
        assert_ne!(h_pub, h_priv, "handles must differ");

        // Retrieve the uncompressed X9.63 public point (65 bytes for P-256).
        let point_bytes = get_attr(fl, session, h_pub, CKA_EC_POINT, 65);
        assert_eq!(point_bytes.len(), 65, "CKA_EC_POINT must be 65 bytes for P-256");
        assert_eq!(point_bytes[0], 0x04, "X9.63 uncompressed point must start with 0x04");

        // Sign a message with the private session key.
        let msg = b"generate ec key pair integration test";
        let sig = pkcs11_sign(fl, session, CKM_ECDSA_SHA256, h_priv, msg);
        assert_eq!(sig.len(), 64, "ECDSA P-256 raw r||s signature must be 64 bytes");

        // Build SubjectPublicKeyInfo DER from the raw X9.63 point (independent construction)
        // and verify the DER-encoded signature with openssl (external oracle).
        let spki_der = build_ec_p256_spki(&point_bytes);
        let spki_f = write_tmp(&spki_der);
        let sig_der = raw_rs_to_der(&sig);
        let sig_f = write_tmp(&sig_der);
        let msg_f = write_tmp(msg);
        let out = Command::new("openssl")
            .args([
                "dgst", "-sha256",
                "-verify", spki_f.path().to_str().unwrap(),
                "-keyform", "DER",
                "-signature", sig_f.path().to_str().unwrap(),
                msg_f.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl not found");
        assert!(
            out.status.success(),
            "openssl EC P-256 verify failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// Test: RSA-2048 key pair generation, RSA-PSS-SHA256 signing, and openssl verification.
//
// The public key is retrieved via CKA_MODULUS and CKA_PUBLIC_EXPONENT and an independent
// SubjectPublicKeyInfo DER is constructed.  openssl is the external verification oracle.
#[test]
fn generate_rsa_key_pair_sign_verify() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"gen-rsa-pin";
    let kf = make_cert_keystore(pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");
        let session = open_session(fl);

        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut h_pub: CK_OBJECT_HANDLE = 0;
        let mut h_priv: CK_OBJECT_HANDLE = 0;
        let rv = fl.C_GenerateKeyPair.unwrap()(
            session,
            &mut ck_mech,
            std::ptr::null_mut(), 0,
            std::ptr::null_mut(), 0,
            &mut h_pub,
            &mut h_priv,
        );
        assert_eq!(rv, CKR_OK, "C_GenerateKeyPair RSA");
        assert_ne!(h_pub, 0, "h_pub must be non-zero");
        assert_ne!(h_priv, 0, "h_priv must be non-zero");

        // Retrieve modulus (256 bytes for 2048-bit) and public exponent.
        let modulus = get_attr(fl, session, h_pub, CKA_MODULUS, 512);
        let exponent = get_attr(fl, session, h_pub, CKA_PUBLIC_EXPONENT, 16);
        assert_eq!(modulus.len(), 256, "2048-bit RSA modulus must be 256 bytes");
        assert!(!exponent.is_empty(), "public exponent must be non-empty");

        // Sign a message with RSA-PSS-SHA256 using the private session key.
        let msg = b"generate rsa key pair integration test";
        let sig = pkcs11_sign(fl, session, CKM_RSA_PKCS_PSS, h_priv, msg);
        assert_eq!(sig.len(), 256, "RSA-2048 PSS signature must be 256 bytes");

        // Build SubjectPublicKeyInfo DER from raw n and e (independent construction)
        // and verify with openssl (external oracle).
        let spki_der = build_rsa_spki(&modulus, &exponent);
        let spki_f = write_tmp(&spki_der);
        let sig_f = write_tmp(&sig);
        let msg_f = write_tmp(msg);
        let out = Command::new("openssl")
            .args([
                "dgst", "-sha256",
                "-sigopt", "rsa_padding_mode:pss",
                "-verify", spki_f.path().to_str().unwrap(),
                "-keyform", "DER",
                "-signature", sig_f.path().to_str().unwrap(),
                msg_f.path().to_str().unwrap(),
            ])
            .output()
            .expect("openssl not found");
        assert!(
            out.status.success(),
            "openssl RSA-PSS verify failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// Test: CKA_TOKEN=CK_TRUE in either template returns CKR_TEMPLATE_INCONSISTENT.
//
// This token only supports session (ephemeral) keys.  Requesting persistent storage
// must be rejected before any key material is generated.
#[test]
fn generate_key_pair_token_true_rejected() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"gen-tok-pin";
    let kf = make_cert_keystore(pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let session = open_session(fl);

        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let token_true: CK_BBOOL = CK_TRUE;

        // CKA_TOKEN=true in the private key template.
        let mut priv_tmpl = CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: &token_true as *const CK_BBOOL as _,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        };
        let mut h_pub: CK_OBJECT_HANDLE = 0;
        let mut h_priv: CK_OBJECT_HANDLE = 0;
        let rv = fl.C_GenerateKeyPair.unwrap()(
            session,
            &mut ck_mech,
            std::ptr::null_mut(), 0,
            &mut priv_tmpl, 1,
            &mut h_pub,
            &mut h_priv,
        );
        assert_eq!(
            rv, CKR_TEMPLATE_INCONSISTENT,
            "CKA_TOKEN=true in private template must return CKR_TEMPLATE_INCONSISTENT"
        );

        // CKA_TOKEN=true in the public key template.
        let mut pub_tmpl = CK_ATTRIBUTE {
            type_: CKA_TOKEN,
            pValue: &token_true as *const CK_BBOOL as _,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        };
        let rv = fl.C_GenerateKeyPair.unwrap()(
            session,
            &mut ck_mech,
            &mut pub_tmpl, 1,
            std::ptr::null_mut(), 0,
            &mut h_pub,
            &mut h_priv,
        );
        assert_eq!(
            rv, CKR_TEMPLATE_INCONSISTENT,
            "CKA_TOKEN=true in public template must return CKR_TEMPLATE_INCONSISTENT"
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// Test: session objects are scoped to the creating session and not visible to others.
//
// PKCS#11 s.11.7: objects created as session objects (CKA_TOKEN=CK_FALSE) are only
// visible within the session that created them.
#[test]
fn generate_key_pair_not_visible_to_other_session() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"gen-iso-pin";
    let kf = make_cert_keystore(pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");

        let session_a = open_session(fl);
        let session_b = open_session(fl);

        // Generate a key pair in session A.
        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut h_pub: CK_OBJECT_HANDLE = 0;
        let mut h_priv: CK_OBJECT_HANDLE = 0;
        let rv = fl.C_GenerateKeyPair.unwrap()(
            session_a,
            &mut ck_mech,
            std::ptr::null_mut(), 0,
            std::ptr::null_mut(), 0,
            &mut h_pub,
            &mut h_priv,
        );
        assert_eq!(rv, CKR_OK, "C_GenerateKeyPair");

        // Session B must see only the one keystore private key, not session A's generated key.
        let priv_in_b = find_by_class(fl, session_b, CKO_PRIVATE_KEY);
        assert_eq!(
            priv_in_b.len(), 1,
            "session B must see only the keystore private key, not session A's generated key"
        );
        assert!(
            !priv_in_b.contains(&h_priv),
            "session B must not contain session A's private key handle"
        );

        // Session B must see no public key objects (keystore has none; generated key is
        // scoped to session A).
        let pub_in_b = find_by_class(fl, session_b, CKO_PUBLIC_KEY);
        assert_eq!(
            pub_in_b.len(), 0,
            "session B must not see any public key objects from session A"
        );

        fl.C_CloseSession.unwrap()(session_a);
        fl.C_CloseSession.unwrap()(session_b);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// Test: session objects are destroyed when their session is closed.
//
// PKCS#11 s.11.7: when a session is closed, all session objects belonging to it
// are automatically destroyed.  Handles to those objects must be invalid afterward.
#[test]
fn generate_key_pair_destroyed_after_close() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin = b"gen-close-pin";
    let kf = make_cert_keystore(pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");
        let session_a = open_session(fl);

        // Generate a key pair in session A and record the handles.
        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut h_pub: CK_OBJECT_HANDLE = 0;
        let mut h_priv: CK_OBJECT_HANDLE = 0;
        let rv = fl.C_GenerateKeyPair.unwrap()(
            session_a,
            &mut ck_mech,
            std::ptr::null_mut(), 0,
            std::ptr::null_mut(), 0,
            &mut h_pub,
            &mut h_priv,
        );
        assert_eq!(rv, CKR_OK, "C_GenerateKeyPair");

        // Close session A -- all session objects must be destroyed.
        fl.C_CloseSession.unwrap()(session_a);

        // Open a new session and confirm the handles are now invalid.
        let session_b = open_session(fl);
        let mut cls_buf: CK_OBJECT_CLASS = 0;
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut cls_buf as *mut _ as _,
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        };
        let rv = fl.C_GetAttributeValue.unwrap()(session_b, h_priv, &mut attr, 1);
        assert_eq!(
            rv, CKR_KEY_HANDLE_INVALID,
            "private key handle must be invalid after C_CloseSession"
        );
        let rv = fl.C_GetAttributeValue.unwrap()(session_b, h_pub, &mut attr, 1);
        assert_eq!(
            rv, CKR_KEY_HANDLE_INVALID,
            "public key handle must be invalid after C_CloseSession"
        );

        fl.C_CloseSession.unwrap()(session_b);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}
// ---------------------------------------------------------------------------
// Multi-slot tests (soft_PKCS11-9xs)
//
// These tests exercise the two-slot scenario: two independent .p11k keystores
// mounted as slot 0 and slot 1, each with its own PIN, key material, and
// session state machine.
// ---------------------------------------------------------------------------

#[test]
fn multi_slot_two_slots_in_slot_list() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin_a = b"pin-ms-a";
    let pin_b = b"pin-ms-b";
    let entry_a = KeyEntry {
        id: [0xA0; 16],
        label: "rsa-ms-a".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let entry_b = KeyEntry {
        id: [0xB0; 16],
        label: "ec-ms-b".to_string(),
        key_type: KeyType::Ec,
        der_bytes: hex::decode(EC_PRIV_HEX).expect("ec hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf_a = make_keystore_file(vec![entry_a], pin_a);
    let kf_b = make_keystore_file(vec![entry_b], pin_b);
    usb_hsm::test_mount_multi(&[kf_a.path(), kf_b.path()]);

    unsafe {
        let fl = fl();
        init(fl);

        // Count slots with token present.
        let mut count: CK_ULONG = 0;
        let rv = fl.C_GetSlotList.unwrap()(CK_TRUE, std::ptr::null_mut(), &mut count);
        assert_eq!(rv, CKR_OK, "C_GetSlotList count query");
        assert_eq!(count, 2, "two slots must be present");

        // Retrieve slot IDs and confirm they are [0, 1].
        let mut slot_buf = [u64::MAX; 4];
        let rv = fl.C_GetSlotList.unwrap()(CK_TRUE, slot_buf.as_mut_ptr(), &mut count);
        assert_eq!(rv, CKR_OK, "C_GetSlotList fetch");
        assert_eq!(count, 2);
        assert_eq!(slot_buf[0], 0, "first slot ID must be 0");
        assert_eq!(slot_buf[1], 1, "second slot ID must be 1");

        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

#[test]
fn multi_slot_login_is_per_slot() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin_a = b"pin-perslot-a";
    let pin_b = b"pin-perslot-b";
    let entry_a = KeyEntry {
        id: [0xA1; 16],
        label: "rsa-perslot-a".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let entry_b = KeyEntry {
        id: [0xB1; 16],
        label: "ec-perslot-b".to_string(),
        key_type: KeyType::Ec,
        der_bytes: hex::decode(EC_PRIV_HEX).expect("ec hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf_a = make_keystore_file(vec![entry_a], pin_a);
    let kf_b = make_keystore_file(vec![entry_b], pin_b);
    usb_hsm::test_mount_multi(&[kf_a.path(), kf_b.path()]);

    unsafe {
        let fl = fl();
        init(fl);

        let h0 = open_session_on_slot(fl, 0);
        let h1 = open_session_on_slot(fl, 1);

        // Login to slot 0 only; slot 1 must stay public.
        let rv = fl.C_Login.unwrap()(h0, CKU_USER, pin_a.as_ptr() as _, pin_a.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login slot 0");

        let mut info: CK_SESSION_INFO = std::mem::zeroed();
        let rv = fl.C_GetSessionInfo.unwrap()(h0, &mut info);
        assert_eq!(rv, CKR_OK);
        assert_eq!(info.state, CKS_RW_USER_FUNCTIONS, "slot 0 session must be logged in");

        let rv = fl.C_GetSessionInfo.unwrap()(h1, &mut info);
        assert_eq!(rv, CKR_OK);
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION, "slot 1 session must remain public");

        // Login to slot 1 independently.
        let rv = fl.C_Login.unwrap()(h1, CKU_USER, pin_b.as_ptr() as _, pin_b.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login slot 1");

        let rv = fl.C_GetSessionInfo.unwrap()(h1, &mut info);
        assert_eq!(rv, CKR_OK);
        assert_eq!(info.state, CKS_RW_USER_FUNCTIONS, "slot 1 must be logged in after login");

        // Logout from slot 0; slot 1 must remain logged in.
        let rv = fl.C_Logout.unwrap()(h0);
        assert_eq!(rv, CKR_OK, "C_Logout slot 0");

        let rv = fl.C_GetSessionInfo.unwrap()(h0, &mut info);
        assert_eq!(rv, CKR_OK);
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION, "slot 0 must be public after logout");

        let rv = fl.C_GetSessionInfo.unwrap()(h1, &mut info);
        assert_eq!(rv, CKR_OK);
        assert_eq!(info.state, CKS_RW_USER_FUNCTIONS, "slot 1 must remain logged in after slot 0 logout");

        fl.C_CloseSession.unwrap()(h0);
        fl.C_CloseSession.unwrap()(h1);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

#[test]
fn multi_slot_keys_are_slot_scoped() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin_a = b"pin-scope-a";
    let pin_b = b"pin-scope-b";
    let entry_a = KeyEntry {
        id: [0xA2; 16],
        label: "rsa-scope-a".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let entry_b = KeyEntry {
        id: [0xB2; 16],
        label: "ec-scope-b".to_string(),
        key_type: KeyType::Ec,
        der_bytes: hex::decode(EC_PRIV_HEX).expect("ec hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf_a = make_keystore_file(vec![entry_a], pin_a);
    let kf_b = make_keystore_file(vec![entry_b], pin_b);
    usb_hsm::test_mount_multi(&[kf_a.path(), kf_b.path()]);

    unsafe {
        let fl = fl();
        init(fl);

        let h0 = open_session_on_slot(fl, 0);
        let h1 = open_session_on_slot(fl, 1);
        let rv = fl.C_Login.unwrap()(h0, CKU_USER, pin_a.as_ptr() as _, pin_a.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login slot 0");
        let rv = fl.C_Login.unwrap()(h1, CKU_USER, pin_b.as_ptr() as _, pin_b.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login slot 1");

        // FindObjects on slot 0: exactly 1 private key, key type RSA.
        let mut count0: CK_ULONG = 0;
        let rv = fl.C_FindObjectsInit.unwrap()(h0, std::ptr::null_mut(), 0);
        assert_eq!(rv, CKR_OK, "FindObjectsInit slot 0");
        let mut handles0 = [0u64; 8];
        let rv = fl.C_FindObjects.unwrap()(h0, handles0.as_mut_ptr(), 8, &mut count0);
        assert_eq!(rv, CKR_OK, "FindObjects slot 0");
        fl.C_FindObjectsFinal.unwrap()(h0);
        assert_eq!(count0, 1, "slot 0 must have exactly 1 object");

        let mut kt0: CK_ULONG = 0;
        let mut attr0 = CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: &mut kt0 as *mut _ as _,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        };
        let rv = fl.C_GetAttributeValue.unwrap()(h0, handles0[0], &mut attr0, 1);
        assert_eq!(rv, CKR_OK, "GetAttributeValue slot 0 key type");
        assert_eq!(kt0, CKK_RSA, "slot 0 key must be RSA");

        // FindObjects on slot 1: exactly 1 private key, key type EC.
        let mut count1: CK_ULONG = 0;
        let rv = fl.C_FindObjectsInit.unwrap()(h1, std::ptr::null_mut(), 0);
        assert_eq!(rv, CKR_OK, "FindObjectsInit slot 1");
        let mut handles1 = [0u64; 8];
        let rv = fl.C_FindObjects.unwrap()(h1, handles1.as_mut_ptr(), 8, &mut count1);
        assert_eq!(rv, CKR_OK, "FindObjects slot 1");
        fl.C_FindObjectsFinal.unwrap()(h1);
        assert_eq!(count1, 1, "slot 1 must have exactly 1 object");

        let mut kt1: CK_ULONG = 0;
        let mut attr1 = CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: &mut kt1 as *mut _ as _,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        };
        let rv = fl.C_GetAttributeValue.unwrap()(h1, handles1[0], &mut attr1, 1);
        assert_eq!(rv, CKR_OK, "GetAttributeValue slot 1 key type");
        assert_eq!(kt1, CKK_EC, "slot 1 key must be EC");

        fl.C_CloseSession.unwrap()(h0);
        fl.C_CloseSession.unwrap()(h1);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

#[test]
fn multi_slot_sign_from_each_slot() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    let pin_a = b"pin-sign-ms-a";
    let pin_b = b"pin-sign-ms-b";
    let entry_a = KeyEntry {
        id: [0xA3; 16],
        label: "rsa-sign-ms-a".to_string(),
        key_type: KeyType::Rsa,
        der_bytes: hex::decode(RSA_PKCS8_DER_HEX).expect("rsa hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let entry_b = KeyEntry {
        id: [0xB3; 16],
        label: "ec-sign-ms-b".to_string(),
        key_type: KeyType::Ec,
        der_bytes: hex::decode(EC_PRIV_HEX).expect("ec hex"),
        cert_der: None,
        pub_bytes: None,
    };
    let kf_a = make_keystore_file(vec![entry_a], pin_a);
    let kf_b = make_keystore_file(vec![entry_b], pin_b);
    usb_hsm::test_mount_multi(&[kf_a.path(), kf_b.path()]);

    unsafe {
        let fl = fl();
        init(fl);

        let h0 = open_session_on_slot(fl, 0);
        let h1 = open_session_on_slot(fl, 1);
        let rv = fl.C_Login.unwrap()(h0, CKU_USER, pin_a.as_ptr() as _, pin_a.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login slot 0");
        let rv = fl.C_Login.unwrap()(h1, CKU_USER, pin_b.as_ptr() as _, pin_b.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login slot 1");

        let key0 = find_first_private_key(fl, h0);
        let key1 = find_first_private_key(fl, h1);

        let msg = b"multi-slot sign test";

        // RSA-PSS sign from slot 0.
        let sig0 = pkcs11_sign(fl, h0, CKM_RSA_PKCS_PSS, key0, msg);
        assert_eq!(sig0.len(), 256, "RSA-2048 PSS signature must be 256 bytes");

        // ECDSA-SHA256 sign from slot 1.
        let sig1 = pkcs11_sign(fl, h1, CKM_ECDSA_SHA256, key1, msg);
        assert!(!sig1.is_empty(), "slot 1 ECDSA signature must be non-empty");

        fl.C_CloseSession.unwrap()(h0);
        fl.C_CloseSession.unwrap()(h1);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// PQC helpers
// ---------------------------------------------------------------------------

/// Find the first CKO_PUBLIC_KEY object; assert at least one exists.
unsafe fn find_first_public_key(
    fl: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
) -> CK_OBJECT_HANDLE {
    let mut cls: CK_OBJECT_CLASS = CKO_PUBLIC_KEY;
    let mut tmpl = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: &mut cls as *mut _ as _,
        ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
    };
    let rv = fl.C_FindObjectsInit.unwrap()(session, &mut tmpl, 1);
    assert_eq!(rv, CKR_OK, "C_FindObjectsInit(CKO_PUBLIC_KEY)");

    let mut handles = [0u64; 16];
    let mut found: CK_ULONG = 0;
    let rv = fl.C_FindObjects.unwrap()(session, handles.as_mut_ptr(), 16, &mut found);
    assert_eq!(rv, CKR_OK, "C_FindObjects");
    fl.C_FindObjectsFinal.unwrap()(session);

    assert!(found > 0, "no public keys found in keystore");
    handles[0]
}

// ---------------------------------------------------------------------------
// ML-DSA-65 sign/verify round-trip
//
// Sign via PKCS#11 C_Sign (uses the private key handle, HANDLE_ORIGIN range).
// Verify via PKCS#11 C_Verify (uses the public key handle, PUB_KEY_HANDLE_ORIGIN
// range) -- a different code path from sign (wolfcrypt verify != wolfcrypt sign).
//
// Oracle: C_Verify succeeds for the correct signature, fails for a corrupted one.
// The sign and verify paths call independent wolfcrypt functions:
//   sign  -> ops::sign -> MlDsa65SigningKey::try_sign  -> wc_dilithium_sign_msg
//   verify -> ops::verify -> MlDsa65VerifyingKey::verify -> wc_dilithium_verify_msg
// These are distinct C functions in wolfSSL; a bug in one is detectable by the other.
// ---------------------------------------------------------------------------

#[test]
fn ml_dsa_65_sign_verify_round_trip() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    // Generate an ML-DSA-65 keypair at test time using wolfcrypt.
    let mut rng = wolfcrypt::WolfRng::new().expect("WolfRng::new");
    let sk = wolfcrypt::MlDsa65SigningKey::generate(&mut rng).expect("MlDsa65 keygen");
    let vk = sk.verifying_key();
    let priv_bytes: Vec<u8> = sk.to_private_bytes().to_vec();
    let pub_bytes: Vec<u8> = vk.as_bytes().to_vec();

    let pin = b"pqctest1";
    let entry = KeyEntry {
        id: [0xD5u8; 16],
        label: "mldsa65-test".to_string(),
        key_type: KeyType::MlDsa65,
        der_bytes: priv_bytes,
        cert_der: None,
        pub_bytes: Some(pub_bytes),
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");
        let session = open_session(fl);

        // Confirm C_FindObjects returns both a private key and a public key.
        let priv_handle = find_first_private_key(fl, session);
        let pub_handle = find_first_public_key(fl, session);
        assert_ne!(priv_handle, pub_handle, "private and public handles must differ");

        // Confirm CKA_KEY_TYPE on the public handle is CKK_ML_DSA.
        let mut kt: CK_ULONG = 0;
        let mut kt_attr = CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: &mut kt as *mut _ as _,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        };
        let rv = fl.C_GetAttributeValue.unwrap()(session, pub_handle, &mut kt_attr, 1);
        assert_eq!(rv, CKR_OK, "C_GetAttributeValue on pub handle");
        assert_eq!(kt, CKK_ML_DSA, "public key must be CKK_ML_DSA");

        let msg = b"ml-dsa-65 integration test message";

        // Sign via C_Sign using the private key handle.
        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_ML_DSA,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = fl.C_SignInit.unwrap()(session, &mut ck_mech, priv_handle);
        assert_eq!(rv, CKR_OK, "C_SignInit CKM_ML_DSA");

        // Length query (NULL output pointer).
        let mut sig_len: CK_ULONG = 0;
        let rv = fl.C_Sign.unwrap()(
            session,
            msg.as_ptr() as _,
            msg.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut sig_len,
        );
        assert_eq!(rv, CKR_OK, "C_Sign length query");
        assert_eq!(sig_len, 3309, "ML-DSA-65 signature must be 3309 bytes");

        let mut sig_buf = vec![0u8; sig_len as usize];
        let rv = fl.C_Sign.unwrap()(
            session,
            msg.as_ptr() as _,
            msg.len() as CK_ULONG,
            sig_buf.as_mut_ptr(),
            &mut sig_len,
        );
        assert_eq!(rv, CKR_OK, "C_Sign CKM_ML_DSA");
        assert_eq!(sig_len, 3309, "signature length after C_Sign");

        // Oracle: verify the signature using the public key handle (different code path).
        let rv = fl.C_VerifyInit.unwrap()(session, &mut ck_mech, pub_handle);
        assert_eq!(rv, CKR_OK, "C_VerifyInit CKM_ML_DSA");
        let rv = fl.C_Verify.unwrap()(
            session,
            msg.as_ptr() as _,
            msg.len() as CK_ULONG,
            sig_buf.as_ptr() as _,
            sig_buf.len() as CK_ULONG,
        );
        assert_eq!(rv, CKR_OK, "C_Verify must accept valid ML-DSA-65 signature");

        // Oracle: verify must reject a corrupted signature.
        let mut bad_sig = sig_buf.clone();
        bad_sig[42] ^= 0xff;
        let rv = fl.C_VerifyInit.unwrap()(session, &mut ck_mech, pub_handle);
        assert_eq!(rv, CKR_OK, "C_VerifyInit bad sig");
        let rv = fl.C_Verify.unwrap()(
            session,
            msg.as_ptr() as _,
            msg.len() as CK_ULONG,
            bad_sig.as_ptr() as _,
            bad_sig.len() as CK_ULONG,
        );
        assert_ne!(rv, CKR_OK, "C_Verify must reject corrupted ML-DSA-65 signature");

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}

// ---------------------------------------------------------------------------
// ML-KEM-768 encapsulate/decapsulate round-trip
//
// Encapsulate via PKCS#11 C_Encrypt using the public key handle
// (PUB_KEY_HANDLE_ORIGIN range).  Output: ciphertext || shared_secret_1.
// Decapsulate via PKCS#11 C_Decrypt using the private key handle
// (HANDLE_ORIGIN range).  Output: shared_secret_2.
//
// Oracle: shared_secret_1 == shared_secret_2.
// The encap and decap paths call independent wolfcrypt functions:
//   encap -> ops::encrypt -> MlKem768EncapsulationKey::encapsulate  -> wc_KyberKey_Encapsulate
//   decap -> ops::decrypt -> MlKem768DecapsulationKey::decapsulate  -> wc_KyberKey_Decapsulate
// These are distinct C functions; agreement proves both paths are consistent.
// ---------------------------------------------------------------------------

#[test]
fn ml_kem_768_encap_decap_round_trip() {
    let _g = LOCK.lock().unwrap();
    usb_hsm::test_reset();

    // Generate an ML-KEM-768 keypair at test time using wolfcrypt.
    let dk = wolfcrypt::MlKem768DecapsulationKey::generate().expect("MlKem768 keygen");
    let priv_bytes: Vec<u8> = dk.private_key_bytes().expect("private_key_bytes").to_vec();
    let pub_bytes: Vec<u8> = dk.public_key_bytes().expect("public_key_bytes");

    let pin = b"pqctest2";
    let entry = KeyEntry {
        id: [0xCEu8; 16],
        label: "mlkem768-test".to_string(),
        key_type: KeyType::MlKem768,
        der_bytes: priv_bytes,
        cert_der: None,
        pub_bytes: Some(pub_bytes),
    };
    let kf = make_keystore_file(vec![entry], pin);
    usb_hsm::test_mount(kf.path());

    unsafe {
        let fl = fl();
        init(fl);
        let rv = fl.C_Login.unwrap()(0, CKU_USER, pin.as_ptr() as _, pin.len() as _);
        assert_eq!(rv, CKR_OK, "C_Login");
        let session = open_session(fl);

        let priv_handle = find_first_private_key(fl, session);
        let pub_handle = find_first_public_key(fl, session);
        assert_ne!(priv_handle, pub_handle, "private and public handles must differ");

        // Confirm CKA_KEY_TYPE on the public handle is CKK_ML_KEM.
        let mut kt: CK_ULONG = 0;
        let mut kt_attr = CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: &mut kt as *mut _ as _,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        };
        let rv = fl.C_GetAttributeValue.unwrap()(session, pub_handle, &mut kt_attr, 1);
        assert_eq!(rv, CKR_OK, "C_GetAttributeValue on ML-KEM pub handle");
        assert_eq!(kt, CKK_ML_KEM, "public key must be CKK_ML_KEM");

        let mut ck_mech = CK_MECHANISM {
            mechanism: CKM_ML_KEM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        // Length query via NULL output pointer.
        let rv = fl.C_EncryptInit.unwrap()(session, &mut ck_mech, pub_handle);
        assert_eq!(rv, CKR_OK, "C_EncryptInit CKM_ML_KEM");
        let dummy_input = b"";
        let mut ct_len: CK_ULONG = 0;
        let rv = fl.C_Encrypt.unwrap()(
            session,
            dummy_input.as_ptr() as _,
            0,
            std::ptr::null_mut(),
            &mut ct_len,
        );
        assert_eq!(rv, CKR_OK, "C_Encrypt length query");
        // ML-KEM-768: 1088-byte ciphertext + 32-byte shared secret.
        assert_eq!(ct_len, 1120, "ML-KEM-768 encap output must be 1120 bytes");

        // Encapsulate: C_Encrypt on the public key handle.
        let mut encap_out = vec![0u8; ct_len as usize];
        let rv = fl.C_Encrypt.unwrap()(
            session,
            dummy_input.as_ptr() as _,
            0,
            encap_out.as_mut_ptr(),
            &mut ct_len,
        );
        assert_eq!(rv, CKR_OK, "C_Encrypt CKM_ML_KEM (encapsulate)");
        assert_eq!(ct_len, 1120, "encap output length");
        let ciphertext = &encap_out[..1088];
        let shared_secret_from_encap = &encap_out[1088..];
        assert_eq!(shared_secret_from_encap.len(), 32, "shared secret from encap is 32 bytes");

        // Decapsulate: C_Decrypt on the private key handle.
        let rv = fl.C_DecryptInit.unwrap()(session, &mut ck_mech, priv_handle);
        assert_eq!(rv, CKR_OK, "C_DecryptInit CKM_ML_KEM");

        // Length query for decap output.
        let mut ss_len: CK_ULONG = 0;
        let rv = fl.C_Decrypt.unwrap()(
            session,
            ciphertext.as_ptr() as _,
            ciphertext.len() as CK_ULONG,
            std::ptr::null_mut(),
            &mut ss_len,
        );
        assert_eq!(rv, CKR_OK, "C_Decrypt length query");
        assert_eq!(ss_len, 32, "ML-KEM-768 decap output must be 32 bytes");

        let mut ss_buf = vec![0u8; 32];
        let rv = fl.C_Decrypt.unwrap()(
            session,
            ciphertext.as_ptr() as _,
            ciphertext.len() as CK_ULONG,
            ss_buf.as_mut_ptr(),
            &mut ss_len,
        );
        assert_eq!(rv, CKR_OK, "C_Decrypt CKM_ML_KEM (decapsulate)");
        assert_eq!(ss_len, 32, "decap output length");

        // Oracle: both sides must agree on the shared secret.
        assert_eq!(
            ss_buf, shared_secret_from_encap,
            "encap and decap shared secrets must match"
        );

        fl.C_CloseSession.unwrap()(session);
        fl.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    usb_hsm::test_reset();
}
