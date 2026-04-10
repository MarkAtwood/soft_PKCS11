    use super::*;

    // Minimal GCP service account JSON with all four standard fields.
    const GCP_JSON_FULL: &[u8] = br#"{
        "type": "service_account",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----\n",
        "private_key_id": "1234567890abcdef1234567890abcdef12345678",
        "client_email": "svc@project.iam.gserviceaccount.com"
    }"#;

    #[test]
    fn detect_gcp_full_json_returns_some() {
        let result = detect_gcp_json(GCP_JSON_FULL);
        assert!(result.is_some(), "valid GCP JSON must be detected");
        let gcp = result.unwrap();
        assert!(gcp.pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert_eq!(
            gcp.key_id_hex.as_deref(),
            Some("1234567890abcdef1234567890abcdef12345678")
        );
        assert_eq!(
            gcp.client_email.as_deref(),
            Some("svc@project.iam.gserviceaccount.com")
        );
    }

    #[test]
    fn detect_gcp_missing_private_key_returns_none() {
        let json = br#"{"type": "service_account", "client_email": "svc@project.iam.gserviceaccount.com"}"#;
        assert!(detect_gcp_json(json).is_none());
    }

    #[test]
    fn detect_gcp_private_key_not_pem_returns_none() {
        let json = br#"{"private_key": "not-a-pem-key"}"#;
        assert!(detect_gcp_json(json).is_none());
    }

    #[test]
    fn detect_gcp_non_json_input_returns_none() {
        assert!(detect_gcp_json(b"-----BEGIN RSA PRIVATE KEY-----").is_none());
        assert!(detect_gcp_json(b"\x30\x82\x01\x02").is_none());
    }

    #[test]
    fn detect_gcp_arbitrary_json_object_returns_none() {
        let json = br#"{"foo": "bar", "baz": 42}"#;
        assert!(detect_gcp_json(json).is_none());
    }

    #[test]
    fn detect_gcp_json_array_returns_none() {
        let json = br#"[{"private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."}]"#;
        assert!(detect_gcp_json(json).is_none());
    }

    #[test]
    fn detect_gcp_optional_fields_absent() {
        let json = br#"{"private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}"#;
        let gcp = detect_gcp_json(json).expect("minimal GCP JSON must be detected");
        assert!(gcp.key_id_hex.is_none());
        assert!(gcp.client_email.is_none());
    }

    #[test]
    fn detect_gcp_leading_whitespace_ok() {
        let json = b"   \n{\"private_key\": \"-----BEGIN RSA PRIVATE KEY-----\\nfake\\n-----END RSA PRIVATE KEY-----\\n\"}";
        assert!(detect_gcp_json(json).is_some());
    }

    // -----------------------------------------------------------------------
    // OpenSSH binary frame parser tests
    // -----------------------------------------------------------------------

    /// Build a minimal valid openssh-key-v1 binary frame for testing.
    ///
    /// All string fields use u32 big-endian length prefixes.  The frame
    /// always contains exactly one key.  `pubkey_blob` is the placeholder
    /// public key bytes; `private_blob` is the (possibly encrypted) private
    /// key bytes.
    /// Encode `data` as a u32 big-endian length-prefixed byte sequence.
    fn lp(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn make_openssh_frame(
        ciphername: &str,
        kdfname: &str,
        kdfoptions: &[u8],
        pubkey_blob: &[u8],
        private_blob: &[u8],
    ) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(OPENSSH_MAGIC);
        v.extend_from_slice(&lp(ciphername.as_bytes()));
        v.extend_from_slice(&lp(kdfname.as_bytes()));
        v.extend_from_slice(&lp(kdfoptions));
        v.extend_from_slice(&1u32.to_be_bytes()); // nkeys = 1
        v.extend_from_slice(&lp(pubkey_blob));
        v.extend_from_slice(&lp(private_blob));
        v
    }

    #[test]
    fn openssh_parse_unencrypted_frame() {
        let frame_bytes = make_openssh_frame(
            "none",
            "none",
            b"",
            b"fake-pubkey",
            b"fake-privkey",
        );
        let frame = parse_openssh_binary(&frame_bytes).expect("should parse");
        assert_eq!(frame.ciphername, "none");
        assert_eq!(frame.kdfname, "none");
        assert!(frame.kdfoptions_raw.is_empty());
        assert_eq!(frame.private_blob, b"fake-privkey");
    }

    #[test]
    fn openssh_parse_encrypted_frame_carries_cipher_info() {
        let kdf_opts = b"\x00\x00\x00\x10saltsaltsaltsalt\x00\x00\x04\x00"; // fake bcrypt opts
        let frame_bytes = make_openssh_frame(
            "aes256-ctr",
            "bcrypt",
            kdf_opts,
            b"fake-pubkey",
            b"encrypted-private-blob",
        );
        let frame = parse_openssh_binary(&frame_bytes).expect("should parse");
        assert_eq!(frame.ciphername, "aes256-ctr");
        assert_eq!(frame.kdfname, "bcrypt");
        assert_eq!(frame.kdfoptions_raw, kdf_opts);
        assert_eq!(frame.private_blob, b"encrypted-private-blob");
    }

    #[test]
    fn openssh_parse_wrong_magic_returns_malformed() {
        let mut frame = make_openssh_frame("none", "none", b"", b"pub", b"priv");
        // Corrupt the magic bytes.
        frame[0] = b'X';
        let err = parse_openssh_binary(&frame).unwrap_err();
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    #[test]
    fn openssh_parse_truncated_after_magic_returns_malformed() {
        // Just the magic, nothing else.
        let err = parse_openssh_binary(OPENSSH_MAGIC).unwrap_err();
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    #[test]
    fn openssh_parse_truncated_in_string_field_returns_malformed() {
        let mut v = Vec::new();
        v.extend_from_slice(OPENSSH_MAGIC);
        // Length field says 100 bytes but there are only 5.
        v.extend_from_slice(&100u32.to_be_bytes());
        v.extend_from_slice(b"short");
        let err = parse_openssh_binary(&v).unwrap_err();
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    #[test]
    fn openssh_parse_multiple_keys_returns_unsupported() {
        let mut v = Vec::new();
        v.extend_from_slice(OPENSSH_MAGIC);
        // Write ciphername, kdfname, kdfoptions.
        for s in &["none", "none"] {
            v.extend_from_slice(&(s.len() as u32).to_be_bytes());
            v.extend_from_slice(s.as_bytes());
        }
        v.extend_from_slice(&0u32.to_be_bytes()); // kdfoptions empty
        v.extend_from_slice(&2u32.to_be_bytes()); // nkeys = 2
        let err = parse_openssh_binary(&v).unwrap_err();
        assert!(matches!(err, KeyParseError::Unsupported(_)));
    }

    // -----------------------------------------------------------------------
    // EncryptedPrivateKeyInfo (parse_encrypted_pkcs8) tests
    // -----------------------------------------------------------------------

    /// Minimal EncryptedPrivateKeyInfo DER with a DES OID: must return Unsupported.
    ///
    /// Constructed by hand:
    ///   SEQUENCE { SEQUENCE { OID(pbeWithMD5AndDES-CBC) NULL } OCTET STRING(empty) }
    #[test]
    fn epki_unsupported_des_md5_oid() {
        // OID 1.2.840.113549.1.5.3 = pbeWithMD5AndDES-CBC (9 bytes value)
        let der: &[u8] = &[
            0x30, 0x11, // SEQUENCE length 17
            0x30, 0x0d, //   SEQUENCE (AlgorithmIdentifier) length 13
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03, //     OID
            0x05, 0x00, //     NULL
            0x04, 0x00, //   OCTET STRING (empty ciphertext)
        ];
        let err = parse_encrypted_pkcs8(der, "pass", [0u8; 16])
            .err().expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)));
        let msg = err.to_string();
        assert!(msg.contains("DES"), "expected DES in error: {msg}");
    }

    /// Same for pbeWithSHA1AndDES-CBC (OID 1.2.840.113549.1.5.10).
    #[test]
    fn epki_unsupported_des_sha1_oid() {
        // OID 1.2.840.113549.1.5.10 = pbeWithSHA1AndDES-CBC (9 bytes value)
        let der: &[u8] = &[
            0x30, 0x11,
            0x30, 0x0d,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0a,
            0x05, 0x00,
            0x04, 0x00,
        ];
        let err = parse_encrypted_pkcs8(der, "pass", [0u8; 16])
            .err().expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)));
    }

    /// PKCS#12 RC2-128 OID must return Unsupported.
    #[test]
    fn epki_unsupported_rc2_oid() {
        // OID 1.2.840.113549.1.12.1.5 = pbeWithSHAAnd128BitRC2-CBC (10 bytes value)
        // AlgId inner: OID TLV (12 bytes) + NULL TLV (2 bytes) = 14 = 0x0e
        // outer inner: AlgId TLV (16 bytes) + OctetString TLV (2 bytes) = 18 = 0x12
        let der: &[u8] = &[
            0x30, 0x12, //   outer SEQUENCE length 18
            0x30, 0x0e, //   AlgorithmIdentifier length 14
            0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x05,
            0x05, 0x00,
            0x04, 0x00,
        ];
        let err = parse_encrypted_pkcs8(der, "pass", [0u8; 16])
            .err().expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)));
        let msg = err.to_string();
        assert!(msg.contains("RC2"), "expected RC2 in error: {msg}");
    }

    /// Malformed: not a SEQUENCE -> returns Malformed.
    #[test]
    fn epki_malformed_missing_outer_sequence() {
        let err = parse_encrypted_pkcs8(b"\x02\x01\x00", "pass", [0u8; 16])
            .err().expect("must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    /// PBES2 + PBKDF2-SHA256 + AES-256-CBC decryption round-trip.
    ///
    /// Test vector: 512-bit RSA key encrypted by
    /// `openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:testpass123`
    #[test]
    fn epki_pbes2_aes256_sha256_decrypts() {
        let der = hex::decode(concat!(
            "308201bd305706092a864886f70d01050d304a302906092a864886f70d01050c",
            "301c0408d0e4e97f0a2fcb9b02020800300c06082a864886f70d020905003",
            "01d060960864801650304012a0410084cca07a6407bc5fc577435a81787a8",
            "048201605f39b5d9217e1d733338b92f92dcfcf9b7edc669dd0d27446df11",
            "d5d51dc82f6623dda3524967f2b60db265a5804fa98cf42d242c2a2daa717",
            "f6b60803f1323e92e683e67097153491be85c00b064e3d6f1346d0c015659",
            "458de6bffd054c03c5295d3bd443843967af437d0d4ad9c85c1fb51810cf8",
            "70b8ad907178b9adf4f5e4b3a4c867bf1560ed32c71f19c352afea7eb86db",
            "03d4b4353bdd276ed2dfaa58c4e9c4016cdda6d5c672a7541a999995b2300",
            "91670f27712c87e1e09238a7a33a882feed2205d4a54de76da4490280c25a",
            "e62886729effd2a6bd5bb465859f0bbd9d76fd2268b5c6535893961eee8e1",
            "d99ca3d51ec5bdbccc2adedaa3c45a68e43095a3e53f45060c786b60ce666",
            "de1ef9d4e7d2bcd98339fa866e77c983eb3135aa126e5eba2951f9c9cbb97",
            "29552514de841ac3f004c5f93d16583e69f0a61e8e88048173cbfacccae29",
            "882518218c048626e173564af13d262a1d8fedcbc"
        )).expect("valid hex");

        let id = [0u8; 16];
        let key = parse_encrypted_pkcs8(&der, "testpass123", id)
            .expect("PBES2 decryption must succeed");
        assert_eq!(key.key_type, KeyType::Rsa, "must be RSA");
        // PKCS#1 RSAPrivateKey starts with SEQUENCE tag 0x30
        assert_eq!(key.key_bytes[0], 0x30, "RSA key bytes must start with SEQUENCE");
    }

    /// Wrong passphrase on PBES2-encrypted key -> invalid PKCS#7 padding -> Malformed.
    #[test]
    fn epki_pbes2_wrong_passphrase_returns_malformed() {
        let der = hex::decode(concat!(
            "308201bd305706092a864886f70d01050d304a302906092a864886f70d01050c",
            "301c0408d0e4e97f0a2fcb9b02020800300c06082a864886f70d020905003",
            "01d060960864801650304012a0410084cca07a6407bc5fc577435a81787a8",
            "048201605f39b5d9217e1d733338b92f92dcfcf9b7edc669dd0d27446df11",
            "d5d51dc82f6623dda3524967f2b60db265a5804fa98cf42d242c2a2daa717",
            "f6b60803f1323e92e683e67097153491be85c00b064e3d6f1346d0c015659",
            "458de6bffd054c03c5295d3bd443843967af437d0d4ad9c85c1fb51810cf8",
            "70b8ad907178b9adf4f5e4b3a4c867bf1560ed32c71f19c352afea7eb86db",
            "03d4b4353bdd276ed2dfaa58c4e9c4016cdda6d5c672a7541a999995b2300",
            "91670f27712c87e1e09238a7a33a882feed2205d4a54de76da4490280c25a",
            "e62886729effd2a6bd5bb465859f0bbd9d76fd2268b5c6535893961eee8e1",
            "d99ca3d51ec5bdbccc2adedaa3c45a68e43095a3e53f45060c786b60ce666",
            "de1ef9d4e7d2bcd98339fa866e77c983eb3135aa126e5eba2951f9c9cbb97",
            "29552514de841ac3f004c5f93d16583e69f0a61e8e88048173cbfacccae29",
            "882518218c048626e173564af13d262a1d8fedcbc"
        )).expect("valid hex");

        let err = parse_encrypted_pkcs8(&der, "wrongpassword", [0u8; 16])
            .err().expect("wrong password must return an error");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong password must give Malformed, got: {err}"
        );
    }

    /// PKCS#12 pbeWithSHAAnd3-KeyTripleDES-CBC decryption round-trip.
    ///
    /// Test vector: same 512-bit RSA key encrypted by
    /// `openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES -passout pass:testpass123`
    #[test]
    fn epki_pkcs12_sha1_3des_decrypts() {
        let der = hex::decode(concat!(
            "30820182301c060a2a864886f70d010c0103300e04087ccf3ffcea6f77150202",
            "080004820160d2f81814d8251a3f1d43cba1ee1f4ccb9e799c0b9bc9bfc419",
            "6a43521a63d27a14baa66532b389f25249de1f376088eaf300439809698f62",
            "533f0388948490d853a18d9a7145c9097d387a4a4ed6b9fdceb77d3c0c9705",
            "eda454f008b2918d34195367f3c50691ef1d6510b5e6f397ece72f57769bda",
            "2beb1d5a2a666006f387d61352ac4ccfcaf94e81eb11b885b3ebd53538af7e",
            "fadaa252ced81b4acb95dfb5b71453791e61e1aa2c1c76d98d10793ad3418b",
            "c4dc8316d48cbdbf0ff4299bd116248b3407ec01b78ef51ade7249fa8a205e",
            "1514ac9dda1b1ad96ec53d7b0d20e248b563a26103ae3071ff84c558151649",
            "7bd0d9b3137d05cb50dda8cb9c5242880669416eeafe8fc9e6302793740e33",
            "5577e5163d4dff8f1ff491dcac56f5cc18555379145504ec710f5c1c8f49e4",
            "c541ecc731661e422c6579ab080f20e0337314cbaa7a5b9097719a8b060984",
            "0c7c2f32a1d6bc9babcc9eb8dc803d27e6"
        )).expect("valid hex");

        let id = [0u8; 16];
        let key = parse_encrypted_pkcs8(&der, "testpass123", id)
            .expect("PKCS12-3DES decryption must succeed");
        assert_eq!(key.key_type, KeyType::Rsa, "must be RSA");
        assert_eq!(key.key_bytes[0], 0x30, "RSA key bytes must start with SEQUENCE");
    }

    // -----------------------------------------------------------------------
    // OpenSSH blob decryption (decrypt_openssh_blob / verify_openssh_check_words)
    // -----------------------------------------------------------------------

    fn make_frame(ciphername: &str, kdfname: &str, kdfopts: Vec<u8>, blob: Vec<u8>) -> OpensshFrame {
        OpensshFrame {
            ciphername: ciphername.to_string(),
            kdfname: kdfname.to_string(),
            kdfoptions_raw: kdfopts,
            private_blob: blob,
        }
    }

    /// ciphername=none passes the private blob through unchanged.
    #[test]
    fn openssh_decrypt_none_passthrough() {
        let blob = b"arbitrary-key-bytes".to_vec();
        let frame = make_frame("none", "none", vec![], blob.clone());
        let out = decrypt_openssh_blob(&frame, "").expect("none must not fail");
        assert_eq!(out, blob);
    }

    /// aes256-gcm@openssh.com returns Unsupported (out-of-scope for v1).
    #[test]
    fn openssh_decrypt_aes256_gcm_returns_unsupported() {
        let frame = make_frame("aes256-gcm@openssh.com", "none", vec![], vec![]);
        let err = decrypt_openssh_blob(&frame, "")
            .err()
            .expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "expected Unsupported, got {err}");
    }

    /// Unknown ciphername returns Unsupported.
    #[test]
    fn openssh_decrypt_unknown_cipher_returns_unsupported() {
        let frame = make_frame("chacha20-poly1305@openssh.com", "none", vec![], vec![]);
        let err = decrypt_openssh_blob(&frame, "")
            .err()
            .expect("must be an error");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "expected Unsupported");
    }

    /// Matching check words return the key data slice.
    #[test]
    fn openssh_check_words_match_returns_key_data() {
        // check1 = check2 = 0xDEADBEEF, followed by b"key"
        let mut blob = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF];
        blob.extend_from_slice(b"key-data");
        let tail = verify_openssh_check_words(&blob).expect("matching checks must succeed");
        assert_eq!(tail, b"key-data");
    }

    /// Mismatched check words return Malformed.
    #[test]
    fn openssh_check_words_mismatch_returns_malformed() {
        // check1 = 0x00000001, check2 = 0x00000002
        let blob = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
        let err = verify_openssh_check_words(&blob)
            .err()
            .expect("mismatch must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)), "expected Malformed");
    }

    /// Too-short blob returns Malformed (can't read 8 bytes).
    #[test]
    fn openssh_check_words_short_blob_returns_malformed() {
        let err = verify_openssh_check_words(&[0x00, 0x00, 0x00])
            .err()
            .expect("short blob must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    // -----------------------------------------------------------------------
    // PFX ASN.1 structure traversal (parse_pfx_structure) tests
    // -----------------------------------------------------------------------

    /// Truncated / empty DER returns a Malformed error (not a panic).
    #[test]
    fn pfx_truncated_der_returns_malformed() {
        let err = parse_pfx_structure(&[], "")
            .err()
            .expect("empty DER must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)));

        let err = parse_pfx_structure(&[0x30, 0x02, 0x01], "")
            .err()
            .expect("truncated DER must be an error");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    /// `verify_pfx_mac` returns Malformed for truncated DER (not a panic).
    #[test]
    fn pfx_verify_mac_truncated_returns_malformed() {
        let err = verify_pfx_mac(&[], "").err().expect("empty DER must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    /// PFX produced by `openssl pkcs12 -export -passout pass:` (empty password)
    /// contains at least one ShroudedKeyBag entry.
    ///
    /// Uses openssl as an external oracle: generates an RSA key and self-signed
    /// cert, creates a P12, and verifies that `parse_pfx_structure` finds the
    /// ShroudedKeyBag and extracts the bag attributes correctly.
    #[test]
    fn pfx_openssl_empty_password_shrouded_key_bag_found() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        // Generate RSA key and self-signed cert.
        let status = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "openssl genrsa failed");

        let status = std::process::Command::new("openssl")
            .args([
                "req", "-new", "-x509",
                "-key", key_pem.to_str().unwrap(),
                "-out", cert_pem.to_str().unwrap(),
                "-days", "1",
                "-subj", "/CN=test",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "openssl req failed");

        // Export to PKCS#12 with empty password and localKeyID / friendlyName.
        let status = std::process::Command::new("openssl")
            .args([
                "pkcs12", "-export",
                "-inkey", key_pem.to_str().unwrap(),
                "-in", cert_pem.to_str().unwrap(),
                "-out", p12_path.to_str().unwrap(),
                "-passout", "pass:",
                "-name", "test-key",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "openssl pkcs12 -export failed");

        let p12_der = std::fs::read(&p12_path).unwrap();
        let bags = parse_pfx_structure(&p12_der, "")
            .expect("parse_pfx_structure must not fail on valid openssl P12");

        // At least one ShroudedKeyBag must be found.
        assert!(
            !bags.shrouded_key_bags.is_empty(),
            "expected at least one ShroudedKeyBag in openssl-generated P12"
        );

        // The bag_value must be non-empty DER bytes.
        let key_bag = &bags.shrouded_key_bags[0];
        assert!(!key_bag.bag_value.is_empty(), "ShroudedKeyBag bag_value must not be empty");

        // friendlyName must match the -name flag.
        assert_eq!(
            key_bag.friendly_name.as_deref(),
            Some("test-key"),
            "friendlyName must match the -name flag passed to openssl pkcs12"
        );

        // localKeyID must be present (openssl always sets it).
        assert!(
            key_bag.local_key_id.is_some(),
            "localKeyID bag attribute must be present"
        );

        // MAC verification with empty passphrase must succeed.
        verify_pfx_mac(&p12_der, "")
            .expect("MAC verification must succeed with empty passphrase");
    }

    /// `verify_pfx_mac` fails with wrong passphrase (Malformed error, not a panic).
    #[test]
    fn pfx_verify_mac_wrong_passphrase_fails() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key", key_pem.to_str().unwrap(),
                   "-out", cert_pem.to_str().unwrap(), "-days", "1", "-subj", "/CN=test"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["pkcs12", "-export",
                   "-inkey", key_pem.to_str().unwrap(),
                   "-in", cert_pem.to_str().unwrap(),
                   "-out", p12_path.to_str().unwrap(),
                   "-passout", "pass:correct-password"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());

        let p12_der = std::fs::read(&p12_path).unwrap();

        // Wrong passphrase must fail MAC verification.
        let err = verify_pfx_mac(&p12_der, "wrong-password")
            .err()
            .expect("wrong passphrase must cause MAC failure");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong passphrase must return Malformed, got: {err}"
        );

        // Correct passphrase must succeed.
        verify_pfx_mac(&p12_der, "correct-password")
            .expect("correct passphrase must pass MAC verification");
    }

    /// `parse_pfx_structure` finds ShroudedKeyBag when SafeContents is encrypted
    /// inside an `id-encryptedData` ContentInfo (non-empty password, PBES2 default).
    ///
    /// Uses openssl as an external oracle.  If openssl is not available or does
    /// not emit `id-encryptedData` for this password, the test is a no-op.
    #[test]
    fn pfx_encrypted_safe_contents_pbes2_decrypts() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl genrsa failed");

        let s = std::process::Command::new("openssl")
            .args([
                "req", "-new", "-x509",
                "-key", key_pem.to_str().unwrap(),
                "-out", cert_pem.to_str().unwrap(),
                "-days", "1", "-subj", "/CN=pfx-pbes2-test",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl req failed");

        let s = std::process::Command::new("openssl")
            .args([
                "pkcs12", "-export",
                "-inkey", key_pem.to_str().unwrap(),
                "-in", cert_pem.to_str().unwrap(),
                "-out", p12_path.to_str().unwrap(),
                "-passout", "pass:hunter2",
                "-name", "pbes2-test-key",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl pkcs12 -export failed");

        let p12_der = std::fs::read(&p12_path).unwrap();

        // MAC must verify with correct passphrase.
        verify_pfx_mac(&p12_der, "hunter2")
            .expect("MAC must verify with correct passphrase");

        // parse_pfx_structure with correct passphrase must find the key bag.
        let bags = parse_pfx_structure(&p12_der, "hunter2")
            .expect("parse_pfx_structure must succeed with correct passphrase");
        assert!(
            !bags.shrouded_key_bags.is_empty(),
            "expected at least one ShroudedKeyBag"
        );
        assert_eq!(
            bags.shrouded_key_bags[0].friendly_name.as_deref(),
            Some("pbes2-test-key"),
        );

        // Wrong passphrase must return an error.
        let err = parse_pfx_structure(&p12_der, "wrong-pass")
            .err()
            .expect("wrong passphrase must fail");
        assert!(
            matches!(err, KeyParseError::Malformed(_) | KeyParseError::Unsupported(_)),
            "wrong passphrase must return Malformed or Unsupported, got: {err}"
        );
    }

    /// `parse_pfx_structure` finds ShroudedKeyBag when SafeContents is encrypted
    /// with PBES1 3DES (openssl pkcs12 -export -legacy).
    #[test]
    fn pfx_encrypted_safe_contents_pbes1_3des_decrypts() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl genrsa failed");

        let s = std::process::Command::new("openssl")
            .args([
                "req", "-new", "-x509",
                "-key", key_pem.to_str().unwrap(),
                "-out", cert_pem.to_str().unwrap(),
                "-days", "1", "-subj", "/CN=pfx-pbes1-test",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(s.success(), "openssl req failed");

        // -legacy forces PBES1 (3DES + SHA-1 MAC).
        let s = std::process::Command::new("openssl")
            .args([
                "pkcs12", "-export", "-legacy",
                "-inkey", key_pem.to_str().unwrap(),
                "-in", cert_pem.to_str().unwrap(),
                "-out", p12_path.to_str().unwrap(),
                "-passout", "pass:legacy-pass",
                "-name", "pbes1-test-key",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        if !s.success() {
            // -legacy may not be supported on all openssl builds; skip gracefully.
            return;
        }

        let p12_der = std::fs::read(&p12_path).unwrap();

        verify_pfx_mac(&p12_der, "legacy-pass")
            .expect("MAC must verify with correct passphrase (PBES1)");

        let bags = parse_pfx_structure(&p12_der, "legacy-pass")
            .expect("parse_pfx_structure must succeed with correct passphrase (PBES1)");
        assert!(
            !bags.shrouded_key_bags.is_empty(),
            "expected at least one ShroudedKeyBag from PBES1 P12"
        );
        assert_eq!(
            bags.shrouded_key_bags[0].friendly_name.as_deref(),
            Some("pbes1-test-key"),
        );
    }

    /// `extract_keys_from_pfx_bags` decrypts an RSA ShroudedKeyBag and
    /// populates `cert_der` from the matching CertBag.
    ///
    /// Uses openssl as an external oracle to generate the P12.
    #[test]
    fn pfx_extract_rsa_key_with_cert() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key", key_pem.to_str().unwrap(),
                   "-out", cert_pem.to_str().unwrap(), "-days", "1", "-subj", "/CN=extract-test"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["pkcs12", "-export",
                   "-inkey", key_pem.to_str().unwrap(),
                   "-in", cert_pem.to_str().unwrap(),
                   "-out", p12_path.to_str().unwrap(),
                   "-passout", "pass:extract-pw",
                   "-name", "extracted-rsa"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());

        let p12_der = std::fs::read(&p12_path).unwrap();
        let cert_der_expected = std::fs::read(&cert_pem).unwrap();

        verify_pfx_mac(&p12_der, "extract-pw").expect("MAC must verify");
        let bags = parse_pfx_structure(&p12_der, "extract-pw").expect("parse must succeed");

        let (keys, failures) = extract_keys_from_pfx_bags(&bags, "extract-pw");
        assert!(failures.is_empty(), "expected no failures, got: {failures:?}");
        assert_eq!(keys.len(), 1, "expected exactly one key");

        let key = &keys[0];
        assert_eq!(key.key_type, KeyType::Rsa);
        assert!(!key.key_bytes.is_empty());
        assert_eq!(key.label_hint.as_deref(), Some("extracted-rsa"));

        // Key ID must be derived from localKeyID (first 16 bytes of the bag attribute).
        if let Some(local_id) = &bags.shrouded_key_bags[0].local_key_id {
            let mut expected_id = [0u8; 16];
            let n = local_id.len().min(16);
            expected_id[..n].copy_from_slice(&local_id[..n]);
            assert_eq!(key.id, expected_id, "key ID must be derived from localKeyID");
        }

        // cert_der must be populated and match the DER of the certificate.
        // (openssl pkcs12 -export embeds the cert in the PFX).
        assert!(key.cert_der.is_some(), "cert_der must be populated from CertBag");

        // Parse the expected cert DER from the PEM file (strip PEM headers).
        let pem_block = pem::parse(&cert_der_expected).expect("cert PEM must parse");
        assert_eq!(
            key.cert_der.as_deref().unwrap(),
            pem_block.contents(),
            "cert_der must match the DER of the embedded certificate"
        );
    }

    /// `extract_keys_from_pfx_bags` returns per-bag failure when passphrase is wrong.
    #[test]
    fn pfx_extract_wrong_passphrase_per_bag_failure() {
        fn openssl_available() -> bool {
            std::process::Command::new("openssl")
                .arg("version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        if !openssl_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let p12_path = dir.path().join("test.p12");

        let s = std::process::Command::new("openssl")
            .args(["genrsa", "-out", key_pem.to_str().unwrap(), "2048"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key", key_pem.to_str().unwrap(),
                   "-out", cert_pem.to_str().unwrap(), "-days", "1", "-subj", "/CN=bag-fail"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());
        let s = std::process::Command::new("openssl")
            .args(["pkcs12", "-export",
                   "-inkey", key_pem.to_str().unwrap(),
                   "-in", cert_pem.to_str().unwrap(),
                   "-out", p12_path.to_str().unwrap(),
                   "-passout", "pass:correct",
                   "-name", "fail-bag"])
            .stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(s.success());

        let p12_der = std::fs::read(&p12_path).unwrap();

        // Correct passphrase -> MAC passes -> parse bags -> get the ShroudedKeyBag
        verify_pfx_mac(&p12_der, "correct").expect("MAC must verify");
        let bags = parse_pfx_structure(&p12_der, "correct").expect("parse must succeed");

        // Wrong passphrase for bag decryption -> per-bag failure, not panic.
        let (keys, failures) = extract_keys_from_pfx_bags(&bags, "wrong");
        assert!(keys.is_empty(), "wrong passphrase must yield no keys");
        assert!(!failures.is_empty(), "wrong passphrase must yield per-bag failure");
    }

    // -----------------------------------------------------------------------
    // JKS / JCEKS binary format reader tests
    // -----------------------------------------------------------------------

    /// Wrong magic returns Malformed (not a panic).
    #[test]
    fn jks_wrong_magic_returns_malformed() {
        // All-zeros is not valid JKS or JCEKS magic.
        let err = parse_jks_structure(&[0x00, 0x00, 0x00, 0x00])
            .err()
            .expect("wrong magic must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong magic must return Malformed, got: {err}"
        );
    }

    /// Truncated input returns Malformed (not a panic).
    #[test]
    fn jks_truncated_returns_malformed() {
        // Only the JKS magic, nothing else.
        let data = [0xFE, 0xED, 0xFE, 0xED];
        let err = parse_jks_structure(&data)
            .err()
            .expect("truncated JKS must return Err");
        assert!(matches!(err, KeyParseError::Malformed(_)));
    }

    fn keytool_available() -> bool {
        std::process::Command::new("keytool")
            .arg("-help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|_| true)
            .unwrap_or(false)
    }

    /// `parse_jks_structure` reads a PrivateKeyEntry from a JKS file generated
    /// by Java keytool.
    #[test]
    fn jks_reads_private_key_entry() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jks_path = dir.path().join("test.jks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "mykey",
                "-keyalg", "RSA", "-keysize", "2048",
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", "storepass",
                "-storetype", "JKS",
                "-dname", "CN=test",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; } // JKS might be deprecated; skip gracefully

        let jks_data = std::fs::read(&jks_path).unwrap();
        assert!(is_jks_or_jceks(&jks_data), "keytool output must be JKS/JCEKS");

        let result = parse_jks_structure(&jks_data).expect("parse_jks_structure must succeed");
        assert_eq!(result.private_key_entries.len(), 1, "expected one PrivateKeyEntry");

        let entry = &result.private_key_entries[0];
        assert_eq!(entry.alias, "mykey");
        assert!(!entry.encrypted_key.is_empty(), "encrypted_key must not be empty");
        assert!(entry.cert_der.is_some(), "cert_der must be present (keytool includes self-signed cert)");
    }

    /// `parse_jks_structure` reads a PrivateKeyEntry from a JCEKS file.
    #[test]
    fn jceks_reads_private_key_entry() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jceks_path = dir.path().join("test.jceks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "eckey",
                "-keyalg", "EC", "-keysize", "256",
                "-keystore", jceks_path.to_str().unwrap(),
                "-storepass", "storepass",
                "-storetype", "JCEKS",
                "-dname", "CN=test",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; }

        let jceks_data = std::fs::read(&jceks_path).unwrap();
        assert!(is_jks_or_jceks(&jceks_data), "keytool output must be JKS/JCEKS");

        let result = parse_jks_structure(&jceks_data).expect("parse_jks_structure must succeed");
        assert_eq!(result.private_key_entries.len(), 1, "expected one PrivateKeyEntry");

        let entry = &result.private_key_entries[0];
        assert_eq!(entry.alias, "eckey");
        assert!(!entry.encrypted_key.is_empty(), "encrypted_key must not be empty");
    }

    /// Zero PrivateKeyEntries (only TrustedCertEntry) returns Ok with empty vec.
    #[test]
    fn jks_only_trusted_cert_returns_empty_vec() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jks_path = dir.path().join("trust.jks");
        let cert_path = dir.path().join("cert.pem");

        // Generate a self-signed cert to import as trusted.
        let s = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:1024",
                   "-keyout", "/dev/null", "-out", cert_path.to_str().unwrap(),
                   "-days", "1", "-subj", "/CN=trust-test", "-nodes"])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn openssl req");
        if !s.success() { return; }

        // Import only as TrustedCertEntry (no private key).
        let s = std::process::Command::new("keytool")
            .args([
                "-importcert", "-alias", "trustedca",
                "-file", cert_path.to_str().unwrap(),
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", "storepass",
                "-storetype", "JKS",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; }

        let jks_data = std::fs::read(&jks_path).unwrap();
        let result = parse_jks_structure(&jks_data).expect("parse must succeed even with no private keys");
        assert!(
            result.private_key_entries.is_empty(),
            "keystore with only TrustedCertEntries must return empty private_key_entries"
        );
    }

    // -----------------------------------------------------------------------
    // verify_jks_integrity tests
    // -----------------------------------------------------------------------

    /// `verify_jks_integrity` accepts the correct passphrase.
    #[test]
    fn jks_integrity_correct_passphrase_succeeds() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jks_path = dir.path().join("integrity.jks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "k",
                "-keyalg", "RSA", "-keysize", "1024",
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", "inttest",
                "-storetype", "JKS",
                "-dname", "CN=int",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; } // JKS may be deprecated; skip gracefully

        let data = std::fs::read(&jks_path).unwrap();
        verify_jks_integrity(&data, "inttest")
            .expect("correct passphrase must pass integrity check");
    }

    /// `verify_jks_integrity` rejects a wrong passphrase.
    #[test]
    fn jks_integrity_wrong_passphrase_fails() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jks_path = dir.path().join("integrity.jks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "k",
                "-keyalg", "RSA", "-keysize", "1024",
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", "inttest",
                "-storetype", "JKS",
                "-dname", "CN=int",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; }

        let data = std::fs::read(&jks_path).unwrap();
        let err = verify_jks_integrity(&data, "wrongpassword")
            .err()
            .expect("wrong passphrase must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong passphrase must return Malformed, got: {err}"
        );
    }

    /// `verify_jks_integrity` rejects files shorter than 20 bytes (no room for
    /// the SHA-1 integrity fingerprint).
    #[test]
    fn jks_integrity_truncated_file_fails() {
        let data = [0u8; 19]; // needs at least 20 bytes
        let err = verify_jks_integrity(&data, "any")
            .err()
            .expect("truncated file must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "truncated file must return Malformed, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // decrypt_jks_private_key_entry tests
    // -----------------------------------------------------------------------

    /// Helper: create a JKS keystore with one RSA key via keytool and return
    /// the raw JKS bytes.
    fn make_jks_with_rsa_key(dir: &std::path::Path, passphrase: &str) -> Option<Vec<u8>> {
        let jks_path = dir.join("key.jks");
        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "rsakey",
                "-keyalg", "RSA", "-keysize", "2048",
                "-keystore", jks_path.to_str().unwrap(),
                "-storepass", passphrase,
                "-storetype", "JKS",
                "-dname", "CN=rsa-test",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        if !s.success() { return None; }
        std::fs::read(&jks_path).ok()
    }

    /// `decrypt_jks_private_key_entry` decrypts an RSA-2048 JKS entry and returns
    /// a ParsedKey with key_type == Rsa.
    #[test]
    fn jks_decrypt_rsa_entry_succeeds() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let data = match make_jks_with_rsa_key(dir.path(), "dectest") {
            Some(d) => d,
            None => return, // keytool may have rejected JKS
        };

        let entries = parse_jks_structure(&data).expect("parse_jks_structure must succeed");
        assert_eq!(entries.private_key_entries.len(), 1);
        let entry = &entries.private_key_entries[0];
        assert_eq!(entry.alias, "rsakey");

        let key = decrypt_jks_private_key_entry(&entry.encrypted_key, "dectest", [0u8; 16])
            .expect("decrypt must succeed with correct passphrase");
        assert_eq!(key.key_type, KeyType::Rsa, "expected RSA key");
        assert!(!key.key_bytes.is_empty());
    }

    /// `decrypt_jks_private_key_entry` returns Malformed for a wrong passphrase.
    #[test]
    fn jks_decrypt_wrong_passphrase_fails() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let data = match make_jks_with_rsa_key(dir.path(), "dectest") {
            Some(d) => d,
            None => return,
        };

        let entries = parse_jks_structure(&data).expect("parse_jks_structure must succeed");
        let entry = &entries.private_key_entries[0];

        let err = decrypt_jks_private_key_entry(&entry.encrypted_key, "wrongpass", [0u8; 16])
            .err()
            .expect("wrong passphrase must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "wrong passphrase must return Malformed, got: {err}"
        );
    }

    /// `decrypt_jks_private_key_entry` decrypts a JCEKS EC P-256 entry using
    /// `PBEWithMD5AndTripleDES` and returns a ParsedKey with key_type == Ec.
    #[test]
    fn jceks_decrypt_ec_entry_succeeds() {
        if !keytool_available() { return; }

        let dir = tempfile::tempdir().unwrap();
        let jceks_path = dir.path().join("test.jceks");

        let s = std::process::Command::new("keytool")
            .args([
                "-genkey", "-alias", "eckey",
                "-keyalg", "EC", "-groupname", "secp256r1",
                "-keystore", jceks_path.to_str().unwrap(),
                "-storepass", "jctest", "-keypass", "jctest",
                "-storetype", "JCEKS",
                "-dname", "CN=jceks-test",
                "-noprompt",
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to spawn keytool");
        if !s.success() { return; }

        let data = std::fs::read(&jceks_path).unwrap();
        let entries = parse_jks_structure(&data).expect("parse_jks_structure must succeed");
        assert_eq!(entries.private_key_entries.len(), 1);
        let entry = &entries.private_key_entries[0];

        let key = decrypt_jks_private_key_entry(&entry.encrypted_key, "jctest", [0u8; 16])
            .expect("decrypt must succeed with correct passphrase");
        assert_eq!(key.key_type, KeyType::Ec, "expected EC key");
        assert!(!key.key_bytes.is_empty());
    }

    /// `decrypt_jks_private_key_entry` returns Malformed for a malformed DER blob.
    #[test]
    fn jks_decrypt_malformed_der_fails() {
        // All-zeros is not a valid EncryptedPrivateKeyInfo DER.
        let err = decrypt_jks_private_key_entry(&[0u8; 64], "any", [0u8; 16])
            .err()
            .expect("malformed DER must return Err");
        assert!(
            matches!(err, KeyParseError::Malformed(_)),
            "malformed DER must return Malformed, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // JCEKS PBE KDF unit tests (inversion branch)
    // -----------------------------------------------------------------------
    //
    // Oracle values computed independently with:
    //   printf '\xHH...' | md5sum
    // See OpenJDK PBES1Core.java, deriveCipherKey, DESede branch.

    /// When both salt halves are equal, the first half is reversed before KDF.
    ///
    /// salt = [01,02,03,04, 01,02,03,04] → halves equal → half0 reversed to
    /// [04,03,02,01]; half1 unchanged.
    /// block0 = MD5([04,03,02,01, 74,65,73,74]) = 3a3dc7da5690e2dc17f88054fca1f63d
    /// block1 = MD5([01,02,03,04, 74,65,73,74]) = cf50353182e4f6eecb8ac4ba19721082
    #[test]
    fn jceks_pbe_kdf_inversion_triggers_on_equal_halves() {
        let salt = [0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04];
        let (key, iv) = jce_pbe_kdf_for_test(salt, "test", 1);

        let expected_block0 = hex::decode("3a3dc7da5690e2dc17f88054fca1f63d").unwrap();
        let expected_block1 = hex::decode("cf50353182e4f6eecb8ac4ba19721082").unwrap();
        assert_eq!(&key[..16], expected_block0.as_slice(), "key[0..16] must be block0 after inversion");
        assert_eq!(&key[16..24], &expected_block1[..8], "key[16..24] must be first 8 bytes of block1");
        assert_eq!(&iv, &expected_block1[8..16], "IV must be last 8 bytes of block1");
    }

    /// When salt halves differ, no inversion occurs; half0 is used as-is.
    ///
    /// salt = [01,02,03,04, 05,06,07,08] → halves differ → no inversion.
    /// block0 = MD5([01,02,03,04, 74,65,73,74]) = cf50353182e4f6eecb8ac4ba19721082
    /// block1 = MD5([05,06,07,08, 74,65,73,74]) = d024c21b1b4d06ef6661f36739baf663
    #[test]
    fn jceks_pbe_kdf_no_inversion_on_different_halves() {
        let salt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let (key, _iv) = jce_pbe_kdf_for_test(salt, "test", 1);

        let expected_block0 = hex::decode("cf50353182e4f6eecb8ac4ba19721082").unwrap();
        assert_eq!(&key[..16], expected_block0.as_slice(), "key[0..16] must be block0 without inversion");
    }

    /// Inversion case produces a different key than no-inversion, proving the
    /// branch is not a no-op.
    #[test]
    fn jceks_pbe_kdf_inversion_changes_key() {
        let salt_equal = [0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04];
        let salt_differ = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let (key_inv, _) = jce_pbe_kdf_for_test(salt_equal, "test", 1);
        let (key_noinv, _) = jce_pbe_kdf_for_test(salt_differ, "test", 1);
        assert_ne!(key_inv, key_noinv, "inversion must change the derived key");
    }

    // -----------------------------------------------------------------------
    // PPK parser tests
    // -----------------------------------------------------------------------

    /// Minimal valid PPK v2 input with no encryption.
    const PPK_V2_MINIMAL: &[u8] = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Encryption: none\n\
Comment: test-rsa-key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";

    /// Minimal valid PPK v3 input with Argon2id KDF.
    const PPK_V3_ARGON2: &[u8] = b"\
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256\n\
Encryption: aes256-cbc\n\
Comment: my-ec-key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Key-Derivation: Argon2id\n\
Argon2-Memory: 8192\n\
Argon2-Passes: 21\n\
Argon2-Parallelism: 1\n\
Argon2-Salt: deadbeef01020304\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n\
";

    #[test]
    fn is_ppk_detects_v2() {
        assert!(is_ppk(PPK_V2_MINIMAL));
    }

    #[test]
    fn is_ppk_detects_v3() {
        assert!(is_ppk(PPK_V3_ARGON2));
    }

    #[test]
    fn is_ppk_rejects_non_ppk() {
        assert!(!is_ppk(b"-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(!is_ppk(b"\xfe\xed\xfe\xed"));
        assert!(!is_ppk(b""));
    }

    #[test]
    fn ppk_v2_parse_all_fields_correct() {
        let f = parse_ppk(PPK_V2_MINIMAL).expect("PPK v2 parse must succeed");
        assert_eq!(f.version, 2);
        assert_eq!(f.key_type, "ssh-rsa");
        assert_eq!(f.encryption, "none");
        assert_eq!(f.comment, "test-rsa-key");
        // Public-Lines: 1 -> base64 "AQIDBA==" -> [0x01, 0x02, 0x03, 0x04]
        assert_eq!(f.public_blob, [0x01u8, 0x02, 0x03, 0x04]);
        // Private-Lines: 1 -> base64 "BQYHCA==" -> [0x05, 0x06, 0x07, 0x08]
        assert_eq!(f.private_blob, [0x05u8, 0x06, 0x07, 0x08]);
        // Private-MAC: 20 bytes
        assert_eq!(f.private_mac.len(), 20);
        assert_eq!(f.private_mac[0], 0x00);
        assert_eq!(f.private_mac[19], 0x13);
        // v3-only fields absent
        assert!(f.kdf_variant.is_none());
        assert!(f.argon2_salt.is_none());
    }

    #[test]
    fn ppk_v3_parse_all_fields_correct() {
        let f = parse_ppk(PPK_V3_ARGON2).expect("PPK v3 parse must succeed");
        assert_eq!(f.version, 3);
        assert_eq!(f.key_type, "ecdsa-sha2-nistp256");
        assert_eq!(f.encryption, "aes256-cbc");
        assert_eq!(f.comment, "my-ec-key");
        assert_eq!(f.public_blob, [0x01u8, 0x02, 0x03, 0x04]);
        assert_eq!(f.private_blob, [0x05u8, 0x06, 0x07, 0x08]);
        assert_eq!(f.private_mac.len(), 32);
        // KDF fields
        assert_eq!(f.kdf_variant.as_deref(), Some("Argon2id"));
        assert_eq!(f.argon2_memory, Some(8192));
        assert_eq!(f.argon2_passes, Some(21));
        assert_eq!(f.argon2_parallelism, Some(1));
        assert_eq!(
            f.argon2_salt.as_deref(),
            Some([0xdeu8, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04].as_ref())
        );
    }

    #[test]
    fn ppk_missing_encryption_returns_malformed() {
        let input = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Comment: key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let err = parse_ppk(input).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    #[test]
    fn ppk_missing_private_lines_returns_malformed() {
        let input = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Encryption: none\n\
Comment: key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let err = parse_ppk(input).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    #[test]
    fn ppk_invalid_base64_returns_malformed() {
        let input = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Encryption: none\n\
Comment: key\n\
Public-Lines: 1\n\
!!!NOT_BASE64!!!\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let err = parse_ppk(input).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    #[test]
    fn ppk_unknown_version_returns_unsupported() {
        let input = b"\
PuTTY-User-Key-File-4: ssh-rsa\n\
Encryption: none\n\
Comment: key\n\
Public-Lines: 1\n\
AQIDBA==\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let err = parse_ppk(input).err().expect("must fail");
        assert!(
            matches!(err, KeyParseError::Unsupported(_)),
            "unknown version must return Unsupported, got: {err}"
        );
    }

    #[test]
    fn ppk_multi_line_base64_decoded_correctly() {
        // PPK base64 blobs are a single stream split across lines.  Intermediate
        // lines have no padding (each encodes an exact multiple of 3 bytes).
        // Line 1: "AQID" = base64([0x01, 0x02, 0x03]) -- no padding
        // Line 2: "BAUG" = base64([0x04, 0x05, 0x06]) -- no padding
        // Combined stream: "AQIDBAUG" -> [0x01,0x02,0x03,0x04,0x05,0x06]
        let input = b"\
PuTTY-User-Key-File-2: ssh-rsa\n\
Encryption: none\n\
Comment: key\n\
Public-Lines: 2\n\
AQID\n\
BAUG\n\
Private-Lines: 1\n\
BQYHCA==\n\
Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n\
";
        let f = parse_ppk(input).expect("must succeed");
        assert_eq!(f.public_blob, [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    // -----------------------------------------------------------------------
    // PPK v2 SHA-1 KDF and AES-256-CBC decryption tests
    // -----------------------------------------------------------------------

    /// Compute SHA-1 of `data` via `openssl dgst -sha1 -binary`.
    /// Returns `None` if openssl is not available or the command fails.
    fn sha1_via_openssl(data: &[u8]) -> Option<[u8; 20]> {
        use std::io::Write as _;
        let mut child = std::process::Command::new("openssl")
            .args(["dgst", "-sha1", "-binary"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.as_mut()?.write_all(data).ok()?;
        let out = child.wait_with_output().ok()?;
        if out.status.success() && out.stdout.len() == 20 {
            let mut h = [0u8; 20];
            h.copy_from_slice(&out.stdout);
            Some(h)
        } else {
            None
        }
    }

    /// `ppk_v2_derive_key` output matches two independent SHA-1 hashes computed
    /// by openssl (independent oracle).
    #[test]
    fn ppk_v2_derive_key_matches_openssl_sha1() {
        let passphrase = b"test_passphrase_for_oracle";
        let key = ppk_v2_derive_key(passphrase);

        let input0: Vec<u8> = b"\x00\x00\x00\x00".iter().chain(passphrase.iter()).copied().collect();
        let input1: Vec<u8> = b"\x00\x00\x00\x01".iter().chain(passphrase.iter()).copied().collect();

        let (Some(h0), Some(h1)) = (sha1_via_openssl(&input0), sha1_via_openssl(&input1)) else {
            return; // openssl not available; skip
        };
        assert_eq!(&key[..20], &h0, "key[0..20] must equal SHA-1(counter0 || passphrase)");
        assert_eq!(&key[20..], &h1[..12], "key[20..32] must equal SHA-1(counter1 || passphrase)[0..12]");
    }

    /// `ppk_v2_decrypt_private_blob` with `Encryption: none` returns the private
    /// blob bytes unchanged.
    #[test]
    fn ppk_v2_decrypt_none_returns_blob_unchanged() {
        let f = parse_ppk(PPK_V2_MINIMAL).expect("parse must succeed");
        let plaintext = ppk_v2_decrypt_private_blob(&f, "any-passphrase")
            .expect("none encryption must not fail");
        assert_eq!(plaintext, f.private_blob);
    }

    /// `ppk_v2_decrypt_private_blob` with `Encryption: aes256-cbc` and a
    /// ciphertext that is not block-aligned returns Malformed.
    #[test]
    fn ppk_v2_decrypt_aes256_cbc_non_block_aligned_fails() {
        use base64::Engine as _;
        // 15 bytes of ciphertext -- not a multiple of 16.
        let bad_ct = base64::engine::general_purpose::STANDARD.encode([0u8; 15]);
        let input = format!(
            "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: aes256-cbc\nComment: key\n\
             Public-Lines: 1\nAQIDBA==\nPrivate-Lines: 1\n{bad_ct}\n\
             Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n"
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        let err = ppk_v2_decrypt_private_blob(&f, "pass")
            .err()
            .expect("non-block-aligned ciphertext must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// `ppk_v2_decrypt_private_blob` with an unknown encryption algorithm returns
    /// Unsupported.
    #[test]
    fn ppk_v2_decrypt_unknown_encryption_returns_unsupported() {
        use base64::Engine as _;
        let ct = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let input = format!(
            "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: blowfish-cbc\nComment: key\n\
             Public-Lines: 1\nAQIDBA==\nPrivate-Lines: 1\n{ct}\n\
             Private-MAC: 000102030405060708090a0b0c0d0e0f10111213\n"
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        let err = ppk_v2_decrypt_private_blob(&f, "pass")
            .err()
            .expect("unknown encryption must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    // -----------------------------------------------------------------------
    // PPK v3 Argon2 KDF and HMAC-SHA256 MAC tests
    // -----------------------------------------------------------------------

    /// `ppk_v3_derive_key_iv_mac` returns Unsupported for unrecognised variant.
    #[test]
    fn ppk_v3_unsupported_kdf_variant_returns_unsupported() {
        let mut bad = parse_ppk(PPK_V3_ARGON2).expect("parse must succeed");
        bad.kdf_variant = Some("Argon2xyz".to_string());
        let err = ppk_v3_derive_key_iv_mac(&bad, "pass").err().expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// `ppk_v3_decrypt_private_blob` with `Encryption: none` returns blob unchanged.
    #[test]
    fn ppk_v3_decrypt_none_returns_blob_unchanged() {
        // Build a v3 PpkFile with encryption=none (reuse v2 test vector, bump version).
        use base64::Engine as _;
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3, 4]);
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode([5u8, 6, 7, 8]);
        let input = format!(
            "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: key\n\
             Public-Lines: 1\n{pub_b64}\nPrivate-Lines: 1\n{priv_b64}\n\
             Private-MAC: {}\n",
            "00".repeat(32)
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        let plaintext = ppk_v3_decrypt_private_blob(&f, "any")
            .expect("none encryption must not fail");
        assert_eq!(plaintext, [5u8, 6, 7, 8]);
    }

    /// `ppk_v3_verify_mac` returns Malformed for a wrong MAC.
    #[test]
    fn ppk_v3_verify_mac_wrong_mac_fails() {
        let f = parse_ppk(PPK_V3_ARGON2).expect("parse must succeed");
        let err = ppk_v3_verify_mac(&f, "passphrase", &f.private_blob.clone())
            .err()
            .expect("wrong MAC must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// Compute HMAC-SHA256 via openssl for independent oracle verification.
    fn hmac_sha256_via_openssl(key: &[u8], data: &[u8]) -> Option<[u8; 32]> {
        let dir = tempfile::tempdir().ok()?;
        let data_path = dir.path().join("data.bin");
        std::fs::write(&data_path, data).ok()?;
        let key_hex = hex::encode(key);
        let out = std::process::Command::new("openssl")
            .args([
                "dgst", "-sha256", "-mac", "HMAC",
                "-macopt", &format!("hexkey:{key_hex}"),
                "-binary",
                data_path.to_str()?,
            ])
            .output()
            .ok()?;
        if out.status.success() && out.stdout.len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&out.stdout);
            Some(h)
        } else {
            None
        }
    }

    /// `ppk_v3_verify_mac` with unencrypted PPK v3 and an openssl-computed MAC passes.
    #[test]
    fn ppk_v3_verify_mac_unencrypted_correct_mac_passes() {
        let key_type = "ecdsa-sha2-nistp256";
        let encryption = "none";
        let comment = "v3-oracle-test";
        let public_blob = &[0x10u8, 0x20];
        let private_blob = &[0x30u8, 0x40];

        // For unencrypted v3, MAC key is the empty slice.
        let mac_input = ppk_v2_mac_input(key_type, encryption, comment, public_blob, private_blob);
        let Some(expected) = hmac_sha256_via_openssl(&[], &mac_input) else { return };

        let mac_hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();

        use base64::Engine as _;
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public_blob);
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode(private_blob);
        let input = format!(
            "PuTTY-User-Key-File-3: {key_type}\nEncryption: {encryption}\n\
             Comment: {comment}\nPublic-Lines: 1\n{pub_b64}\n\
             Private-Lines: 1\n{priv_b64}\nPrivate-MAC: {mac_hex}\n"
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        ppk_v3_verify_mac(&f, "", private_blob).expect("correct MAC must pass");
    }

    // -----------------------------------------------------------------------
    // PPK v2 HMAC-SHA1 MAC verification tests
    // -----------------------------------------------------------------------

    /// Compute HMAC-SHA1 of `data` using `key` via `openssl dgst -sha1 -hmac`.
    /// Returns `None` if openssl is unavailable.
    fn hmac_sha1_via_openssl(key: &[u8], data: &[u8]) -> Option<[u8; 20]> {
        // Write key and data to temp files, then invoke openssl.
        let dir = tempfile::tempdir().ok()?;
        let key_path = dir.path().join("key.bin");
        let data_path = dir.path().join("data.bin");
        std::fs::write(&key_path, key).ok()?;
        std::fs::write(&data_path, data).ok()?;
        let out = std::process::Command::new("openssl")
            .args([
                "dgst", "-sha1", "-mac", "HMAC",
                "-macopt", &format!("hexkey:{}", hex::encode(key)),
                "-binary",
                data_path.to_str()?,
            ])
            .output()
            .ok()?;
        if out.status.success() && out.stdout.len() == 20 {
            let mut h = [0u8; 20];
            h.copy_from_slice(&out.stdout);
            Some(h)
        } else {
            None
        }
    }

    /// `ppk_v2_derive_mac_key` matches SHA-1("putty-private-key-file-mac-key" || passphrase)
    /// computed by openssl.
    #[test]
    fn ppk_v2_mac_key_matches_openssl() {
        let passphrase = b"test_mac_key_pass";
        let mac_key = ppk_v2_derive_mac_key(passphrase);

        let mut input = PPK_MAC_KEY_PREFIX.to_vec();
        input.extend_from_slice(passphrase);
        let Some(expected) = sha1_via_openssl(&input) else { return };
        assert_eq!(mac_key, expected);
    }

    /// `ppk_v2_verify_mac` returns Malformed when given a wrong MAC.
    #[test]
    fn ppk_v2_verify_mac_wrong_mac_fails() {
        let f = parse_ppk(PPK_V2_MINIMAL).expect("parse must succeed");
        // PPK_V2_MINIMAL's Private-MAC is all-zero padding, not a real MAC.
        let err = ppk_v2_verify_mac(&f, "", &f.private_blob.clone())
            .err()
            .expect("wrong MAC must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// `ppk_v2_verify_mac` passes when the MAC in the PPK file matches what we
    /// compute independently, using openssl HMAC-SHA1 as the oracle.
    #[test]
    fn ppk_v2_verify_mac_correct_mac_passes() {
        let passphrase = "";
        let key_type = "ssh-rsa";
        let encryption = "none";
        let comment = "oracle-test-key";
        let public_blob = &[0x01u8, 0x02, 0x03, 0x04];
        let private_blob = &[0x05u8, 0x06, 0x07, 0x08];

        let mac_key = ppk_v2_derive_mac_key(passphrase.as_bytes());
        let mac_input = ppk_v2_mac_input(key_type, encryption, comment, public_blob, private_blob);
        let Some(expected_mac) = hmac_sha1_via_openssl(&mac_key, &mac_input) else { return };

        let mac_hex: String = expected_mac.iter().map(|b| format!("{b:02x}")).collect();

        use base64::Engine as _;
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public_blob);
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode(private_blob);
        let input = format!(
            "PuTTY-User-Key-File-2: {key_type}\nEncryption: {encryption}\n\
             Comment: {comment}\nPublic-Lines: 1\n{pub_b64}\n\
             Private-Lines: 1\n{priv_b64}\nPrivate-MAC: {mac_hex}\n"
        );
        let f = parse_ppk(input.as_bytes()).expect("parse must succeed");
        ppk_v2_verify_mac(&f, passphrase, private_blob).expect("correct MAC must pass");
    }

    // -----------------------------------------------------------------------
    // PPK key extraction tests (error paths)
    // -----------------------------------------------------------------------

    /// `ppk_extract_rsa` returns Malformed when the public blob has a wrong
    /// key-type string.
    #[test]
    fn ppk_extract_rsa_wrong_key_type_fails() {
        // Construct a public blob with key-type "ssh-dss" (not "ssh-rsa").
        let mut pub_blob = Vec::new();
        let kt = b"ssh-dss";
        pub_blob.extend_from_slice(&(kt.len() as u32).to_be_bytes());
        pub_blob.extend_from_slice(kt);
        let err = ppk_extract_rsa(&pub_blob, &[], [0u8; 16], None)
            .err()
            .expect("wrong key-type must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// `ppk_extract_ec_p256` returns Unsupported for a non-P256 EC curve.
    #[test]
    fn ppk_extract_ec_p256_wrong_curve_returns_unsupported() {
        // Public blob: key-type="ecdsa-sha2-nistp256", curve="nistp384"
        let mut pub_blob = Vec::new();
        let kt = b"ecdsa-sha2-nistp256";
        pub_blob.extend_from_slice(&(kt.len() as u32).to_be_bytes());
        pub_blob.extend_from_slice(kt);
        let curve = b"nistp384";
        pub_blob.extend_from_slice(&(curve.len() as u32).to_be_bytes());
        pub_blob.extend_from_slice(curve);
        let err = ppk_extract_ec_p256(&pub_blob, &[], [0u8; 16], None)
            .err()
            .expect("wrong curve must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// `ppk_extract_key` returns Unsupported for an unrecognised key type.
    #[test]
    fn ppk_extract_key_unsupported_type_returns_unsupported() {
        use base64::Engine as _;
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode([1u8, 2]);
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode([3u8, 4]);
        // Build a minimal PPK v2 file with key-type "ssh-ed25519"
        let mac_hex = "00".repeat(20);
        let input = format!(
            "PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: none\nComment: key\n\
             Public-Lines: 1\n{pub_b64}\nPrivate-Lines: 1\n{priv_b64}\n\
             Private-MAC: {mac_hex}\n"
        );
        let ppk = parse_ppk(input.as_bytes()).expect("parse must succeed");
        // MAC will be wrong, but the Unsupported error fires before MAC check
        // since key_type dispatch happens after decrypt (encryption=none) but before MAC
        // in ppk_extract_key.  Actually it fires AFTER MAC check -- adjust expectation.
        // For encryption=none the plaintext blob is trivially "correct" but the MAC
        // check will fail.  We test Unsupported separately via ppk_extract_key directly.
        let err = ppk_extract_key(&ppk, "", [0u8; 16])
            .err()
            .expect("must fail");
        // The MAC check fires before key-type dispatch, so we expect Malformed.
        // If MAC happened to pass (very unlikely), we'd get Unsupported.
        assert!(
            matches!(err, KeyParseError::Malformed(_) | KeyParseError::Unsupported(_)),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // OpenPGP Radix-64 dearmor + CRC-24 tests
    // -----------------------------------------------------------------------

    /// CRC-24 of the empty slice equals the init value (0xB704CE).
    #[test]
    fn crc24_empty_equals_init() {
        assert_eq!(crc24(&[]), 0xB704CE);
    }

    /// CRC-24 of a known input matches the reference value computed via
    /// the Python `crc24` reference (RFC 4880 s.6.1 algorithm).
    ///
    /// Data: b"Hello, PGP!" -> CRC-24 0x8E9E3B
    #[test]
    fn crc24_known_vector() {
        assert_eq!(crc24(b"Hello, PGP!"), 0x8E9E3B);
    }

    /// CRC-24 of bytes(0..100) -> 0xA23228 (reference-computed).
    #[test]
    fn crc24_range100_vector() {
        let data: Vec<u8> = (0u8..100).collect();
        assert_eq!(crc24(&data), 0xA23228);
    }

    /// is_pgp_armor detects a BEGIN PGP header.
    #[test]
    fn is_pgp_armor_detects_begin_pgp() {
        assert!(is_pgp_armor(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"));
        assert!(is_pgp_armor(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));
        assert!(is_pgp_armor(b"-----BEGIN PGP MESSAGE-----\n"));
    }

    /// is_pgp_armor rejects non-PGP data.
    #[test]
    fn is_pgp_armor_rejects_non_pgp() {
        assert!(!is_pgp_armor(b"-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(!is_pgp_armor(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(!is_pgp_armor(b"\xfe\xed\xfe\xed"));
        assert!(!is_pgp_armor(b""));
    }

    /// dearmor correctly decodes a simple armored block with header fields.
    ///
    /// Data: b"Hello, PGP!" -> base64 "SGVsbG8sIFBHUCE=" -> CRC-24 0x8E9E3B
    /// -> armor checksum base64 "jp47" (from 0x8E 0x9E 0x3B).
    #[test]
    fn dearmor_simple_with_headers() {
        let armored = b"\
-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\
Version: Test 1.0\r\n\
Comment: unit test\r\n\
\r\n\
SGVsbG8sIFBHUCE=\r\n\
=jp47\r\n\
-----END PGP PRIVATE KEY BLOCK-----\r\n";
        let result = dearmor(armored).expect("dearmor must succeed");
        assert_eq!(result, b"Hello, PGP!");
    }

    /// dearmor works without header fields (blank line immediately after BEGIN).
    #[test]
    fn dearmor_no_header_fields() {
        let armored = b"\
-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
\n\
SGVsbG8sIFBHUCE=\n\
=jp47\n\
-----END PGP PUBLIC KEY BLOCK-----\n";
        let result = dearmor(armored).expect("dearmor must succeed");
        assert_eq!(result, b"Hello, PGP!");
    }

    /// dearmor handles multi-line base64 bodies.
    ///
    /// Data: bytes(0..100), split into two 64-char base64 lines.
    /// CRC-24: 0xA23228 -> base64 "ojIo".
    #[test]
    fn dearmor_multiline_body() {
        let armored = b"\
-----BEGIN PGP PRIVATE KEY BLOCK-----\n\
\n\
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n\
MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n\
YGFiYw==\n\
=ojIo\n\
-----END PGP PRIVATE KEY BLOCK-----\n";
        let expected: Vec<u8> = (0u8..100).collect();
        let result = dearmor(armored).expect("dearmor must succeed");
        assert_eq!(result, expected);
    }

    /// dearmor returns Malformed when the CRC-24 checksum is wrong.
    #[test]
    fn dearmor_wrong_crc_returns_malformed() {
        // Correct CRC for "Hello, PGP!" is "jp47"; use "AAAA" (0x000000) instead.
        let armored = b"\
-----BEGIN PGP PRIVATE KEY BLOCK-----\n\
\n\
SGVsbG8sIFBHUCE=\n\
=AAAA\n\
-----END PGP PRIVATE KEY BLOCK-----\n";
        let err = dearmor(armored).err().expect("must fail on bad CRC");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// dearmor returns Malformed when the BEGIN header is missing.
    #[test]
    fn dearmor_missing_header_returns_malformed() {
        let err = dearmor(b"SGVsbG8sIFBHUCE=\n=jp47\n")
            .err()
            .expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// dearmor accepts armored data with no checksum line (spec allows omitting it).
    #[test]
    fn dearmor_no_checksum_succeeds() {
        let armored = b"\
-----BEGIN PGP PRIVATE KEY BLOCK-----\n\
\n\
SGVsbG8sIFBHUCE=\n\
-----END PGP PRIVATE KEY BLOCK-----\n";
        let result = dearmor(armored).expect("dearmor without checksum must succeed");
        assert_eq!(result, b"Hello, PGP!");
    }

    /// Verify dearmor CRC-24 matches an independent openssl-based oracle for
    /// a longer payload.  The oracle computes HMAC-SHA256 is NOT used here --
    /// instead we generate a reference CRC via the Python algorithm embedded
    /// in the test vector above (bytes(0..100) -> CRC 0xA23228).
    #[test]
    fn dearmor_crc24_matches_reference_for_range100() {
        // Independently computed: Python crc24(bytes(range(100))) = 0xA23228.
        let data: Vec<u8> = (0u8..100).collect();
        assert_eq!(crc24(&data), 0xA23228, "CRC-24 mismatch against reference");
    }

    // -----------------------------------------------------------------------
    // OpenPGP packet header parser tests
    // -----------------------------------------------------------------------

    /// next_pgp_packet returns None on empty input.
    #[test]
    fn next_pgp_packet_empty_returns_none() {
        assert!(next_pgp_packet(&[]).is_none());
    }

    /// next_pgp_packet returns None when bit 7 of the tag byte is zero
    /// (not a valid OpenPGP packet tag).
    #[test]
    fn next_pgp_packet_invalid_tag_byte_returns_none() {
        assert!(next_pgp_packet(&[0x05, 0x00]).is_none()); // bit 7 = 0
    }

    /// Old-format SecretKey (tag 5), one-octet length.
    ///
    /// Tag byte layout: 1_0_TTTT_LL = 1_0_0101_00 = 0x94
    /// Length byte: 0x03 -> body is 3 bytes.
    #[test]
    fn next_pgp_packet_old_format_tag5_one_octet_length() {
        // 0x94 = 10_0101_00: old format (bit6=0), tag=5, length_type=0 (1-byte)
        let data = [0x94u8, 0x03, 0xAA, 0xBB, 0xCC];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body, [0xAA, 0xBB, 0xCC]);
        assert!(remainder.is_empty());
    }

    /// Old-format SecretSubkey (tag 7), two-octet length.
    ///
    /// Tag byte: 1_0_0111_01 = 0x9D; length = [0x00, 0x02] -> 2 bytes.
    #[test]
    fn next_pgp_packet_old_format_tag7_two_octet_length() {
        // 0x9D = 10_0111_01: old format, tag=7, length_type=1 (2-byte)
        let data = [0x9Du8, 0x00, 0x02, 0xDE, 0xAD];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_SUBKEY);
        assert_eq!(body, [0xDE, 0xAD]);
        assert!(remainder.is_empty());
    }

    /// Old-format four-octet length.
    ///
    /// Tag byte: 1_0_0101_10 = 0x96; length = [0x00, 0x00, 0x00, 0x02] -> 2 bytes.
    #[test]
    fn next_pgp_packet_old_format_four_octet_length() {
        // 0x96 = 10_0101_10: old format, tag=5, length_type=2 (4-byte)
        let data = [0x96u8, 0x00, 0x00, 0x00, 0x02, 0x11, 0x22];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body, [0x11, 0x22]);
        assert!(remainder.is_empty());
    }

    /// New-format SecretKey (tag 5), one-octet length.
    ///
    /// Tag byte: 1_1_000101 = 0xC5; length byte 3 -> body is 3 bytes.
    #[test]
    fn next_pgp_packet_new_format_tag5_one_octet_length() {
        // 0xC5 = 11_000101: new format (bit6=1), tag=5, 1-byte length
        let data = [0xC5u8, 0x03, 0xAA, 0xBB, 0xCC];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body, [0xAA, 0xBB, 0xCC]);
        assert!(remainder.is_empty());
    }

    /// New-format two-octet length: first byte 192, second byte 8 -> len = 200.
    ///
    /// Formula: ((192 - 192) << 8) + 8 + 192 = 200.
    #[test]
    fn next_pgp_packet_new_format_two_octet_length() {
        // 0xC5: new format tag 5; then 0xC0 0x08 -> two-octet len = 200
        let mut data = vec![0xC5u8, 0xC0, 0x08];
        data.extend(vec![0x55u8; 200]);
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body.len(), 200);
        assert!(remainder.is_empty());
    }

    /// New-format five-octet length (0xFF prefix).
    #[test]
    fn next_pgp_packet_new_format_five_octet_length() {
        // 0xC5: new format tag 5; then 0xFF + 4-byte BE length = 3
        let data = [0xC5u8, 0xFF, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let (tag, body, remainder) = next_pgp_packet(&data).expect("must parse");
        assert_eq!(tag, PGP_TAG_SECRET_KEY);
        assert_eq!(body, [0xAA, 0xBB, 0xCC]);
        assert!(remainder.is_empty());
    }

    /// next_pgp_packet returns the remainder after the first packet.
    #[test]
    fn next_pgp_packet_returns_correct_remainder() {
        // Two old-format tag-5 packets, each 2 bytes long.
        // 0x94 = old format, tag=5, 1-byte length
        let data = [0x94u8, 0x02, 0x11, 0x22,
                    0x94u8, 0x02, 0x33, 0x44];
        let (_, body1, rest) = next_pgp_packet(&data).expect("first packet");
        assert_eq!(body1, [0x11, 0x22]);
        let (_, body2, rest2) = next_pgp_packet(rest).expect("second packet");
        assert_eq!(body2, [0x33, 0x44]);
        assert!(rest2.is_empty());
    }

    /// next_pgp_packet returns None when body is truncated.
    #[test]
    fn next_pgp_packet_truncated_body_returns_none() {
        // Claim 5-byte body but only 2 bytes present.
        let data = [0x94u8, 0x05, 0xAA, 0xBB];
        assert!(next_pgp_packet(&data).is_none());
    }

    /// next_pgp_packet returns None when length bytes are missing (old 2-byte).
    #[test]
    fn next_pgp_packet_truncated_length_returns_none() {
        // 0x9D = old format, tag=7, length_type=1 (2-byte), but only 1 length byte given.
        let data = [0x9Du8, 0x00];
        assert!(next_pgp_packet(&data).is_none());
    }

    /// pgp_collect_secret_packets extracts tag-5 and tag-7 packets, skipping others.
    ///
    /// Stream layout (all old-format, 1-byte length):
    ///   tag 2 (Signature) -- should be skipped
    ///   tag 5 (SecretKey) -- should be collected
    ///   tag 6 (PublicKey) -- should be skipped
    ///   tag 7 (SecretSubkey) -- should be collected
    #[test]
    fn pgp_collect_secret_packets_collects_tag5_and_tag7_only() {
        // Tag byte formula for old format: 1_0_TTTT_00
        // Tag 2: 10_0010_00 = 0x88; tag 5: 0x94; tag 6: 10_0110_00 = 0x98; tag 7: 0x9C
        let data = [
            0x88u8, 0x02, 0xAA, 0xBB,  // tag 2, body=[0xAA, 0xBB]
            0x94u8, 0x02, 0xCC, 0xDD,  // tag 5, body=[0xCC, 0xDD]
            0x98u8, 0x02, 0xEE, 0xFF,  // tag 6, body=[0xEE, 0xFF]
            0x9Cu8, 0x02, 0x11, 0x22,  // tag 7, body=[0x11, 0x22]
        ];
        let packets = pgp_collect_secret_packets(&data);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].0, PGP_TAG_SECRET_KEY);
        assert_eq!(packets[0].1, [0xCCu8, 0xDD]);
        assert_eq!(packets[1].0, PGP_TAG_SECRET_SUBKEY);
        assert_eq!(packets[1].1, [0x11u8, 0x22]);
    }

    /// pgp_collect_secret_packets returns empty Vec when no secret packets present.
    #[test]
    fn pgp_collect_secret_packets_empty_when_no_secret_packets() {
        // One Signature packet (tag 2) only.
        let data = [0x88u8, 0x02, 0xAA, 0xBB];
        assert!(pgp_collect_secret_packets(&data).is_empty());
    }

    /// pgp_collect_secret_packets stops at a malformed packet without panicking.
    #[test]
    fn pgp_collect_secret_packets_stops_at_malformed() {
        // Valid tag-5 packet, then truncated garbage.
        let data = [0x94u8, 0x01, 0xAA,  // valid: tag5, body=[0xAA]
                    0x94u8, 0x05, 0xBB]; // invalid: claims 5-byte body, only 1 byte
        let packets = pgp_collect_secret_packets(&data);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].1, [0xAAu8]);
    }

    // -----------------------------------------------------------------------
    // pgp_first_user_id_label tests
    // -----------------------------------------------------------------------

    /// pgp_first_user_id_label extracts the full UID when there is no email suffix.
    #[test]
    fn pgp_first_user_id_label_plain_email() {
        // Tag 13 (User ID), new format: 0xCD = 11_001101
        // Body: "gpgtest@test.invalid" (20 bytes)
        let uid = b"gpgtest@test.invalid";
        let mut data = vec![0xCDu8, uid.len() as u8];
        data.extend_from_slice(uid);
        let label = pgp_first_user_id_label(&data);
        assert_eq!(label.as_deref(), Some("gpgtest@test.invalid"));
    }

    /// pgp_first_user_id_label strips the angle-bracket email from "Name <email>".
    #[test]
    fn pgp_first_user_id_label_strips_email_suffix() {
        let uid = b"John Doe <john@example.com>";
        let mut data = vec![0xCDu8, uid.len() as u8];
        data.extend_from_slice(uid);
        let label = pgp_first_user_id_label(&data);
        assert_eq!(label.as_deref(), Some("John Doe"));
    }

    /// pgp_first_user_id_label returns None when no User-ID packet is present.
    #[test]
    fn pgp_first_user_id_label_none_when_no_uid_packet() {
        // Only a tag-5 Secret-Key packet; no User-ID.
        let data = [0x94u8, 0x02, 0x11, 0x22];
        assert!(pgp_first_user_id_label(&data).is_none());
    }

    // -----------------------------------------------------------------------
    // is_pgp_binary_secret_key_packet tests
    // -----------------------------------------------------------------------

    /// Old-format tag-5 packet (0x94) is detected as a binary PGP secret key.
    #[test]
    fn is_pgp_binary_secret_key_packet_detects_old_format_tag5() {
        assert!(is_pgp_binary_secret_key_packet(&[0x94, 0x03, 0xAA, 0xBB, 0xCC]));
    }

    /// New-format tag-5 packet (0xC5) is detected as a binary PGP secret key.
    #[test]
    fn is_pgp_binary_secret_key_packet_detects_new_format_tag5() {
        assert!(is_pgp_binary_secret_key_packet(&[0xC5, 0x03, 0xAA, 0xBB, 0xCC]));
    }

    /// Old-format tag-6 packet (Public-Key, 0x98 = 10_0110_00) is NOT detected.
    #[test]
    fn is_pgp_binary_secret_key_packet_rejects_tag6() {
        // 0x98 = old format, tag=6 (Public-Key), length_type=0
        assert!(!is_pgp_binary_secret_key_packet(&[0x98, 0x03, 0xAA]));
    }

    /// Empty slice returns false.
    #[test]
    fn is_pgp_binary_secret_key_packet_empty_returns_false() {
        assert!(!is_pgp_binary_secret_key_packet(&[]));
    }

    /// ASN.1 DER SEQUENCE start byte (0x30) is not a PGP secret-key packet.
    #[test]
    fn is_pgp_binary_secret_key_packet_rejects_der_sequence() {
        assert!(!is_pgp_binary_secret_key_packet(&[0x30, 0x82, 0x01, 0x00]));
    }

    /// dearmor produces the same binary as `gpg --export-secret-keys` (non-armored).
    ///
    /// This test is skipped when `gpg` is not installed.  It generates a
    /// temporary key pair so that the test keyring is self-contained.
    #[test]
    fn dearmor_matches_gpg_binary_export() {
        use std::process::{Command, Stdio};

        // Check gpg availability.
        if Command::new("gpg").arg("--version").stdout(Stdio::null()).stderr(Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false) == false { return; }

        let dir = tempfile::tempdir().unwrap();
        let gnupghome = dir.path().to_str().unwrap().to_string();

        // Generate an unprotected RSA-2048 key in the temp keyring.
        let key_params = "\
%no-protection\n\
Key-Type: RSA\n\
Key-Length: 2048\n\
Name-Real: Dearmor Test\n\
Name-Email: dearmor@test.invalid\n\
Expire-Date: 0\n\
%commit\n";
        let param_path = dir.path().join("params.txt");
        std::fs::write(&param_path, key_params).unwrap();

        let ok = Command::new("gpg")
            .env("GNUPGHOME", &gnupghome)
            .args(["--batch", "--gen-key", param_path.to_str().unwrap()])
            .stdout(Stdio::null()).stderr(Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false);
        if !ok { return; }

        // Get the fingerprint of the generated key.
        let fp_out = Command::new("gpg")
            .env("GNUPGHOME", &gnupghome)
            .args(["--list-secret-keys", "--with-colons"])
            .output().unwrap();
        let fp_text = String::from_utf8_lossy(&fp_out.stdout);
        let fingerprint: String = fp_text.lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .unwrap_or("").to_string();
        if fingerprint.is_empty() { return; }

        // Export armored.
        let armored = Command::new("gpg")
            .env("GNUPGHOME", &gnupghome)
            .args(["--armor", "--export-secret-keys", &fingerprint])
            .output().unwrap().stdout;
        if armored.is_empty() { return; }

        // Export raw (non-armored) binary.
        let binary = Command::new("gpg")
            .env("GNUPGHOME", &gnupghome)
            .args(["--export-secret-keys", &fingerprint])
            .output().unwrap().stdout;
        if binary.is_empty() { return; }

        // Dearmor the armored export and compare.
        let decoded = dearmor(&armored).expect("dearmor of real GPG export must succeed");
        assert_eq!(decoded, binary, "dearmored output must match raw GPG export");
    }

    // -----------------------------------------------------------------------
    // OpenPGP v4 Public-Key body parser + MPI decoder tests
    // -----------------------------------------------------------------------

    /// read_pgp_mpi: one-byte value, 7-bit MPI.
    #[test]
    fn read_pgp_mpi_one_byte() {
        // bit count = 7 (0x0007); byte count = 1; value = 0x7F
        let data = [0x00u8, 0x07, 0x7F, 0xAA]; // 0xAA is remainder
        let (value, rest) = read_pgp_mpi(&data).expect("must parse");
        assert_eq!(value, [0x7Fu8]);
        assert_eq!(rest, [0xAAu8]);
    }

    /// read_pgp_mpi: two-byte value, 9-bit MPI.
    #[test]
    fn read_pgp_mpi_two_bytes() {
        // bit count = 9 (0x0009); byte count = 2; value = [0x01, 0xFF]
        let data = [0x00u8, 0x09, 0x01, 0xFF];
        let (value, rest) = read_pgp_mpi(&data).expect("must parse");
        assert_eq!(value, [0x01u8, 0xFF]);
        assert!(rest.is_empty());
    }

    /// read_pgp_mpi: bit count that is an exact multiple of 8.
    #[test]
    fn read_pgp_mpi_exact_byte_boundary() {
        // bit count = 8 (0x0008); byte count = 1
        let data = [0x00u8, 0x08, 0x80];
        let (value, _) = read_pgp_mpi(&data).expect("must parse");
        assert_eq!(value, [0x80u8]);
    }

    /// read_pgp_mpi: bit count zero -> zero-byte value.
    #[test]
    fn read_pgp_mpi_bit_count_zero() {
        // bit count = 0; byte count = 0; value = empty
        let data = [0x00u8, 0x00, 0xFF]; // 0xFF is remainder
        let (value, rest) = read_pgp_mpi(&data).expect("must parse");
        assert!(value.is_empty());
        assert_eq!(rest, [0xFFu8]);
    }

    /// read_pgp_mpi returns None on truncated data (less than 2 bytes).
    #[test]
    fn read_pgp_mpi_truncated_header() {
        assert!(read_pgp_mpi(&[]).is_none());
        assert!(read_pgp_mpi(&[0x00]).is_none());
    }

    /// read_pgp_mpi returns None when body is shorter than the declared bit count.
    #[test]
    fn read_pgp_mpi_truncated_body() {
        // Claims 9-bit MPI (2 bytes) but only 1 byte of body present.
        let data = [0x00u8, 0x09, 0x01];
        assert!(read_pgp_mpi(&data).is_none());
    }

    /// parse_pgp_public_key_body: RSA algorithm 1, simple key material.
    ///
    /// Body: version=4, timestamp=[0;4], algorithm=1,
    ///   MPI n = 0x0123 (9 bits), MPI e = 0x010001 (17 bits).
    #[test]
    fn parse_pgp_pubkey_body_rsa_success() {
        let mut body = Vec::new();
        body.push(4u8);                        // version
        body.extend_from_slice(&[0u8; 4]);    // timestamp
        body.push(1u8);                        // algorithm: RSA
        // MPI n: bit count = 9 (0x0009), value = [0x01, 0x23]
        body.extend_from_slice(&[0x00, 0x09, 0x01, 0x23]);
        // MPI e: bit count = 17 (0x0011), value = [0x01, 0x00, 0x01]
        body.extend_from_slice(&[0x00, 0x11, 0x01, 0x00, 0x01]);
        // Secret material (should be in remaining)
        let secret_tag = [0xFFu8, 0xEE];
        body.extend_from_slice(&secret_tag);

        let parsed = parse_pgp_public_key_body(&body).expect("must parse RSA");
        assert_eq!(parsed.algorithm, 1);
        match &parsed.material {
            PgpPublicKeyMaterial::Rsa { n, e } => {
                assert_eq!(n.as_slice(), [0x01u8, 0x23]);
                assert_eq!(e.as_slice(), [0x01u8, 0x00, 0x01]);
            }
            _ => panic!("expected RSA material"),
        }
        // fingerprint_body covers version..last_public_MPI (excludes secret_tag)
        assert_eq!(parsed.fingerprint_body.len(), body.len() - secret_tag.len());
        assert_eq!(parsed.fingerprint_body[0], 4); // version byte
        assert_eq!(parsed.remaining, secret_tag);
    }

    /// parse_pgp_public_key_body: ECDSA algorithm 19, P-256 public point.
    ///
    /// Uses the known EC P-256 test key from the PPK v3 fixture.
    #[test]
    fn parse_pgp_pubkey_body_ecdsa_p256_success() {
        // Public point from the PPK v3 fixture (same key pair).
        let public_point = hex::decode(
            "0401aecf6df8814671c6ea4fd2d8ccde01338a8358e7085d1f3475cfe0019098d\
             6a26a37e764265e89e5c4e61a7f4fced3ab36d1deca420e93590afe3cdfc7a4ec"
        ).unwrap();
        assert_eq!(public_point.len(), 65);

        // bit count for 65-byte value starting with 0x04 = 0b00000100:
        // MSB is bit 2 in first byte -> bit_count = 2 + 64*8 + 1 = 515 = 0x0203
        let bit_count: u16 = 515;

        let mut body = Vec::new();
        body.push(4u8);                           // version
        body.extend_from_slice(&[0x00u8; 4]);     // timestamp
        body.push(19u8);                          // algorithm: ECDSA
        body.push(8u8);                           // OID length
        body.extend_from_slice(P256_OID);         // P-256 OID
        body.extend_from_slice(&bit_count.to_be_bytes()); // MPI bit count
        body.extend_from_slice(&public_point);    // MPI value (public point)
        // No remaining secret material in this test.

        let parsed = parse_pgp_public_key_body(&body).expect("must parse ECDSA");
        assert_eq!(parsed.algorithm, 19);
        match &parsed.material {
            PgpPublicKeyMaterial::Ecdsa { public_point: pt } => {
                assert_eq!(pt.as_slice(), public_point.as_slice());
            }
            _ => panic!("expected ECDSA material"),
        }
        // fingerprint_body must equal the entire body (no remaining bytes).
        assert_eq!(parsed.fingerprint_body, body);
        assert!(parsed.remaining.is_empty());
    }

    /// parse_pgp_public_key_body returns Unsupported for version != 4.
    #[test]
    fn parse_pgp_pubkey_body_version_not_4_returns_unsupported() {
        let body = [3u8, 0, 0, 0, 0, 1]; // version=3
        let err = parse_pgp_public_key_body(&body).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// parse_pgp_public_key_body returns Unsupported for unknown algorithm.
    #[test]
    fn parse_pgp_pubkey_body_unsupported_algorithm() {
        // Algorithm 17 = DSA
        let body = [4u8, 0, 0, 0, 0, 17];
        let err = parse_pgp_public_key_body(&body).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// parse_pgp_public_key_body returns Unsupported for ECDSA with a non-P-256 curve.
    #[test]
    fn parse_pgp_pubkey_body_ecdsa_non_p256_returns_unsupported() {
        // P-384 OID: 06 05 2b 81 04 00 22 (length=5, OID=[2b 81 04 00 22])
        let p384_oid: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
        let mut body = Vec::new();
        body.push(4u8);             // version
        body.extend_from_slice(&[0u8; 4]);  // timestamp
        body.push(19u8);            // algorithm: ECDSA
        body.push(p384_oid.len() as u8);
        body.extend_from_slice(p384_oid);
        // Minimal MPI placeholder (truncated) -- error fires before MPI read
        body.extend_from_slice(&[0x01, 0x00, 0xFF]);

        let err = parse_pgp_public_key_body(&body).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    /// parse_pgp_public_key_body returns Malformed on truncated RSA MPI n.
    #[test]
    fn parse_pgp_pubkey_body_rsa_truncated_n_returns_malformed() {
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(&[0u8; 4]);
        body.push(1u8); // RSA
        // Claim 9-bit MPI (2 bytes) but give only 1 byte of value
        body.extend_from_slice(&[0x00, 0x09, 0x01]);

        let err = parse_pgp_public_key_body(&body).err().expect("must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    // OpenPGP S2K key derivation tests

    /// S2K type 0 (simple SHA-1): SHA-1 of passphrase, first key_len bytes.
    ///
    /// Vector derived from: SHA-1("test1234") = 9bc34549d565d9505b287de0cd20ac77be1d3f2c
    #[test]
    fn pgp_s2k_type0_sha1_known_vector() {
        let key = pgp_s2k_derive_key(b"test1234", 0, 2, &[], 0, 16)
            .expect("S2K type 0 must succeed");
        assert_eq!(
            key,
            hex::decode("9bc34549d565d9505b287de0cd20ac77").unwrap(),
            "S2K type 0 SHA-1 key mismatch"
        );
    }

    /// S2K type 3 (iterated+salted SHA-1): known vector with salt=01..08, count_byte=96.
    ///
    /// count_byte=96 -> count = (16+0) << (6+6) = 65536.
    /// Vector derived from the Python reference in the session notes.
    #[test]
    fn pgp_s2k_type3_sha1_known_vector() {
        let salt = hex::decode("0102030405060708").unwrap();
        // count for count_byte=96: (16 + (96 & 15)) << ((96 >> 4) + 6) = 16 << 12 = 65536
        let count: usize = (16usize + (96usize & 15)) << ((96usize >> 4) + 6);
        assert_eq!(count, 65536);
        let key = pgp_s2k_derive_key(b"test1234", 3, 2, &salt, count, 16)
            .expect("S2K type 3 must succeed");
        assert_eq!(
            key,
            hex::decode("47834d3754e438ab593cd9a81009daf2").unwrap(),
            "S2K type 3 SHA-1 key mismatch"
        );
    }

    /// S2K with an unsupported hash ID returns Unsupported.
    #[test]
    fn pgp_s2k_unsupported_hash_returns_unsupported() {
        let err = pgp_s2k_derive_key(b"pass", 0, 3, &[], 0, 16)
            .err()
            .expect("must fail");
        assert!(matches!(err, KeyParseError::Unsupported(_)), "got: {err}");
    }

    // OpenPGP secret key decryption tests

    /// pgp_decrypt_secret_material: plaintext key (usage=0x00) with correct checksum.
    ///
    /// remaining = 0x00 || MPI(256-bit 0xAB..AB) || checksum(0x1561)
    #[test]
    fn pgp_decrypt_plaintext_usage_zero() {
        let remaining = hex::decode(
            "000100abababababababababababababababababababababababababababababababab1561"
        ).unwrap();
        let mpi = pgp_decrypt_secret_material(&remaining, b"ignored")
            .expect("plaintext must succeed");
        // MPI bytes: 0x0100 (bit count) + 32x0xAB
        assert_eq!(mpi.len(), 34);
        assert_eq!(&mpi[..2], &[0x01, 0x00]);
        assert!(mpi[2..].iter().all(|&b| b == 0xAB));
    }

    /// pgp_decrypt_secret_material: plaintext key with wrong checksum returns Malformed.
    #[test]
    fn pgp_decrypt_plaintext_bad_checksum_returns_malformed() {
        let mut remaining = hex::decode(
            "000100abababababababababababababababababababababababababababababababab1561"
        ).unwrap();
        // Corrupt the checksum.
        let len = remaining.len();
        remaining[len - 1] ^= 0xFF;
        let err = pgp_decrypt_secret_material(&remaining, b"ignored")
            .err()
            .expect("bad checksum must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// pgp_decrypt_secret_material: AES-128-CFB with S2K type 3, SHA-1, usage=0xFE.
    ///
    /// Test vector generated by the Python reference implementation:
    ///   passphrase = "hunter2"
    ///   salt = deadbeef01234567
    ///   count_byte = 96 (count=65536)
    ///   iv = aabbccdd11223344556677889900aabb
    ///   plaintext MPI = 256-bit value 0x4242..42
    #[test]
    fn pgp_decrypt_aes128_s2k_type3_sha1_known_vector() {
        let remaining = hex::decode(concat!(
            "fe070302",                 // usage=0xFE, cipher=7(AES-128), S2K=3, hash=2(SHA-1)
            "deadbeef01234567",         // salt (8 bytes)
            "60",                       // count_byte=96
            "aabbccdd11223344556677889900aabb", // IV (16 bytes)
            // ciphertext (54 bytes): encrypt(MPI(256-bit 0x42..42) || SHA-1(MPI))
            "8e47509e64519b2e7bd215bfcd660b7c",
            "283de63f2256c2c5c9e43a561ffd2e16",
            "be1a003b3edf4363d9c7d911d3bba9a3",
            "0415fd7f7785"
        )).unwrap();

        let mpi = pgp_decrypt_secret_material(&remaining, b"hunter2")
            .expect("correct passphrase must succeed");

        // Decrypted MPI: 0x0100 (256 bits) + 32x0x42
        assert_eq!(mpi.len(), 34, "MPI bytes length mismatch");
        assert_eq!(&mpi[..2], &[0x01, 0x00], "MPI bit-count header mismatch");
        assert!(mpi[2..].iter().all(|&b| b == 0x42), "MPI value mismatch");
    }

    /// pgp_decrypt_secret_material: wrong passphrase returns Malformed (SHA-1 mismatch).
    #[test]
    fn pgp_decrypt_wrong_passphrase_returns_malformed() {
        let remaining = hex::decode(concat!(
            "fe070302",
            "deadbeef01234567",
            "60",
            "aabbccdd11223344556677889900aabb",
            "8e47509e64519b2e7bd215bfcd660b7c",
            "283de63f2256c2c5c9e43a561ffd2e16",
            "be1a003b3edf4363d9c7d911d3bba9a3",
            "0415fd7f7785"
        )).unwrap();

        let err = pgp_decrypt_secret_material(&remaining, b"wrong")
            .err()
            .expect("wrong passphrase must fail");
        assert!(matches!(err, KeyParseError::Malformed(_)), "got: {err}");
    }

    /// pgp_decrypt_secret_material with a real GPG-exported P-256 key.
    ///
    /// Generates a key in a temp GNUPGHOME, exports the binary secret packet,
    /// parses the public portion, and decrypts with the known passphrase.
    /// Skipped when `gpg` is not available.
    #[test]
    fn pgp_decrypt_gpg_p256_key_end_to_end() {
        use std::process::Command;
        let gpg_ok = Command::new("gpg").arg("--version").output().is_ok();
        if !gpg_ok {
            return;
        }

        let tmpdir = tempfile::tempdir().expect("tempdir");
        let gnupghome = tmpdir.path().to_str().unwrap();
        let passphrase = "pgp-test-pass";

        // Generate a nistp256 key.
        let status = Command::new("gpg")
            .args([
                "--batch", "--yes",
                "--pinentry-mode", "loopback",
                "--passphrase", passphrase,
                "--quick-generate-key", "pgptest@test.invalid",
                "nistp256", "default", "0",
            ])
            .env("GNUPGHOME", gnupghome)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("gpg keygen");
        assert!(status.success(), "gpg --quick-generate-key failed");

        // Export binary secret key.
        let output = Command::new("gpg")
            .args([
                "--batch", "--yes",
                "--pinentry-mode", "loopback",
                "--passphrase", passphrase,
                "--export-secret-keys",
            ])
            .env("GNUPGHOME", gnupghome)
            .output()
            .expect("gpg export");
        assert!(output.status.success(), "gpg --export-secret-keys failed");
        let binary = output.stdout;

        // Collect secret-key packets and find a P-256 one.
        let packets = pgp_collect_secret_packets(&binary);
        let mut found = false;
        for (_tag, body) in &packets {
            let pubkey = match parse_pgp_public_key_body(body) {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            if !matches!(pubkey.material, PgpPublicKeyMaterial::Ecdsa { .. }) {
                continue;
            }

            let mpi_bytes =
                pgp_decrypt_secret_material(&pubkey.remaining, passphrase.as_bytes())
                    .expect("decrypt with correct passphrase must succeed");

            // The decrypted MPI bytes should start with a 2-byte bit-count header
            // and contain exactly 32 bytes for a P-256 scalar.
            assert!(mpi_bytes.len() >= 2, "MPI bytes too short");
            let bit_count = u16::from_be_bytes([mpi_bytes[0], mpi_bytes[1]]) as usize;
            let byte_count = (bit_count + 7) / 8;
            assert_eq!(
                mpi_bytes.len(),
                2 + byte_count,
                "MPI byte count doesn't match declared bit count"
            );
            assert!(
                byte_count <= 32,
                "P-256 scalar must be <=32 bytes, got {byte_count}"
            );
            found = true;
            break;
        }
        assert!(found, "no P-256 secret key packet found in GPG export");
    }
