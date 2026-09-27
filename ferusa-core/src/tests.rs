#[cfg(test)]
mod crypto_tests {
    use crate::crypto::*;
    use crate::error::FerusaError;

    const PHONE_SHARE: [u8; 32] = [0xA5; 32];
    const OTHER_PHONE_SHARE: [u8; 32] = [0x5A; 32];

    fn vault_key(password: &[u8], salt: &[u8; 16], phone_share: &[u8; 32]) -> [u8; 32] {
        let local_secret = derive_local_secret(password, salt).unwrap();
        combine_vault_key(&local_secret, phone_share).unwrap()
    }

    // ── derive_keys ──────────────────────────────────────────

    #[test]
    fn derive_keys_is_deterministic() {
        let salt = new_salt();
        let k1 = derive_keys(b"hunter2", &salt).unwrap();
        let k2 = derive_keys(b"hunter2", &salt).unwrap();
        assert_eq!(k1.local_secret, k2.local_secret);
    }

    #[test]
    fn different_passwords_give_different_keys() {
        let salt = new_salt();
        let k1 = derive_keys(b"password_a", &salt).unwrap();
        let k2 = derive_keys(b"password_b", &salt).unwrap();
        assert_ne!(k1.local_secret, k2.local_secret);
    }

    #[test]
    fn different_salts_give_different_keys() {
        let s1 = new_salt();
        let s2 = new_salt();
        let k1 = derive_keys(b"same_password", &s1).unwrap();
        let k2 = derive_keys(b"same_password", &s2).unwrap();
        assert_ne!(k1.local_secret, k2.local_secret);
    }

    #[test]
    fn vault_key_requires_phone_share() {
        let salt = new_salt();
        let local_secret = derive_local_secret(b"test", &salt).unwrap();
        let vault_key = combine_vault_key(&local_secret, &PHONE_SHARE).unwrap();

        assert_ne!(vault_key, local_secret);
        assert_ne!(
            vault_key,
            combine_vault_key(&local_secret, &OTHER_PHONE_SHARE).unwrap()
        );
    }

    // ── encrypt / decrypt ────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let salt = new_salt();
        let vault_key = vault_key(b"correct_password", &salt, &PHONE_SHARE);
        let plaintext = b"super secret vault data";

        let blob = encrypt_vault(&vault_key, salt, plaintext).unwrap();
        let recovered = decrypt_vault(&vault_key, &blob).unwrap();

        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let salt = new_salt();
        let key_correct = vault_key(b"correct", &salt, &PHONE_SHARE);
        let key_wrong_password = vault_key(b"wrong", &salt, &PHONE_SHARE);
        let key_wrong_share = vault_key(b"correct", &salt, &OTHER_PHONE_SHARE);

        let blob = encrypt_vault(&key_correct, salt, b"secret").unwrap();

        assert!(
            decrypt_vault(&key_wrong_password, &blob).is_err(),
            "decryption with wrong password should fail"
        );
        assert!(
            decrypt_vault(&key_wrong_share, &blob).is_err(),
            "decryption with wrong phone share should fail"
        );
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let salt = new_salt();
        let vault_key = vault_key(b"password", &salt, &PHONE_SHARE);
        let mut blob = encrypt_vault(&vault_key, salt, b"secret data").unwrap();

        let mid = blob.ciphertext.len() / 2;
        blob.ciphertext[mid] ^= 0xFF;

        assert!(decrypt_vault(&vault_key, &blob).is_err());
    }

    #[test]
    fn each_encryption_uses_unique_nonce() {
        let salt = new_salt();
        let vault_key = vault_key(b"pw", &salt, &PHONE_SHARE);
        let b1 = encrypt_vault(&vault_key, salt, b"data").unwrap();
        let b2 = encrypt_vault(&vault_key, salt, b"data").unwrap();
        assert_ne!(b1.nonce, b2.nonce, "nonces must be unique");
        assert_ne!(b1.ciphertext, b2.ciphertext, "ciphertexts must differ");
    }

    #[test]
    fn blob_serialise_roundtrip() {
        let salt = new_salt();
        let vault_key = vault_key(b"pw", &salt, &PHONE_SHARE);
        let blob = encrypt_vault(&vault_key, salt, b"hello vault").unwrap();

        let bytes = blob.to_bytes();
        let blob2 = crate::crypto::EncryptedBlob::from_bytes(&bytes).unwrap();
        let recovered = decrypt_vault(&vault_key, &blob2).unwrap();
        assert_eq!(blob2.salt(), salt);
        assert_eq!(recovered, b"hello vault");
    }

    #[test]
    fn encrypted_blob_serializes_requested_nonzero_salt() {
        let salt = [0x42; 16];
        let vault_key = vault_key(b"pw", &salt, &PHONE_SHARE);
        let blob = encrypt_vault(&vault_key, salt, b"hello vault").unwrap();
        let bytes = blob.to_bytes();

        assert_eq!(blob.salt(), salt);
        assert_eq!(
            &bytes[8..24],
            &salt,
            "serialized vault blob must carry the caller-provided salt"
        );
    }

    #[test]
    fn blob_from_bytes_rejects_too_short_input() {
        let err = match crate::crypto::EncryptedBlob::from_bytes(&[0u8; 55]) {
            Ok(_) => panic!("short blob must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, FerusaError::BlobTooShort { len: 55 }));
        assert_eq!(err.to_string(), "blob too short: 55 bytes");
    }

    #[test]
    fn v1_flat_blob_is_rejected() {
        let err = match crate::crypto::EncryptedBlob::from_bytes(&[0u8; 56]) {
            Ok(_) => panic!("legacy v1 blob must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, FerusaError::UnsupportedVaultBlob { .. }));
        assert!(err.to_string().contains("legacy v1 blobs are unsupported"));
    }

    // ── correlation code ─────────────────────────────────────

    #[test]
    fn correlation_code_in_range() {
        for _ in 0..1000 {
            let code = random_correlation_code();
            assert!(code >= 1000, "code {code} < 1000");
            assert!(code <= 9999, "code {code} > 9999");
        }
    }

    #[test]
    fn correlation_codes_are_not_all_identical() {
        let codes: Vec<u16> = (0..20).map(|_| random_correlation_code()).collect();
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert!(unique.len() > 1, "all codes were identical — RNG is broken");
    }
}

#[cfg(test)]
mod transport_tests {
    use crate::auth::{
        AuthRequest, AuthResponse, PairingActivate, PairingActivateAck, PairingCommit,
        PairingCommitAck, PairingHello, PairingReady,
    };
    use crate::error::FerusaError;
    use crate::transport::FerusaMessage;
    use crate::types::VaultAction;
    use uuid::Uuid;

    fn sample_request() -> AuthRequest {
        AuthRequest {
            pairing_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            correlation_code: 1234,
            action: VaultAction::Read,
            entry_title: Some("GitHub".into()),
            unlock_share_requested: true,
            timestamp: 1_700_000_000_000,
        }
    }

    fn sample_response() -> AuthResponse {
        AuthResponse {
            pairing_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            correlation_code: 5678,
            action: VaultAction::Delete,
            approved: true,
            unlock_share: Some([0xCDu8; 32]),
            timestamp: 1_700_000_000_001,
            signature: vec![0xABu8; 64],
        }
    }

    #[test]
    fn encode_decode_pairing_hello_preserves_verification_code() {
        let msg = FerusaMessage::PairingHello(PairingHello {
            pairing_id: Uuid::new_v4(),
            approval_public_key_der: vec![1, 2, 3],
            phone_share: [0xAB; 32],
            verification_code: 7,
        });
        let bytes = msg.encode().unwrap();
        let decoded = FerusaMessage::decode(&bytes).unwrap();
        match decoded {
            FerusaMessage::PairingHello(hello) => {
                assert_eq!(hello.verification_code, 7);
                assert_eq!(hello.phone_share, [0xAB; 32]);
            }
            _ => panic!("expected PairingHello variant"),
        }
    }

    #[test]
    fn pairing_commit_protocol_messages_roundtrip() {
        let pairing_id = Uuid::new_v4();
        let messages = [
            FerusaMessage::PairingReady(PairingReady {
                pairing_id,
                signature: vec![1, 2, 3],
            }),
            FerusaMessage::PairingCommit(PairingCommit { pairing_id }),
            FerusaMessage::PairingCommitAck(PairingCommitAck { pairing_id }),
            FerusaMessage::PairingActivate(PairingActivate { pairing_id }),
            FerusaMessage::PairingActivateAck(PairingActivateAck { pairing_id }),
        ];

        for message in messages {
            let encoded = message.encode().unwrap();
            assert!(FerusaMessage::decode(&encoded).is_ok());
        }
    }

    #[test]
    fn pairing_protocol_uses_v5_alpn() {
        assert_eq!(crate::transport::FERUSA_ALPN, b"ferusa/auth/5");
    }

    #[test]
    fn encode_decode_request_roundtrip() {
        let msg = FerusaMessage::Request(sample_request());
        let bytes = msg.encode().unwrap();
        let decoded = FerusaMessage::decode(&bytes).unwrap();
        match decoded {
            FerusaMessage::Request(r) => {
                assert_eq!(r.correlation_code, 1234);
                assert_eq!(r.action, VaultAction::Read);
                assert_eq!(r.entry_title, Some("GitHub".into()));
                assert!(r.unlock_share_requested);
            }
            _ => panic!("expected Request variant"),
        }
    }

    #[test]
    fn encode_decode_response_roundtrip() {
        let msg = FerusaMessage::Response(sample_response());
        let bytes = msg.encode().unwrap();
        let decoded = FerusaMessage::decode(&bytes).unwrap();
        match decoded {
            FerusaMessage::Response(r) => {
                assert_eq!(r.correlation_code, 5678);
                assert!(r.approved);
                assert_eq!(r.unlock_share, Some([0xCDu8; 32]));
                assert_eq!(r.signature, vec![0xABu8; 64]);
            }
            _ => panic!("expected Response variant"),
        }
    }

    #[test]
    fn length_prefix_is_correct() {
        let msg = FerusaMessage::Request(sample_request());
        let bytes = msg.encode().unwrap();
        let declared_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(declared_len, bytes.len() - 4);
    }

    #[test]
    fn truncated_bytes_returns_error() {
        let msg = FerusaMessage::Request(sample_request());
        let bytes = msg.encode().unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        let err = FerusaMessage::decode(truncated).unwrap_err();
        assert!(matches!(
            err,
            FerusaError::MessageTruncated {
                expected: _,
                got: _
            }
        ));
        assert!(err.to_string().starts_with("message truncated: expected "));
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn overflowing_total_length_returns_error() {
        let err = FerusaMessage::decode(&u32::MAX.to_le_bytes()).unwrap_err();
        assert!(matches!(
            err,
            FerusaError::MessageTruncated {
                expected,
                got: 0
            } if expected == u32::MAX as usize
        ));
    }

    #[test]
    fn trailing_bytes_return_error() {
        let msg = FerusaMessage::Request(sample_request());
        let mut bytes = msg.encode().unwrap();
        let expected = bytes.len();
        bytes.extend_from_slice(b"extra");

        let err = FerusaMessage::decode(&bytes).unwrap_err();
        assert!(matches!(
            err,
            FerusaError::MessageTrailingBytes { expected: e, got: g }
                if e == expected && g == expected + 5
        ));
        assert!(
            err.to_string().starts_with("message has trailing bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn too_short_returns_error() {
        let err = FerusaMessage::decode(&[0x01, 0x00]).unwrap_err();
        assert!(matches!(err, FerusaError::MessageTooShort));
        assert_eq!(err.to_string(), "message too short");
    }

    #[test]
    fn invalid_json_returns_error() {
        let payload = b"not json";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);

        let err = FerusaMessage::decode(&bytes).unwrap_err();
        assert!(matches!(err, FerusaError::Json { .. }));
        assert!(!err.to_string().is_empty());
    }
}

#[cfg(test)]
mod error_tests {
    use crate::error::FerusaError;

    #[test]
    fn ferusa_error_messages_preserve_context() {
        let cases = [
            (
                FerusaError::Argon2Params {
                    details: "bad params".into(),
                },
                "argon2 params: bad params",
            ),
            (
                FerusaError::Argon2Hash {
                    details: "hash failed".into(),
                },
                "argon2 hash failed: hash failed",
            ),
            (
                FerusaError::HkdfExpandVaultKey {
                    details: "bad length".into(),
                },
                "hkdf expand vault_key: bad length",
            ),
            (
                FerusaError::HkdfExpandIrohHmac {
                    details: "bad length".into(),
                },
                "hkdf expand iroh_hmac: bad length",
            ),
            (
                FerusaError::BuildCipher {
                    details: "cipher error".into(),
                },
                "build cipher: cipher error",
            ),
            (
                FerusaError::Encrypt {
                    details: "encrypt error".into(),
                },
                "encrypt failed: encrypt error",
            ),
            (
                FerusaError::Decrypt {
                    details: "decrypt error".into(),
                },
                "decrypt failed (wrong key or tampered): decrypt error",
            ),
            (
                FerusaError::MessageTruncated {
                    expected: 10,
                    got: 3,
                },
                "message truncated: expected 10 payload bytes, got 3",
            ),
            (
                FerusaError::Json {
                    details: "json error".into(),
                },
                "json error",
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }
}

#[cfg(test)]
mod types_tests {
    use crate::types::{Entry, Vault, VaultAction, VAULT_VERSION};
    use uuid::Uuid;
    use zeroize::Zeroize;

    #[test]
    fn vault_default_is_empty() {
        let v = Vault::default();
        assert_eq!(v.version, VAULT_VERSION);
        assert!(v.entries.is_empty());
    }

    #[test]
    fn vault_serialise_roundtrip() {
        let mut vault = Vault::default();
        vault.entries.push(Entry {
            id: Uuid::new_v4(),
            title: "GitHub".into(),
            username: Some("alice".into()),
            password: "s3cr3t".into(),
            url: Some("https://github.com".into()),
            notes: None,
            tags: vec!["work".into()],
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
        });

        let json = serde_json::to_string(&vault).unwrap();
        let decoded: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].title, "GitHub");
        assert_eq!(decoded.entries[0].password, "s3cr3t");
    }

    #[test]
    fn vault_validation_rejects_unknown_schema_version() {
        let mut vault = Vault::default();
        vault.version = VAULT_VERSION + 1;
        assert!(vault.validate().is_err());
    }

    #[test]
    fn vault_zeroize_clears_plaintext_fields() {
        let mut vault = Vault::default();
        vault.entries.push(Entry {
            id: Uuid::new_v4(),
            title: "GitHub".into(),
            username: Some("alice".into()),
            password: "s3cr3t".into(),
            url: Some("https://github.com".into()),
            notes: Some("recovery codes".into()),
            tags: vec!["work".into()],
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
        });

        vault.zeroize();

        assert_eq!(vault.version, 0);
        assert!(vault.entries.is_empty());
    }

    #[test]
    fn vault_action_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&VaultAction::Unlock).unwrap(),
            r#""unlock""#
        );
        assert_eq!(
            serde_json::to_string(&VaultAction::List).unwrap(),
            r#""list""#
        );
        assert_eq!(
            serde_json::to_string(&VaultAction::Read).unwrap(),
            r#""read""#
        );
        assert_eq!(
            serde_json::to_string(&VaultAction::Create).unwrap(),
            r#""create""#
        );
        assert_eq!(
            serde_json::to_string(&VaultAction::Update).unwrap(),
            r#""update""#
        );
        assert_eq!(
            serde_json::to_string(&VaultAction::Delete).unwrap(),
            r#""delete""#
        );
        assert_eq!(
            serde_json::to_string(&VaultAction::Passwd).unwrap(),
            r#""passwd""#
        );
        assert_eq!(
            serde_json::to_string(&VaultAction::Pair).unwrap(),
            r#""pair""#
        );
    }

    #[test]
    fn vault_action_deserialises_lowercase() {
        let a: VaultAction = serde_json::from_str(r#""unlock""#).unwrap();
        assert_eq!(a, VaultAction::Unlock);

        let a: VaultAction = serde_json::from_str(r#""list""#).unwrap();
        assert_eq!(a, VaultAction::List);

        let a: VaultAction = serde_json::from_str(r#""read""#).unwrap();
        assert_eq!(a, VaultAction::Read);

        let a: VaultAction = serde_json::from_str(r#""passwd""#).unwrap();
        assert_eq!(a, VaultAction::Passwd);

        let a: VaultAction = serde_json::from_str(r#""pair""#).unwrap();
        assert_eq!(a, VaultAction::Pair);
    }
}

#[cfg(test)]
mod auth_tests {
    use crate::auth::{
        validate_auth_exchange_timestamps, validate_auth_timestamp, AuthRequest, AuthResponse,
        AuthTimestampError, AUTH_TIMESTAMP_MAX_SKEW_MS,
    };
    use crate::types::VaultAction;
    use uuid::Uuid;

    fn sample_exchange(now_ms: u64) -> (AuthRequest, AuthResponse) {
        let req = AuthRequest {
            pairing_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            correlation_code: 1234,
            action: VaultAction::Read,
            entry_title: None,
            unlock_share_requested: false,
            timestamp: now_ms,
        };
        let resp = AuthResponse {
            pairing_id: req.pairing_id,
            request_id: req.request_id,
            correlation_code: req.correlation_code,
            action: req.action,
            approved: true,
            unlock_share: None,
            timestamp: now_ms,
            signature: Vec::new(),
        };
        (req, resp)
    }

    #[test]
    fn auth_timestamp_accepts_values_inside_skew_window() {
        let now_ms = 1_700_000_000_000;

        assert!(validate_auth_timestamp(now_ms, now_ms).is_ok());
        assert!(validate_auth_timestamp(now_ms - AUTH_TIMESTAMP_MAX_SKEW_MS, now_ms).is_ok());
        assert!(validate_auth_timestamp(now_ms + AUTH_TIMESTAMP_MAX_SKEW_MS, now_ms).is_ok());
    }

    #[test]
    fn auth_timestamp_rejects_stale_and_future_values() {
        let now_ms = 1_700_000_000_000;

        assert!(matches!(
            validate_auth_timestamp(now_ms - AUTH_TIMESTAMP_MAX_SKEW_MS - 1, now_ms),
            Err(AuthTimestampError::TooOld { .. })
        ));
        assert!(matches!(
            validate_auth_timestamp(now_ms + AUTH_TIMESTAMP_MAX_SKEW_MS + 1, now_ms),
            Err(AuthTimestampError::TooFarInFuture { .. })
        ));
    }

    #[test]
    fn auth_exchange_validates_request_and_response_timestamps() {
        let now_ms = 1_700_000_000_000;
        let (mut req, mut resp) = sample_exchange(now_ms);

        assert!(validate_auth_exchange_timestamps(&req, &resp, now_ms).is_ok());

        req.timestamp = now_ms - AUTH_TIMESTAMP_MAX_SKEW_MS - 1;
        assert!(matches!(
            validate_auth_exchange_timestamps(&req, &resp, now_ms),
            Err(AuthTimestampError::TooOld { .. })
        ));

        req.timestamp = now_ms;
        resp.timestamp = now_ms + AUTH_TIMESTAMP_MAX_SKEW_MS + 1;
        assert!(matches!(
            validate_auth_exchange_timestamps(&req, &resp, now_ms),
            Err(AuthTimestampError::TooFarInFuture { .. })
        ));
    }
}

#[cfg(test)]
mod integration_tests {
    use crate::auth::{AuthRequest, AuthResponse};
    use crate::crypto::*;
    use crate::types::{Vault, VaultAction};
    use uuid::Uuid;

    const PHONE_SHARE: [u8; 32] = [0xA5; 32];

    #[test]
    fn full_vault_encrypt_decrypt() {
        let salt = new_salt();
        let local_secret = derive_local_secret(b"my_master_password", &salt).unwrap();
        let vault_key = combine_vault_key(&local_secret, &PHONE_SHARE).unwrap();

        let mut vault = Vault::default();
        vault.entries.push(crate::types::Entry {
            id: Uuid::new_v4(),
            title: "AWS".into(),
            username: Some("admin".into()),
            password: "correct_horse_battery_staple".into(),
            url: None,
            notes: None,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        });

        let plaintext = serde_json::to_vec(&vault).unwrap();
        let blob = encrypt_vault(&vault_key, salt, &plaintext).unwrap();
        let recovered = decrypt_vault(&vault_key, &blob).unwrap();
        let vault2: Vault = serde_json::from_slice(&recovered).unwrap();

        assert_eq!(vault2.entries[0].password, "correct_horse_battery_staple");
    }

    #[test]
    fn full_auth_response_sign_verify_tamper() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let public_key = ring::signature::KeyPair::public_key(&key_pair)
            .as_ref()
            .to_vec();

        let req = AuthRequest {
            pairing_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            correlation_code: 7777,
            action: VaultAction::Create,
            entry_title: Some("Secret".into()),
            unlock_share_requested: true,
            timestamp: 1_700_000_000_000,
        };
        let mut resp = AuthResponse {
            pairing_id: req.pairing_id,
            request_id: req.request_id,
            correlation_code: req.correlation_code,
            action: VaultAction::Create,
            approved: true,
            unlock_share: Some(PHONE_SHARE),
            timestamp: 1_700_000_000_000,
            signature: Vec::new(),
        };

        let payload = canonical_approval_payload(&req, &resp).unwrap();
        resp.signature = key_pair.sign(&rng, &payload).unwrap().as_ref().to_vec();
        assert!(
            verify_approval_signature(&public_key, &req, &resp),
            "valid response should verify"
        );

        resp.action = VaultAction::Delete;
        assert!(
            !verify_approval_signature(&public_key, &req, &resp),
            "tampered action should not verify"
        );
    }
}
