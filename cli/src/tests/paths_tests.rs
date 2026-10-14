#[cfg(test)]
mod tests {
    use crate::storage::paths::{write_private_file, PairingData, PairingStatus, Paths};
    use ferusa_core::crypto::{
        combine_vault_key, decrypt_vault, encrypt_vault, new_salt, EncryptedBlob,
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn paths_load_returns_ok() {
        let paths = Paths::load();
        assert!(paths.is_ok(), "Paths::load() failed: {:?}", paths.err());
    }

    #[test]
    fn vault_enc_is_inside_data_dir() {
        let paths = Paths::load().unwrap();
        assert!(paths.vault_enc.starts_with(&paths.data_dir));
        assert!(paths.vault_salt.starts_with(&paths.data_dir));
        assert!(paths.peer_id.starts_with(&paths.data_dir));
        assert!(paths.phone_id.starts_with(&paths.data_dir));
        assert!(paths.hmac_key.starts_with(&paths.data_dir));
    }

    #[test]
    fn vault_exists_false_when_files_absent() {
        let tmp = tempfile_paths();
        assert!(!tmp.vault_exists());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_data_dir_sets_private_permissions() {
        let tmp = tempfile_paths();
        tmp.ensure_data_dir().unwrap();

        let mode = std::fs::metadata(&tmp.data_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_sets_private_permissions() {
        let tmp = tempfile_paths();
        tmp.ensure_data_dir().unwrap();

        write_private_file(&tmp.hmac_key, &[7u8; 32]).unwrap();

        assert_eq!(std::fs::read(&tmp.hmac_key).unwrap(), [7u8; 32]);
        let mode = std::fs::metadata(&tmp.hmac_key)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn pairing_status_missing_phone_id_when_absent() {
        let tmp = tempfile_paths();
        assert_eq!(tmp.pairing_status(), PairingStatus::MissingPhoneId);
    }

    #[test]
    fn pairing_status_rejects_partial_legacy_phone_file() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();
        std::fs::write(&tmp.phone_id, "aabbcc").unwrap();

        assert!(matches!(
            tmp.pairing_status(),
            PairingStatus::InvalidPairing(_)
        ));
    }

    #[test]
    fn pairing_status_rejects_legacy_split_files() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();
        std::fs::write(&tmp.phone_id, "aabbcc").unwrap();
        std::fs::write(&tmp.hmac_key, [0u8; 32]).unwrap();

        assert!(matches!(
            tmp.pairing_status(),
            PairingStatus::InvalidPairing(_)
        ));
    }

    #[tokio::test]
    async fn pairing_status_rejects_any_legacy_hmac_file() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();

        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .unwrap();
        std::fs::write(&tmp.phone_id, hex::encode(endpoint.id().as_bytes())).unwrap();
        endpoint.close().await;

        std::fs::write(&tmp.hmac_key, [0u8; 31]).unwrap();

        assert!(matches!(
            tmp.pairing_status(),
            PairingStatus::InvalidPairing(_)
        ));
    }

    #[tokio::test]
    async fn pairing_status_rejects_valid_legacy_split_files() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();

        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .unwrap();
        std::fs::write(&tmp.phone_id, hex::encode(endpoint.id().as_bytes())).unwrap();
        endpoint.close().await;

        std::fs::write(&tmp.hmac_key, [0u8; 32]).unwrap();

        assert!(matches!(
            tmp.pairing_status(),
            PairingStatus::InvalidPairing(_)
        ));
    }

    #[tokio::test]
    async fn pairing_status_ready_with_atomic_pairing_state() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();

        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .unwrap();
        let phone = endpoint.id();
        endpoint.close().await;
        let pairing_id = uuid::Uuid::new_v4();
        let approval_public_key_der = vec![9u8; 65];

        tmp.write_pairing_data(&crate::storage::paths::PairingData {
            pairing_id,
            phone_node_id: phone,
            approval_public_key_der: approval_public_key_der.clone(),
            created_at_ms: 42,
            credential_revision: None,
        })
        .unwrap();

        assert_eq!(tmp.pairing_status(), PairingStatus::Ready);
        let pairing = tmp.read_pairing_data().unwrap();
        assert_eq!(pairing.pairing_id, pairing_id);
        assert_eq!(pairing.phone_node_id, phone);
        assert_eq!(pairing.approval_public_key_der, approval_public_key_der);
        assert!(tmp.pairing_state().exists());
        assert!(!tmp.phone_id.exists());
        assert!(!tmp.hmac_key.exists());
    }

    #[tokio::test]
    async fn prepared_pairing_transaction_recovery_keeps_old_live_generation() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();

        let old_pairing = pairing_data(1).await;
        let new_pairing = pairing_data(2).await;
        write_private_file(&tmp.vault_enc, b"old vault").unwrap();
        tmp.write_pairing_data(&old_pairing).unwrap();
        write_private_file(&tmp.pending_vault_enc(), b"new vault").unwrap();
        tmp.write_pending_pairing_data(&new_pairing).unwrap();
        tmp.write_pairing_transaction_prepared(new_pairing.pairing_id)
            .unwrap();

        tmp.recover_pairing_transaction().unwrap();

        assert_eq!(std::fs::read(&tmp.vault_enc).unwrap(), b"old vault");
        assert_eq!(
            tmp.read_pairing_data().unwrap().pairing_id,
            old_pairing.pairing_id
        );
        assert!(tmp.pending_vault_enc().exists());
        assert!(tmp.pending_pairing_state().exists());
        assert!(tmp.pairing_transaction_state().exists());
        assert_eq!(
            std::fs::read(tmp.rollback_vault_enc()).unwrap(),
            b"old vault"
        );
        assert!(tmp.rollback_pairing_state().exists());
    }

    #[tokio::test]
    async fn phone_committed_pairing_recovers_after_partial_vault_rename() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();

        let old_pairing = pairing_data(1).await;
        let new_pairing = pairing_data(2).await;
        write_private_file(&tmp.vault_enc, b"old vault").unwrap();
        tmp.write_pairing_data(&old_pairing).unwrap();
        write_private_file(&tmp.pending_vault_enc(), b"new vault").unwrap();
        tmp.write_pending_pairing_data(&new_pairing).unwrap();
        tmp.write_pairing_transaction_prepared(new_pairing.pairing_id)
            .unwrap();
        tmp.write_pairing_transaction_phone_committed(new_pairing.pairing_id)
            .unwrap();
        std::fs::rename(tmp.pending_vault_enc(), &tmp.vault_enc).unwrap();

        tmp.recover_pairing_transaction().unwrap();
        tmp.recover_pairing_transaction().unwrap();

        assert_eq!(std::fs::read(&tmp.vault_enc).unwrap(), b"new vault");
        assert_eq!(
            tmp.read_pairing_data().unwrap().pairing_id,
            new_pairing.pairing_id
        );
        assert!(!tmp.pending_pairing_state().exists());
        assert!(tmp.pairing_transaction_state().exists());
        assert!(tmp.rollback_vault_enc().exists());
        assert!(tmp.rollback_pairing_state().exists());

        tmp.write_pairing_transaction_fully_activated(new_pairing.pairing_id)
            .unwrap();
        tmp.recover_pairing_transaction().unwrap();
        assert!(!tmp.pairing_transaction_state().exists());
        assert!(!tmp.rollback_vault_enc().exists());
        assert!(!tmp.rollback_pairing_state().exists());
    }

    #[tokio::test]
    async fn replacement_restart_decrypts_existing_vault_with_new_phone_share() {
        let paths = tempfile_paths();
        std::fs::create_dir_all(&paths.data_dir).unwrap();

        let old_pairing = pairing_data(1).await;
        let new_pairing = pairing_data(2).await;
        let local_secret = [0x11; 32];
        let old_phone_share = [0x22; 32];
        let new_phone_share = [0x33; 32];
        let plaintext = br#"{"version":1,"entries":[{"title":"existing-secret"}]}"#;
        let salt = new_salt();
        let old_key = combine_vault_key(&local_secret, &old_phone_share).unwrap();
        let new_key = combine_vault_key(&local_secret, &new_phone_share).unwrap();

        let old_blob = encrypt_vault(&old_key, salt, plaintext).unwrap();
        write_private_file(&paths.vault_enc, &old_blob.to_bytes()).unwrap();
        paths.write_pairing_data(&old_pairing).unwrap();

        let new_blob = encrypt_vault(&new_key, salt, plaintext).unwrap();
        write_private_file(&paths.pending_vault_enc(), &new_blob.to_bytes()).unwrap();
        paths.write_pending_pairing_data(&new_pairing).unwrap();
        paths
            .write_pairing_transaction_prepared(new_pairing.pairing_id)
            .unwrap();

        paths.recover_pairing_transaction().unwrap();
        let still_old =
            EncryptedBlob::from_bytes(&std::fs::read(&paths.vault_enc).unwrap()).unwrap();
        assert_eq!(decrypt_vault(&old_key, &still_old).unwrap(), plaintext);

        paths
            .write_pairing_transaction_phone_committed(new_pairing.pairing_id)
            .unwrap();

        let restarted = paths_with_data_dir(paths.data_dir.clone());
        restarted.recover_pairing_transaction().unwrap();
        let activated =
            EncryptedBlob::from_bytes(&std::fs::read(&restarted.vault_enc).unwrap()).unwrap();
        assert_eq!(decrypt_vault(&new_key, &activated).unwrap(), plaintext);
        assert!(decrypt_vault(&old_key, &activated).is_err());
        assert_eq!(
            restarted.read_pairing_data().unwrap().pairing_id,
            new_pairing.pairing_id
        );

        restarted
            .write_pairing_transaction_fully_activated(new_pairing.pairing_id)
            .unwrap();
        restarted.recover_pairing_transaction().unwrap();
        assert!(!restarted.pairing_transaction_state().exists());
    }

    #[tokio::test]
    async fn phone_committed_pairing_refuses_activation_without_required_rollback() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();

        let old_pairing = pairing_data(1).await;
        let new_pairing = pairing_data(2).await;
        write_private_file(&tmp.vault_enc, b"old vault").unwrap();
        tmp.write_pairing_data(&old_pairing).unwrap();
        write_private_file(&tmp.pending_vault_enc(), b"new vault").unwrap();
        tmp.write_pending_pairing_data(&new_pairing).unwrap();
        tmp.write_pairing_transaction_prepared(new_pairing.pairing_id)
            .unwrap();
        tmp.write_pairing_transaction_phone_committed(new_pairing.pairing_id)
            .unwrap();
        std::fs::remove_file(tmp.rollback_vault_enc()).unwrap();

        assert!(tmp.recover_pairing_transaction().is_err());
        assert_eq!(std::fs::read(&tmp.vault_enc).unwrap(), b"old vault");
        assert!(tmp.pending_vault_enc().exists());
    }

    #[tokio::test]
    async fn stale_pending_pairing_without_transaction_is_cleared() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();

        tmp.write_pending_pairing_data(&pairing_data(3).await)
            .unwrap();
        write_private_file(&tmp.pending_vault_enc(), b"new vault").unwrap();

        tmp.recover_pairing_transaction().unwrap();

        assert!(!tmp.pending_pairing_state().exists());
        assert!(!tmp.pending_vault_enc().exists());
    }

    #[test]
    fn pairing_status_ignores_interrupted_atomic_pairing_temp_file() {
        let tmp = tempfile_paths();
        std::fs::create_dir_all(&tmp.data_dir).unwrap();
        std::fs::write(tmp.data_dir.join(".pairing.json.tmp-crash"), b"partial").unwrap();

        assert_eq!(tmp.pairing_status(), PairingStatus::MissingPhoneId);
        assert!(!tmp.pairing_state().exists());
    }

    #[test]
    fn dev_2fa_stub_marker_roundtrips() {
        let tmp = tempfile_paths();
        tmp.ensure_data_dir().unwrap();

        assert!(!tmp.has_dev_2fa_stub_marker());
        tmp.write_dev_2fa_stub_marker().unwrap();

        assert!(tmp.has_dev_2fa_stub_marker());
        let marker = tmp.read_dev_2fa_stub_marker().unwrap();
        assert_eq!(marker.version, 1);
        assert!(marker.warning.contains("not production-compatible"));
        tmp.ensure_dev_2fa_stub_marker().unwrap();
    }

    #[test]
    fn production_guard_rejects_dev_2fa_stub_marker() {
        let tmp = tempfile_paths();
        tmp.ensure_data_dir().unwrap();
        tmp.write_dev_2fa_stub_marker().unwrap();

        let err = tmp.ensure_not_dev_2fa_stub_vault().unwrap_err();
        assert!(err.to_string().contains("not production-compatible"));
    }

    #[test]
    fn dev_2fa_stub_marker_is_required_for_dev_share() {
        let tmp = tempfile_paths();
        tmp.ensure_data_dir().unwrap();

        let err = tmp.ensure_dev_2fa_stub_marker().unwrap_err();
        assert!(err.to_string().contains("marker missing"));
    }

    #[test]
    fn private_atomic_write_replaces_file_without_using_stale_temp() {
        let tmp = tempfile_paths();
        tmp.ensure_data_dir().unwrap();

        write_private_file(&tmp.vault_enc, b"old vault").unwrap();
        std::fs::write(
            tmp.data_dir.join(".vault.enc.tmp-stale"),
            b"partial new vault",
        )
        .unwrap();
        write_private_file(&tmp.vault_enc, b"new vault").unwrap();

        assert_eq!(std::fs::read(&tmp.vault_enc).unwrap(), b"new vault");
        assert_eq!(
            std::fs::read(tmp.data_dir.join(".vault.enc.tmp-stale")).unwrap(),
            b"partial new vault"
        );
    }

    fn tempfile_paths() -> Paths {
        let tmp = std::env::temp_dir().join(format!(
            "ferusa_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        paths_with_data_dir(tmp)
    }

    fn paths_with_data_dir(data_dir: std::path::PathBuf) -> Paths {
        Paths {
            vault_enc: data_dir.join("vault.enc"),
            vault_salt: data_dir.join("vault.salt"),
            peer_id: data_dir.join("peer.id"),
            phone_id: data_dir.join("phone.id"),
            hmac_key: data_dir.join("hmac.key"),
            clipboard_cmd: data_dir.join("clipboard.cmd"),
            data_dir,
        }
    }

    async fn pairing_data(byte: u8) -> PairingData {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await
            .unwrap();
        let phone = endpoint.id();
        endpoint.close().await;

        PairingData {
            pairing_id: uuid::Uuid::new_v4(),
            phone_node_id: phone,
            approval_public_key_der: vec![byte; 65],
            created_at_ms: byte as u64,
            credential_revision: None,
        }
    }
}
