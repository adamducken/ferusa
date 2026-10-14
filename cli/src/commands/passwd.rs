use crate::session::SharedState;
use anyhow::Result;
#[cfg(any(test, feature = "dev-2fa-stub"))]
mod legacy {
    #[cfg(feature = "dev-2fa-stub")]
    use std::io::ErrorKind;
    use std::path::Path;

    #[cfg(any(test, feature = "dev-2fa-stub"))]
    use anyhow::bail;
    use anyhow::{Context, Result};
    #[cfg(feature = "dev-2fa-stub")]
    use log::debug;
    #[cfg(feature = "dev-2fa-stub")]
    use log::info;
    use log::warn;

    use ferusa_core::crypto::{combine_vault_key, encrypt_vault, DerivedKeys};
    #[cfg(feature = "dev-2fa-stub")]
    use ferusa_core::crypto::{derive_keys, new_salt};
    #[cfg(feature = "dev-2fa-stub")]
    use ferusa_core::types::VaultAction;
    use zeroize::{Zeroize, Zeroizing};

    use crate::interface::ui;
    #[cfg(feature = "dev-2fa-stub")]
    use crate::password::validate_master_password;
    use crate::session::SharedState;
    #[cfg(feature = "dev-2fa-stub")]
    use crate::session::{ensure_unlocked_for, lock_session, UnlockStatus};
    use crate::storage::paths::{write_private_file, Paths};
    #[cfg(feature = "dev-2fa-stub")]
    use crate::twofa::dispatch::request_approval;

    #[cfg(feature = "dev-2fa-stub")]
    fn remove_legacy_vault_salt(paths: &Paths) -> Result<()> {
        match std::fs::remove_file(&paths.vault_salt) {
            Ok(()) => debug!("[ferusa:cli]: cmd_passwd removed legacy vault.salt"),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) if e.kind() == ErrorKind::IsADirectory => {
                warn!(
                "[ferusa:cli]: cmd_passwd legacy vault.salt path is not a file; leaving it in place"
            );
            }
            Err(e) => return Err(e).with_context(|| format!("remove {:?}", paths.vault_salt)),
        }
        Ok(())
    }

    async fn rotate_vault(
        state: &SharedState,
        paths: &Paths,
        new_keys: &DerivedKeys,
        new_salt: [u8; 16],
        write: impl FnOnce(&Path, &[u8]) -> Result<()>,
        cleanup: impl FnOnce(&Paths) -> Result<()>,
    ) -> Result<()> {
        let mut guard = state.lock().await;
        let s = guard.as_mut().context("session not unlocked")?;
        let new_vault_key = combine_vault_key(&new_keys.local_secret, &s.phone_share)
            .context("combine vault key")?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&s.vault).context("serialize vault")?);
        let blob = encrypt_vault(&new_vault_key, new_salt, plaintext.as_slice())
            .context("encrypt vault")?;

        if let Err(error) = write(&paths.vault_enc, &blob.to_bytes()) {
            // Rename may already have committed. Never let another command save with
            // the old key; drop secrets and the vault lock before awaiting shutdown.
            let stale_conn = s.phone_conn.take();
            *guard = None;
            drop(guard);
            if let Some(conn) = stale_conn {
                conn.close().await;
            }
            return Err(error).context(
            "write vault.enc: password change outcome uncertain; session locked, unlock again to verify the password",
        );
        }

        s.local_secret.zeroize();
        s.vault_key.zeroize();
        s.local_secret = new_keys.local_secret;
        s.vault_key = new_vault_key;
        s.vault_salt = new_salt;
        if let Err(error) = cleanup(paths) {
            warn!("[ferusa:cli]: password changed; legacy vault.salt cleanup failed: {error:#}");
            ui::info("password changed; could not remove obsolete vault.salt");
        }
        Ok(())
    }

    #[cfg(feature = "dev-2fa-stub")]
    pub async fn cmd_passwd(state: SharedState) -> Result<()> {
        info!("[ferusa:cli]: cmd_passwd start");

        let paths = Paths::load()?;
        debug!("[ferusa:cli]: cmd_passwd paths loaded");

        let unlock_status = ensure_unlocked_for(&state, &paths, VaultAction::Passwd, None)
            .await
            .map_err(|e| {
                ui::failed("could not unlock vault");
                e
            })?;
        debug!("[ferusa:cli]: cmd_passwd vault unlocked");

        println!();
        ui::info("changing master password requires 2FA approval");
        if matches!(unlock_status, UnlockStatus::AlreadyUnlocked) {
            ui::execute("requesting 2FA approval for CHANGE_PASSWORD");
            request_approval(&state, VaultAction::Passwd, None)
                .await
                .map_err(|e| {
                    ui::failed("2FA approval failed or was denied");
                    e
                })?;
            ui::success("2FA approved");
        }
        println!();

        // — collect and validate new password —
        ui::input("provide new master password");
        let pw1 = Zeroizing::new(
            rpassword::prompt_password("new master password: ").context("read new password")?,
        );

        if let Err(e) = validate_master_password(&pw1) {
            ui::failed(&e.to_string());
            warn!(
                "[ferusa:cli]: cmd_passwd new password rejected ({}) characters",
                pw1.chars().count()
            );
            return Err(e);
        }

        let pw2 = Zeroizing::new(
            rpassword::prompt_password("confirm new master password: ")
                .context("confirm new password")?,
        );

        if pw1.as_str() != pw2.as_str() {
            ui::failed("passwords do not match");
            warn!("[ferusa:cli]: cmd_passwd confirmation mismatch");
            bail!("passwords do not match");
        }
        debug!("[ferusa:cli]: cmd_passwd new password confirmed");

        // — derive new keys —
        ui::execute("deriving new keys");
        let new_salt = new_salt();
        let new_keys = derive_keys(pw1.as_bytes(), &new_salt).context("key derivation")?;
        drop(pw1);
        drop(pw2);
        debug!("[ferusa:cli]: cmd_passwd new keys derived");

        // — re-encrypt and write vault —
        ui::execute("re-encrypting vault with new key");
        rotate_vault(
            &state,
            &paths,
            &new_keys,
            new_salt,
            write_private_file,
            remove_legacy_vault_salt,
        )
        .await?;
        ui::success("vault re-encrypted and saved");

        let stale_conn = {
            let mut guard = state.lock().await;
            guard.as_mut().and_then(|s| s.phone_conn.take())
        };
        if let Some(conn) = stale_conn {
            conn.close().await;
            debug!("[ferusa:cli]: cmd_passwd stale phone connection closed");
        }

        // — lock session —
        ui::execute("locking session");
        lock_session(&state).await;
        info!("[ferusa:cli]: cmd_passwd password changed, session locked");

        println!();
        ui::success("password changed — vault re-encrypted");
        ui::info("phone pairing preserved");

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::session::{save_vault, SessionState};
        use ferusa_core::crypto::{decrypt_vault, EncryptedBlob};
        use ferusa_core::types::Vault;
        use std::io::ErrorKind;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        fn fixture() -> (tempfile::TempDir, Paths, SharedState) {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path();
            let paths = Paths {
                data_dir: p.to_path_buf(),
                vault_enc: p.join("vault.enc"),
                vault_salt: p.join("vault.salt"),
                peer_id: p.join("peer.id"),
                phone_id: p.join("phone.id"),
                hmac_key: p.join("hmac.key"),
                clipboard_cmd: p.join("clipboard.cmd"),
            };
            let session = SessionState {
                vault: Vault::default(),
                local_secret: [1; 32],
                vault_key: combine_vault_key(&[1; 32], &[2; 32]).unwrap(),
                phone_share: [2; 32],
                vault_salt: [3; 16],
                pairing: None,
                pending_requests: Default::default(),
                endpoint: None,
                phone_conn: None,
                vault_lock: Some(paths.acquire_vault_lock().unwrap()),
            };
            let blob = encrypt_vault(
                &session.vault_key,
                session.vault_salt,
                &serde_json::to_vec(&session.vault).unwrap(),
            )
            .unwrap();
            write_private_file(&paths.vault_enc, &blob.to_bytes()).unwrap();
            (dir, paths, Arc::new(Mutex::new(Some(session))))
        }

        fn assert_rotated(paths: &Paths) {
            let bytes = std::fs::read(&paths.vault_enc).unwrap();
            let blob = EncryptedBlob::from_bytes(&bytes).unwrap();
            assert_eq!(blob.salt(), [5; 16]);
            assert!(decrypt_vault(&combine_vault_key(&[4; 32], &[2; 32]).unwrap(), &blob).is_ok());
            assert!(decrypt_vault(&combine_vault_key(&[1; 32], &[2; 32]).unwrap(), &blob).is_err());
        }

        #[tokio::test]
        async fn cleanup_failure_keeps_rotated_session_keys() {
            let (_dir, paths, state) = fixture();
            rotate_vault(
                &state,
                &paths,
                &DerivedKeys {
                    local_secret: [4; 32],
                },
                [5; 16],
                write_private_file,
                |_| Err(std::io::Error::from(ErrorKind::PermissionDenied).into()),
            )
            .await
            .unwrap();
            {
                let guard = state.lock().await;
                let session = guard.as_ref().unwrap();
                assert_eq!(session.local_secret, [4; 32]);
                assert_eq!(session.vault_salt, [5; 16]);
            }
            save_vault(&state, &paths).await.unwrap();
            assert_rotated(&paths);
        }

        #[tokio::test]
        async fn post_replacement_sync_error_locks_session_and_releases_vault_lock() {
            let (_dir, paths, state) = fixture();
            let result = rotate_vault(
                &state,
                &paths,
                &DerivedKeys {
                    local_secret: [4; 32],
                },
                [5; 16],
                |path, bytes| {
                    write_private_file(path, bytes)?;
                    // Model a parent-directory sync error after the rename committed.
                    bail!("injected parent-directory sync failure")
                },
                |_| panic!("cleanup must not run after an uncertain write"),
            )
            .await;
            assert!(result.unwrap_err().to_string().contains("session locked"));
            assert!(state.lock().await.is_none());
            assert!(save_vault(&state, &paths).await.is_err());
            assert_rotated(&paths);
            let _lock = paths.acquire_vault_lock().unwrap();
        }
    }
}
#[cfg(feature = "dev-2fa-stub")]
pub use legacy::cmd_passwd;

#[cfg(all(target_os = "linux", not(feature = "dev-2fa-stub")))]
pub async fn cmd_passwd(state: SharedState) -> Result<()> {
    super::enroll::cmd_passwd_with_recovery(state, None).await
}

pub async fn cmd_passwd_with_recovery(
    state: SharedState,
    selected: Option<&std::path::Path>,
) -> Result<()> {
    #[cfg(feature = "dev-2fa-stub")]
    {
        let _ = selected;
        return cmd_passwd(state).await;
    }
    #[cfg(all(target_os = "linux", not(feature = "dev-2fa-stub")))]
    {
        super::enroll::cmd_passwd_with_recovery(state, selected).await
    }
    #[cfg(all(not(target_os = "linux"), not(feature = "dev-2fa-stub")))]
    {
        anyhow::bail!("mandatory recovery requires the Linux storage topology resolver")
    }
}

#[cfg(all(not(target_os = "linux"), not(feature = "dev-2fa-stub")))]
pub async fn cmd_passwd(state: SharedState) -> Result<()> {
    cmd_passwd_with_recovery(state, None).await
}
