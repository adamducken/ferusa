//! Candidate enrollment shared by setup, replacement, and offline restoration.
use super::pair::{begin_pair_with_phone, commit_and_activate_pairing, confirm_pairing_ready};
use crate::net::cli_peer::CliPeer;
use crate::session::{ensure_unlocked_for, lock_session, SharedState, UnlockStatus};
use crate::storage::external::ExternalDestination;
use crate::storage::paths::{PairingData, PairingTxnPhase, Paths};
use anyhow::{bail, Context, Result};
use ferusa_core::crypto::{combine_vault_key, derive_keys, new_salt, DerivedKeys};
use ferusa_core::recovery::RecoveryPurpose;
use ferusa_core::types::{Vault, VaultAction};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

pub fn recovery_directory(selected: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = selected {
        return Ok(path.to_path_buf());
    }
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        bail!("supply --recovery-dir DIR naming a mounted external USB directory");
    }
    print!("recovery USB directory: ");
    std::io::stdout().flush()?;
    let mut path = String::new();
    std::io::stdin().read_line(&mut path)?;
    let path = path.trim_end_matches(['\r', '\n']);
    if path.is_empty() || path.len() > 8192 {
        bail!("recovery directory missing or too long");
    }
    Ok(PathBuf::from(path))
}

pub async fn choose_master_password() -> Result<([u8; 16], DerivedKeys)> {
    tokio::task::spawn_blocking(|| {
        let first = Zeroizing::new(rpassword::prompt_password("new master password: ")?);
        crate::password::validate_master_password(&first)?;
        let second = Zeroizing::new(rpassword::prompt_password("confirm master password: ")?);
        if first.as_str() != second.as_str() {
            bail!("passwords do not match");
        }
        let salt = new_salt();
        let keys = derive_keys(first.as_bytes(), &salt)?;
        Ok((salt, keys))
    })
    .await
    .context("password derivation worker failed")?
}

fn matching_transaction(paths: &Paths, purpose: RecoveryPurpose) -> Result<bool> {
    if !paths.pairing_transaction_state().exists() {
        return Ok(false);
    }
    let txn = paths.read_pairing_transaction()?;
    if txn
        .recovery
        .as_ref()
        .is_none_or(|recovery| recovery.purpose != purpose)
    {
        bail!("another credential operation is pending; resume its original command");
    }
    if !paths.peer_id.is_file() {
        bail!("original target desktop identity is missing; refusing a different enrollment");
    }
    Ok(true)
}

pub async fn cmd_init_with_recovery(selected: Option<&Path>) -> Result<()> {
    let paths = Paths::load()?;
    paths.ensure_data_dir()?;
    let _lock = paths.acquire_vault_lock()?;
    paths.ensure_not_dev_2fa_stub_vault()?;
    let resume = matching_transaction(&paths, RecoveryPurpose::InitialSetup)?;
    if !resume && (paths.vault_exists() || super::pair::has_pairing_files(&paths)) {
        bail!(
            "vault or pairing already exists; use passwd, pair, or recover into a fresh directory"
        );
    }
    let to = recovery_directory(selected)?;
    ExternalDestination::open(&to, &paths.vault_enc, &[])?;
    let endpoint = Arc::new(CliPeer::init(&paths.peer_id).await?.into_endpoint());
    if !resume {
        paths.begin_credential_transaction(
            RecoveryPurpose::InitialSetup,
            *endpoint.id().as_bytes(),
            None,
        )?;
    }
    let result = enroll_vault(
        &paths,
        &to,
        Some(Zeroizing::new(Vault::default())),
        None,
        endpoint.clone(),
    )
    .await;
    endpoint.close().await;
    result?;
    println!("Vault initialized at {}. Safely eject and store the recovery drive separately from your phone, laptop, and vault backups.", paths.data_dir.display());
    println!("Configure a clipboard command with ferusa config set; then use ferusa add <title>.");
    Ok(())
}

pub async fn cmd_pair_with_recovery(state: SharedState, selected: Option<&Path>) -> Result<()> {
    let paths = Paths::load()?;
    let resume = matching_transaction(&paths, RecoveryPurpose::PairingChange)?;
    if !resume && !paths.has_pairing_data() {
        bail!("2FA unavailable: {}", paths.pairing_status());
    }
    let to = recovery_directory(selected)?;
    ExternalDestination::open(&to, &paths.vault_enc, &[])?;
    if resume {
        lock_session(&state).await;
        let _lock = paths.acquire_vault_lock()?;
        let endpoint = Arc::new(CliPeer::init(&paths.peer_id).await?.into_endpoint());
        paths.resume_candidate_preparation()?;
        let original = if paths.read_pairing_transaction()?.phase == PairingTxnPhase::Preparing {
            Some(open_original_for_change(&paths, endpoint.clone(), VaultAction::Pair).await?)
        } else {
            None
        };
        let (vault, factor) = match original {
            Some((vault, salt, local, _share)) => (Some(vault), Some((salt, local))),
            None => (None, None),
        };
        let result = enroll_vault(&paths, &to, vault, factor, endpoint.clone()).await;
        endpoint.close().await;
        result?;
    } else {
        let unlocked = ensure_unlocked_for(&state, &paths, VaultAction::Pair, None).await?;
        if matches!(unlocked, UnlockStatus::AlreadyUnlocked) {
            crate::twofa::dispatch::request_approval(&state, VaultAction::Pair, None).await?;
        }
        let (vault, local_secret, salt, endpoint) = {
            let guard = state.lock().await;
            let session = guard.as_ref().context("session locked")?;
            (
                Zeroizing::new(session.vault.clone()),
                Zeroizing::new(session.local_secret),
                session.vault_salt,
                session
                    .endpoint
                    .clone()
                    .context("real phone endpoint unavailable")?,
            )
        };
        paths.begin_credential_transaction(
            RecoveryPurpose::PairingChange,
            *endpoint.id().as_bytes(),
            None,
        )?;
        let result = enroll_vault(
            &paths,
            &to,
            Some(vault),
            Some((salt, local_secret)),
            endpoint.clone(),
        )
        .await;
        lock_session(&state).await;
        endpoint.close().await;
        result?;
    }
    println!("Replacement phone and recovery confirmed. Session locked.");
    historical_reminder();
    Ok(())
}

async fn open_original_for_change(
    paths: &Paths,
    endpoint: Arc<iroh::Endpoint>,
    action: VaultAction,
) -> Result<(
    Zeroizing<Vault>,
    [u8; 16],
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
)> {
    let pairing = paths.read_pairing_data()?;
    let share =
        Zeroizing::new(crate::twofa::request_unlock_share(endpoint, pairing, action, None).await?);
    let password = Zeroizing::new(rpassword::prompt_password("master password: ")?);
    let blob = crate::storage::vault::load_vault_blob(&paths.vault_enc)?;
    let salt = blob.salt();
    let keys = derive_keys(password.as_bytes(), &salt)?;
    let key = Zeroizing::new(combine_vault_key(&keys.local_secret, &share)?);
    let vault = Zeroizing::new(crate::storage::vault::decrypt_vault_blob(&blob, &key)?);
    Ok((vault, salt, Zeroizing::new(keys.local_secret), share))
}

pub async fn cmd_passwd_with_recovery(state: SharedState, selected: Option<&Path>) -> Result<()> {
    let paths = Paths::load()?;
    let resume = matching_transaction(&paths, RecoveryPurpose::PasswordChange)?;
    if !resume && !paths.has_pairing_data() {
        bail!("2FA unavailable: {}", paths.pairing_status());
    }
    let to = recovery_directory(selected)?;
    ExternalDestination::open(&to, &paths.vault_enc, &[])?;
    let (endpoint, vault, candidate_share, _lock) = if resume {
        lock_session(&state).await;
        let lock = paths.acquire_vault_lock()?;
        paths.recover_pairing_transaction()?;
        let endpoint = Arc::new(CliPeer::init(&paths.peer_id).await?.into_endpoint());
        paths.resume_candidate_preparation()?;
        let (vault, share) =
            if paths.read_pairing_transaction()?.phase == PairingTxnPhase::Preparing {
                let (vault, _salt, _local, share) =
                    open_original_for_change(&paths, endpoint.clone(), VaultAction::Passwd).await?;
                (Some(vault), Some(share))
            } else {
                (None, None)
            };
        (endpoint, vault, share, lock)
    } else {
        let status = ensure_unlocked_for(&state, &paths, VaultAction::Passwd, None).await?;
        if matches!(status, UnlockStatus::AlreadyUnlocked) {
            crate::twofa::dispatch::request_approval(&state, VaultAction::Passwd, None).await?;
        }
        let mut guard = state.lock().await;
        let session = guard.as_mut().context("session locked")?;
        let endpoint = session
            .endpoint
            .clone()
            .context("real phone endpoint unavailable")?;
        let vault = Zeroizing::new(session.vault.clone());
        let share = Zeroizing::new(session.phone_share);
        let lock = session
            .vault_lock
            .take()
            .context("session vault lock missing")?;
        drop(guard);
        paths.begin_credential_transaction(
            RecoveryPurpose::PasswordChange,
            *endpoint.id().as_bytes(),
            None,
        )?;
        (endpoint, Some(vault), Some(share), lock)
    };
    // Session cannot survive any candidate promotion or uncertain outcome.
    lock_session(&state).await;
    let result = async {
        let txn = paths.read_pairing_transaction()?;
        if txn.phase == PairingTxnPhase::FullyActivated {
            return paths.complete_credential_transaction();
        }
        if txn.phase == PairingTxnPhase::Preparing {
            let (salt, keys) = choose_master_password().await?;
            let mut pairing = paths.read_pairing_data()?;
            pairing.credential_revision = Some(txn.recovery.as_ref().unwrap().credential_revision);
            paths.record_candidate_pairing(&pairing)?;
            // The ordinary password-change approval permits preparing ciphertext.
            // Recovery extraction still requires its own fresh consent and both PINs.
            let share = candidate_share.context("authorized candidate share unavailable")?;
            let key = Zeroizing::new(combine_vault_key(&keys.local_secret, &share)?);
            let vault = vault.context("original vault unavailable")?;
            paths.prepare_candidate_vault(
                &crate::storage::vault::encrypt_vault_blob(&vault, &key, salt)?.to_bytes(),
            )?;
        }
        super::recovery::create_password_candidate(&paths, &to, &endpoint).await?;
        if paths.read_pairing_transaction()?.phase == PairingTxnPhase::RecoveryVerified {
            paths.record_commit_intent()?;
        }
        paths.recover_pairing_transaction()?;
        paths.write_pairing_transaction_fully_activated(
            paths.read_pairing_transaction()?.pairing_id,
        )?;
        paths.complete_credential_transaction()
    }
    .await;
    endpoint.close().await;
    result.context(
        "password change incomplete; resume ferusa passwd with the original recovery directory",
    )?;
    println!("Password changed, matching recovery confirmed, session locked.");
    historical_reminder();
    Ok(())
}

pub async fn enroll_vault(
    paths: &Paths,
    to: &Path,
    vault: Option<Zeroizing<Vault>>,
    selected_factor: Option<([u8; 16], Zeroizing<[u8; 32]>)>,
    endpoint: Arc<iroh::Endpoint>,
) -> Result<()> {
    paths.recover_pairing_transaction()?;
    let txn = paths.read_pairing_transaction()?;
    if txn.phase == PairingTxnPhase::FullyActivated {
        return paths.complete_credential_transaction();
    }
    let recovery = txn
        .recovery
        .as_ref()
        .context("mandatory recovery journal missing")?;
    if recovery.desktop_id != *endpoint.id().as_bytes() {
        bail!("target desktop identity changed");
    }
    paths.resume_candidate_preparation()?;
    let prepared = paths.read_pairing_transaction()?.phase != PairingTxnPhase::Preparing;
    let factor = if prepared {
        None
    } else {
        Some(match selected_factor {
            Some(factor) => factor,
            None => {
                let (salt, keys) = choose_master_password().await?;
                (salt, Zeroizing::new(keys.local_secret))
            }
        })
    };
    let exchange = begin_pair_with_phone(paths, endpoint).await?;
    let pairing = if prepared {
        paths.transaction_pairing()?
    } else {
        let pairing = PairingData {
            pairing_id: exchange.secrets.pairing_id,
            phone_node_id: exchange.secrets.phone_node_id,
            approval_public_key_der: exchange.secrets.approval_public_key_der.clone(),
            created_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as u64,
            credential_revision: Some(recovery.credential_revision),
        };
        paths.record_candidate_pairing(&pairing)?;
        let (salt, local) = factor.context("candidate password factor missing")?;
        let share = Zeroizing::new(exchange.secrets.phone_share);
        let vault = vault
            .context("candidate plaintext unavailable; resume with original recovery sources")?;
        let bytes = tokio::task::spawn_blocking(move || -> Result<_> {
            let key = Zeroizing::new(combine_vault_key(&local, &share)?);
            Ok(crate::storage::vault::encrypt_vault_blob(&vault, &key, salt)?.to_bytes())
        })
        .await??;
        paths.prepare_candidate_vault(&bytes)?;
        pairing
    };
    let mut transport = confirm_pairing_ready(exchange.transport, &pairing, paths).await?;
    super::recovery::create_candidate(paths, to, &mut transport).await?;
    commit_and_activate_pairing(paths, transport, pairing.pairing_id)
        .await
        .context("credential outcome incomplete; retain target state and resume the same command")
}

pub fn historical_reminder() {
    println!("Safely eject and store the recovery drive in a secure location, separate from your phone, laptop, and vault backups. Do not carry it around with your phone.");
    println!("Refresh your recovery file when your master password or either phone PIN changes. Older copies still require the password and PINs used when they were created; changing your credentials does not revoke those copies.");
}
