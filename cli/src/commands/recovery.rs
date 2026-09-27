#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use anyhow::{bail, Context, Result};
    use ferusa_core::auth::validate_auth_timestamp;
    use ferusa_core::recovery::{
        canonical_recovery_authorized, canonical_recovery_consent, canonical_recovery_finished,
        checked_recovery_frame_len, recovery_file_digest, recovery_vault_digest,
        validate_recovery_envelope, verify_recovery_signature, RecoveryBegin, RecoveryContext,
        RecoveryFinish, RecoveryFinished, RecoveryMaterial, RecoveryPins, RecoveryPurpose,
        MAX_RECOVERY_PASSWORD_BYTES,
    };
    use ferusa_core::transport::{FerusaMessage, FERUSA_ALPN};
    use iroh::EndpointAddr;
    use rand::{Rng, RngCore};
    use serde::Serialize;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use ferusa_core::crypto::EncryptedBlob;
    use ferusa_core::recovery::{open_recovery, seal_recovery, RECOVERY_FILE_LEN};
    use ferusa_core::types::Vault;

    use crate::net::cli_peer::CliPeer;
    use crate::storage::external::{
        open_no_symlinks, require_separate_sources, ExternalDestination,
    };
    use crate::storage::paths::{write_private_file, Paths};
    use crate::storage::vault::{open_vault_with_share, read_vault_blob};

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn check_response_context(
        actual: &RecoveryContext,
        expected: &RecoveryBegin,
        desktop_id: [u8; 32],
    ) -> Result<()> {
        actual.validate()?;
        if actual.begin != *expected || actual.desktop_id != desktop_id {
            bail!("phone recovery response does not match the requested operation");
        }
        Ok(())
    }

    async fn send_frame(
        send: &mut iroh::endpoint::SendStream,
        message: FerusaMessage,
        deadline: Instant,
    ) -> Result<()> {
        let bytes = message.encode()?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("recovery request expired");
        }
        tokio::time::timeout(
            remaining.min(Duration::from_secs(10)),
            send.write_all(&bytes),
        )
        .await
        .context("recovery write timed out")??;
        Ok(())
    }

    async fn recv_frame(
        recv: &mut iroh::endpoint::RecvStream,
        deadline: Instant,
    ) -> Result<FerusaMessage> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("recovery request expired");
        }
        let mut header = [0u8; 4];
        tokio::time::timeout(remaining, recv.read_exact(&mut header[..1]))
            .await
            .context("timed out waiting for phone recovery frame")?
            .context("read first recovery byte")?;
        tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(10)),
            async {
                recv.read_exact(&mut header[1..])
                    .await
                    .context("read recovery header")?;
                let len = checked_recovery_frame_len(header)?;
                let mut frame = Zeroizing::new(vec![0u8; len + 4]);
                frame[..4].copy_from_slice(&header);
                recv.read_exact(&mut frame[4..])
                    .await
                    .context("read recovery payload")?;
                FerusaMessage::decode(&frame).map_err(anyhow::Error::from)
            },
        )
        .await
        .context("recovery frame transfer timed out")?
    }

    #[derive(Serialize)]
    struct RecoveryCompletion<'a> {
        version: u8,
        pairing_id: Uuid,
        credential_revision: Uuid,
        vault_digest: [u8; 32],
        file_id: Uuid,
        envelope_digest: [u8; 32],
        finished: &'a RecoveryFinished,
    }

    pub async fn cmd_create(to: &Path) -> Result<()> {
        create_or_confirm(Some(to), None).await
    }

    pub async fn cmd_confirm(from: &Path) -> Result<()> {
        create_or_confirm(None, Some(from)).await
    }

    async fn create_or_confirm(to: Option<&Path>, from: Option<&Path>) -> Result<()> {
        let paths = Paths::load()?;
        paths.ensure_not_dev_2fa_stub_vault()?;
        if paths.pairing_transaction_state().exists() {
            bail!("finish the pending pairing transaction before creating recovery material");
        }
        if !paths.peer_id.exists() {
            bail!("desktop pairing identity is missing");
        }
        let _vault_lock = paths
            .acquire_vault_lock()
            .context("lock vault for recovery creation")?;
        let pairing = paths.read_pairing_data().context("load active pairing")?;
        let vault_file = open_no_symlinks(&paths.vault_enc, false)?;
        let blob = read_vault_blob(&vault_file)?;
        let vault_digest = recovery_vault_digest(&blob.to_bytes());
        let (destination, existing) = if let Some(from) = from {
            let parent = from
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let destination = ExternalDestination::open(parent, &paths.vault_enc, &[])
                .context("validate recovery file's external device")?;
            let file = open_no_symlinks(from, false)?;
            require_separate_sources(&file, &vault_file)?;
            let bytes = read_exact_recovery(&file)?;
            validate_recovery_envelope(&bytes)?;
            (destination, Some((from.to_path_buf(), file, bytes)))
        } else {
            let directory = to.context("recovery destination missing")?;
            (
                ExternalDestination::open(directory, &paths.vault_enc, &[])
                    .context("validate external recovery destination")?,
                None,
            )
        };
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let planned_file_id = existing.is_none().then(Uuid::new_v4);
        let expected_envelope_digest = existing
            .as_ref()
            .map(|(_, _, bytes)| recovery_file_digest(bytes));
        let begin = RecoveryBegin {
            request_id: Uuid::new_v4(),
            pairing_id: pairing.pairing_id,
            purpose: if existing.is_some() {
                RecoveryPurpose::ConfirmExisting
            } else {
                RecoveryPurpose::Create
            },
            transaction_id: None,
            credential_revision: Uuid::new_v4(),
            file_id: planned_file_id,
            expected_envelope_digest,
            vault_digest,
            nonce,
            correlation_code: rand::rng().random_range(1000..=9999),
            timestamp_ms: now_ms(),
        };
        begin.validate()?;
        println!("This recovery file can replace your phone when used with your master password and both phone PINs. Keep it in a secure location, separate from your phone, laptop, and vault backups. Do not carry it around with your phone. Anyone who copies it can attempt to guess those credentials without your phone's biometric checks or PIN attempt limits.");
        println!("You also need your encrypted vault to recover your passwords. This recovery drive contains no vault data. If you lose the vault and have no separate backup, this file cannot restore it.");
        println!(
            "Match correlation code {:04} on your phone and approve this recovery request.",
            begin.correlation_code
        );
        let peer = CliPeer::init(&paths.peer_id).await?;
        let desktop_id = *peer.endpoint.id().as_bytes();
        let conn = tokio::time::timeout(
            Duration::from_secs(15),
            peer.endpoint
                .connect(EndpointAddr::new(pairing.phone_node_id), FERUSA_ALPN),
        )
        .await
        .context("timed out connecting to paired phone")??;
        let (mut send, mut recv) = conn.open_bi().await.context("open recovery stream")?;
        let deadline = Instant::now() + Duration::from_secs(70);
        send_frame(
            &mut send,
            FerusaMessage::RecoveryBegin(begin.clone()),
            deadline,
        )
        .await?;
        let consent = match recv_frame(&mut recv, deadline).await? {
            FerusaMessage::RecoveryConsent(value) => value,
            FerusaMessage::RecoveryRejected(value) => {
                bail!("phone rejected recovery: {:?}", value.code)
            }
            _ => bail!("phone did not send recovery consent"),
        };
        check_response_context(&consent.context, &begin, desktop_id)?;
        validate_auth_timestamp(consent.timestamp_ms, now_ms())?;
        if !verify_recovery_signature(
            &pairing.approval_public_key_der,
            &canonical_recovery_consent(&consent)?,
            &consent.signature,
        ) {
            bail!("phone recovery consent signature invalid");
        }
        let (password, pin4, pin6) = prompt_credentials()?;
        if password.len() > MAX_RECOVERY_PASSWORD_BYTES {
            bail!("master password exceeds recovery input limit");
        }
        let pins = RecoveryPins {
            instance_id: consent.context.instance_id,
            request_id: begin.request_id,
            challenge: consent.context.phone_challenge,
            pin4: pin4.to_string(),
            pin6: pin6.to_string(),
        };
        send_frame(&mut send, FerusaMessage::RecoveryPins(pins), deadline).await?;
        let authorized = match recv_frame(&mut recv, deadline).await? {
            FerusaMessage::RecoveryAuthorized(value) => value,
            FerusaMessage::RecoveryRejected(value) => {
                bail!("phone rejected recovery: {:?}", value.code)
            }
            _ => bail!("phone did not authorize recovery"),
        };
        if authorized.context != consent.context {
            bail!("recovery authorization context changed");
        }
        validate_auth_timestamp(authorized.timestamp_ms, now_ms())?;
        if !verify_recovery_signature(
            &pairing.approval_public_key_der,
            &canonical_recovery_authorized(&authorized)?,
            &authorized.signature,
        ) {
            bail!("phone recovery authorization signature invalid");
        }
        let vault = Zeroizing::new(
            open_vault_with_share(&blob, password.as_bytes(), &authorized.phone_share).context(
                "master password does not open current vault with authorized phone share",
            )?,
        );
        drop(vault);
        let (written, readback) = if let Some((path, original, bytes)) = existing {
            let reopened = open_no_symlinks(&path, false)?;
            let first = original.metadata()?;
            let second = reopened.metadata()?;
            if first.dev() != second.dev() || first.ino() != second.ino() {
                bail!("recovery file changed during phone confirmation");
            }
            let readback = read_exact_recovery(&reopened)?;
            if readback != bytes {
                bail!("recovery file changed during phone confirmation");
            }
            require_separate_sources(&reopened, &vault_file)?;
            (path, readback)
        } else {
            let file_id = planned_file_id.context("new recovery file ID missing")?;
            let material = RecoveryMaterial {
                file_id,
                created_at_ms: now_ms(),
                pairing_id: pairing.pairing_id,
                phone_share: Zeroizing::new(authorized.phone_share),
            };
            let envelope = seal_recovery(&material, password.as_bytes(), &pin4, &pin6)?;
            let written = destination
                .write_recovery(file_id, &envelope)
                .context("write recovery file; any partial file remains unverified")?;
            let reopened = open_no_symlinks(&written, false)?;
            (written, read_exact_recovery(&reopened)?)
        };
        let opened = open_recovery(&readback, password.as_bytes(), &pin4, &pin6)?;
        let file_id = opened.file_id;
        if planned_file_id.is_some_and(|id| id != file_id)
            || opened.pairing_id != pairing.pairing_id
            || *opened.phone_share != authorized.phone_share
        {
            bail!("recovery file read-back does not match authorization");
        }
        let vault = Zeroizing::new(open_vault_with_share(
            &blob,
            password.as_bytes(),
            &opened.phone_share,
        )?);
        drop(vault);
        destination.revalidate()?;
        let envelope_digest = recovery_file_digest(&readback);
        let finish = RecoveryFinish {
            instance_id: consent.context.instance_id,
            request_id: begin.request_id,
            challenge: consent.context.phone_challenge,
            file_id,
            envelope_digest,
        };
        if let Err(error) =
            send_frame(&mut send, FerusaMessage::RecoveryFinish(finish), deadline).await
        {
            return Err(error).context(
                "recovery file written; creation not confirmed. Reconnect your phone and verify",
            );
        }
        let finished = match recv_frame(&mut recv, deadline).await {
            Ok(FerusaMessage::RecoveryFinished(value)) => value,
            Ok(FerusaMessage::RecoveryRejected(value)) => {
                bail!("phone rejected recovery finish: {:?}", value.code)
            }
            Ok(_) => bail!("recovery file written; phone confirmation was unexpected"),
            Err(error) => return Err(error).context(
                "recovery file written; creation not confirmed. Reconnect your phone and verify",
            ),
        };
        if finished.context != consent.context
            || finished.file_id != file_id
            || finished.envelope_digest != envelope_digest
        {
            bail!("recovery file written; phone confirmation does not match exact file");
        }
        validate_auth_timestamp(finished.timestamp_ms, now_ms())?;
        if !verify_recovery_signature(
            &pairing.approval_public_key_der,
            &canonical_recovery_finished(&finished)?,
            &finished.signature,
        ) {
            bail!("recovery file written; phone confirmation signature invalid");
        }
        destination.revalidate()?;
        let completion = RecoveryCompletion {
            version: 1,
            pairing_id: pairing.pairing_id,
            credential_revision: begin.credential_revision,
            vault_digest,
            file_id,
            envelope_digest,
            finished: &finished,
        };
        write_private_file(
            &paths.data_dir.join("recovery.json"),
            &serde_json::to_vec(&completion)?,
        )
        .context("recovery file usable, but completion metadata could not be saved")?;
        conn.close(0u32.into(), b"recovery confirmed");
        peer.close().await;
        println!("Recovery file confirmed at {}. Safely eject and store the drive separately from your phone and laptop.", written.display());
        Ok(())
    }

    fn read_exact_recovery(file: &File) -> Result<[u8; RECOVERY_FILE_LEN]> {
        let before = file.metadata().context("stat recovery file")?;
        if !before.is_file() || before.len() != RECOVERY_FILE_LEN as u64 {
            bail!("recovery file must be exactly {RECOVERY_FILE_LEN} bytes");
        }
        let mut bytes = [0u8; RECOVERY_FILE_LEN];
        (&*file)
            .read_exact(&mut bytes)
            .context("read recovery file")?;
        let mut extra = [0u8; 1];
        if (&*file).read(&mut extra)? != 0 {
            bail!("recovery file has trailing data");
        }
        let after = file.metadata().context("stat recovery file after read")?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            bail!("recovery file changed while reading");
        }
        Ok(bytes)
    }

    fn prompt_credentials() -> Result<(Zeroizing<String>, Zeroizing<String>, Zeroizing<String>)> {
        let password = Zeroizing::new(rpassword::prompt_password(
            "recovery-file master password: ",
        )?);
        let pin4 = Zeroizing::new(rpassword::prompt_password("phone PIN 1 (4 digits): ")?);
        let pin6 = Zeroizing::new(rpassword::prompt_password("phone PIN 2 (6 digits): ")?);
        Ok((password, pin4, pin6))
    }

    fn authenticate_vault(
        blob: &EncryptedBlob,
        material: &RecoveryMaterial,
        password: &[u8],
    ) -> Result<Zeroizing<Vault>> {
        open_vault_with_share(blob, password, &material.phone_share).map(Zeroizing::new)
    }

    pub fn cmd_verify(from: &Path, vault_path: &Path) -> Result<()> {
        let recovery_file = open_no_symlinks(from, false).context("open recovery file")?;
        let vault_file = open_no_symlinks(vault_path, false).context("open vault source")?;
        require_separate_sources(&recovery_file, &vault_file)
            .context("recovery file and vault must be on separate physical devices")?;
        let recovery_bytes = read_exact_recovery(&recovery_file)?;
        validate_recovery_envelope(&recovery_bytes)?;
        let vault_before = vault_file.metadata()?;
        let blob = read_vault_blob(&vault_file)?;
        let vault_after = vault_file.metadata()?;
        if vault_before.dev() != vault_after.dev()
            || vault_before.ino() != vault_after.ino()
            || vault_before.len() != vault_after.len()
            || vault_before.mtime() != vault_after.mtime()
            || vault_before.mtime_nsec() != vault_after.mtime_nsec()
            || vault_before.ctime() != vault_after.ctime()
            || vault_before.ctime_nsec() != vault_after.ctime_nsec()
        {
            bail!("vault source changed while reading");
        }
        require_separate_sources(&recovery_file, &vault_file)?;

        println!("Recovery uses your master password and both phone PINs. No new password.");
        println!("This drive restores access, not your vault data. If you lose the vault and have no separate copy, recovery cannot restore your passwords.");
        let (password, pin4, pin6) = prompt_credentials()?;
        let material = open_recovery(&recovery_bytes, password.as_bytes(), &pin4, &pin6)
            .context("authenticate recovery file")?;
        let vault = match authenticate_vault(&blob, &material, password.as_bytes()) {
            Ok(vault) => vault,
            Err(_) => {
                println!("The selected vault did not open with the recovery-file password. It may use a newer vault password, have a different phone share, or be damaged.");
                let separate_password =
                    Zeroizing::new(rpassword::prompt_password("separate vault password: ")?);
                authenticate_vault(&blob, &material, separate_password.as_bytes())
                    .context("vault password/share mismatch or damaged vault")?
            }
        };
        drop(vault);
        require_separate_sources(&recovery_file, &vault_file)?;
        println!(
            "Recovery file {} from pairing {} is compatible with the selected encrypted vault.",
            material.file_id, material.pairing_id
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::{cmd_confirm, cmd_create, cmd_verify};

#[cfg(not(target_os = "linux"))]
pub async fn cmd_confirm(_from: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!("recovery confirmation requires the Linux storage topology resolver")
}

#[cfg(not(target_os = "linux"))]
pub async fn cmd_create(_to: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!("recovery creation requires the Linux storage topology resolver")
}

#[cfg(not(target_os = "linux"))]
pub fn cmd_verify(_from: &std::path::Path, _vault: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!("offline recovery verification requires the Linux storage topology resolver")
}
