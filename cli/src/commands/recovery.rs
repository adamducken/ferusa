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
    };
    use ferusa_core::transport::{FerusaMessage, FERUSA_ALPN};
    use iroh::EndpointAddr;
    use rand::{Rng, RngCore};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use ferusa_core::crypto::EncryptedBlob;
    use ferusa_core::recovery::{open_recovery, seal_recovery, RECOVERY_FILE_LEN};
    use ferusa_core::types::Vault;

    use crate::net::cli_peer::CliPeer;
    use crate::storage::external::{
        open_no_symlinks, require_separate_sources, ExternalDestination,
    };
    use crate::storage::paths::Paths;
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

    pub async fn cmd_create(to: &Path) -> Result<()> {
        create_or_confirm(Some(to), None, None).await
    }
    pub async fn cmd_confirm(from: &Path) -> Result<()> {
        create_or_confirm(None, Some(from), None).await
    }
    pub async fn cmd_create_in_session(
        to: &Path,
        state: &crate::session::SharedState,
    ) -> Result<()> {
        create_or_confirm(Some(to), None, Some(state)).await
    }

    async fn create_or_confirm(
        to: Option<&Path>,
        from: Option<&Path>,
        state: Option<&crate::session::SharedState>,
    ) -> Result<()> {
        let paths = Paths::load()?;
        paths.ensure_not_dev_2fa_stub_vault()?;
        if paths.pairing_transaction_state().exists() {
            bail!("resume the pending credential operation before standalone recovery creation");
        }
        if !paths.peer_id.exists() {
            bail!("desktop pairing identity is missing");
        }
        let session_endpoint = if let Some(state) = state {
            state
                .lock()
                .await
                .as_ref()
                .and_then(|session| session.endpoint.clone())
        } else {
            None
        };
        let _vault_lock = if session_endpoint.is_some() {
            None
        } else {
            Some(
                paths
                    .acquire_vault_lock()
                    .context("lock vault for recovery creation")?,
            )
        };
        let mut pairing = paths.read_pairing_data()?;
        let revision = pairing.credential_revision.unwrap_or_else(Uuid::new_v4);
        let endpoint = if let Some(endpoint) = session_endpoint {
            endpoint
        } else {
            std::sync::Arc::new(CliPeer::init(&paths.peer_id).await?.into_endpoint())
        };
        let conn = tokio::time::timeout(
            Duration::from_secs(15),
            endpoint.connect(EndpointAddr::new(pairing.phone_node_id), FERUSA_ALPN),
        )
        .await
        .context(
            "timed out connecting to paired phone; both applications must support protocol v5",
        )??;
        let (mut send, mut recv) =
            tokio::time::timeout(Duration::from_secs(10), conn.open_bi()).await??;
        let purpose = if from.is_some() {
            RecoveryPurpose::ConfirmExisting
        } else {
            RecoveryPurpose::Create
        };
        let result = run_online(
            OnlineTarget {
                paths: &paths,
                pairing: &pairing,
                vault_path: &paths.vault_enc,
                to,
                from,
                purpose,
                transaction_id: None,
                revision,
            },
            &conn,
            &mut send,
            &mut recv,
        )
        .await;
        conn.close(0u32.into(), b"recovery exchange complete");
        if state.is_none() {
            endpoint.close().await;
        }
        let (written, finished) = result?;
        pairing.credential_revision = Some(revision);
        paths
            .save_recovery_record(&pairing, finished)
            .context("recovery file usable, but completion metadata could not be saved")?;
        paths
            .write_pairing_data(&pairing)
            .context("confirmed recovery saved; retry to finish required policy upgrade")?;
        println!("Recovery file confirmed at {}. Safely eject and store the drive separately from your phone, laptop, and vault backups. Consider a second recovery copy on another external device.", written.display());
        Ok(())
    }

    pub async fn create_candidate(
        paths: &Paths,
        to: &Path,
        transport: &mut crate::commands::pair::PairingCommitTransport,
    ) -> Result<()> {
        let txn = paths.read_pairing_transaction()?;
        let recovery = txn
            .recovery
            .as_ref()
            .context("candidate transaction missing")?;
        let pairing = paths.transaction_pairing()?;
        let from = candidate_confirmation_path(recovery);
        if recovery
            .recovery_file
            .as_ref()
            .is_some_and(|path| path.exists())
            && from.is_none()
        {
            println!("Previous recovery file is unverified or changed; preserving it and using a new filename.");
        }
        let (written, finished) = run_online(
            OnlineTarget {
                paths,
                pairing: &pairing,
                vault_path: &paths.transaction_vault(),
                to: Some(to),
                from,
                purpose: recovery.purpose,
                transaction_id: Some(recovery.transaction_id),
                revision: recovery.credential_revision,
            },
            &transport.conn,
            &mut transport.send,
            &mut transport.recv,
        )
        .await?;
        paths.record_candidate_receipt(finished)?;
        println!(
            "Candidate recovery file confirmed at {}.",
            written.display()
        );
        Ok(())
    }

    pub async fn create_password_candidate(
        paths: &Paths,
        to: &Path,
        endpoint: &iroh::Endpoint,
    ) -> Result<()> {
        let txn = paths.read_pairing_transaction()?;
        let recovery = txn
            .recovery
            .as_ref()
            .context("password transaction missing")?;
        let pairing = paths.transaction_pairing()?;
        let conn = tokio::time::timeout(
            Duration::from_secs(15),
            endpoint.connect(EndpointAddr::new(pairing.phone_node_id), FERUSA_ALPN),
        )
        .await??;
        let (mut send, mut recv) =
            tokio::time::timeout(Duration::from_secs(10), conn.open_bi()).await??;
        let from = candidate_confirmation_path(recovery);
        let result = run_online(
            OnlineTarget {
                paths,
                pairing: &pairing,
                vault_path: &paths.transaction_vault(),
                to: Some(to),
                from,
                purpose: RecoveryPurpose::PasswordChange,
                transaction_id: Some(recovery.transaction_id),
                revision: recovery.credential_revision,
            },
            &conn,
            &mut send,
            &mut recv,
        )
        .await;
        conn.close(0u32.into(), b"password recovery complete");
        let (_, finished) = result?;
        paths.record_candidate_receipt(finished)
    }

    fn candidate_confirmation_path(
        recovery: &crate::storage::recovery::RecoveryTxn,
    ) -> Option<&Path> {
        recovery.recovery_file.as_deref().filter(|path| {
            open_no_symlinks(path, false)
                .ok()
                .and_then(|file| read_exact_recovery(&file).ok())
                .is_some_and(|bytes| {
                    validate_recovery_envelope(&bytes).is_ok()
                        && recovery.envelope_digest == Some(recovery_file_digest(&bytes))
                })
        })
    }

    struct OnlineTarget<'a> {
        paths: &'a Paths,
        pairing: &'a crate::storage::paths::PairingData,
        vault_path: &'a Path,
        to: Option<&'a Path>,
        from: Option<&'a Path>,
        purpose: RecoveryPurpose,
        transaction_id: Option<Uuid>,
        revision: Uuid,
    }

    async fn run_online(
        target: OnlineTarget<'_>,
        conn: &iroh::endpoint::Connection,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Result<(std::path::PathBuf, RecoveryFinished)> {
        let OnlineTarget {
            paths,
            pairing,
            vault_path,
            to,
            from,
            purpose,
            transaction_id,
            revision,
        } = target;
        let vault_file = open_no_symlinks(vault_path, false)?;
        let blob = read_vault_blob(&vault_file)?;
        let vault_digest = recovery_vault_digest(&blob.to_bytes());
        let known_backups = if transaction_id.is_some() {
            paths
                .read_pairing_transaction()?
                .recovery
                .and_then(|recovery| recovery.sources)
                .map(|sources| vec![sources.vault_file])
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let (destination, existing) = if let Some(from) = from {
            let parent = from
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let destination = ExternalDestination::open(parent, vault_path, &known_backups)?;
            let file = open_no_symlinks(from, false)?;
            require_separate_sources(&file, &vault_file)?;
            let bytes = read_exact_recovery(&file)?;
            validate_recovery_envelope(&bytes)?;
            (destination, Some((from.to_path_buf(), file, bytes)))
        } else {
            (
                ExternalDestination::open(
                    to.context("recovery destination missing")?,
                    vault_path,
                    &known_backups,
                )?,
                None,
            )
        };
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let expected_envelope_digest = existing
            .as_ref()
            .map(|(_, _, bytes)| recovery_file_digest(bytes));
        let file_id = if transaction_id.is_some() && existing.is_some() {
            paths
                .read_pairing_transaction()?
                .recovery
                .and_then(|txn| txn.file_id)
        } else {
            existing.is_none().then(Uuid::new_v4)
        };
        let begin = RecoveryBegin {
            request_id: Uuid::new_v4(),
            pairing_id: pairing.pairing_id,
            purpose,
            transaction_id,
            credential_revision: revision,
            file_id,
            expected_envelope_digest,
            vault_digest,
            nonce,
            correlation_code: rand::rng().random_range(1000..=9999),
            timestamp_ms: now_ms(),
        };
        if transaction_id.is_some() && existing.is_some() {
            let recorded = paths.read_pairing_transaction()?.recovery.unwrap();
            if recorded.envelope_digest != expected_envelope_digest {
                bail!("recorded recovery file changed before confirmation");
            }
        }
        begin.validate()?;
        println!("This recovery file can replace your phone when used with your master password and both phone PINs. Keep it in a secure location, separate from your phone, laptop, and vault backups. Do not carry it around with your phone. Anyone who copies it can attempt to guess those credentials without your phone's biometric checks or PIN attempt limits.");
        println!("Recovery uses your master password and both phone PINs. No new password.");
        println!("You also need your encrypted vault to recover your passwords. This recovery drive contains no vault data. If you lose the vault and have no separate backup, this file cannot restore it.");
        println!(
            "Match correlation code {:04} on your phone and approve this recovery request.",
            begin.correlation_code
        );
        let desktop_id = if let Some(txn) = transaction_id {
            let _ = txn;
            paths
                .read_pairing_transaction()?
                .recovery
                .unwrap()
                .desktop_id
        } else {
            let key = Zeroizing::new(std::fs::read(&paths.peer_id)?);
            let raw = Zeroizing::new(
                <[u8; 32]>::try_from(key.as_slice()).context("invalid peer identity")?,
            );
            *iroh::SecretKey::from_bytes(&raw).public().as_bytes()
        };
        let deadline = Instant::now() + Duration::from_secs(70);
        send_frame(send, FerusaMessage::RecoveryBegin(begin.clone()), deadline).await?;
        let consent = match recv_frame(recv, deadline).await? {
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
        let (password, pin4, pin6) =
            crate::password_input::recovery_credentials(conn, deadline).await?;
        let pins = RecoveryPins {
            instance_id: consent.context.instance_id,
            request_id: begin.request_id,
            challenge: consent.context.phone_challenge,
            pin4: pin4.to_string(),
            pin6: pin6.to_string(),
        };
        send_frame(send, FerusaMessage::RecoveryPins(pins), deadline).await?;
        let authorized = match recv_frame(recv, deadline).await? {
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
        let work_paths = paths.clone();
        let work_pairing = pairing.clone();
        let work_conn = conn.clone();
        let (written, file_id, envelope_digest, destination) = tokio::task::spawn_blocking(move || -> Result<_> {
            let check = || -> Result<()> { if Instant::now() >= deadline || work_conn.close_reason().is_some() { bail!("recovery expired or phone disconnected"); } Ok(()) };
            check()?;
            let vault = Zeroizing::new(open_vault_with_share(&blob, password.as_bytes(), &authorized.phone_share).context("master password does not open candidate/current vault with authorized phone share")?); drop(vault);
            check()?;
            let (written, readback) = if let Some((path, original, bytes)) = existing {
                let reopened = open_no_symlinks(&path, false)?;
                let first = original.metadata()?; let second = reopened.metadata()?;
                if first.dev() != second.dev() || first.ino() != second.ino() { bail!("recovery file changed during confirmation"); }
                let readback = read_exact_recovery(&reopened)?;
                if readback != bytes { bail!("recovery file changed during confirmation"); }
                require_separate_sources(&reopened, &vault_file)?;
                (path, readback)
            } else {
                let material = RecoveryMaterial { file_id: file_id.context("new recovery file ID missing")?, created_at_ms: now_ms(),
                    pairing_id: work_pairing.pairing_id, phone_share: Zeroizing::new(authorized.phone_share) };
                let envelope = seal_recovery(&material, password.as_bytes(), &pin4, &pin6)?;
                check()?;
                let planned = to_owned_path(&destination, material.file_id);
                let attempt = crate::storage::recovery::RecoveryAttempt { pairing_id: work_pairing.pairing_id,
                    credential_revision: revision, file_id: material.file_id, envelope_digest: recovery_file_digest(&envelope), path: planned };
                if transaction_id.is_some() { work_paths.record_candidate_attempt(attempt)?; } else { work_paths.save_recovery_attempt(attempt)?; }
                let written = destination.write_recovery(material.file_id, &envelope).context("recovery write/read-back failed; any partial file remains unverified")?;
                let reopened = open_no_symlinks(&written, false)?;
                (written, read_exact_recovery(&reopened)?)
            };
            let opened = open_recovery(&readback, password.as_bytes(), &pin4, &pin6).context("recovery file written; read-back authentication failed; creation not confirmed")?;
            if file_id.is_some_and(|id| id != opened.file_id) || opened.pairing_id != work_pairing.pairing_id || *opened.phone_share != authorized.phone_share { bail!("recovery read-back does not match authorization"); }
            let vault = Zeroizing::new(open_vault_with_share(&blob, password.as_bytes(), &opened.phone_share)?); drop(vault);
            check().context("recovery file written; creation not confirmed. Reconnect your phone and verify")?;
            destination.revalidate()?;
            Ok((written, opened.file_id, recovery_file_digest(&readback), destination))
        }).await.context("recovery verification worker failed")??;
        let finish = RecoveryFinish {
            instance_id: consent.context.instance_id,
            request_id: begin.request_id,
            challenge: consent.context.phone_challenge,
            file_id,
            envelope_digest,
        };
        let finish_result = async {
            send_frame(send, FerusaMessage::RecoveryFinish(finish), deadline).await?;
            let finished = match recv_frame(recv, deadline).await? {
                FerusaMessage::RecoveryFinished(value) => value,
                FerusaMessage::RecoveryRejected(value) => {
                    bail!("phone rejected recovery finish: {:?}", value.code)
                }
                _ => bail!("unexpected phone recovery confirmation"),
            };
            if finished.context != consent.context
                || finished.file_id != file_id
                || finished.envelope_digest != envelope_digest
            {
                bail!("phone confirmation does not match exact file");
            }
            validate_auth_timestamp(finished.timestamp_ms, now_ms())?;
            if !verify_recovery_signature(
                &pairing.approval_public_key_der,
                &canonical_recovery_finished(&finished)?,
                &finished.signature,
            ) {
                bail!("phone recovery confirmation signature invalid");
            }
            destination.revalidate()?;
            Ok::<_, anyhow::Error>(finished)
        }
        .await
        .context(
            "recovery file written; creation not confirmed. Reconnect your phone and verify",
        )?;
        Ok((written, finish_result))
    }

    fn to_owned_path(destination: &ExternalDestination, id: Uuid) -> std::path::PathBuf {
        destination.path().join(format!("ferusa-recovery-{id}.frb"))
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

    fn open_offline_sources(
        from: &Path,
        vault_path: &Path,
    ) -> Result<(
        RecoveryMaterial,
        Zeroizing<Vault>,
        crate::storage::recovery::RecoverySources,
    )> {
        let source_lock_path = vault_path
            .parent()
            .unwrap_or(Path::new("."))
            .join("vault.lock");
        let _source_lock = if vault_path
            .file_name()
            .is_some_and(|name| name == "vault.enc")
            && source_lock_path.exists()
        {
            Some(
                crate::storage::paths::acquire_existing_file_lock(&source_lock_path)
                    .context("lock surviving vault source without modifying it")?,
            )
        } else {
            None
        };
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
        require_separate_sources(&recovery_file, &vault_file)?;
        let sources = crate::storage::recovery::RecoverySources {
            recovery_file: absolute_path(from)?,
            vault_file: absolute_path(vault_path)?,
            recovery_digest: recovery_file_digest(&recovery_bytes),
            vault_digest: recovery_vault_digest(&blob.to_bytes()),
        };
        Ok((material, vault, sources))
    }

    pub fn cmd_verify(from: &Path, vault_path: &Path) -> Result<()> {
        let (material, vault, _) = open_offline_sources(from, vault_path)?;
        drop(vault);
        println!(
            "Recovery file {} from pairing {} is compatible with the selected encrypted vault.",
            material.file_id, material.pairing_id
        );
        Ok(())
    }

    fn absolute_path(path: &Path) -> Result<std::path::PathBuf> {
        if path.is_absolute() {
            Ok(path.to_owned())
        } else {
            Ok(std::env::current_dir()?.join(path))
        }
    }

    fn shell_path(path: &Path) -> String {
        use std::os::unix::ffi::OsStrExt;
        match path.to_str() {
            Some(text) => format!("'{}'", text.replace('\'', "'\"'\"'")),
            None => {
                let escaped: String = path
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("\\x{byte:02x}"))
                    .collect();
                format!("$'{escaped}'")
            }
        }
    }

    pub async fn cmd_recover(
        from: &Path,
        vault_path: &Path,
        into: &Path,
        selected: Option<&Path>,
    ) -> Result<()> {
        let target = absolute_path(into)?;
        let parent_path = target
            .parent()
            .context("target needs an existing parent directory")?;
        let parent = open_no_symlinks(parent_path, true)
            .context("open fresh target's parent without symlinks")?;
        let paths = Paths::from_data_dir(target.clone());
        let existing = match std::fs::symlink_metadata(&target) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    bail!("recovery target is not a private directory");
                }
                if !paths.pairing_transaction_state().exists() {
                    bail!("recovery target already exists; choose a fresh directory");
                }
                let txn = paths.read_pairing_transaction()?;
                let recovery = txn
                    .recovery
                    .as_ref()
                    .filter(|r| r.purpose == RecoveryPurpose::LostPhoneRecovery)
                    .context("target belongs to another operation")?;
                let sources = recovery
                    .sources
                    .as_ref()
                    .context("restore source binding missing")?;
                if sources.recovery_file != absolute_path(from)?
                    || sources.vault_file != absolute_path(vault_path)?
                {
                    bail!("resume recover with its original source paths");
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let to = super::super::enroll::recovery_directory(selected)?;
        let known = vec![absolute_path(vault_path)?];
        ExternalDestination::open(&to, &paths.vault_enc, &known)
            .context("validate replacement recovery device before enrollment")?;
        let existing_lock = if existing {
            Some(paths.acquire_vault_lock()?)
        } else {
            None
        };
        let prepared = existing && {
            paths.resume_candidate_preparation()?;
            paths.read_pairing_transaction()?.phase
                != crate::storage::paths::PairingTxnPhase::Preparing
        };
        let offline = if prepared {
            None
        } else {
            Some(open_offline_sources(from, vault_path)?)
        };
        // A recovered share is never installed in SharedState or copied from the source identity.
        if !existing {
            let recovery_file = open_no_symlinks(from, false)?;
            require_separate_sources(&recovery_file, &parent)
                .context("restored target must be separate from recovery-file storage")?;
            let name = target.file_name().context("invalid recovery target")?;
            rustix::fs::mkdirat(&parent, name, rustix::fs::Mode::from(0o700))
                .context("claim new recovery directory exclusively")?;
            parent.sync_all()?;
        }
        paths.ensure_data_dir()?;
        let target_dir = open_no_symlinks(&target, true)?;
        if from.exists() {
            require_separate_sources(&open_no_symlinks(from, false)?, &target_dir)?;
        }
        let _lock = match existing_lock {
            Some(lock) => lock,
            None => paths.acquire_vault_lock()?,
        };
        let (vault, sources) = match offline {
            Some((material, vault, sources)) => {
                drop(material);
                (Some(vault), Some(sources))
            }
            None => (None, None),
        };
        if existing && !paths.peer_id.is_file() {
            bail!("target desktop identity missing; cannot substitute another identity");
        }
        if !existing {
            let identity = CliPeer::prepare_identity(&paths.peer_id)?;
            paths.begin_credential_transaction(
                RecoveryPurpose::LostPhoneRecovery,
                *identity.public().as_bytes(),
                sources,
            )?;
        } else if let Some(sources) = sources {
            let txn = paths.read_pairing_transaction()?;
            let saved = txn.recovery.as_ref().unwrap().sources.as_ref().unwrap();
            if saved.recovery_digest != sources.recovery_digest
                || saved.vault_digest != sources.vault_digest
            {
                bail!("original recovery sources changed; refusing a different restore");
            }
        }
        let endpoint = std::sync::Arc::new(CliPeer::init(&paths.peer_id).await?.into_endpoint());
        let result =
            super::super::enroll::enroll_vault(&paths, &to, vault, None, endpoint.clone()).await;
        endpoint.close().await;
        result.context("restore incomplete; original encrypted sources preserved; resume recover with the same target")?;
        println!("Vault restored into {}. The original vault and recovery file were preserved. Safely eject and store your recovery drive separately.", target.display());
        println!(
            "Use normal phone-gated access: FERUSA_DATA_DIR={} ferusa list",
            shell_path(&target)
        );
        super::super::enroll::historical_reminder();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    cmd_confirm, cmd_create, cmd_create_in_session, cmd_recover, cmd_verify, create_candidate,
    create_password_candidate,
};

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

#[cfg(not(target_os = "linux"))]
pub async fn cmd_recover(
    _from: &std::path::Path,
    _vault: &std::path::Path,
    _into: &std::path::Path,
    _recovery_dir: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    anyhow::bail!("offline restoration requires the Linux storage topology resolver")
}

pub async fn cmd_create_interactive() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = super::enroll::recovery_directory(None)?;
        cmd_create(&path).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("recovery creation requires the Linux storage topology resolver")
    }
}
