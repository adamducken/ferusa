//! Non-secret recovery policy and the existing credential transaction journal.
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ferusa_core::enrollment::{EnrollmentContext, RecoveryReference};
use ferusa_core::recovery::{
    canonical_recovery_finished, recovery_vault_digest, verify_recovery_signature,
    RecoveryFinished, RecoveryPurpose,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::paths::{
    copy_private_file, fsync_parent, write_private_file, PairingData, PairingTxnFile,
    PairingTxnPhase, Paths,
};

pub(crate) fn read_metadata(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        bail!("metadata is not a regular file");
    }
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        bail!("metadata exceeds 64 KiB");
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySources {
    #[serde(with = "path_bytes")]
    pub recovery_file: PathBuf,
    #[serde(with = "path_bytes")]
    pub vault_file: PathBuf,
    pub recovery_digest: [u8; 32],
    pub vault_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryTxn {
    pub transaction_id: Uuid,
    pub purpose: RecoveryPurpose,
    pub credential_revision: Uuid,
    pub desktop_id: [u8; 32],
    pub previous_vault_digest: Option<[u8; 32]>,
    pub candidate_vault_digest: Option<[u8; 32]>,
    pub file_id: Option<Uuid>,
    #[serde(with = "optional_path_bytes")]
    pub recovery_file: Option<PathBuf>,
    pub envelope_digest: Option<[u8; 32]>,
    pub finished: Option<RecoveryFinished>,
    pub sources: Option<RecoverySources>,
}

impl RecoveryTxn {
    pub fn enrollment(&self) -> Result<EnrollmentContext> {
        let context = EnrollmentContext {
            version: 5,
            desktop_id: self.desktop_id,
            transaction_id: self.transaction_id,
            purpose: self.purpose,
            credential_revision: self.credential_revision,
        };
        context.validate()?;
        Ok(context)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAttempt {
    pub pairing_id: Uuid,
    pub credential_revision: Uuid,
    pub file_id: Uuid,
    pub envelope_digest: [u8; 32],
    #[serde(with = "path_bytes")]
    pub path: PathBuf,
}

// UTF-8 paths keep the original metadata representation; other Unix paths retain
// their exact bytes. Paths are resume hints, never arbitrary promotion targets.
mod path_bytes {
    use super::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    pub(super) enum Representation {
        Text(String),
        Bytes(Vec<u8>),
    }
    pub(super) fn representation(path: &Path) -> Representation {
        match path.to_str() {
            Some(text) => Representation::Text(text.to_owned()),
            None => Representation::Bytes(path.as_os_str().as_bytes().to_vec()),
        }
    }
    pub(super) fn from_representation(value: Representation) -> Result<PathBuf> {
        let bytes = match value {
            Representation::Text(text) => text.into_bytes(),
            Representation::Bytes(bytes) => bytes,
        };
        if bytes.len() > 8192 || bytes.contains(&0) {
            bail!("invalid metadata path");
        }
        Ok(std::ffi::OsString::from_vec(bytes).into())
    }
    pub fn serialize<S: serde::Serializer>(
        path: &Path,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        representation(path).serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<PathBuf, D::Error> {
        from_representation(Representation::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}
mod optional_path_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        path: &Option<PathBuf>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        path.as_deref()
            .map(path_bytes::representation)
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<PathBuf>, D::Error> {
        Option::<path_bytes::Representation>::deserialize(deserializer)?
            .map(path_bytes::from_representation)
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRecord {
    pub version: u8,
    pub pairing_id: Uuid,
    pub credential_revision: Uuid,
    pub vault_digest: [u8; 32],
    pub file_id: Uuid,
    pub envelope_digest: [u8; 32],
    pub finished: RecoveryFinished,
    #[serde(default)]
    pub pending_attempt: Option<RecoveryAttempt>,
}

fn validate_receipt(
    pairing: &PairingData,
    revision: Uuid,
    digest: [u8; 32],
    finished: &RecoveryFinished,
) -> Result<()> {
    finished.context.validate()?;
    if finished.context.begin.pairing_id != pairing.pairing_id
        || finished.context.begin.credential_revision != revision
        || finished.context.begin.vault_digest != digest
        || finished.file_id.is_nil()
        || finished
            .context
            .begin
            .file_id
            .is_some_and(|id| id != finished.file_id)
        || finished
            .context
            .begin
            .expected_envelope_digest
            .is_some_and(|value| value != finished.envelope_digest)
        || !verify_recovery_signature(
            &pairing.approval_public_key_der,
            &canonical_recovery_finished(finished)?,
            &finished.signature,
        )
    {
        bail!("recovery receipt does not match generation, credentials, vault, and file");
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<[u8; 32]> {
    let blob = super::vault::load_vault_blob(path)?;
    Ok(recovery_vault_digest(&blob.to_bytes()))
}

impl Paths {
    pub fn recovery_state(&self) -> PathBuf {
        self.data_dir.join("recovery.json")
    }

    pub fn require_recovery_complete(&self) -> Result<()> {
        if self.pairing_transaction_state().exists() {
            let txn = self.read_pairing_transaction()?;
            if let Some(recovery) = txn.recovery {
                bail!(
                    "recovery setup incomplete; resume ferusa {} with the original paths",
                    match recovery.purpose {
                        RecoveryPurpose::InitialSetup => "init",
                        RecoveryPurpose::PairingChange => "pair",
                        RecoveryPurpose::PasswordChange => "passwd",
                        RecoveryPurpose::LostPhoneRecovery => "recover",
                        _ => "recovery create",
                    }
                );
            }
        }
        if !self.pairing_state().exists() {
            return Ok(());
        }
        let pairing = self.read_pairing_data()?;
        let Some(revision) = pairing.credential_revision else {
            return Ok(());
        };
        let record = self
            .read_recovery_record()
            .context("mandatory recovery record missing or invalid; run ferusa recovery create")?;
        if record.version != 1
            || record.pairing_id != pairing.pairing_id
            || record.credential_revision != revision
            || record.file_id != record.finished.file_id
            || record.envelope_digest != record.finished.envelope_digest
        {
            bail!("mandatory recovery incomplete; run ferusa recovery create");
        }
        validate_receipt(&pairing, revision, record.vault_digest, &record.finished)
    }

    pub fn read_recovery_record(&self) -> Result<RecoveryRecord> {
        serde_json::from_slice(&read_metadata(&self.recovery_state())?)
            .context("parse recovery record")
    }

    pub fn save_recovery_record(
        &self,
        pairing: &PairingData,
        finished: RecoveryFinished,
    ) -> Result<()> {
        let revision = pairing
            .credential_revision
            .context("required credential revision missing")?;
        validate_receipt(
            pairing,
            revision,
            finished.context.begin.vault_digest,
            &finished,
        )?;
        let record = RecoveryRecord {
            version: 1,
            pairing_id: pairing.pairing_id,
            credential_revision: revision,
            vault_digest: finished.context.begin.vault_digest,
            file_id: finished.file_id,
            envelope_digest: finished.envelope_digest,
            finished,
            pending_attempt: None,
        };
        write_private_file(&self.recovery_state(), &serde_json::to_vec(&record)?)
    }

    pub fn save_recovery_attempt(&self, attempt: RecoveryAttempt) -> Result<()> {
        // A failed refresh retains the previous confirmed record.
        if self.recovery_state().exists() {
            let mut record = self.read_recovery_record()?;
            record.pending_attempt = Some(attempt);
            write_private_file(&self.recovery_state(), &serde_json::to_vec(&record)?)
        } else {
            write_private_file(
                &self.data_dir.join("recovery_attempt.json"),
                &serde_json::to_vec(&attempt)?,
            )
        }
    }

    pub fn begin_credential_transaction(
        &self,
        purpose: RecoveryPurpose,
        desktop_id: [u8; 32],
        sources: Option<RecoverySources>,
    ) -> Result<PairingTxnFile> {
        if self.pairing_transaction_state().exists() {
            bail!("credential transaction already exists");
        }
        if !matches!(
            purpose,
            RecoveryPurpose::InitialSetup
                | RecoveryPurpose::PairingChange
                | RecoveryPurpose::PasswordChange
                | RecoveryPurpose::LostPhoneRecovery
        ) {
            bail!("invalid credential operation");
        }
        let had_live_vault = self.vault_enc.exists();
        let had_live_pairing = self.pairing_state().exists();
        let previous_vault_digest = if had_live_vault {
            Some(digest_file(&self.vault_enc)?)
        } else {
            None
        };
        let recovery = RecoveryTxn {
            transaction_id: Uuid::new_v4(),
            purpose,
            credential_revision: Uuid::new_v4(),
            desktop_id,
            previous_vault_digest,
            candidate_vault_digest: None,
            file_id: None,
            recovery_file: None,
            envelope_digest: None,
            finished: None,
            sources,
        };
        let file = PairingTxnFile {
            version: 3,
            phase: PairingTxnPhase::Preparing,
            pairing_id: Uuid::nil(),
            had_live_vault,
            had_live_pairing,
            recovery: Some(recovery),
        };
        self.write_pairing_transaction(file)?;
        if had_live_vault {
            copy_private_file(&self.vault_enc, &self.rollback_vault_enc())?;
        }
        if had_live_pairing {
            copy_private_file(&self.pairing_state(), &self.rollback_pairing_state())?;
        }
        if self.recovery_state().exists() {
            copy_private_file(
                &self.recovery_state(),
                &self.data_dir.join("rollback_recovery.json"),
            )?;
        }
        self.read_pairing_transaction()
    }

    pub fn record_candidate_pairing(&self, pairing: &PairingData) -> Result<()> {
        let mut txn = self.read_pairing_transaction()?;
        let recovery = txn
            .recovery
            .as_ref()
            .context("not a recovery transaction")?;
        if (!txn.pairing_id.is_nil() && txn.pairing_id != pairing.pairing_id)
            || pairing.credential_revision != Some(recovery.credential_revision)
            || txn.phase != PairingTxnPhase::Preparing
        {
            bail!("candidate generation mismatch");
        }
        txn.pairing_id = pairing.pairing_id;
        self.write_pairing_transaction(txn)?;
        self.write_pending_pairing_data(pairing)
    }

    pub fn prepare_candidate_vault(&self, bytes: &[u8]) -> Result<()> {
        let mut txn = self.read_pairing_transaction()?;
        if txn.phase != PairingTxnPhase::Preparing || txn.pairing_id.is_nil() {
            bail!("candidate pairing not recorded");
        }
        let recovery = txn
            .recovery
            .as_mut()
            .context("not a recovery transaction")?;
        let digest = recovery_vault_digest(bytes);
        if self.pending_vault_enc().exists()
            && recovery
                .candidate_vault_digest
                .is_some_and(|old| old != digest)
        {
            bail!("candidate ciphertext already bound; resume the original candidate");
        }
        // Record ciphertext identity before the write so a crash cannot replace it silently.
        recovery.candidate_vault_digest = Some(digest);
        self.write_pairing_transaction(txn)?;
        write_private_file(&self.pending_vault_enc(), bytes)?;
        let mut txn = self.read_pairing_transaction()?;
        txn.phase = PairingTxnPhase::CandidatePrepared;
        self.write_pairing_transaction(txn)
    }

    pub fn resume_candidate_preparation(&self) -> Result<()> {
        let mut txn = self.read_pairing_transaction()?;
        if txn.phase == PairingTxnPhase::Preparing && self.pending_vault_enc().exists() {
            let recovery = txn
                .recovery
                .as_ref()
                .context("not a recovery transaction")?;
            if Some(digest_file(&self.pending_vault_enc())?) != recovery.candidate_vault_digest {
                bail!("interrupted candidate does not match journal; repair required");
            }
            txn.phase = PairingTxnPhase::CandidatePrepared;
            self.write_pairing_transaction(txn)?;
        }
        Ok(())
    }

    pub fn record_candidate_attempt(&self, attempt: RecoveryAttempt) -> Result<()> {
        let mut txn = self.read_pairing_transaction()?;
        let recovery = txn
            .recovery
            .as_mut()
            .context("not a recovery transaction")?;
        if attempt.pairing_id != txn.pairing_id
            || attempt.credential_revision != recovery.credential_revision
        {
            bail!("attempt generation mismatch");
        }
        recovery.file_id = Some(attempt.file_id);
        recovery.envelope_digest = Some(attempt.envelope_digest);
        recovery.recovery_file = Some(attempt.path);
        self.write_pairing_transaction(txn)
    }

    pub fn record_candidate_receipt(&self, finished: RecoveryFinished) -> Result<()> {
        let mut txn = self.read_pairing_transaction()?;
        let pairing = self.transaction_pairing()?;
        let recovery = txn
            .recovery
            .as_mut()
            .context("not a recovery transaction")?;
        let digest = recovery
            .candidate_vault_digest
            .context("candidate digest missing")?;
        validate_receipt(&pairing, recovery.credential_revision, digest, &finished)?;
        if finished.context.begin.transaction_id != Some(recovery.transaction_id)
            || finished.context.begin.purpose != recovery.purpose
            || finished.context.desktop_id != recovery.desktop_id
        {
            bail!("receipt transaction mismatch");
        }
        recovery.file_id = Some(finished.file_id);
        recovery.envelope_digest = Some(finished.envelope_digest);
        recovery.finished = Some(finished);
        if matches!(
            txn.phase,
            PairingTxnPhase::CandidatePrepared | PairingTxnPhase::RecoveryVerified
        ) {
            txn.phase = PairingTxnPhase::RecoveryVerified;
        }
        self.write_pairing_transaction(txn)
    }

    pub fn transaction_pairing(&self) -> Result<PairingData> {
        if self.pending_pairing_state().exists() {
            self.read_pending_pairing_data()
        } else {
            self.read_pairing_data()
        }
    }

    pub fn transaction_vault(&self) -> PathBuf {
        if self.pending_vault_enc().exists() {
            self.pending_vault_enc()
        } else {
            self.vault_enc.clone()
        }
    }

    pub fn recovery_reference(&self) -> Result<RecoveryReference> {
        let txn = self.read_pairing_transaction()?;
        let recovery = txn.recovery.context("not a recovery transaction")?;
        RecoveryReference::from_finished(
            recovery
                .finished
                .as_ref()
                .context("recovery not confirmed")?,
        )
        .map_err(Into::into)
    }

    pub fn record_commit_intent(&self) -> Result<()> {
        let mut txn = self.read_pairing_transaction()?;
        if txn.phase != PairingTxnPhase::RecoveryVerified {
            bail!("fresh recovery confirmation required before commit");
        }
        let expected = txn
            .recovery
            .as_ref()
            .unwrap()
            .candidate_vault_digest
            .unwrap();
        if digest_file(&self.transaction_vault())? != expected {
            bail!("candidate vault changed before commit");
        }
        txn.phase = PairingTxnPhase::CommitIntent;
        self.write_pairing_transaction(txn)
    }

    pub(crate) fn validate_recovery_transaction(&self, txn: &PairingTxnFile) -> Result<()> {
        let recovery = txn.recovery.as_ref().context("recovery journal missing")?;
        if recovery.transaction_id.is_nil()
            || recovery.credential_revision.is_nil()
            || recovery.desktop_id == [0; 32]
            || !matches!(
                recovery.purpose,
                RecoveryPurpose::InitialSetup
                    | RecoveryPurpose::PasswordChange
                    | RecoveryPurpose::PairingChange
                    | RecoveryPurpose::LostPhoneRecovery
            )
            || (txn.phase != PairingTxnPhase::Preparing
                && (txn.pairing_id.is_nil() || recovery.candidate_vault_digest.is_none()))
            || (matches!(
                txn.phase,
                PairingTxnPhase::RecoveryVerified
                    | PairingTxnPhase::CommitIntent
                    | PairingTxnPhase::PhoneCommitted
                    | PairingTxnPhase::LocallyActivated
                    | PairingTxnPhase::FullyActivated
            ) && recovery.finished.is_none())
            || txn.phase == PairingTxnPhase::Prepared
        {
            bail!("inconsistent recovery transaction");
        }
        if let Some(finished) = &recovery.finished {
            let reference = RecoveryReference::from_finished(finished)?;
            if reference.pairing_id != txn.pairing_id
                || reference.transaction_id != recovery.transaction_id
                || reference.credential_revision != recovery.credential_revision
                || Some(reference.vault_digest) != recovery.candidate_vault_digest
                || Some(reference.file_id) != recovery.file_id
                || Some(reference.envelope_digest) != recovery.envelope_digest
            {
                bail!("journal recovery binding mismatch");
            }
        }
        Ok(())
    }

    pub(crate) fn promote_recovery_candidate(&self, txn: &PairingTxnFile) -> Result<()> {
        let recovery = txn.recovery.as_ref().unwrap();
        if !(txn.phase == PairingTxnPhase::PhoneCommitted
            || (txn.phase == PairingTxnPhase::CommitIntent
                && recovery.purpose == RecoveryPurpose::PasswordChange))
        {
            bail!("commit acknowledgement required before promotion");
        }
        let candidate = recovery
            .candidate_vault_digest
            .context("candidate digest missing")?;
        if self.vault_enc.exists() {
            let live = digest_file(&self.vault_enc)?;
            if live != candidate && Some(live) != recovery.previous_vault_digest {
                bail!("live vault matches neither original nor candidate; repair required");
            }
        } else if txn.had_live_vault {
            bail!("original vault missing; repair required");
        }
        if self.pending_vault_enc().exists() {
            if digest_file(&self.pending_vault_enc())? != candidate {
                bail!("candidate digest mismatch");
            }
            std::fs::rename(self.pending_vault_enc(), &self.vault_enc)?;
            fsync_parent(&self.vault_enc)?;
        }
        if digest_file(&self.vault_enc)? != candidate {
            bail!("candidate vault unavailable");
        }
        if self.pairing_state().exists() {
            let live = self.read_pairing_data()?;
            if live.pairing_id != txn.pairing_id
                || live.credential_revision != Some(recovery.credential_revision)
            {
                if !txn.had_live_pairing {
                    bail!("unrelated pairing appeared in target; repair required");
                }
                let old = read_metadata(&self.rollback_pairing_state())?;
                if read_metadata(&self.pairing_state())? != old {
                    bail!("live pairing changed; repair required");
                }
            }
        }
        if self.pending_pairing_state().exists() {
            let pending = self.read_pending_pairing_data()?;
            if pending.pairing_id != txn.pairing_id
                || pending.credential_revision != Some(recovery.credential_revision)
            {
                bail!("candidate pairing mismatch");
            }
            std::fs::rename(self.pending_pairing_state(), self.pairing_state())?;
            fsync_parent(&self.pairing_state())?;
        }
        let pairing = self.read_pairing_data()?;
        if pairing.pairing_id != txn.pairing_id
            || pairing.credential_revision != Some(recovery.credential_revision)
        {
            bail!("candidate pairing unavailable");
        }
        Ok(())
    }

    pub(crate) fn recover_credential_transaction(&self, txn: &PairingTxnFile) -> Result<()> {
        let recovery = txn.recovery.as_ref().unwrap();
        if txn.phase == PairingTxnPhase::PhoneCommitted
            || (txn.phase == PairingTxnPhase::CommitIntent
                && recovery.purpose == RecoveryPurpose::PasswordChange)
        {
            self.promote_recovery_candidate(txn)?;
            self.write_pairing_transaction_locally_activated(txn.pairing_id)?;
        }
        Ok(())
    }

    pub fn complete_credential_transaction(&self) -> Result<()> {
        let txn = self.read_pairing_transaction()?;
        if txn.phase != PairingTxnPhase::FullyActivated {
            bail!("generation activation not acknowledged");
        }
        let recovery = txn.recovery.as_ref().unwrap();
        if digest_file(&self.vault_enc)? != recovery.candidate_vault_digest.unwrap() {
            bail!("activated vault digest mismatch");
        }
        self.save_recovery_record(
            &self.read_pairing_data()?,
            recovery.finished.clone().context("receipt missing")?,
        )?;
        self.clear_pending_pairing()?;
        for name in ["rollback_recovery.json", "recovery_attempt.json"] {
            let path = self.data_dir.join(name);
            if path.exists() {
                std::fs::remove_file(&path)?;
                fsync_parent(&path)?;
            }
        }
        self.require_recovery_complete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferusa_core::crypto::{combine_vault_key, encrypt_vault};
    use ferusa_core::recovery::{RecoveryBegin, RecoveryContext};
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
    };

    struct Fixture {
        _directory: tempfile::TempDir,
        paths: Paths,
        pairing: PairingData,
        signer: EcdsaKeyPair,
        original: Vec<u8>,
        candidate: Vec<u8>,
    }
    fn encrypted(byte: u8) -> Vec<u8> {
        let key = combine_vault_key(&[byte; 32], &[9; 32]).unwrap();
        encrypt_vault(&key, [byte; 16], br#"{"entries":[]}"#)
            .unwrap()
            .to_bytes()
    }
    fn fixture(purpose: RecoveryPurpose) -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(directory.path().to_owned());
        paths.ensure_data_dir().unwrap();
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let mut pairing = PairingData {
            pairing_id: Uuid::new_v4(),
            phone_node_id: iroh::SecretKey::generate().public(),
            approval_public_key_der: signer.public_key().as_ref().to_vec(),
            created_at_ms: 1,
            credential_revision: None,
        };
        let original = encrypted(1);
        let candidate = encrypted(2);
        write_private_file(&paths.vault_enc, &original).unwrap();
        paths.write_pairing_data(&pairing).unwrap();
        paths.require_recovery_complete().unwrap();
        let txn = paths
            .begin_credential_transaction(purpose, [3; 32], None)
            .unwrap();
        pairing.credential_revision = Some(txn.recovery.as_ref().unwrap().credential_revision);
        if purpose != RecoveryPurpose::PasswordChange {
            pairing.pairing_id = Uuid::new_v4();
        }
        paths.record_candidate_pairing(&pairing).unwrap();
        paths.prepare_candidate_vault(&candidate).unwrap();
        Fixture {
            _directory: directory,
            paths,
            pairing,
            signer,
            original,
            candidate,
        }
    }
    fn receipt(f: &Fixture) -> RecoveryFinished {
        let txn = f.paths.read_pairing_transaction().unwrap();
        let recovery = txn.recovery.unwrap();
        let file_id = Uuid::new_v4();
        let mut receipt = RecoveryFinished {
            context: RecoveryContext {
                begin: RecoveryBegin {
                    request_id: Uuid::new_v4(),
                    pairing_id: txn.pairing_id,
                    purpose: recovery.purpose,
                    transaction_id: Some(recovery.transaction_id),
                    credential_revision: recovery.credential_revision,
                    file_id: Some(file_id),
                    expected_envelope_digest: None,
                    vault_digest: recovery.candidate_vault_digest.unwrap(),
                    nonce: [4; 32],
                    correlation_code: 1234,
                    timestamp_ms: 1,
                },
                instance_id: Uuid::new_v4(),
                desktop_id: [3; 32],
                phone_challenge: [5; 32],
                phone_session_generation: 6,
            },
            file_id,
            envelope_digest: [7; 32],
            timestamp_ms: 2,
            signature: Vec::new(),
        };
        receipt.signature = f
            .signer
            .sign(
                &SystemRandom::new(),
                &canonical_recovery_finished(&receipt).unwrap(),
            )
            .unwrap()
            .as_ref()
            .to_vec();
        receipt
    }
    fn verified(f: &Fixture) {
        f.paths.record_candidate_receipt(receipt(f)).unwrap();
        f.paths.record_commit_intent().unwrap();
    }

    #[tokio::test]
    async fn required_setup_and_cached_sessions_fail_closed_without_completion() {
        let f = fixture(RecoveryPurpose::InitialSetup);
        assert!(f.paths.require_recovery_complete().is_err());
        let state = std::sync::Arc::new(tokio::sync::Mutex::new(Some(
            crate::session::SessionState {
                vault: ferusa_core::types::Vault::default(),
                local_secret: [1; 32],
                vault_key: [2; 32],
                phone_share: [9; 32],
                vault_salt: [1; 16],
                pairing: None,
                pending_requests: Default::default(),
                endpoint: None,
                phone_conn: None,
                vault_lock: None,
            },
        )));
        assert!(crate::session::ensure_unlocked(&state, &f.paths)
            .await
            .is_err());
        assert!(crate::session::save_vault(&state, &f.paths).await.is_err());
        f.paths.write_pairing_data(&f.pairing).unwrap();
        std::fs::remove_file(f.paths.pairing_transaction_state()).unwrap();
        assert!(f.paths.require_recovery_complete().is_err());
        let record = receipt_from_pairing(&f.pairing);
        write_private_file(&f.paths.recovery_state(), &record).unwrap();
        assert!(f.paths.require_recovery_complete().is_err());
    }
    fn receipt_from_pairing(pairing: &PairingData) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"version":1,"pairing_id":pairing.pairing_id,"credential_revision":pairing.credential_revision})).unwrap()
    }

    #[test]
    fn precommit_restart_retains_original_and_tracked_candidate() {
        let f = fixture(RecoveryPurpose::LostPhoneRecovery);
        f.paths.recover_pairing_transaction().unwrap();
        assert_eq!(std::fs::read(&f.paths.vault_enc).unwrap(), f.original);
        assert_eq!(
            std::fs::read(f.paths.pending_vault_enc()).unwrap(),
            f.candidate
        );
        assert!(f.paths.pairing_transaction_state().is_file());
        assert!(f
            .paths
            .write_pairing_transaction_phone_committed(f.pairing.pairing_id)
            .is_err());
    }

    #[test]
    fn recovery_receipt_rejects_substituted_revision_generation_and_vault() {
        let f = fixture(RecoveryPurpose::PairingChange);
        for field in 0..4 {
            let mut changed = receipt(&f);
            match field {
                0 => changed.context.begin.credential_revision = Uuid::new_v4(),
                1 => changed.context.begin.pairing_id = Uuid::new_v4(),
                2 => changed.context.begin.vault_digest[0] ^= 1,
                _ => changed.context.begin.transaction_id = Some(Uuid::new_v4()),
            }
            changed.signature = f
                .signer
                .sign(
                    &SystemRandom::new(),
                    &canonical_recovery_finished(&changed).unwrap(),
                )
                .unwrap()
                .as_ref()
                .to_vec();
            assert!(f.paths.record_candidate_receipt(changed).is_err());
        }
        assert_eq!(
            f.paths.read_pairing_transaction().unwrap().phase,
            PairingTxnPhase::CandidatePrepared
        );
    }

    #[test]
    fn partial_promotion_finishes_forward_after_restart_and_keeps_gate() {
        let f = fixture(RecoveryPurpose::PairingChange);
        verified(&f);
        f.paths
            .write_pairing_transaction_phone_committed(f.pairing.pairing_id)
            .unwrap();
        // Crash after vault rename and before pairing rename/journal sync.
        std::fs::rename(f.paths.pending_vault_enc(), &f.paths.vault_enc).unwrap();
        f.paths.recover_pairing_transaction().unwrap();
        f.paths.recover_pairing_transaction().unwrap();
        assert_eq!(std::fs::read(&f.paths.vault_enc).unwrap(), f.candidate);
        assert_eq!(
            f.paths.read_pairing_data().unwrap().credential_revision,
            f.pairing.credential_revision
        );
        assert!(f.paths.require_recovery_complete().is_err());
        f.paths
            .write_pairing_transaction_fully_activated(f.pairing.pairing_id)
            .unwrap();
        f.paths.complete_credential_transaction().unwrap();
        f.paths.require_recovery_complete().unwrap();
        assert!(!f.paths.pairing_transaction_state().exists());
    }

    #[test]
    fn password_commit_intent_is_resumable_without_phone_generation_change() {
        let f = fixture(RecoveryPurpose::PasswordChange);
        verified(&f);
        let old = f.paths.read_pairing_data().unwrap().pairing_id;
        f.paths.recover_pairing_transaction().unwrap();
        assert_eq!(f.paths.read_pairing_data().unwrap().pairing_id, old);
        assert_eq!(
            f.paths.read_pairing_transaction().unwrap().phase,
            PairingTxnPhase::LocallyActivated
        );
        assert!(f.paths.require_recovery_complete().is_err());
        f.paths
            .write_pairing_transaction_fully_activated(old)
            .unwrap();
        f.paths.complete_credential_transaction().unwrap();
        assert_eq!(std::fs::read(&f.paths.vault_enc).unwrap(), f.candidate);
    }

    #[test]
    fn unexpected_live_or_candidate_bytes_are_never_overwritten() {
        for mutate_candidate in [false, true] {
            let f = fixture(RecoveryPurpose::PairingChange);
            verified(&f);
            f.paths
                .write_pairing_transaction_phone_committed(f.pairing.pairing_id)
                .unwrap();
            let unexpected = encrypted(8);
            let changed = if mutate_candidate {
                f.paths.pending_vault_enc()
            } else {
                f.paths.vault_enc.clone()
            };
            write_private_file(&changed, &unexpected).unwrap();
            assert!(f.paths.recover_pairing_transaction().is_err());
            assert_eq!(std::fs::read(changed).unwrap(), unexpected);
            assert!(f.paths.pairing_transaction_state().exists());
        }
    }

    #[test]
    fn fresh_target_never_overwrites_an_unrelated_pairing() {
        let f = fixture(RecoveryPurpose::LostPhoneRecovery);
        let mut txn = f.paths.read_pairing_transaction().unwrap();
        txn.had_live_pairing = false;
        f.paths.write_pairing_transaction(txn).unwrap();
        let unexpected = read_metadata(&f.paths.pairing_state()).unwrap();
        verified(&f);
        f.paths
            .write_pairing_transaction_phone_committed(f.pairing.pairing_id)
            .unwrap();
        assert!(f.paths.recover_pairing_transaction().is_err());
        assert_eq!(read_metadata(&f.paths.pairing_state()).unwrap(), unexpected);
        assert!(f.paths.require_recovery_complete().is_err());
    }

    #[test]
    fn failed_refresh_preserves_last_confirmed_receipt() {
        let f = fixture(RecoveryPurpose::PasswordChange);
        verified(&f);
        f.paths.recover_pairing_transaction().unwrap();
        f.paths
            .write_pairing_transaction_fully_activated(f.pairing.pairing_id)
            .unwrap();
        f.paths.complete_credential_transaction().unwrap();
        let previous = f.paths.read_recovery_record().unwrap();
        f.paths
            .save_recovery_attempt(RecoveryAttempt {
                pairing_id: f.pairing.pairing_id,
                credential_revision: f.pairing.credential_revision.unwrap(),
                file_id: Uuid::new_v4(),
                envelope_digest: [8; 32],
                path: PathBuf::from("/external/attempt.frb"),
            })
            .unwrap();
        let current = f.paths.read_recovery_record().unwrap();
        assert_eq!(previous.finished.signature, current.finished.signature);
        assert_eq!(previous.file_id, current.file_id);
        assert!(current.pending_attempt.is_some());
        f.paths.require_recovery_complete().unwrap();
    }

    #[test]
    fn metadata_limits_and_symlinks_fail_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.json");
        std::fs::write(&path, vec![b' '; 65_537]).unwrap();
        assert!(read_metadata(&path).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_metadata(&link).is_err());
    }

    #[test]
    fn non_utf8_path_hints_round_trip_without_changing_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(
            b"/external/recovery-\xff.frb".to_vec(),
        ));
        let attempt = RecoveryAttempt {
            pairing_id: Uuid::new_v4(),
            credential_revision: Uuid::new_v4(),
            file_id: Uuid::new_v4(),
            envelope_digest: [7; 32],
            path: path.clone(),
        };
        let parsed: RecoveryAttempt =
            serde_json::from_slice(&serde_json::to_vec(&attempt).unwrap()).unwrap();
        assert_eq!(parsed.path, path);
    }
}
