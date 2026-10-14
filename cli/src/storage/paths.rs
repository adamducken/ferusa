use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[cfg(not(unix))]
compile_error!(
    "ferusa CLI supports Unix targets only: vault locking and atomic private-file writes require Unix filesystem semantics"
);

#[cfg(not(unix))]
fn unsupported_platform() -> ! {
    unreachable!("non-Unix builds are rejected at compile time")
}

// NOTE: this is really a filesystem/data-file status, not a 2FA protocol status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingStatus {
    Ready,
    Pending,
    MissingPhoneId,
    InvalidPhoneId(String),
    InvalidPairing(String),
}

#[derive(Debug, Clone)]
pub struct PairingData {
    pub pairing_id: Uuid,
    pub phone_node_id: iroh::PublicKey,
    pub approval_public_key_der: Vec<u8>,
    pub created_at_ms: u64,
    pub credential_revision: Option<Uuid>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PairingFile {
    version: u8,
    pairing_id: Uuid,
    phone_node_id: String,
    approval_public_key_der: String,
    created_at_ms: u64,
    #[serde(default)]
    credential_revision: Option<Uuid>,
    #[serde(default)]
    recovery_policy: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingTxnPhase {
    Preparing,
    CandidatePrepared,
    RecoveryVerified,
    CommitIntent,
    Prepared,
    PhoneCommitted,
    LocallyActivated,
    FullyActivated,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PairingTxnFile {
    pub(crate) version: u8,
    pub phase: PairingTxnPhase,
    pub pairing_id: Uuid,
    pub(crate) had_live_vault: bool,
    pub(crate) had_live_pairing: bool,
    #[serde(default)]
    pub recovery: Option<super::recovery::RecoveryTxn>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DevTwofaStubMarker {
    pub version: u8,
    pub warning: String,
}

const DEV_2FA_STUB_MARKER_WARNING: &str =
    "This vault was created with the deterministic dev 2FA stub and is not production-compatible.";

#[cfg(unix)]
pub struct VaultLock {
    _file: File,
}

#[cfg(not(unix))]
pub struct VaultLock {
    _file: File,
}

impl fmt::Display for PairingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => write!(f, "paired"),
            Self::Pending => write!(f, "pairing transaction pending"),
            Self::MissingPhoneId => write!(f, "not paired with a phone"),
            Self::InvalidPhoneId(reason) => write!(f, "pairing data invalid (phone.id: {reason})"),
            Self::InvalidPairing(reason) => write!(f, "pairing data invalid: {reason}"),
        }
    }
}

/// All file-system paths used by the CLI.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub vault_enc: PathBuf,
    pub vault_salt: PathBuf,
    pub peer_id: PathBuf,  // CLI's own iroh secret key
    pub phone_id: PathBuf, // phone's iroh NodeId (hex)
    pub hmac_key: PathBuf, // shared HMAC key (32 raw bytes)
    pub clipboard_cmd: PathBuf,
}

const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[cfg(unix)]
pub(crate) fn fsync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .with_context(|| format!("open parent dir {:?}", parent))?
            .sync_all()
            .with_context(|| format!("sync parent dir {:?}", parent))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn fsync_parent(_path: &Path) -> Result<()> {
    unsupported_platform()
}

#[cfg(unix)]
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(PRIVATE_DIR_MODE);
    builder
        .create(path)
        .with_context(|| format!("create data dir {:?}", path))?;

    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat data dir {:?}", path))?;
    if meta.file_type().is_symlink() {
        bail!("refusing to use symlinked data dir {:?}", path);
    }
    if !meta.file_type().is_dir() {
        bail!("data dir path is not a directory {:?}", path);
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .with_context(|| format!("chmod 0700 {:?}", path))?;
    fsync_parent(path)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    let _ = path;
    unsupported_platform()
}

#[cfg(unix)]
pub fn restrict_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("stat private file {:?}", path))?;
    if meta.file_type().is_symlink() {
        bail!("refusing to chmod symlinked private file {:?}", path);
    }
    if !meta.file_type().is_file() {
        bail!("private path is not a file {:?}", path);
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .with_context(|| format!("chmod 0600 {:?}", path))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn restrict_private_file(_path: &Path) -> Result<()> {
    unsupported_platform()
}

#[cfg(unix)]
pub fn open_private_append_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_private_dir(parent)?;
    }

    match std::fs::symlink_metadata(path) {
        Ok(_) => restrict_private_file(path)?,
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("stat private append file {:?}", path)),
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .with_context(|| format!("open private append file {:?}", path))?;
    restrict_private_file(path)?;
    Ok(file)
}

#[cfg(not(unix))]
pub fn open_private_append_file(_path: &Path) -> Result<File> {
    unsupported_platform()
}

#[cfg(unix)]
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            ensure_private_dir(parent)?;
        }
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("private-file");
    let tmp = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let mut created_tmp = false;
    let write_result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .open(&tmp)
            .with_context(|| format!("create private temp file {:?}", tmp))?;
        created_tmp = true;
        file.write_all(contents)
            .with_context(|| format!("write private temp file {:?}", tmp))?;
        file.sync_all()
            .with_context(|| format!("sync private temp file {:?}", tmp))?;
        drop(file);

        restrict_private_file(&tmp)?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename {:?} -> {:?}", tmp, path))?;
        fsync_parent(path)?;
        Ok(())
    })();

    if write_result.is_err() && created_tmp {
        let _ = std::fs::remove_file(&tmp);
    }

    write_result
}

pub(crate) fn copy_private_file(from: &Path, to: &Path) -> Result<()> {
    let contents = std::fs::read(from).with_context(|| format!("read private file {:?}", from))?;
    write_private_file(to, &contents).with_context(|| format!("copy {:?} -> {:?}", from, to))
}

#[derive(Debug)]
pub struct PrivateFileBackup {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

impl PrivateFileBackup {
    pub fn capture(path: PathBuf) -> Result<Self> {
        let contents = match std::fs::read(&path) {
            Ok(contents) => Some(contents),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("read backup file {:?}", path)),
        };
        Ok(Self { path, contents })
    }

    fn restore(&self) -> Result<()> {
        match &self.contents {
            Some(contents) => write_private_file(&self.path, contents)
                .with_context(|| format!("restore private file {:?}", self.path)),
            None => match std::fs::remove_file(&self.path) {
                Ok(()) => {
                    fsync_parent(&self.path)?;
                    Ok(())
                }
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
                Err(e) => {
                    Err(e).with_context(|| format!("remove created private file {:?}", self.path))
                }
            },
        }
    }
}

pub fn capture_private_files(
    paths: impl IntoIterator<Item = PathBuf>,
) -> Result<Vec<PrivateFileBackup>> {
    paths.into_iter().map(PrivateFileBackup::capture).collect()
}

pub fn restore_private_files(backups: &[PrivateFileBackup]) -> Result<()> {
    for backup in backups.iter().rev() {
        backup.restore()?;
    }
    Ok(())
}

#[cfg(test)]
mod rollback_tests {
    use super::{capture_private_files, restore_private_files, write_private_file};

    #[test]
    fn restore_private_files_restores_original_contents_and_removes_created_files() {
        let temp = tempfile::tempdir().expect("temp dir");
        let existing = temp.path().join("existing");
        let created = temp.path().join("created");

        write_private_file(&existing, b"old").expect("write old");
        let backups =
            capture_private_files([existing.clone(), created.clone()]).expect("capture backups");

        write_private_file(&existing, b"new").expect("write new");
        write_private_file(&created, b"created").expect("write created");

        restore_private_files(&backups).expect("restore backups");

        assert_eq!(std::fs::read(&existing).expect("read restored"), b"old");
        assert!(!created.exists());
    }
}

#[cfg(unix)]
pub fn acquire_file_lock(path: &Path) -> Result<VaultLock> {
    use std::os::fd::AsRawFd;
    use std::os::raw::c_int;
    use std::os::unix::fs::OpenOptionsExt;

    const LOCK_EX: c_int = 2;

    unsafe extern "C" {
        fn flock(fd: c_int, operation: c_int) -> c_int;
    }

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            ensure_private_dir(parent)?;
        }
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .with_context(|| format!("open lock file {:?}", path))?;

    // Blocking OS file lock. Released automatically when `file` is dropped,
    // including process exit/crash.
    let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("lock file {:?}", path));
    }

    Ok(VaultLock { _file: file })
}

/// Lock an existing writer's lock without creating files or changing source permissions.
pub fn acquire_existing_file_lock(path: &Path) -> Result<VaultLock> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    unsafe extern "C" {
        fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        bail!("source lock is not a regular file");
    }
    if unsafe { flock(file.as_raw_fd(), 2) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(VaultLock { _file: file })
}

#[cfg(not(unix))]
pub fn acquire_file_lock(path: &Path) -> Result<VaultLock> {
    let _ = path;
    unsupported_platform()
}

#[cfg(not(unix))]
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let _ = (path, contents);
    unsupported_platform()
}

impl Paths {
    pub fn load() -> Result<Self> {
        let data_dir = match std::env::var_os("FERUSA_DATA_DIR") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            Some(_) => bail!("FERUSA_DATA_DIR must name a directory"),
            None => dirs::data_dir()
                .context("cannot determine XDG data dir")?
                .join("ferusa"),
        };
        Ok(Self::from_data_dir(data_dir))
    }

    pub fn from_data_dir(data_dir: PathBuf) -> Self {
        Self {
            vault_enc: data_dir.join("vault.enc"),
            vault_salt: data_dir.join("vault.salt"),
            peer_id: data_dir.join("peer.id"),
            phone_id: data_dir.join("phone.id"),
            hmac_key: data_dir.join("hmac.key"),
            clipboard_cmd: data_dir.join("clipboard.cmd"),
            data_dir,
        }
    }

    pub fn ensure_data_dir(&self) -> Result<()> {
        ensure_private_dir(&self.data_dir)
    }

    pub fn vault_exists(&self) -> bool {
        self.vault_enc.exists()
    }

    pub fn pairing_status(&self) -> PairingStatus {
        if self.pending_pairing_state().exists() {
            return PairingStatus::Pending;
        }
        if self.pairing_transaction_state().exists() {
            return PairingStatus::Pending;
        }

        if self.pairing_state().exists() {
            return match self.read_pairing_data_from_state() {
                Ok(_) => PairingStatus::Ready,
                Err(PairingReadError::Phone(reason)) => PairingStatus::InvalidPhoneId(reason),
                Err(PairingReadError::State(reason)) => PairingStatus::InvalidPairing(reason),
            };
        }

        if self.phone_id.exists() || self.hmac_key.exists() {
            return PairingStatus::InvalidPairing(
                "legacy HMAC pairing files are unsupported; re-pair this dev vault".into(),
            );
        }

        PairingStatus::MissingPhoneId
    }

    pub fn has_pairing_data(&self) -> bool {
        matches!(self.pairing_status(), PairingStatus::Ready)
    }

    pub fn pairing_state(&self) -> PathBuf {
        self.data_dir.join("pairing.json")
    }

    pub fn pending_pairing_state(&self) -> PathBuf {
        self.data_dir.join("pending_pairing.json")
    }

    pub fn pairing_transaction_state(&self) -> PathBuf {
        self.data_dir.join("pairing_txn.json")
    }

    pub fn pending_vault_enc(&self) -> PathBuf {
        self.data_dir.join("pending_vault.enc")
    }

    pub fn rollback_vault_enc(&self) -> PathBuf {
        self.data_dir.join("rollback_vault.enc")
    }

    pub fn rollback_pairing_state(&self) -> PathBuf {
        self.data_dir.join("rollback_pairing.json")
    }

    pub fn vault_lock(&self) -> PathBuf {
        self.data_dir.join("vault.lock")
    }

    pub fn dev_2fa_stub_marker(&self) -> PathBuf {
        self.data_dir.join("dev-2fa-stub.json")
    }

    pub fn acquire_vault_lock(&self) -> Result<VaultLock> {
        acquire_file_lock(&self.vault_lock())
    }

    pub fn has_dev_2fa_stub_marker(&self) -> bool {
        self.dev_2fa_stub_marker().exists()
    }

    pub(crate) fn read_dev_2fa_stub_marker(&self) -> Result<DevTwofaStubMarker> {
        let raw = std::fs::read(self.dev_2fa_stub_marker()).context("read dev-2fa-stub.json")?;
        let marker: DevTwofaStubMarker =
            serde_json::from_slice(&raw).context("parse dev-2fa-stub.json")?;
        if marker.version != 1 {
            bail!("unsupported dev 2FA stub marker version {}", marker.version);
        }
        Ok(marker)
    }

    pub fn write_dev_2fa_stub_marker(&self) -> Result<()> {
        let marker = DevTwofaStubMarker {
            version: 1,
            warning: DEV_2FA_STUB_MARKER_WARNING.to_owned(),
        };
        let json = serde_json::to_vec_pretty(&marker).context("serialize dev 2FA stub marker")?;
        write_private_file(&self.dev_2fa_stub_marker(), &json).context("write dev-2fa-stub.json")
    }

    pub fn ensure_dev_2fa_stub_marker(&self) -> Result<()> {
        if !self.has_dev_2fa_stub_marker() {
            bail!("dev 2FA stub vault marker missing; refusing to use deterministic phone share");
        }
        self.read_dev_2fa_stub_marker().map(|_| ())
    }

    pub fn ensure_not_dev_2fa_stub_vault(&self) -> Result<()> {
        if self.has_dev_2fa_stub_marker() {
            bail!(
                "dev 2FA stub vault is not production-compatible; recreate the vault with real phone pairing"
            );
        }
        Ok(())
    }

    pub fn read_pairing_data(&self) -> Result<PairingData> {
        if self.pairing_state().exists() {
            return self
                .read_pairing_data_from_state()
                .map_err(PairingReadError::into_anyhow);
        }
        Err(anyhow::anyhow!("not paired with a phone"))
    }

    pub fn read_pending_pairing_data(&self) -> Result<PairingData> {
        let raw = super::recovery::read_metadata(&self.pending_pairing_state())
            .context("read pending_pairing.json")?;
        let file: PairingFile =
            serde_json::from_slice(&raw).context("parse pending_pairing.json")?;
        parse_pairing_file(file).map_err(PairingReadError::into_anyhow)
    }

    pub fn write_pairing_data(&self, data: &PairingData) -> Result<()> {
        let file = PairingFile {
            version: if data.credential_revision.is_some() {
                4
            } else {
                3
            },
            pairing_id: data.pairing_id,
            phone_node_id: hex::encode(data.phone_node_id.as_bytes()),
            approval_public_key_der: hex::encode(&data.approval_public_key_der),
            created_at_ms: data.created_at_ms,
            credential_revision: data.credential_revision,
            recovery_policy: data.credential_revision.map(|_| "required".to_owned()),
        };
        let json = serde_json::to_vec_pretty(&file).context("serialize pairing data")?;
        write_private_file(&self.pairing_state(), &json).context("write pairing.json")?;

        // Remove obsolete split files after the atomic state file is durable.
        if self.phone_id.exists() {
            let _ = std::fs::remove_file(&self.phone_id);
        }
        if self.hmac_key.exists() {
            let _ = std::fs::remove_file(&self.hmac_key);
        }
        Ok(())
    }

    pub fn write_pending_pairing_data(&self, data: &PairingData) -> Result<()> {
        let file = PairingFile {
            version: if data.credential_revision.is_some() {
                4
            } else {
                3
            },
            pairing_id: data.pairing_id,
            phone_node_id: hex::encode(data.phone_node_id.as_bytes()),
            approval_public_key_der: hex::encode(&data.approval_public_key_der),
            created_at_ms: data.created_at_ms,
            credential_revision: data.credential_revision,
            recovery_policy: data.credential_revision.map(|_| "required".to_owned()),
        };
        let json = serde_json::to_vec_pretty(&file).context("serialize pending pairing data")?;
        write_private_file(&self.pending_pairing_state(), &json)
            .context("write pending_pairing.json")
    }

    pub fn write_pairing_transaction_prepared(&self, pairing_id: Uuid) -> Result<()> {
        if self.pairing_transaction_state().exists() {
            bail!("pairing transaction already exists");
        }
        self.clear_rollback_pairing_files()?;
        let had_live_vault = self.vault_enc.exists();
        let had_live_pairing = self.pairing_state().exists();
        if had_live_vault {
            copy_private_file(&self.vault_enc, &self.rollback_vault_enc())
                .context("capture rollback vault")?;
        }
        if had_live_pairing {
            copy_private_file(&self.pairing_state(), &self.rollback_pairing_state())
                .context("capture rollback pairing")?;
        }
        self.write_pairing_transaction(PairingTxnFile {
            version: 2,
            phase: PairingTxnPhase::Prepared,
            pairing_id,
            had_live_vault,
            had_live_pairing,
            recovery: None,
        })
    }

    pub fn write_pairing_transaction_phone_committed(&self, pairing_id: Uuid) -> Result<()> {
        self.advance_pairing_transaction(PairingTxnPhase::PhoneCommitted, pairing_id)
    }

    pub fn write_pairing_transaction_locally_activated(&self, pairing_id: Uuid) -> Result<()> {
        self.advance_pairing_transaction(PairingTxnPhase::LocallyActivated, pairing_id)
    }

    pub fn write_pairing_transaction_fully_activated(&self, pairing_id: Uuid) -> Result<()> {
        self.advance_pairing_transaction(PairingTxnPhase::FullyActivated, pairing_id)
    }

    fn advance_pairing_transaction(&self, phase: PairingTxnPhase, pairing_id: Uuid) -> Result<()> {
        let mut file = self.read_pairing_transaction()?;
        if file.pairing_id != pairing_id {
            bail!("pairing transaction id mismatch");
        }
        if file.recovery.is_some()
            && !matches!(
                (file.phase, phase),
                (
                    PairingTxnPhase::CommitIntent,
                    PairingTxnPhase::PhoneCommitted
                ) | (
                    PairingTxnPhase::PhoneCommitted,
                    PairingTxnPhase::LocallyActivated
                ) | (
                    PairingTxnPhase::CommitIntent,
                    PairingTxnPhase::LocallyActivated
                ) | (
                    PairingTxnPhase::LocallyActivated,
                    PairingTxnPhase::FullyActivated
                )
            )
        {
            bail!("invalid credential transaction transition");
        }
        file.phase = phase;
        self.write_pairing_transaction(file)
    }

    pub(crate) fn write_pairing_transaction(&self, file: PairingTxnFile) -> Result<()> {
        let json = serde_json::to_vec_pretty(&file).context("serialize pairing transaction")?;
        write_private_file(&self.pairing_transaction_state(), &json)
            .context("write pairing_txn.json")
    }

    pub fn read_pairing_transaction(&self) -> Result<PairingTxnFile> {
        let raw = super::recovery::read_metadata(&self.pairing_transaction_state())?;
        let file: PairingTxnFile =
            serde_json::from_slice(&raw).context("parse pairing_txn.json")?;
        if !matches!(file.version, 2 | 3) || (file.version == 3) != file.recovery.is_some() {
            bail!("unsupported pairing transaction version {}", file.version);
        }
        if file.version == 3 {
            self.validate_recovery_transaction(&file)?;
        }
        Ok(file)
    }

    pub fn promote_pending_pairing(&self) -> Result<()> {
        let txn = self.read_pairing_transaction()?;
        if txn.recovery.is_some() {
            return self.promote_recovery_candidate(&txn);
        }
        if txn.phase != PairingTxnPhase::PhoneCommitted {
            bail!("phone commit acknowledgement required before local activation");
        }
        if txn.had_live_vault && !self.rollback_vault_enc().exists() {
            bail!("rollback vault missing before local activation");
        }
        if txn.had_live_pairing && !self.rollback_pairing_state().exists() {
            bail!("rollback pairing missing before local activation");
        }
        if self.pending_vault_enc().exists() {
            std::fs::rename(self.pending_vault_enc(), &self.vault_enc)
                .context("promote pending vault")?;
            fsync_parent(&self.vault_enc)?;
        } else if !self.vault_enc.exists() {
            bail!("pending and live vault missing during local activation");
        }
        if self.pending_pairing_state().exists() {
            std::fs::rename(self.pending_pairing_state(), self.pairing_state())
                .context("promote pending pairing")?;
            fsync_parent(&self.pairing_state())?;
        } else if !self.pairing_state().exists() {
            bail!("pending and live pairing missing during local activation");
        }
        Ok(())
    }

    pub fn clear_pending_pairing(&self) -> Result<()> {
        for path in [
            self.pending_pairing_state(),
            self.pending_vault_enc(),
            self.pairing_transaction_state(),
            self.rollback_pairing_state(),
            self.rollback_vault_enc(),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => fsync_parent(&path)?,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("remove pending file {:?}", path)),
            }
        }
        Ok(())
    }

    fn clear_rollback_pairing_files(&self) -> Result<()> {
        for path in [self.rollback_pairing_state(), self.rollback_vault_enc()] {
            match std::fs::remove_file(&path) {
                Ok(()) => fsync_parent(&path)?,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("remove rollback file {:?}", path))
                }
            }
        }
        Ok(())
    }

    pub fn recover_pairing_transaction(&self) -> Result<()> {
        if !self.pairing_transaction_state().exists() {
            if self.pending_pairing_state().exists()
                || self.pending_vault_enc().exists()
                || self.rollback_pairing_state().exists()
                || self.rollback_vault_enc().exists()
            {
                self.clear_pending_pairing()
                    .context("clear stale untracked pending pairing")?;
            }
            return Ok(());
        }

        let txn = self.read_pairing_transaction()?;
        if txn.recovery.is_some() {
            return self.recover_credential_transaction(&txn);
        }
        match txn.phase {
            PairingTxnPhase::Preparing
            | PairingTxnPhase::CandidatePrepared
            | PairingTxnPhase::RecoveryVerified
            | PairingTxnPhase::CommitIntent => bail!("invalid legacy transaction phase"),
            PairingTxnPhase::Prepared | PairingTxnPhase::LocallyActivated => {}
            PairingTxnPhase::PhoneCommitted => {
                self.promote_pending_pairing()
                    .context("finish pairing transaction promotion")?;
                self.write_pairing_transaction_locally_activated(txn.pairing_id)
                    .context("mark pairing transaction locally activated")?;
            }
            PairingTxnPhase::FullyActivated => {
                self.clear_pending_pairing()
                    .context("clear fully activated pairing transaction")?;
            }
        }
        Ok(())
    }

    fn read_pairing_data_from_state(&self) -> std::result::Result<PairingData, PairingReadError> {
        let raw = super::recovery::read_metadata(&self.pairing_state())
            .map_err(|e| PairingReadError::State(e.to_string()))?;
        let file: PairingFile =
            serde_json::from_slice(&raw).map_err(|e| PairingReadError::State(e.to_string()))?;
        parse_pairing_file(file)
    }
}

enum PairingReadError {
    Phone(String),
    State(String),
}

impl PairingReadError {
    fn into_anyhow(self) -> anyhow::Error {
        match self {
            Self::Phone(reason) => anyhow::anyhow!("invalid phone id: {reason}"),
            Self::State(reason) => anyhow::anyhow!("invalid pairing state: {reason}"),
        }
    }
}

fn parse_pairing_file(file: PairingFile) -> std::result::Result<PairingData, PairingReadError> {
    if !matches!(file.version, 3 | 4)
        || (file.version == 4
            && (file.credential_revision.is_none_or(|id| id.is_nil())
                || file.recovery_policy.as_deref() != Some("required")))
        || (file.version == 3
            && (file.credential_revision.is_some() || file.recovery_policy.is_some()))
        || file.pairing_id.is_nil()
    {
        return Err(PairingReadError::State(format!(
            "unsupported version {}",
            file.version
        )));
    }

    let phone_bytes = hex::decode(file.phone_node_id.trim())
        .map_err(|e| PairingReadError::Phone(format!("invalid hex: {e}")))?;
    if phone_bytes.len() != 32 {
        return Err(PairingReadError::Phone(format!(
            "expected 32 bytes, got {}",
            phone_bytes.len()
        )));
    }
    let mut phone_arr = [0u8; 32];
    phone_arr.copy_from_slice(&phone_bytes);
    let phone_node_id = iroh::PublicKey::from_bytes(&phone_arr)
        .map_err(|e| PairingReadError::Phone(format!("invalid node id: {e}")))?;

    let approval_public_key_der = hex::decode(file.approval_public_key_der.trim())
        .map_err(|e| PairingReadError::State(format!("invalid public key hex: {e}")))?;
    if approval_public_key_der.is_empty() {
        return Err(PairingReadError::State("empty approval public key".into()));
    }

    Ok(PairingData {
        pairing_id: file.pairing_id,
        phone_node_id,
        approval_public_key_der,
        created_at_ms: file.created_at_ms,
        credential_revision: file.credential_revision,
    })
}
