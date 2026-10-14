//! Linux-only recovery storage capability. Unknown backing layouts fail closed.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use rustix::fs::{openat, statx, syncfs, AtFlags, Mode, OFlags, StatxFlags, CWD};
use thiserror::Error;
use uuid::Uuid;

use ferusa_core::recovery::RECOVERY_FILE_LEN;

#[derive(Debug, Error)]
pub enum ExternalError {
    #[error("unsupported storage topology: {0}")]
    UnsupportedTopology(String),
    #[error("recovery destination is not positively identified USB storage")]
    NotExternal,
    #[error(
        "recovery storage shares a physical device with system, home, vault, or backup storage"
    )]
    SamePhysicalDevice,
    #[error("recovery mount or backing device changed during the operation")]
    MountChanged,
    #[error("recovery filesystem durability could not be established: {0}")]
    DurabilityUnavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    mount_id: u64,
    device: (u32, u32),
    inode: u64,
}

#[derive(Clone, Debug)]
struct Topology {
    identity: Identity,
    leaves: HashSet<PathBuf>,
    filesystem: String,
    usb: bool,
}

pub struct ExternalDestination {
    directory: File,
    path: PathBuf,
    topology: Topology,
    protected_paths: Vec<PathBuf>,
}

/// Open every component without following symbolic links, including the final one.
pub fn open_no_symlinks(path: &Path, directory: bool) -> Result<File> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut opened: File = openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let components: Vec<_> = absolute.components().collect();
    for (index, component) in components.iter().enumerate() {
        let name = match component {
            Component::Normal(name) => name,
            Component::RootDir | Component::CurDir => continue,
            _ => bail!("path contains traversal or an unsupported component"),
        };
        let last = index == components.len() - 1;
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if !last || directory {
            flags |= OFlags::DIRECTORY;
        } else {
            flags |= OFlags::NONBLOCK;
        }
        opened = openat(&opened, *name, flags, Mode::empty())
            .with_context(|| format!("open path component {:?}", name))?
            .into();
    }
    let meta = opened.metadata()?;
    if directory && !meta.is_dir() || !directory && !meta.is_file() {
        bail!(
            "path is not a {}",
            if directory {
                "directory"
            } else {
                "regular file"
            }
        );
    }
    Ok(opened)
}

fn identity(file: &File) -> Result<Identity> {
    let stat = statx(
        file,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::MNT_ID | StatxFlags::BASIC_STATS,
    )
    .context("read mount identity")?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 || stat.stx_mnt_id == 0 {
        return Err(
            ExternalError::UnsupportedTopology("kernel does not report mount ID".into()).into(),
        );
    }
    Ok(Identity {
        mount_id: stat.stx_mnt_id,
        device: (stat.stx_dev_major, stat.stx_dev_minor),
        inode: stat.stx_ino,
    })
}

fn mount_fields(mountinfo: &str, mount_id: u64) -> Result<((u32, u32), String)> {
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<_> = left.split_ascii_whitespace().collect();
        if fields.len() < 6 || fields[0].parse::<u64>().ok() != Some(mount_id) {
            continue;
        }
        let Some((major, minor)) = fields[2].split_once(':') else {
            break;
        };
        let fs = right
            .split_ascii_whitespace()
            .next()
            .context("mountinfo filesystem missing")?;
        return Ok(((major.parse()?, minor.parse()?), fs.to_owned()));
    }
    Err(ExternalError::UnsupportedTopology("mount ID absent from mountinfo".into()).into())
}

fn is_usb_disk(disk: &Path) -> bool {
    let mut cursor = Some(disk);
    while let Some(path) = cursor {
        if fs::read_link(path.join("subsystem"))
            .ok()
            .and_then(|target| target.file_name().map(|name| name == "usb"))
            .unwrap_or(false)
        {
            return true;
        }
        cursor = path.parent();
    }
    false
}

fn backing_disks(sysroot: &Path, device: (u32, u32)) -> Result<(HashSet<PathBuf>, bool)> {
    let mut pending = vec![(device, 0usize, false)];
    let mut active = HashSet::new();
    let mut seen = HashSet::new();
    let mut leaves = HashSet::new();
    let mut all_usb = true;
    while let Some(((major, minor), depth, leaving)) = pending.pop() {
        if leaving {
            active.remove(&(major, minor));
            continue;
        }
        if active.contains(&(major, minor)) {
            return Err(
                ExternalError::UnsupportedTopology("cycle in backing-device graph".into()).into(),
            );
        }
        if depth > 32 || (seen.len() >= 256 && !seen.contains(&(major, minor))) {
            return Err(ExternalError::UnsupportedTopology(
                "backing-device graph exceeds limit".into(),
            )
            .into());
        }
        if !seen.insert((major, minor)) {
            continue;
        }
        active.insert((major, minor));
        pending.push(((major, minor), depth, true));
        let node = fs::canonicalize(sysroot.join("dev/block").join(format!("{major}:{minor}")))
            .with_context(|| format!("resolve block device {major}:{minor}"))?;
        let disk = if node.join("partition").exists() {
            node.parent()
                .context("partition has no disk parent")?
                .to_path_buf()
        } else {
            node.clone()
        };
        let slaves = disk.join("slaves");
        let entries = fs::read_dir(&slaves)
            .with_context(|| format!("inspect backing devices of {:?}", disk))?;
        let mut found_slave = false;
        for entry in entries {
            let child = entry?;
            let raw = fs::read_to_string(child.path().join("dev"))
                .or_else(|_| fs::read_to_string(fs::canonicalize(child.path())?.join("dev")))?;
            let (major, minor) = raw
                .trim()
                .split_once(':')
                .context("invalid slave device number")?;
            pending.push(((major.parse()?, minor.parse()?), depth + 1, false));
            found_slave = true;
        }
        if !found_slave {
            if !disk.join("dev").exists() {
                return Err(ExternalError::UnsupportedTopology(
                    "backing disk has no device number".into(),
                )
                .into());
            }
            if disk.components().any(|part| part.as_os_str() == "virtual") {
                return Err(ExternalError::UnsupportedTopology(
                    "unresolved virtual block device".into(),
                )
                .into());
            }
            all_usb &= is_usb_disk(&disk);
            leaves.insert(disk);
        }
    }
    if leaves.is_empty() {
        return Err(ExternalError::UnsupportedTopology("no physical backing disk".into()).into());
    }
    Ok((leaves, all_usb))
}

fn topology(file: &File, mountinfo: &str, sysroot: &Path) -> Result<Topology> {
    let id = identity(file)?;
    let (mount_device, filesystem) = mount_fields(mountinfo, id.mount_id)?;
    if !matches!(filesystem.as_str(), "ext4" | "vfat" | "exfat") {
        return Err(ExternalError::UnsupportedTopology(format!(
            "filesystem {filesystem} has no validated physical-device resolver"
        ))
        .into());
    }
    if mount_device != id.device {
        return Err(ExternalError::UnsupportedTopology(
            "mount device number disagrees with descriptor".into(),
        )
        .into());
    }
    let (leaves, usb) = backing_disks(sysroot, mount_device)?;
    Ok(Topology {
        identity: id,
        leaves,
        filesystem,
        usb,
    })
}

fn current_topology(file: &File) -> Result<Topology> {
    let mounts = fs::read_to_string("/proc/self/mountinfo").context("read mountinfo")?;
    topology(file, &mounts, Path::new("/sys"))
}

fn existing_parent(path: &Path) -> Result<PathBuf> {
    let mut cursor = path;
    while !cursor.is_dir() {
        cursor = cursor.parent().context("no existing parent directory")?;
    }
    Ok(cursor.to_path_buf())
}

fn open_protected_path(path: &Path) -> Result<File> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => open_no_symlinks(path, false),
        Ok(metadata) if metadata.is_dir() => open_no_symlinks(path, true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            open_no_symlinks(&existing_parent(path)?, true)
        }
        Err(error) => Err(error.into()),
        _ => Err(ExternalError::UnsupportedTopology(
            "protected storage path is not a regular file or directory".into(),
        )
        .into()),
    }
}

impl ExternalDestination {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn open(path: &Path, vault_path: &Path, known_backup_paths: &[PathBuf]) -> Result<Self> {
        let directory = open_no_symlinks(path, true)?;
        let topology = current_topology(&directory)?;
        if !topology.usb {
            return Err(ExternalError::NotExternal.into());
        }
        if !matches!(topology.filesystem.as_str(), "ext4" | "vfat" | "exfat") {
            return Err(ExternalError::UnsupportedTopology(format!(
                "recovery destination filesystem {} is not supported",
                topology.filesystem
            ))
            .into());
        }
        let mut protected_paths = vec![
            PathBuf::from("/"),
            dirs::home_dir().context("home directory unavailable")?,
            existing_parent(vault_path)?,
            vault_path.to_owned(),
        ];
        protected_paths.extend(known_backup_paths.iter().cloned());
        for protected in &protected_paths {
            let opened = open_protected_path(protected)?;
            let other = current_topology(&opened)?;
            if !topology.leaves.is_disjoint(&other.leaves) {
                return Err(ExternalError::SamePhysicalDevice.into());
            }
        }
        Ok(Self {
            directory,
            path: if path.is_absolute() {
                path.to_owned()
            } else {
                std::env::current_dir()?.join(path)
            },
            topology,
            protected_paths,
        })
    }

    pub fn revalidate(&self) -> Result<()> {
        let current = current_topology(&self.directory)?;
        let reopened = open_no_symlinks(&self.path, true)?;
        let path_now = current_topology(&reopened)?;
        if current.identity != self.topology.identity
            || path_now.identity != self.topology.identity
            || current.leaves != self.topology.leaves
            || !current.usb
            || current.filesystem != self.topology.filesystem
        {
            return Err(ExternalError::MountChanged.into());
        }
        for protected in &self.protected_paths {
            let opened = open_protected_path(protected)?;
            if !current
                .leaves
                .is_disjoint(&current_topology(&opened)?.leaves)
            {
                return Err(ExternalError::SamePhysicalDevice.into());
            }
        }
        Ok(())
    }

    pub fn write_recovery(
        &self,
        file_id: Uuid,
        bytes: &[u8; RECOVERY_FILE_LEN],
    ) -> Result<PathBuf> {
        self.revalidate()?;
        let name = format!("ferusa-recovery-{file_id}.frb");
        write_and_read_back(&self.directory, &name, bytes, || self.revalidate())?;
        self.revalidate()?;
        Ok(self.path.join(name))
    }
}

fn write_and_read_back(
    directory: &File,
    name: &str,
    bytes: &[u8; RECOVERY_FILE_LEN],
    mut check: impl FnMut() -> Result<()>,
) -> Result<()> {
    check()?;
    let mut file: File = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from(0o600),
    )?
    .into();
    let created = file.metadata()?;
    if !created.is_file() || created.nlink() != 1 || created.dev() != directory.metadata()?.dev() {
        bail!("created recovery file has unexpected identity");
    }
    file.write_all(bytes).context("write recovery file")?;
    file.sync_all().context("sync recovery file")?;
    drop(file);
    if let Err(error) = directory.sync_all() {
        if !matches!(error.raw_os_error(), Some(code) if code == rustix::io::Errno::INVAL.raw_os_error() || code == rustix::io::Errno::OPNOTSUPP.raw_os_error())
        {
            return Err(error).context("sync recovery directory");
        }
        syncfs(directory).map_err(|fallback| {
            ExternalError::DurabilityUnavailable(format!(
                "directory sync: {error}; filesystem sync: {fallback}"
            ))
        })?;
    }
    check()?;
    let mut reopened: File = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let reopened_meta = reopened.metadata()?;
    if !reopened_meta.is_file()
        || reopened_meta.ino() != created.ino()
        || reopened_meta.dev() != created.dev()
        || reopened_meta.nlink() != 1
    {
        bail!("recovery file changed during read-back");
    }
    let mut readback = Vec::new();
    (&mut reopened)
        .take((RECOVERY_FILE_LEN + 1) as u64)
        .read_to_end(&mut readback)?;
    if readback.as_slice() != bytes {
        bail!("recovery file read-back differs from written bytes");
    }
    check()?;
    Ok(())
}

pub fn require_separate_sources(recovery: &File, vault: &File) -> Result<()> {
    let recovery_topology = current_topology(recovery)?;
    let vault_topology = current_topology(vault)?;
    if !recovery_topology.leaves.is_disjoint(&vault_topology.leaves) {
        return Err(ExternalError::SamePhysicalDevice.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_vault_descriptor_identifies_the_file_not_its_parent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.enc");
        fs::write(&path, b"vault").unwrap();
        let opened = open_protected_path(&path).unwrap();
        assert!(opened.metadata().unwrap().is_file());
        assert_eq!(
            opened.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
    }

    #[test]
    fn multi_device_and_unresolved_filesystems_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let opened = open_no_symlinks(directory.path(), true).unwrap();
        let id = identity(&opened).unwrap();
        for filesystem in ["btrfs", "zfs", "nfs", "fuse", "tmpfs"] {
            let mounts = format!(
                "{} 1 {}:{} / /test rw - {filesystem} /dev/test rw",
                id.mount_id, id.device.0, id.device.1
            );
            let error = topology(&opened, &mounts, Path::new("/sys")).unwrap_err();
            assert!(error
                .to_string()
                .contains("no validated physical-device resolver"));
        }
    }

    #[test]
    fn mountinfo_uses_mount_id_including_bind_mounts() {
        let data = "42 1 8:2 /sub\\040dir /mnt/usb\\040space rw - ext4 /dev/sda2 rw\n43 1 8:2 / /mnt/bind rw - ext4 /dev/sda2 rw";
        assert_eq!(mount_fields(data, 42).unwrap(), ((8, 2), "ext4".into()));
        assert_eq!(mount_fields(data, 43).unwrap(), ((8, 2), "ext4".into()));
        assert!(mount_fields(data, 44).is_err());
    }

    #[test]
    fn no_symlink_components_or_traversal() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("real")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        assert!(open_no_symlinks(&dir.path().join("link"), true).is_err());
        assert!(open_no_symlinks(&dir.path().join("real/../real"), true).is_err());
        assert!(open_no_symlinks(&dir.path().join("./real"), true).is_ok());
    }

    #[test]
    fn partitions_and_mapper_slaves_collapse_to_one_usb_disk() {
        let root = tempfile::tempdir().unwrap();
        let sys = root.path();
        let usb = sys.join("devices/pci/usb1/1-2");
        let disk = usb.join("block/sdx");
        fs::create_dir_all(disk.join("slaves")).unwrap();
        fs::create_dir_all(disk.join("sdx1")).unwrap();
        fs::create_dir_all(disk.join("sdx2")).unwrap();
        fs::write(disk.join("dev"), "8:16").unwrap();
        fs::write(disk.join("sdx1/partition"), "1").unwrap();
        fs::write(disk.join("sdx1/dev"), "8:17").unwrap();
        fs::write(disk.join("sdx2/partition"), "2").unwrap();
        fs::write(disk.join("sdx2/dev"), "8:18").unwrap();
        fs::create_dir_all(sys.join("bus/usb")).unwrap();
        std::os::unix::fs::symlink(sys.join("bus/usb"), usb.join("subsystem")).unwrap();
        fs::create_dir_all(sys.join("dev/block")).unwrap();
        std::os::unix::fs::symlink(disk.join("sdx1"), sys.join("dev/block/8:17")).unwrap();
        std::os::unix::fs::symlink(disk.join("sdx2"), sys.join("dev/block/8:18")).unwrap();
        let mapper = sys.join("devices/virtual/block/dm-0");
        fs::create_dir_all(mapper.join("slaves")).unwrap();
        fs::write(mapper.join("dev"), "253:0").unwrap();
        std::os::unix::fs::symlink(disk.join("sdx2"), mapper.join("slaves/sdx2")).unwrap();
        std::os::unix::fs::symlink(&mapper, sys.join("dev/block/253:0")).unwrap();
        let (first, usb_first) = backing_disks(sys, (8, 17)).unwrap();
        let (second, usb_second) = backing_disks(sys, (8, 18)).unwrap();
        let (mapped, usb_mapped) = backing_disks(sys, (253, 0)).unwrap();
        assert_eq!(first, second);
        assert_eq!(second, mapped);
        assert!(usb_first && usb_second && usb_mapped);
    }

    #[test]
    fn cyclic_backing_devices_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let sys = root.path();
        let mapper = sys.join("devices/virtual/block/dm-0");
        fs::create_dir_all(mapper.join("slaves")).unwrap();
        fs::create_dir_all(sys.join("dev/block")).unwrap();
        fs::write(mapper.join("dev"), "253:0").unwrap();
        std::os::unix::fs::symlink(&mapper, mapper.join("slaves/dm-0")).unwrap();
        std::os::unix::fs::symlink(&mapper, sys.join("dev/block/253:0")).unwrap();
        assert!(backing_disks(sys, (253, 0))
            .unwrap_err()
            .to_string()
            .contains("cycle in backing-device graph"));
    }

    #[test]
    fn real_same_device_sources_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("recovery.frb");
        let second = root.path().join("vault.enc");
        fs::write(&first, b"file").unwrap();
        fs::write(&second, b"vault").unwrap();
        let first = open_no_symlinks(&first, false).unwrap();
        let second = open_no_symlinks(&second, false).unwrap();
        assert!(require_separate_sources(&first, &second).is_err());
    }

    #[test]
    fn direct_writer_preserves_existing_files_and_rejects_symlink() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_no_symlinks(root.path(), true).unwrap();
        let bytes = [0x5a; RECOVERY_FILE_LEN];
        write_and_read_back(&directory, "first.frb", &bytes, || Ok(())).unwrap();
        assert_eq!(fs::read(root.path().join("first.frb")).unwrap(), bytes);
        assert!(
            write_and_read_back(&directory, "first.frb", &[0; RECOVERY_FILE_LEN], || Ok(()))
                .is_err()
        );
        assert_eq!(fs::read(root.path().join("first.frb")).unwrap(), bytes);
        std::os::unix::fs::symlink("first.frb", root.path().join("link.frb")).unwrap();
        assert!(write_and_read_back(&directory, "link.frb", &bytes, || Ok(())).is_err());
    }

    #[test]
    fn direct_writer_stops_on_revalidation_failure() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_no_symlinks(root.path(), true).unwrap();
        let mut calls = 0;
        let result = write_and_read_back(&directory, "failed.frb", &[7; RECOVERY_FILE_LEN], || {
            calls += 1;
            if calls == 2 {
                bail!("injected mount change")
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(root.path().join("failed.frb")).unwrap(),
            [7; RECOVERY_FILE_LEN]
        );
    }

    #[test]
    #[ignore = "requires a disposable mounted USB and FERUSA_USB_TEST_DIR"]
    fn real_usb_write_sync_and_readback() {
        let selected = std::env::var_os("FERUSA_USB_TEST_DIR").expect("FERUSA_USB_TEST_DIR");
        let directory = PathBuf::from(selected);
        let vault = std::env::current_dir()
            .unwrap()
            .join("target/test-vault.enc");
        let destination = ExternalDestination::open(&directory, &vault, &[]).unwrap();
        let bytes = [0x93; RECOVERY_FILE_LEN];
        let file = destination.write_recovery(Uuid::new_v4(), &bytes).unwrap();
        assert_eq!(fs::read(&file).unwrap(), bytes);
        if std::env::var_os("FERUSA_USB_KEEP_TEST_FILE").is_some() {
            eprintln!("retained test file: {}", file.display());
        } else {
            fs::remove_file(file).unwrap();
        }
        destination.directory.sync_all().unwrap();
    }

    #[test]
    #[ignore = "requires a disposable mounted USB and FERUSA_USB_TEST_DIR"]
    fn real_usb_recovery_envelope_opens_separate_vault() {
        use ferusa_core::crypto::{combine_vault_key, derive_local_secret, encrypt_vault};
        use ferusa_core::recovery::{open_recovery, seal_recovery, RecoveryMaterial};
        use ferusa_core::types::Vault;
        use zeroize::Zeroizing;

        let selected = std::env::var_os("FERUSA_USB_TEST_DIR").expect("FERUSA_USB_TEST_DIR");
        let directory = PathBuf::from(selected);
        let laptop = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let vault_path = laptop.path().join("vault.enc");
        let password = b"hardware test master password";
        let share = [0x6b; 32];
        let salt = [0x72; 16];
        let local = Zeroizing::new(derive_local_secret(password, &salt).unwrap());
        let key = Zeroizing::new(combine_vault_key(&local, &share).unwrap());
        let vault =
            encrypt_vault(&key, salt, &serde_json::to_vec(&Vault::default()).unwrap()).unwrap();
        fs::write(&vault_path, vault.to_bytes()).unwrap();

        let material = RecoveryMaterial {
            file_id: Uuid::new_v4(),
            created_at_ms: 1_700_000_000_000,
            pairing_id: Uuid::new_v4(),
            phone_share: Zeroizing::new(share),
        };
        let envelope = seal_recovery(&material, password, "0012", "000345").unwrap();
        let destination = ExternalDestination::open(&directory, &vault_path, &[]).unwrap();
        let written = destination
            .write_recovery(material.file_id, &envelope)
            .unwrap();
        let recovery_file = open_no_symlinks(&written, false).unwrap();
        let vault_file = open_no_symlinks(&vault_path, false).unwrap();
        require_separate_sources(&recovery_file, &vault_file).unwrap();
        let recovered =
            open_recovery(&fs::read(&written).unwrap(), password, "0012", "000345").unwrap();
        let loaded = crate::storage::vault::read_vault_blob(&vault_file).unwrap();
        assert!(crate::storage::vault::open_vault_with_share(
            &loaded,
            password,
            &recovered.phone_share
        )
        .is_ok());
        assert!(
            crate::storage::vault::open_vault_with_share(&loaded, password, &[0x6c; 32]).is_err()
        );
        drop(recovery_file);
        fs::remove_file(&written).unwrap();
        destination.directory.sync_all().unwrap();
    }
}
