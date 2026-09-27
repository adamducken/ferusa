use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use ferusa_core::crypto::{
    combine_vault_key, decrypt_vault, derive_local_secret, EncryptedBlob, VAULT_BLOB_OVERHEAD_BYTES,
};
use ferusa_core::types::{Vault, MAX_VAULT_PLAINTEXT_BYTES};

pub const MAX_VAULT_ENCRYPTED_BYTES: usize = MAX_VAULT_PLAINTEXT_BYTES + VAULT_BLOB_OVERHEAD_BYTES;

pub fn read_vault_blob(file: &File) -> Result<EncryptedBlob> {
    let mut bytes = Vec::new();
    file.take(MAX_VAULT_ENCRYPTED_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read encrypted vault")?;
    if bytes.len() > MAX_VAULT_ENCRYPTED_BYTES {
        bail!("encrypted size limit exceeded: {MAX_VAULT_ENCRYPTED_BYTES} bytes");
    }
    EncryptedBlob::from_bytes(&bytes).context("parse encrypted vault")
}

pub fn load_vault_blob(path: &Path) -> Result<EncryptedBlob> {
    read_vault_blob(&File::open(path).with_context(|| format!("open vault {:?}", path))?)
}

pub fn decrypt_vault_blob(blob: &EncryptedBlob, vault_key: &[u8; 32]) -> Result<Vault> {
    let plaintext = Zeroizing::new(decrypt_vault(vault_key, blob).context("decrypt vault")?);
    if plaintext.len() > MAX_VAULT_PLAINTEXT_BYTES {
        bail!(
            "decrypted vault exceeds the {} MiB limit",
            MAX_VAULT_PLAINTEXT_BYTES / (1024 * 1024)
        );
    }
    let mut vault =
        Zeroizing::new(serde_json::from_slice::<Vault>(&plaintext).context("parse vault data")?);
    vault.validate().map_err(anyhow::Error::msg)?;
    Ok(std::mem::take(&mut *vault))
}

pub fn open_vault_with_share(
    blob: &EncryptedBlob,
    password: &[u8],
    share: &[u8; 32],
) -> Result<Vault> {
    let local = Zeroizing::new(
        derive_local_secret(password, &blob.salt()).context("derive vault local factor")?,
    );
    let key = Zeroizing::new(combine_vault_key(&local, share).context("combine vault factors")?);
    decrypt_vault_blob(blob, &key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferusa_core::crypto::encrypt_vault;
    use ferusa_core::recovery::{open_recovery, seal_recovery, RecoveryMaterial};
    use uuid::Uuid;

    #[test]
    fn recovery_share_opens_compatible_vault_with_separate_newer_password() {
        let share = [0x71; 32];
        let material = RecoveryMaterial {
            file_id: Uuid::new_v4(),
            created_at_ms: 123,
            pairing_id: Uuid::new_v4(),
            phone_share: Zeroizing::new(share),
        };
        let recovery = seal_recovery(&material, b"old master", "0012", "000345").unwrap();
        let opened = open_recovery(&recovery, b"old master", "0012", "000345").unwrap();
        let salt = [0x3a; 16];
        let local = Zeroizing::new(derive_local_secret(b"new master", &salt).unwrap());
        let key = Zeroizing::new(combine_vault_key(&local, &share).unwrap());
        let plaintext = serde_json::to_vec(&Vault::default()).unwrap();
        let vault = encrypt_vault(&key, salt, &plaintext).unwrap();
        assert!(open_vault_with_share(&vault, b"old master", &opened.phone_share).is_err());
        assert!(open_vault_with_share(&vault, b"new master", &[0x72; 32]).is_err());
        assert!(open_vault_with_share(&vault, b"new master", &opened.phone_share).is_ok());
    }
}
