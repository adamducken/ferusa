use anyhow::{bail, Context, Result};
use argon2::password_hash::PasswordHash;
use ferusa_core::crypto::{canonical_pairing_ready_payload, verify_pairing_ready_signature};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};
use tokio::task;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::state::PinKind;
use ferusa_core::enrollment::{
    EnrollmentContext, EnrollmentPrepared, EnrollmentTransition, RecoveryReference,
};
use ferusa_core::recovery::{
    canonical_recovery_finished, verify_recovery_signature, RecoveryFinished,
};

const ACTIVE_PAIRING_GENERATION: &str = "active_pairing_generation";
const STAGING_PAIRING_GENERATION: &str = "staging_pairing_generation";
const PENDING_PAIRING_GENERATION: &str = "pending_pairing_generation";
const COMMITTED_PAIRING_GENERATION: &str = "committed_pairing_generation";
const RETIRING_PAIRING_GENERATION: &str = "retiring_pairing_generation";
const PAIRING_GENERATION_VERSION: u8 = 1;
const PAIRING_GENERATION_PREFIX: &str = "pairing_generation:";

#[cfg(test)]
const PAIRING_METADATA_KEYS: &[&str] = &[
    ACTIVE_PAIRING_GENERATION,
    STAGING_PAIRING_GENERATION,
    PENDING_PAIRING_GENERATION,
    COMMITTED_PAIRING_GENERATION,
    RETIRING_PAIRING_GENERATION,
];

#[cfg(test)]
const LEGACY_PAIRING_KEYS: &[&str] = &[
    "pairing_id",
    "approval_key_alias",
    "approval_public_key_der",
    "phone_share",
    "pin4_hash",
    "pin6_hash",
    "pin4_attempt_state",
    "pin6_attempt_state",
    "cli_node_id",
    "is_setup",
    "pending_pairing_id",
    "pending_approval_key_alias",
    "pending_approval_public_key_der",
    "pending_phone_share",
    "pending_pin4_hash",
    "pending_pin6_hash",
    "pending_cli_node_id",
    "pending_pairing_committed",
];

#[cfg(test)]
const KEYS_TO_CLEAR_ON_RESET: &[&str] = &["pin4_attempt_state", "pin6_attempt_state"];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinAttemptState {
    pub failed_attempts: u8,
    pub cooldown_level: u8,
    /// Legacy wall-clock deadline, retained only for backward-compatible decoding.
    pub cooldown_until_ms: Option<u64>,
    #[serde(default)]
    pub cooldown_started_elapsed_ms: Option<u64>,
    #[serde(default)]
    pub cooldown_boot_count: Option<u64>,
    #[serde(default)]
    pub cooldown_duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAttemptStateWrite {
    Save,
    Clear,
}

fn pin_attempt_key(kind: PinKind) -> &'static str {
    match kind {
        PinKind::FourDigit => "pin4_attempt_state",
        PinKind::SixDigit => "pin6_attempt_state",
    }
}
static STORAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

fn lock_storage(lock: &std::sync::Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("[ferusa:app]: STORAGE_LOCK was poisoned; recovering inner guard instead of panicking");
            poisoned.into_inner()
        }
    }
}

fn storage_guard() -> std::sync::MutexGuard<'static, ()> {
    lock_storage(&STORAGE_LOCK)
}

fn save_entry<R: Runtime>(app: &AppHandle<R>, key: &str, value: &str) -> Result<()> {
    debug!("[ferusa:app]: save_entry key={} (Android Keystore)", key);
    tauri_plugin_keystore::set_secret(app, key, value)
        .map_err(|e| anyhow::anyhow!(e))
        .context("set Android Keystore secret")
}

fn get_entry<R: Runtime>(app: &AppHandle<R>, key: &str) -> Result<Option<String>> {
    debug!("[ferusa:app]: get_entry key={} (Android Keystore)", key);
    let result = tauri_plugin_keystore::get_secret(app, key)
        .map_err(|e| anyhow::anyhow!(e))
        .context("get Android Keystore secret")?;
    debug!(
        "[ferusa:app]: get_entry key={} found={}",
        key,
        result.is_some()
    );
    Ok(result)
}

fn delete_entry<R: Runtime>(app: &AppHandle<R>, key: &str) -> Result<()> {
    debug!("[ferusa:app]: delete_entry key={} (Android Keystore)", key);
    tauri_plugin_keystore::delete_secret(app, key)
        .map_err(|e| anyhow::anyhow!(e))
        .context("delete Android Keystore secret")
}

fn delete_approval_key<R: Runtime>(app: &AppHandle<R>, alias: &str) -> Result<()> {
    debug!(
        "[ferusa:app]: delete_approval_key alias={} (Android Keystore)",
        alias
    );
    tauri_plugin_keystore::delete_approval_key(app, alias)
        .map_err(|e| anyhow::anyhow!(e))
        .context("delete Android approval key")
}

trait PairingStore {
    fn save(&self, key: &str, value: &str) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn delete(&self, key: &str) -> Result<()>;
    fn sign(&self, alias: &str, payload: &[u8]) -> Result<Vec<u8>>;
    fn delete_approval_key(&self, alias: &str) -> Result<()>;
}

struct AppPairingStore<'a, R: Runtime>(&'a AppHandle<R>);

impl<R: Runtime> PairingStore for AppPairingStore<'_, R> {
    fn save(&self, key: &str, value: &str) -> Result<()> {
        save_entry(self.0, key, value)
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        get_entry(self.0, key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        delete_entry(self.0, key)
    }

    fn sign(&self, alias: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let payload_hex = Zeroizing::new(hex::encode(payload));
        let sig_hex = Zeroizing::new(
            tauri_plugin_keystore::sign_approval(self.0, alias, &payload_hex)
                .map_err(|e| anyhow::anyhow!(e))
                .context("sign approval")?,
        );
        hex::decode(&*sig_hex).context("decode approval signature")
    }

    fn delete_approval_key(&self, alias: &str) -> Result<()> {
        delete_approval_key(self.0, alias)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct PairingGeneration {
    #[zeroize(skip)]
    version: u8,
    #[zeroize(skip)]
    pairing_id: uuid::Uuid,
    #[zeroize(skip)]
    approval_public_key_der: Vec<u8>,
    phone_share: [u8; 32],
    pin4_hash: String,
    pin6_hash: String,
    #[zeroize(skip)]
    cli_node_id: [u8; 32],
    #[serde(default)]
    #[zeroize(skip)]
    enrollment: Option<EnrollmentContext>,
    #[serde(default)]
    #[zeroize(skip)]
    prepared: Option<EnrollmentPrepared>,
    #[serde(default)]
    #[zeroize(skip)]
    recovery: Option<RecoveryFinished>,
    #[serde(default)]
    #[zeroize(skip)]
    enrollment_complete: bool,
}

fn approval_key_alias(pairing_id: uuid::Uuid) -> String {
    format!("ferusa_approval_{pairing_id}")
}

fn pairing_generation_key(pairing_id: uuid::Uuid) -> String {
    format!("{PAIRING_GENERATION_PREFIX}{pairing_id}")
}

fn parse_generation_id(key: &str, raw: &str) -> Result<uuid::Uuid> {
    uuid::Uuid::parse_str(raw).with_context(|| format!("parse {key}"))
}

fn load_generation_id<S: PairingStore>(store: &S, key: &str) -> Result<Option<uuid::Uuid>> {
    store
        .get(key)
        .with_context(|| format!("load {key}"))?
        .map(|raw| parse_generation_id(key, &raw))
        .transpose()
}

fn save_generation_id<S: PairingStore>(store: &S, key: &str, pairing_id: uuid::Uuid) -> Result<()> {
    store
        .save(key, &pairing_id.to_string())
        .with_context(|| format!("save {key}"))
}

fn delete_entry_if_present<S: PairingStore>(store: &S, key: &str) {
    if let Err(e) = store.delete(key) {
        warn!(
            "[ferusa:app]: cleanup key={} failed or absent: {:#}",
            key, e
        );
    }
}

fn push_unique_generation(ids: &mut Vec<uuid::Uuid>, pairing_id: uuid::Uuid) {
    if !ids.contains(&pairing_id) {
        ids.push(pairing_id);
    }
}

fn validate_pin_hash(hash: &str, name: &str) -> Result<()> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("parse {name}: {e}"))?;
    if parsed.algorithm.as_str() != "argon2id" {
        bail!("{name} must use argon2id");
    }
    if parsed.salt.is_none() || parsed.hash.is_none() {
        bail!("{name} must contain a salt and hash output");
    }
    Ok(())
}

fn validate_generation_metadata(generation: &PairingGeneration) -> Result<()> {
    if !matches!(generation.version, 1 | 2)
        || (generation.version == 2) != generation.enrollment.is_some()
    {
        bail!(
            "unsupported pairing generation version {}",
            generation.version
        );
    }
    if let Some(context) = &generation.enrollment {
        context.validate()?;
        if context.desktop_id != generation.cli_node_id {
            bail!("enrollment desktop mismatch");
        }
    }
    if generation.approval_public_key_der.is_empty() {
        bail!("approval_public_key_der empty");
    }
    validate_pin_hash(&generation.pin4_hash, "pin4_hash")?;
    validate_pin_hash(&generation.pin6_hash, "pin6_hash")?;
    Ok(())
}

fn validate_generation_key_binding<S: PairingStore>(
    store: &S,
    generation: &PairingGeneration,
) -> Result<()> {
    validate_generation_metadata(generation)?;
    let alias = approval_key_alias(generation.pairing_id);
    let payload = canonical_pairing_ready_payload(generation.pairing_id);
    let signature = store
        .sign(&alias, &payload)
        .context("probe pairing approval key")?;
    if !verify_pairing_ready_signature(
        &generation.approval_public_key_der,
        generation.pairing_id,
        &signature,
    ) {
        bail!("approval key does not match stored public key");
    }
    Ok(())
}

fn store_generation<S: PairingStore>(store: &S, generation: &PairingGeneration) -> Result<()> {
    let key = pairing_generation_key(generation.pairing_id);
    let json = Zeroizing::new(serde_json::to_string(generation).context("serialize generation")?);
    store
        .save(&key, &json)
        .with_context(|| format!("save generation {}", generation.pairing_id))
}

fn load_generation<S: PairingStore>(
    store: &S,
    pairing_id: uuid::Uuid,
) -> Result<PairingGeneration> {
    let key = pairing_generation_key(pairing_id);
    let json = Zeroizing::new(
        store
            .get(&key)
            .with_context(|| format!("load generation {pairing_id}"))?
            .with_context(|| format!("pairing generation {pairing_id} not in store"))?,
    );
    let generation: PairingGeneration =
        serde_json::from_str(&json).with_context(|| format!("parse generation {pairing_id}"))?;
    if generation.pairing_id != pairing_id {
        bail!("pairing generation id mismatch");
    }
    Ok(generation)
}

fn load_metadata_validated_generation<S: PairingStore>(
    store: &S,
    pairing_id: uuid::Uuid,
) -> Result<PairingGeneration> {
    let generation = load_generation(store, pairing_id)?;
    validate_generation_metadata(&generation)?;
    Ok(generation)
}

fn load_key_bound_generation<S: PairingStore>(
    store: &S,
    pairing_id: uuid::Uuid,
) -> Result<PairingGeneration> {
    let generation = load_metadata_validated_generation(store, pairing_id)?;
    validate_generation_key_binding(store, &generation)?;
    Ok(generation)
}

fn remove_generation<S: PairingStore>(store: &S, pairing_id: uuid::Uuid) -> Result<()> {
    store
        .delete_approval_key(&approval_key_alias(pairing_id))
        .with_context(|| format!("delete approval key for generation {pairing_id}"))?;
    store
        .delete(&pairing_generation_key(pairing_id))
        .with_context(|| format!("delete generation {pairing_id}"))
}

fn cleanup_retiring_generation<S: PairingStore>(store: &S) -> Result<()> {
    let Some(retiring) = load_generation_id(store, RETIRING_PAIRING_GENERATION)? else {
        return Ok(());
    };
    if load_generation_id(store, ACTIVE_PAIRING_GENERATION)? == Some(retiring) {
        bail!("refusing to delete active pairing generation");
    }
    remove_generation(store, retiring)?;
    store
        .delete(RETIRING_PAIRING_GENERATION)
        .context("clear retiring pairing generation")
}

fn cleanup_activation_metadata<S: PairingStore>(store: &S, pairing_id: uuid::Uuid) -> Result<()> {
    for key in [
        STAGING_PAIRING_GENERATION,
        PENDING_PAIRING_GENERATION,
        COMMITTED_PAIRING_GENERATION,
    ] {
        if load_generation_id(store, key)? == Some(pairing_id) {
            store
                .delete(key)
                .with_context(|| format!("finalize activation by clearing {key}"))?;
        }
    }
    if let Err(e) = cleanup_retiring_generation(store) {
        warn!(
            "[ferusa:app]: retired pairing generation cleanup failed after activation: {:#}",
            e
        );
    }
    Ok(())
}

fn finalize_active_activation<S: PairingStore>(store: &S) -> Result<()> {
    let active = load_generation_id(store, ACTIVE_PAIRING_GENERATION)?;
    let committed = load_generation_id(store, COMMITTED_PAIRING_GENERATION)?;
    match (active, committed) {
        (Some(active), Some(committed)) if active == committed => {
            cleanup_activation_metadata(store, active)
        }
        _ => Ok(()),
    }
}

fn clear_uncommitted_pending<S: PairingStore>(store: &S) -> Result<()> {
    finalize_active_activation(store)?;
    if load_generation_id(store, COMMITTED_PAIRING_GENERATION)?.is_some() {
        bail!("refusing to clear committed pending pairing");
    }

    let active = load_generation_id(store, ACTIVE_PAIRING_GENERATION)?;
    let mut candidates = Vec::new();
    for key in [STAGING_PAIRING_GENERATION, PENDING_PAIRING_GENERATION] {
        if let Some(pairing_id) = load_generation_id(store, key)? {
            push_unique_generation(&mut candidates, pairing_id);
        }
    }

    for pairing_id in candidates {
        if Some(pairing_id) != active {
            remove_generation(store, pairing_id)?;
        }
    }
    for key in [STAGING_PAIRING_GENERATION, PENDING_PAIRING_GENERATION] {
        store.delete(key).with_context(|| format!("clear {key}"))?;
    }
    Ok(())
}

fn begin_pending_pairing<S: PairingStore>(store: &S, pairing_id: uuid::Uuid) -> Result<()> {
    finalize_active_activation(store)?;
    // Once published, the desktop may have durably prepared this generation.
    // Only a caller that knows the handshake never started may discard it.
    if load_generation_id(store, PENDING_PAIRING_GENERATION)?.is_some() {
        bail!("pairing is pending; resume the original desktop transaction before retrying setup");
    }
    clear_uncommitted_pending(store)?;
    save_generation_id(store, STAGING_PAIRING_GENERATION, pairing_id)
}

fn store_pending_pairing_generation<S: PairingStore>(
    store: &S,
    pairing_id: uuid::Uuid,
    approval_alias: &str,
    approval_public_key_der: &[u8],
    phone_share: &[u8; 32],
    pin4_hash: &str,
    pin6_hash: &str,
    cli_node_id: &[u8; 32],
) -> Result<()> {
    if load_generation_id(store, STAGING_PAIRING_GENERATION)? != Some(pairing_id) {
        bail!("staging pairing generation mismatch");
    }
    if approval_alias != approval_key_alias(pairing_id) {
        bail!("approval key alias does not match pairing generation");
    }
    let generation = PairingGeneration {
        version: PAIRING_GENERATION_VERSION,
        pairing_id,
        approval_public_key_der: approval_public_key_der.to_vec(),
        phone_share: *phone_share,
        pin4_hash: pin4_hash.to_owned(),
        pin6_hash: pin6_hash.to_owned(),
        cli_node_id: *cli_node_id,
        enrollment: None,
        prepared: None,
        recovery: None,
        enrollment_complete: false,
    };
    validate_generation_metadata(&generation)?;
    store_generation(store, &generation)?;
    load_metadata_validated_generation(store, pairing_id)
        .context("validate stored pending generation")?;
    save_generation_id(store, PENDING_PAIRING_GENERATION, pairing_id)?;
    Ok(())
}

pub fn begin_pending_pairing_generation<R: Runtime>(
    app: &AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<()> {
    info!("[ferusa:app]: begin_pending_pairing_generation start");
    let _guard = storage_guard();
    begin_pending_pairing(&AppPairingStore(app), pairing_id)?;
    info!("[ferusa:app]: begin_pending_pairing_generation complete");
    Ok(())
}

pub async fn begin_pending_pairing_generation_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<()> {
    task::spawn_blocking(move || begin_pending_pairing_generation(&app, pairing_id))
        .await
        .context("storage task panicked")?
}

pub fn store_pending_pairing_secrets<R: Runtime>(
    app: &AppHandle<R>,
    pairing_id: uuid::Uuid,
    approval_alias: &str,
    approval_public_key_der: &[u8],
    phone_share: &[u8; 32],
    pin4_hash: &str,
    pin6_hash: &str,
    cli_node_id: &[u8; 32],
) -> Result<()> {
    info!("[ferusa:app]: store_pending_pairing_secrets start (Android Keystore)");
    let _guard = storage_guard();
    store_pending_pairing_generation(
        &AppPairingStore(app),
        pairing_id,
        approval_alias,
        approval_public_key_der,
        phone_share,
        pin4_hash,
        pin6_hash,
        cli_node_id,
    )?;
    info!("[ferusa:app]: store_pending_pairing_secrets complete");
    Ok(())
}

pub async fn store_pending_pairing_secrets_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    pairing_id: uuid::Uuid,
    approval_key_alias: String,
    approval_public_key_der: Vec<u8>,
    phone_share: [u8; 32],
    pin4_hash: String,
    pin6_hash: String,
    cli_node_id: [u8; 32],
) -> Result<()> {
    let phone_share = Zeroizing::new(phone_share);
    task::spawn_blocking(move || {
        let approval_key_alias = Zeroizing::new(approval_key_alias);
        let pin4_hash = Zeroizing::new(pin4_hash);
        let pin6_hash = Zeroizing::new(pin6_hash);
        let cli_node_id = Zeroizing::new(cli_node_id);
        store_pending_pairing_secrets(
            &app,
            pairing_id,
            &approval_key_alias,
            &approval_public_key_der,
            &phone_share,
            &pin4_hash,
            &pin6_hash,
            &cli_node_id,
        )
    })
    .await
    .context("storage task panicked")?
}

fn commit_pending_generation<S: PairingStore>(store: &S, pairing_id: uuid::Uuid) -> Result<()> {
    let generation = load_metadata_validated_generation(store, pairing_id)?;
    if generation.enrollment.is_some() {
        let prepared = generation
            .prepared
            .as_ref()
            .context("candidate vault not bound")?;
        let receipt = generation
            .recovery
            .as_ref()
            .context("mandatory candidate recovery not confirmed")?;
        if !RecoveryReference::from_finished(receipt)?.matches(prepared) {
            bail!("candidate recovery binding mismatch");
        }
    }
    if load_generation_id(store, ACTIVE_PAIRING_GENERATION)? == Some(pairing_id) {
        load_metadata_validated_generation(store, pairing_id)
            .context("validate active generation")?;
        finalize_active_activation(store)?;
        return Ok(());
    }
    if load_generation_id(store, COMMITTED_PAIRING_GENERATION)? == Some(pairing_id) {
        load_metadata_validated_generation(store, pairing_id)
            .context("validate committed generation")?;
        return Ok(());
    }
    if load_generation_id(store, PENDING_PAIRING_GENERATION)? != Some(pairing_id) {
        bail!("pending pairing id mismatch while marking committed");
    }
    load_metadata_validated_generation(store, pairing_id).context("validate pending generation")?;
    save_generation_id(store, COMMITTED_PAIRING_GENERATION, pairing_id)
}

pub fn mark_pending_pairing_committed<R: Runtime>(
    app: &AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<()> {
    info!("[ferusa:app]: mark_pending_pairing_committed start");
    let _guard = storage_guard();
    commit_pending_generation(&AppPairingStore(app), pairing_id)?;
    info!("[ferusa:app]: mark_pending_pairing_committed complete");
    Ok(())
}

pub async fn mark_pending_pairing_committed_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<()> {
    task::spawn_blocking(move || mark_pending_pairing_committed(&app, pairing_id))
        .await
        .context("storage task panicked")?
}

fn abort_unstarted_pairing<S: PairingStore>(store: &S, pairing_id: uuid::Uuid) -> Result<()> {
    for key in [STAGING_PAIRING_GENERATION, PENDING_PAIRING_GENERATION] {
        if load_generation_id(store, key)?.is_some_and(|stored| stored != pairing_id) {
            bail!("refusing to clear a different pairing generation");
        }
    }
    clear_uncommitted_pending(store)
}

/// Only call before starting the network handshake: the desktop cannot yet be prepared.
pub fn clear_pending_pairing<R: Runtime>(app: &AppHandle<R>, pairing_id: uuid::Uuid) -> Result<()> {
    info!("[ferusa:app]: clear_pending_pairing start");
    let _guard = storage_guard();
    abort_unstarted_pairing(&AppPairingStore(app), pairing_id)?;
    info!("[ferusa:app]: clear_pending_pairing complete");
    Ok(())
}

pub async fn clear_pending_pairing_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<()> {
    task::spawn_blocking(move || clear_pending_pairing(&app, pairing_id))
        .await
        .context("storage task panicked")?
}

#[cfg(test)]
fn activate_pending_generation<S: PairingStore>(store: &S) -> Result<StoredSecrets> {
    let pending = load_generation_id(store, PENDING_PAIRING_GENERATION)?
        .context("pending pairing generation not in store")?;
    activate_generation(store, pending)
}

fn activate_generation<S: PairingStore>(
    store: &S,
    pairing_id: uuid::Uuid,
) -> Result<StoredSecrets> {
    if load_generation_id(store, ACTIVE_PAIRING_GENERATION)? == Some(pairing_id) {
        let generation = load_metadata_validated_generation(store, pairing_id)
            .context("validate active generation")?;
        finalize_active_activation(store)?;
        return Ok(generation.into_stored_secrets());
    }
    let pending = load_generation_id(store, PENDING_PAIRING_GENERATION)?
        .context("pending pairing generation not in store")?;
    let committed = load_generation_id(store, COMMITTED_PAIRING_GENERATION)?
        .context("committed pairing generation not in store")?;
    if pending != committed || committed != pairing_id {
        bail!("pending and committed pairing generations do not match");
    }
    let generation = load_metadata_validated_generation(store, committed)
        .context("validate committed generation")?;
    let old_active = load_generation_id(store, ACTIVE_PAIRING_GENERATION)?;
    if old_active != Some(committed) {
        if let Some(old_active) = old_active {
            if load_generation_id(store, RETIRING_PAIRING_GENERATION)?
                .is_some_and(|retiring| retiring != old_active)
            {
                cleanup_retiring_generation(store)
                    .context("clean older retired generation before activation")?;
            }
            save_generation_id(store, RETIRING_PAIRING_GENERATION, old_active)?;
        }
        save_generation_id(store, ACTIVE_PAIRING_GENERATION, committed)
            .context("activate pairing generation")?;
        for key in ["pin4_attempt_state", "pin6_attempt_state"] {
            delete_entry_if_present(store, key);
        }
    }
    cleanup_activation_metadata(store, committed)?;
    Ok(generation.into_stored_secrets())
}

pub fn activate_pairing_generation<R: Runtime>(
    app: &AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<StoredSecrets> {
    info!("[ferusa:app]: activate_pairing_generation start (Android Keystore)");
    let _guard = storage_guard();
    let stored = activate_generation(&AppPairingStore(app), pairing_id)?;
    info!("[ferusa:app]: activate_pairing_generation complete");
    Ok(stored)
}

pub async fn activate_pairing_generation_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<StoredSecrets> {
    task::spawn_blocking(move || activate_pairing_generation(&app, pairing_id))
        .await
        .context("storage task panicked")?
}

pub fn pairing_generation_cli_node_id<R: Runtime>(
    app: &AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<Option<[u8; 32]>> {
    let _guard = storage_guard();
    let store = AppPairingStore(app);
    finalize_active_activation(&store)?;
    let referenced = [
        ACTIVE_PAIRING_GENERATION,
        PENDING_PAIRING_GENERATION,
        COMMITTED_PAIRING_GENERATION,
    ]
    .into_iter()
    .map(|key| load_generation_id(&store, key))
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .flatten()
    .any(|stored| stored == pairing_id);
    if !referenced {
        return Ok(None);
    }
    Ok(Some(load_generation(&store, pairing_id)?.cli_node_id))
}

pub async fn pairing_generation_cli_node_id_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<Option<[u8; 32]>> {
    task::spawn_blocking(move || pairing_generation_cli_node_id(&app, pairing_id))
        .await
        .context("storage task panicked")?
}

fn is_referenced_pairing_cli_node_id_in_store<S: PairingStore>(
    store: &S,
    cli_node_id: &[u8; 32],
) -> Result<bool> {
    for key in [
        ACTIVE_PAIRING_GENERATION,
        PENDING_PAIRING_GENERATION,
        COMMITTED_PAIRING_GENERATION,
    ] {
        if let Some(pairing_id) = load_generation_id(store, key)? {
            if load_generation(store, pairing_id)?.cli_node_id == *cli_node_id {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn is_referenced_pairing_cli_node_id<R: Runtime>(
    app: &AppHandle<R>,
    cli_node_id: &[u8; 32],
) -> Result<bool> {
    let _guard = storage_guard();
    is_referenced_pairing_cli_node_id_in_store(&AppPairingStore(app), cli_node_id)
}

pub async fn is_referenced_pairing_cli_node_id_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    cli_node_id: [u8; 32],
) -> Result<bool> {
    task::spawn_blocking(move || is_referenced_pairing_cli_node_id(&app, &cli_node_id))
        .await
        .context("storage task panicked")?
}

/// Persist the iroh secret key so the Node ID survives app restarts.
pub fn store_iroh_secret_key<R: Runtime>(
    app: &AppHandle<R>,
    secret_key: &iroh::SecretKey,
) -> Result<()> {
    debug!("[ferusa:app]: store_iroh_secret_key (Android Keystore)");
    let _guard = storage_guard();
    let key_bytes = Zeroizing::new(secret_key.to_bytes());
    let key_hex = Zeroizing::new(hex::encode(&*key_bytes));
    save_entry(app, "iroh_secret_key", key_hex.as_str())?;
    debug!("[ferusa:app]: store_iroh_secret_key saved");
    Ok(())
}

pub async fn store_iroh_secret_key_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    secret_key: iroh::SecretKey,
) -> Result<()> {
    task::spawn_blocking(move || store_iroh_secret_key(&app, &secret_key))
        .await
        .context("storage task panicked")?
}

/// Load the persisted iroh secret key, if one exists.
pub fn load_iroh_secret_key<R: Runtime>(app: &AppHandle<R>) -> Result<Option<iroh::SecretKey>> {
    debug!("[ferusa:app]: load_iroh_secret_key (Android Keystore)");
    let _guard = storage_guard();
    let hex_str = match get_entry(app, "iroh_secret_key")? {
        Some(s) => Zeroizing::new(s),
        None => {
            debug!("[ferusa:app]: load_iroh_secret_key not found, will generate new one");
            return Ok(None);
        }
    };
    let bytes = Zeroizing::new(hex::decode(&*hex_str).context("decode iroh secret key")?);
    if bytes.len() != 32 {
        error!(
            "[ferusa:app]: load_iroh_secret_key wrong length: {}",
            bytes.len()
        );
        bail!("iroh secret key wrong length");
    }
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&bytes);
    let key = iroh::SecretKey::from_bytes(&*arr);
    debug!("[ferusa:app]: load_iroh_secret_key loaded successfully");
    Ok(Some(key))
}

pub async fn load_iroh_secret_key_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
) -> Result<Option<iroh::SecretKey>> {
    task::spawn_blocking(move || load_iroh_secret_key(&app))
        .await
        .context("storage task panicked")?
}

pub async fn generate_approval_key_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    alias: String,
) -> Result<Vec<u8>> {
    task::spawn_blocking(move || {
        let public_hex = tauri_plugin_keystore::generate_approval_key(&app, &alias)
            .map_err(|e| anyhow::anyhow!(e))
            .context("generate approval key")?;
        hex::decode(public_hex).context("decode approval public key")
    })
    .await
    .context("storage task panicked")?
}

pub async fn sign_approval_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    alias: String,
    payload: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>> {
    task::spawn_blocking(move || {
        let payload_hex = Zeroizing::new(hex::encode(&*payload));
        let sig_hex = Zeroizing::new(
            tauri_plugin_keystore::sign_approval(&app, &alias, &payload_hex)
                .map_err(|e| anyhow::anyhow!(e))
                .context("sign approval")?,
        );
        hex::decode(&*sig_hex).context("decode approval signature")
    })
    .await
    .context("storage task panicked")?
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StoredSecrets {
    #[zeroize(skip)]
    pub pairing_id: uuid::Uuid,
    pub approval_key_alias: String,
    #[zeroize(skip)]
    pub approval_public_key_der: Vec<u8>,
    pub phone_share: [u8; 32],
    pub pin4_hash: String,
    pub pin6_hash: String,
    pub cli_node_id: [u8; 32],
}

impl StoredSecrets {
    pub fn into_state_secrets(mut self) -> crate::state::Secrets {
        crate::state::Secrets {
            pairing_id: self.pairing_id,
            approval_key_alias: std::mem::take(&mut self.approval_key_alias),
            approval_public_key_der: std::mem::take(&mut self.approval_public_key_der),
            phone_share: std::mem::take(&mut self.phone_share),
            pin4_hash: std::mem::take(&mut self.pin4_hash),
            pin6_hash: std::mem::take(&mut self.pin6_hash),
            cli_node_id: self.cli_node_id,
        }
    }
}

impl PairingGeneration {
    fn into_stored_secrets(mut self) -> StoredSecrets {
        StoredSecrets {
            pairing_id: self.pairing_id,
            approval_key_alias: approval_key_alias(self.pairing_id),
            approval_public_key_der: std::mem::take(&mut self.approval_public_key_der),
            phone_share: std::mem::take(&mut self.phone_share),
            pin4_hash: std::mem::take(&mut self.pin4_hash),
            pin6_hash: std::mem::take(&mut self.pin6_hash),
            cli_node_id: self.cli_node_id,
        }
    }
}

pub fn load_secrets<R: Runtime>(app: &AppHandle<R>) -> Result<StoredSecrets> {
    info!("[ferusa:app]: load_secrets start (Android Keystore)");
    let _guard = storage_guard();
    let store = AppPairingStore(app);
    if let Err(e) = cleanup_retiring_generation(&store) {
        warn!(
            "[ferusa:app]: retired pairing generation cleanup failed during load: {:#}",
            e
        );
    }
    let pairing_id = load_generation_id(&store, ACTIVE_PAIRING_GENERATION)?
        .context("active pairing generation not in store")?;
    let generation =
        load_key_bound_generation(&store, pairing_id).context("validate active generation")?;
    info!("[ferusa:app]: load_secrets complete");
    Ok(generation.into_stored_secrets())
}

pub async fn load_secrets_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
) -> Result<StoredSecrets> {
    task::spawn_blocking(move || load_secrets(&app))
        .await
        .context("storage task panicked")?
}

pub fn is_setup<R: Runtime>(app: &AppHandle<R>) -> Result<bool> {
    debug!("[ferusa:app]: is_setup check (Android Keystore)");
    let _guard = storage_guard();
    let store = AppPairingStore(app);
    let result = is_setup_in_store(&store)?;
    debug!("[ferusa:app]: is_setup result: {}", result);
    Ok(result)
}

fn is_setup_in_store<S: PairingStore>(store: &S) -> Result<bool> {
    finalize_active_activation(store)?;
    if let Err(e) = cleanup_retiring_generation(store) {
        warn!(
            "[ferusa:app]: retired pairing generation cleanup failed during setup check: {:#}",
            e
        );
    }
    let result = match load_generation_id(store, ACTIVE_PAIRING_GENERATION)? {
        Some(pairing_id) => {
            load_metadata_validated_generation(store, pairing_id)
                .context("validate active generation")?;
            true
        }
        None => false,
    };
    Ok(result)
}

pub async fn is_setup_blocking<R: Runtime + 'static>(app: AppHandle<R>) -> Result<bool> {
    task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| is_setup(&app))).map_err(
            |panic| anyhow::anyhow!("storage panic during setup check: {}", panic_message(panic)),
        )?
    })
    .await
    .context("storage task panicked")?
}

fn enrollment_generation<S: PairingStore>(
    store: &S,
    context: &EnrollmentContext,
) -> Result<Option<PairingGeneration>> {
    context.validate()?;
    // Exact public transaction identity selects one referenced generation; no enumeration API.
    for key in [
        PENDING_PAIRING_GENERATION,
        COMMITTED_PAIRING_GENERATION,
        ACTIVE_PAIRING_GENERATION,
    ] {
        if let Some(id) = load_generation_id(store, key)? {
            let generation = load_metadata_validated_generation(store, id)?;
            if generation.enrollment.as_ref() == Some(context) {
                return Ok(Some(generation));
            }
            if key == PENDING_PAIRING_GENERATION {
                bail!("another enrollment is pending; resume its original token");
            }
        }
    }
    Ok(None)
}

pub async fn enrollment_secrets_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    context: EnrollmentContext,
) -> Result<Option<StoredSecrets>> {
    task::spawn_blocking(move || {
        let _guard = storage_guard();
        Ok(enrollment_generation(&AppPairingStore(&app), &context)?
            .map(PairingGeneration::into_stored_secrets))
    })
    .await
    .context("storage task panicked")?
}

fn enrollment_is_pending<S: PairingStore>(store: &S) -> Result<bool> {
    let active_incomplete = match load_generation_id(store, ACTIVE_PAIRING_GENERATION)? {
        Some(id) => {
            let generation = load_metadata_validated_generation(store, id)?;
            generation.enrollment.is_some() && !generation.enrollment_complete
        }
        None => false,
    };
    Ok(active_incomplete
        || load_generation_id(store, PENDING_PAIRING_GENERATION)?.is_some()
        || load_generation_id(store, COMMITTED_PAIRING_GENERATION)?.is_some())
}

pub async fn enrollment_pending_blocking<R: Runtime + 'static>(app: AppHandle<R>) -> Result<bool> {
    task::spawn_blocking(move || {
        let _guard = storage_guard();
        let store = AppPairingStore(&app);
        enrollment_is_pending(&store)
    })
    .await
    .context("storage task panicked")?
}

pub async fn attach_enrollment_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    pairing_id: uuid::Uuid,
    context: EnrollmentContext,
) -> Result<()> {
    task::spawn_blocking(move || {
        let _guard = storage_guard();
        let store = AppPairingStore(&app);
        context.validate()?;
        if load_generation_id(&store, PENDING_PAIRING_GENERATION)? != Some(pairing_id) {
            bail!("pending generation mismatch");
        }
        let mut generation = load_metadata_validated_generation(&store, pairing_id)?;
        if generation.cli_node_id != context.desktop_id
            || generation
                .enrollment
                .as_ref()
                .is_some_and(|old| old != &context)
        {
            bail!("enrollment context mismatch");
        }
        generation.version = 2;
        generation.enrollment = Some(context);
        store_generation(&store, &generation)
    })
    .await
    .context("storage task panicked")?
}

fn bind_enrollment_vault<S: PairingStore>(store: &S, prepared: &EnrollmentPrepared) -> Result<()> {
    let mut generation = enrollment_generation(store, &prepared.context)?
        .context("enrollment generation missing")?;
    if generation.pairing_id != prepared.pairing_id
        || generation
            .prepared
            .as_ref()
            .is_some_and(|old| old != prepared)
    {
        bail!("candidate vault binding changed");
    }
    generation.prepared = Some(prepared.clone());
    store_generation(store, &generation)
}

pub async fn bind_enrollment_vault_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    prepared: EnrollmentPrepared,
) -> Result<()> {
    task::spawn_blocking(move || {
        let _guard = storage_guard();
        let store = AppPairingStore(&app);
        bind_enrollment_vault(&store, &prepared)
    })
    .await
    .context("storage task panicked")?
}

fn store_enrollment_receipt<S: PairingStore>(store: &S, finished: &RecoveryFinished) -> Result<()> {
    let mut generation =
        load_metadata_validated_generation(store, finished.context.begin.pairing_id)?;
    let prepared = generation
        .prepared
        .as_ref()
        .context("candidate vault not bound")?;
    if !RecoveryReference::from_finished(finished)?.matches(prepared)
        || finished.context.desktop_id != generation.cli_node_id
        || finished.context.begin.purpose != prepared.context.purpose
        || !verify_recovery_signature(
            &generation.approval_public_key_der,
            &canonical_recovery_finished(finished)?,
            &finished.signature,
        )
    {
        bail!("candidate receipt binding or signature invalid");
    }
    generation.recovery = Some(finished.clone());
    store_generation(store, &generation)
}

pub async fn store_enrollment_receipt_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    finished: RecoveryFinished,
) -> Result<()> {
    task::spawn_blocking(move || {
        let _guard = storage_guard();
        let store = AppPairingStore(&app);
        store_enrollment_receipt(&store, &finished)
    })
    .await
    .context("storage task panicked")?
}

fn check_enrollment_transition<S: PairingStore>(
    store: &S,
    transition: &EnrollmentTransition,
    desktop: [u8; 32],
) -> Result<()> {
    if ![
        ACTIVE_PAIRING_GENERATION,
        PENDING_PAIRING_GENERATION,
        COMMITTED_PAIRING_GENERATION,
    ]
    .into_iter()
    .map(|key| load_generation_id(store, key))
    .collect::<Result<Vec<_>>>()?
    .contains(&Some(transition.pairing_id))
    {
        bail!("generation not referenced");
    }
    let generation = load_metadata_validated_generation(store, transition.pairing_id)?;
    let receipt = generation
        .recovery
        .as_ref()
        .context("mandatory recovery receipt missing")?;
    if generation.cli_node_id != desktop
        || RecoveryReference::from_finished(receipt)? != transition.recovery
        || transition.pairing_id != transition.recovery.pairing_id
    {
        bail!("recovery transition reference mismatch");
    }
    Ok(())
}

pub async fn check_enrollment_transition_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    transition: EnrollmentTransition,
    desktop: [u8; 32],
) -> Result<()> {
    task::spawn_blocking(move || {
        let _guard = storage_guard();
        let store = AppPairingStore(&app);
        check_enrollment_transition(&store, &transition, desktop)
    })
    .await
    .context("storage task panicked")?
}

pub async fn generation_requires_recovery_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> Result<bool> {
    task::spawn_blocking(move || {
        let _guard = storage_guard();
        Ok(
            load_metadata_validated_generation(&AppPairingStore(&app), pairing_id)?
                .enrollment
                .is_some(),
        )
    })
    .await
    .context("storage task panicked")?
}

#[cfg(test)]
fn clear_pairing_store<S: PairingStore>(store: &S) -> Result<()> {
    let mut generations = Vec::new();
    for key in PAIRING_METADATA_KEYS {
        if let Some(pairing_id) = load_generation_id(store, key)? {
            push_unique_generation(&mut generations, pairing_id);
        }
    }
    for pairing_id in generations {
        remove_generation(store, pairing_id)?;
    }

    for alias_key in ["approval_key_alias", "pending_approval_key_alias"] {
        if let Some(alias) = store
            .get(alias_key)
            .with_context(|| format!("load legacy {alias_key}"))?
        {
            store
                .delete_approval_key(alias.trim())
                .with_context(|| format!("delete legacy approval key {alias}"))?;
        }
    }

    for key in PAIRING_METADATA_KEYS
        .iter()
        .chain(LEGACY_PAIRING_KEYS)
        .chain(KEYS_TO_CLEAR_ON_RESET)
    {
        store
            .delete(key)
            .with_context(|| format!("delete secret {key}"))?;
    }
    Ok(())
}

fn load_pin_attempt_state_entry<R: Runtime>(
    app: &AppHandle<R>,
    kind: PinKind,
) -> Result<PinAttemptState> {
    let key = pin_attempt_key(kind);
    let Some(raw) = get_entry(app, key)? else {
        return Ok(PinAttemptState::default());
    };
    serde_json::from_str(&raw).with_context(|| format!("parse {key}"))
}

fn save_pin_attempt_state_entry<R: Runtime>(
    app: &AppHandle<R>,
    kind: PinKind,
    state: PinAttemptState,
) -> Result<()> {
    let key = pin_attempt_key(kind);
    let raw = serde_json::to_string(&state).context("serialize PIN attempt state")?;
    save_entry(app, key, &raw).with_context(|| format!("save {key}"))
}

fn clear_pin_attempt_state_entry<R: Runtime>(app: &AppHandle<R>, kind: PinKind) -> Result<()> {
    let key = pin_attempt_key(kind);
    delete_entry(app, key).with_context(|| format!("delete {key}"))
}

fn update_pin_attempt_state_with<T>(
    lock: &std::sync::Mutex<()>,
    load: impl FnOnce() -> Result<PinAttemptState>,
    save: impl FnOnce(PinAttemptState) -> Result<()>,
    clear: impl FnOnce() -> Result<()>,
    update: impl FnOnce(&mut PinAttemptState) -> (PinAttemptStateWrite, T),
) -> Result<T> {
    let _guard = lock_storage(lock);
    let mut state = load()?;
    let (write, result) = update(&mut state);
    match write {
        PinAttemptStateWrite::Save => save(state)?,
        PinAttemptStateWrite::Clear => clear()?,
    }
    Ok(result)
}

pub fn update_pin_attempt_state<R: Runtime, T>(
    app: &AppHandle<R>,
    kind: PinKind,
    update: impl FnOnce(&mut PinAttemptState) -> (PinAttemptStateWrite, T),
) -> Result<T> {
    update_pin_attempt_state_with(
        &STORAGE_LOCK,
        || load_pin_attempt_state_entry(app, kind),
        |state| save_pin_attempt_state_entry(app, kind, state),
        || clear_pin_attempt_state_entry(app, kind),
        update,
    )
}

pub async fn update_pin_attempt_state_blocking<R, T, F>(
    app: AppHandle<R>,
    kind: PinKind,
    update: F,
) -> Result<T>
where
    R: Runtime + 'static,
    T: Send + 'static,
    F: FnOnce(&mut PinAttemptState) -> (PinAttemptStateWrite, T) + Send + 'static,
{
    task::spawn_blocking(move || update_pin_attempt_state(&app, kind, update))
        .await
        .context("storage task panicked")?
}

pub async fn complete_enrollment_blocking<R: Runtime + 'static>(
    app: AppHandle<R>,
    context: EnrollmentContext,
    pairing_id: uuid::Uuid,
) -> Result<()> {
    task::spawn_blocking(move || {
        let _guard = storage_guard();
        let store = AppPairingStore(&app);
        if load_generation_id(&store, ACTIVE_PAIRING_GENERATION)? != Some(pairing_id) {
            bail!("activated enrollment generation mismatch");
        }
        let mut generation = load_metadata_validated_generation(&store, pairing_id)?;
        if generation.enrollment.as_ref() != Some(&context) || generation.recovery.is_none() {
            bail!("enrollment completion binding mismatch");
        }
        generation.enrollment_complete = true;
        store_generation(&store, &generation)
    })
    .await
    .context("storage task panicked")?
}

#[cfg(test)]
mod tests {
    use super::{
        abort_unstarted_pairing, activate_generation, activate_pending_generation,
        approval_key_alias, begin_pending_pairing, cleanup_retiring_generation,
        clear_pairing_store, clear_uncommitted_pending, commit_pending_generation,
        is_referenced_pairing_cli_node_id_in_store, is_setup_in_store, load_generation_id,
        load_key_bound_generation, pairing_generation_key, save_generation_id,
        store_pending_pairing_generation, update_pin_attempt_state_with, PairingGeneration,
        PairingStore, PinAttemptState, PinAttemptStateWrite, ACTIVE_PAIRING_GENERATION,
        COMMITTED_PAIRING_GENERATION, PAIRING_GENERATION_VERSION, PENDING_PAIRING_GENERATION,
        RETIRING_PAIRING_GENERATION, STAGING_PAIRING_GENERATION,
    };
    use anyhow::{anyhow, Context, Result};
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
    };
    use std::{
        cell::RefCell,
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex},
        thread,
    };

    const PIN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$MTIzNDU2Nzg5MDEyMzQ1Ng";

    fn modern_candidate(
        store: &TestStore,
    ) -> (
        ferusa_core::enrollment::EnrollmentPrepared,
        ferusa_core::recovery::RecoveryFinished,
    ) {
        use ferusa_core::{
            enrollment::{EnrollmentContext, EnrollmentPrepared},
            recovery::{
                canonical_recovery_finished, RecoveryBegin, RecoveryContext, RecoveryFinished,
                RecoveryPurpose,
            },
        };
        let id = uuid::Uuid::new_v4();
        stage_pending(store, id);
        let context = EnrollmentContext {
            version: 5,
            desktop_id: [0x22; 32],
            transaction_id: uuid::Uuid::new_v4(),
            purpose: RecoveryPurpose::LostPhoneRecovery,
            credential_revision: uuid::Uuid::new_v4(),
        };
        let mut generation = super::load_generation(store, id).unwrap();
        generation.version = 2;
        generation.enrollment = Some(context.clone());
        super::store_generation(store, &generation).unwrap();
        let prepared = EnrollmentPrepared {
            context: context.clone(),
            pairing_id: id,
            vault_digest: [4; 32],
        };
        let file_id = uuid::Uuid::new_v4();
        let mut finished = RecoveryFinished {
            context: RecoveryContext {
                begin: RecoveryBegin {
                    request_id: uuid::Uuid::new_v4(),
                    pairing_id: id,
                    purpose: context.purpose,
                    transaction_id: Some(context.transaction_id),
                    credential_revision: context.credential_revision,
                    file_id: Some(file_id),
                    expected_envelope_digest: None,
                    vault_digest: prepared.vault_digest,
                    nonce: [5; 32],
                    correlation_code: 1234,
                    timestamp_ms: 1,
                },
                instance_id: uuid::Uuid::new_v4(),
                desktop_id: context.desktop_id,
                phone_challenge: [6; 32],
                phone_session_generation: 1,
            },
            file_id,
            envelope_digest: [7; 32],
            timestamp_ms: 2,
            signature: Vec::new(),
        };
        finished.signature = store
            .sign(
                &approval_key_alias(id),
                &canonical_recovery_finished(&finished).unwrap(),
            )
            .unwrap();
        (prepared, finished)
    }

    #[test]
    fn new_generation_cannot_commit_without_durable_matching_recovery() {
        let store = TestStore::default();
        let old = activate_initial_generation(&store);
        let (prepared, finished) = modern_candidate(&store);
        assert!(commit_pending_generation(&store, prepared.pairing_id).is_err());
        super::bind_enrollment_vault(&store, &prepared).unwrap();
        assert!(commit_pending_generation(&store, prepared.pairing_id).is_err());
        store
            .fail_saves
            .borrow_mut()
            .insert(pairing_generation_key(prepared.pairing_id));
        assert!(super::store_enrollment_receipt(&store, &finished).is_err());
        assert!(commit_pending_generation(&store, prepared.pairing_id).is_err());
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(old)
        );
        store.fail_saves.borrow_mut().clear();
        super::store_enrollment_receipt(&store, &finished).unwrap();
        commit_pending_generation(&store, prepared.pairing_id).unwrap();
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(old)
        );
        activate_generation(&store, prepared.pairing_id).unwrap();
        // Activation with a lost final acknowledgement retains the enrollment route.
        assert!(super::enrollment_is_pending(&store).unwrap());
    }

    #[test]
    fn resumed_enrollment_reuses_keys_share_hashes_and_exact_public_context() {
        let store = TestStore::default();
        let (prepared, _finished) = modern_candidate(&store);
        let first = super::enrollment_generation(&store, &prepared.context)
            .unwrap()
            .unwrap();
        let second = super::enrollment_generation(&store, &prepared.context)
            .unwrap()
            .unwrap();
        assert_eq!(first.phone_share, second.phone_share);
        assert_eq!(first.pin4_hash, second.pin4_hash);
        assert_eq!(first.pin6_hash, second.pin6_hash);
        assert_eq!(
            first.approval_public_key_der,
            second.approval_public_key_der
        );
        let mut other = prepared.context.clone();
        other.transaction_id = uuid::Uuid::new_v4();
        assert!(super::enrollment_generation(&store, &other).is_err());
        super::bind_enrollment_vault(&store, &prepared).unwrap();
        let mut changed = prepared;
        changed.vault_digest[0] ^= 1;
        assert!(super::bind_enrollment_vault(&store, &changed).is_err());
    }

    #[test]
    fn recovery_receipts_and_activation_references_cannot_be_substituted() {
        use ferusa_core::enrollment::{EnrollmentTransition, RecoveryReference};
        use ferusa_core::recovery::canonical_recovery_finished;
        let store = TestStore::default();
        let (prepared, finished) = modern_candidate(&store);
        super::bind_enrollment_vault(&store, &prepared).unwrap();
        for field in 0..4 {
            let mut changed = finished.clone();
            match field {
                0 => changed.context.begin.transaction_id = Some(uuid::Uuid::new_v4()),
                1 => changed.context.begin.credential_revision = uuid::Uuid::new_v4(),
                2 => changed.context.begin.vault_digest[0] ^= 1,
                _ => changed.context.desktop_id[0] ^= 1,
            }
            changed.signature = store
                .sign(
                    &approval_key_alias(prepared.pairing_id),
                    &canonical_recovery_finished(&changed).unwrap(),
                )
                .unwrap();
            assert!(super::store_enrollment_receipt(&store, &changed).is_err());
        }
        super::store_enrollment_receipt(&store, &finished).unwrap();
        let transition = EnrollmentTransition {
            pairing_id: prepared.pairing_id,
            recovery: RecoveryReference::from_finished(&finished).unwrap(),
        };
        super::check_enrollment_transition(&store, &transition, prepared.context.desktop_id)
            .unwrap();
        let mut wrong = transition.clone();
        wrong.recovery.envelope_digest[0] ^= 1;
        assert!(
            super::check_enrollment_transition(&store, &wrong, prepared.context.desktop_id)
                .is_err()
        );
        assert!(super::check_enrollment_transition(&store, &transition, [8; 32]).is_err());
    }

    #[derive(Default)]
    struct TestStore {
        secrets: RefCell<HashMap<String, String>>,
        keys: RefCell<HashMap<String, EcdsaKeyPair>>,
        fail_saves: RefCell<HashSet<String>>,
        fail_deletes: RefCell<HashSet<String>>,
        fail_key_deletes: RefCell<HashSet<String>>,
        sign_count: RefCell<usize>,
    }

    impl TestStore {
        fn add_approval_key(&self, pairing_id: uuid::Uuid) -> Vec<u8> {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let key_pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let public_key = key_pair.public_key().as_ref().to_vec();
            self.keys
                .borrow_mut()
                .insert(approval_key_alias(pairing_id), key_pair);
            public_key
        }

        fn has_generation(&self, pairing_id: uuid::Uuid) -> bool {
            self.secrets
                .borrow()
                .contains_key(&pairing_generation_key(pairing_id))
        }

        fn has_approval_key(&self, pairing_id: uuid::Uuid) -> bool {
            self.keys
                .borrow()
                .contains_key(&approval_key_alias(pairing_id))
        }

        fn sign_count(&self) -> usize {
            *self.sign_count.borrow()
        }
    }

    impl PairingStore for TestStore {
        fn save(&self, key: &str, value: &str) -> Result<()> {
            if self.fail_saves.borrow().contains(key) {
                return Err(anyhow!("injected save failure for {key}"));
            }
            self.secrets
                .borrow_mut()
                .insert(key.to_owned(), value.to_owned());
            Ok(())
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            Ok(self.secrets.borrow().get(key).cloned())
        }

        fn delete(&self, key: &str) -> Result<()> {
            if self.fail_deletes.borrow().contains(key) {
                return Err(anyhow!("injected deletion failure for {key}"));
            }
            self.secrets.borrow_mut().remove(key);
            Ok(())
        }

        fn sign(&self, alias: &str, payload: &[u8]) -> Result<Vec<u8>> {
            *self.sign_count.borrow_mut() += 1;
            let rng = SystemRandom::new();
            self.keys
                .borrow()
                .get(alias)
                .with_context(|| format!("approval key {alias} not found"))?
                .sign(&rng, payload)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| anyhow!("signing failed"))
        }

        fn delete_approval_key(&self, alias: &str) -> Result<()> {
            if self.fail_key_deletes.borrow().contains(alias) {
                return Err(anyhow!("injected key deletion failure for {alias}"));
            }
            self.keys.borrow_mut().remove(alias);
            Ok(())
        }
    }

    fn stage_pending(store: &TestStore, pairing_id: uuid::Uuid) {
        begin_pending_pairing(store, pairing_id).unwrap();
        let public_key = store.add_approval_key(pairing_id);
        store_pending_pairing_generation(
            store,
            pairing_id,
            &approval_key_alias(pairing_id),
            &public_key,
            &[0x11; 32],
            PIN_HASH,
            PIN_HASH,
            &[0x22; 32],
        )
        .unwrap();
    }

    fn stage_and_commit(store: &TestStore, pairing_id: uuid::Uuid) {
        stage_pending(store, pairing_id);
        commit_pending_generation(store, pairing_id).unwrap();
    }

    fn activate_initial_generation(store: &TestStore) -> uuid::Uuid {
        let pairing_id = uuid::Uuid::new_v4();
        stage_and_commit(store, pairing_id);
        activate_pending_generation(store).unwrap();
        pairing_id
    }

    #[test]
    fn referenced_active_pending_and_committed_endpoints_are_recovery_peers() {
        for state in ["active", "pending", "committed"] {
            let store = TestStore::default();
            let pairing_id = uuid::Uuid::new_v4();
            match state {
                "active" => {
                    stage_and_commit(&store, pairing_id);
                    activate_pending_generation(&store).unwrap();
                }
                "pending" => stage_pending(&store, pairing_id),
                "committed" => stage_and_commit(&store, pairing_id),
                _ => unreachable!(),
            }

            assert!(is_referenced_pairing_cli_node_id_in_store(&store, &[0x22; 32]).unwrap());
            assert!(!is_referenced_pairing_cli_node_id_in_store(&store, &[0x33; 32]).unwrap());
        }
    }

    #[test]
    fn malformed_pending_generation_never_becomes_publishable() {
        let store = TestStore::default();
        let pairing_id = uuid::Uuid::new_v4();
        begin_pending_pairing(&store, pairing_id).unwrap();
        let public_key = store.add_approval_key(pairing_id);

        assert!(store_pending_pairing_generation(
            &store,
            pairing_id,
            &approval_key_alias(pairing_id),
            &public_key,
            &[0x11; 32],
            "not-a-phc-hash",
            PIN_HASH,
            &[0x22; 32],
        )
        .is_err());
        assert_eq!(
            load_generation_id(&store, PENDING_PAIRING_GENERATION).unwrap(),
            None
        );
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            None
        );
    }

    #[test]
    fn mismatched_approval_key_fails_key_binding_validation() {
        let store = TestStore::default();
        let pairing_id = uuid::Uuid::new_v4();
        begin_pending_pairing(&store, pairing_id).unwrap();
        store.add_approval_key(pairing_id);

        store_pending_pairing_generation(
            &store,
            pairing_id,
            &approval_key_alias(pairing_id),
            &[0x44; 65],
            &[0x11; 32],
            PIN_HASH,
            PIN_HASH,
            &[0x22; 32],
        )
        .unwrap();
        assert_eq!(
            load_generation_id(&store, PENDING_PAIRING_GENERATION).unwrap(),
            Some(pairing_id)
        );
        assert!(load_key_bound_generation(&store, pairing_id).is_err());
    }

    #[test]
    fn setup_check_uses_metadata_validation_without_signing() {
        let store = TestStore::default();
        let active = activate_initial_generation(&store);
        let signs_after_activation = store.sign_count();

        assert!(is_setup_in_store(&store).unwrap());
        assert_eq!(store.sign_count(), signs_after_activation);
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(active)
        );
    }

    #[test]
    fn key_binding_validation_signs_probe_payload() {
        let store = TestStore::default();
        let active = activate_initial_generation(&store);
        let signs_after_activation = store.sign_count();

        load_key_bound_generation(&store, active).unwrap();

        assert_eq!(store.sign_count(), signs_after_activation + 1);
    }

    #[test]
    fn generation_bundle_write_failure_preserves_active_material() {
        let store = TestStore::default();
        let active = activate_initial_generation(&store);
        let pending = uuid::Uuid::new_v4();
        begin_pending_pairing(&store, pending).unwrap();
        let public_key = store.add_approval_key(pending);
        store
            .fail_saves
            .borrow_mut()
            .insert(pairing_generation_key(pending));

        assert!(store_pending_pairing_generation(
            &store,
            pending,
            &approval_key_alias(pending),
            &public_key,
            &[0x11; 32],
            PIN_HASH,
            PIN_HASH,
            &[0x22; 32],
        )
        .is_err());
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(active)
        );
        assert!(store.has_generation(active));
        assert!(store.has_approval_key(active));
    }

    #[test]
    fn failed_active_pointer_flip_retains_old_generation_and_key() {
        let store = TestStore::default();
        let old = activate_initial_generation(&store);
        let new = uuid::Uuid::new_v4();
        stage_and_commit(&store, new);
        store
            .fail_saves
            .borrow_mut()
            .insert(ACTIVE_PAIRING_GENERATION.to_owned());

        assert!(activate_pending_generation(&store).is_err());
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(old)
        );
        assert!(store.has_generation(old));
        assert!(store.has_approval_key(old));
        assert!(store.has_generation(new));
        assert!(store.has_approval_key(new));
    }

    #[test]
    fn successful_activation_flips_pointer_then_removes_old_generation() {
        let store = TestStore::default();
        let old = activate_initial_generation(&store);
        let new = uuid::Uuid::new_v4();
        stage_and_commit(&store, new);

        activate_pending_generation(&store).unwrap();

        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(new)
        );
        assert!(!store.has_generation(old));
        assert!(!store.has_approval_key(old));
        assert!(store.has_generation(new));
        assert!(store.has_approval_key(new));
    }

    #[test]
    fn commit_is_idempotent_and_does_not_flip_active_generation() {
        let store = TestStore::default();
        let old = activate_initial_generation(&store);
        let new = uuid::Uuid::new_v4();
        stage_and_commit(&store, new);

        commit_pending_generation(&store, new).unwrap();

        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(old)
        );
        assert_eq!(
            load_generation_id(&store, COMMITTED_PAIRING_GENERATION).unwrap(),
            Some(new)
        );
    }

    #[test]
    fn activation_retry_succeeds_after_pending_metadata_cleanup() {
        let store = TestStore::default();
        let new = uuid::Uuid::new_v4();
        stage_and_commit(&store, new);

        activate_generation(&store, new).unwrap();
        activate_generation(&store, new).unwrap();

        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(new)
        );
        assert_eq!(
            load_generation_id(&store, COMMITTED_PAIRING_GENERATION).unwrap(),
            None
        );
    }

    #[test]
    fn replayed_activation_preserves_newer_transaction_and_pin_attempts() {
        let store = TestStore::default();
        let active = activate_initial_generation(&store);
        let replacement = uuid::Uuid::new_v4();
        stage_and_commit(&store, replacement);
        store.save("pin4_attempt_state", "four-attempts").unwrap();
        store.save("pin6_attempt_state", "six-attempts").unwrap();

        activate_generation(&store, active).unwrap();

        assert_eq!(
            load_generation_id(&store, STAGING_PAIRING_GENERATION).unwrap(),
            Some(replacement)
        );
        assert_eq!(
            load_generation_id(&store, PENDING_PAIRING_GENERATION).unwrap(),
            Some(replacement)
        );
        assert_eq!(
            load_generation_id(&store, COMMITTED_PAIRING_GENERATION).unwrap(),
            Some(replacement)
        );
        assert_eq!(
            store.get("pin4_attempt_state").unwrap().as_deref(),
            Some("four-attempts")
        );
        assert_eq!(
            store.get("pin6_attempt_state").unwrap().as_deref(),
            Some("six-attempts")
        );

        activate_generation(&store, replacement).unwrap();
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(replacement)
        );
        assert!(store.get("pin4_attempt_state").unwrap().is_none());
        assert!(store.get("pin6_attempt_state").unwrap().is_none());
    }

    #[test]
    fn cleanup_failure_after_pointer_flip_is_recoverable() {
        let store = TestStore::default();
        let old = activate_initial_generation(&store);
        let new = uuid::Uuid::new_v4();
        stage_and_commit(&store, new);
        store
            .fail_key_deletes
            .borrow_mut()
            .insert(approval_key_alias(old));

        activate_pending_generation(&store).unwrap();
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(new)
        );
        assert_eq!(
            load_generation_id(&store, RETIRING_PAIRING_GENERATION).unwrap(),
            Some(old)
        );
        assert!(store.has_generation(old));
        assert!(store.has_approval_key(old));

        store.fail_key_deletes.borrow_mut().clear();
        cleanup_retiring_generation(&store).unwrap();
        assert!(!store.has_generation(old));
        assert!(!store.has_approval_key(old));
        assert_eq!(
            load_generation_id(&store, RETIRING_PAIRING_GENERATION).unwrap(),
            None
        );
    }

    #[test]
    fn activation_metadata_delete_failure_is_retried_before_new_pairing() {
        let store = TestStore::default();
        let active = uuid::Uuid::new_v4();
        stage_and_commit(&store, active);
        store
            .fail_deletes
            .borrow_mut()
            .insert(COMMITTED_PAIRING_GENERATION.to_owned());

        assert!(activate_pending_generation(&store).is_err());
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(active)
        );

        let replacement = uuid::Uuid::new_v4();
        assert!(begin_pending_pairing(&store, replacement).is_err());

        store.fail_deletes.borrow_mut().clear();
        begin_pending_pairing(&store, replacement).unwrap();
        assert_eq!(
            load_generation_id(&store, COMMITTED_PAIRING_GENERATION).unwrap(),
            None
        );
        assert_eq!(
            load_generation_id(&store, STAGING_PAIRING_GENERATION).unwrap(),
            Some(replacement)
        );
    }

    #[test]
    fn new_activation_cannot_overwrite_an_uncleaned_retirement_marker() {
        let store = TestStore::default();
        let first = activate_initial_generation(&store);
        let second = uuid::Uuid::new_v4();
        stage_and_commit(&store, second);
        store
            .fail_key_deletes
            .borrow_mut()
            .insert(approval_key_alias(first));
        activate_pending_generation(&store).unwrap();

        let third = uuid::Uuid::new_v4();
        stage_and_commit(&store, third);
        assert!(activate_pending_generation(&store).is_err());
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(second)
        );
        assert_eq!(
            load_generation_id(&store, RETIRING_PAIRING_GENERATION).unwrap(),
            Some(first)
        );
    }

    #[test]
    fn mismatched_commit_marker_does_not_change_active_generation() {
        let store = TestStore::default();
        let old = activate_initial_generation(&store);
        let new = uuid::Uuid::new_v4();
        stage_and_commit(&store, new);
        store
            .secrets
            .borrow_mut()
            .insert(COMMITTED_PAIRING_GENERATION.to_owned(), old.to_string());

        assert!(activate_pending_generation(&store).is_err());
        assert_eq!(
            load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
            Some(old)
        );
    }

    #[test]
    fn stale_uncommitted_generation_cleanup_preserves_active_material() {
        let store = TestStore::default();
        let active = activate_initial_generation(&store);
        let stale = uuid::Uuid::new_v4();
        begin_pending_pairing(&store, stale).unwrap();
        store.add_approval_key(stale);

        clear_uncommitted_pending(&store).unwrap();

        assert!(store.has_generation(active));
        assert!(store.has_approval_key(active));
        assert!(!store.has_approval_key(stale));
    }

    #[test]
    fn setup_retry_preserves_prepared_desktop_transaction_until_recovery() {
        for replacement in [false, true] {
            let store = TestStore::default();
            let old = replacement.then(|| activate_initial_generation(&store));
            let original = uuid::Uuid::new_v4();
            stage_pending(&store, original);
            // The desktop has persisted Prepared, but its PairingCommit never arrived.
            let before_retry = store.secrets.borrow().clone();

            let error = begin_pending_pairing(&store, uuid::Uuid::new_v4()).unwrap_err();
            assert!(error
                .to_string()
                .contains("resume the original desktop transaction"));
            assert_eq!(*store.secrets.borrow(), before_retry);
            assert!(store.has_approval_key(original));
            assert_eq!(
                load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
                old
            );

            // Recovery uses only persisted state, as after restarting both devices.
            load_key_bound_generation(&store, original).unwrap();
            commit_pending_generation(&store, original).unwrap();
            activate_generation(&store, original).unwrap();
            assert_eq!(
                load_generation_id(&store, ACTIVE_PAIRING_GENERATION).unwrap(),
                Some(original)
            );
        }
    }

    #[test]
    fn setup_retry_can_replace_unpublished_staging_generation() {
        let store = TestStore::default();
        let stale = uuid::Uuid::new_v4();
        begin_pending_pairing(&store, stale).unwrap();
        store.add_approval_key(stale);
        let replacement = uuid::Uuid::new_v4();

        begin_pending_pairing(&store, replacement).unwrap();

        assert!(!store.has_approval_key(stale));
        assert_eq!(
            load_generation_id(&store, STAGING_PAIRING_GENERATION).unwrap(),
            Some(replacement)
        );
    }

    #[test]
    fn pre_handshake_cleanup_only_removes_its_own_generation() {
        let store = TestStore::default();
        let old = activate_initial_generation(&store);
        let stale = uuid::Uuid::new_v4();
        begin_pending_pairing(&store, stale).unwrap();
        let current = uuid::Uuid::new_v4();
        stage_pending(&store, current);
        let before_abort = store.secrets.borrow().clone();

        assert!(abort_unstarted_pairing(&store, stale).is_err());
        assert_eq!(*store.secrets.borrow(), before_abort);
        assert!(store.has_approval_key(current));

        abort_unstarted_pairing(&store, current).unwrap();
        assert!(!store.has_generation(current));
        assert!(!store.has_approval_key(current));
        assert!(store.has_generation(old));
        assert!(store.has_approval_key(old));
        begin_pending_pairing(&store, uuid::Uuid::new_v4()).unwrap();
    }

    #[test]
    fn reset_removes_pairing_generations_but_preserves_iroh_identity() {
        let store = TestStore::default();
        let active = activate_initial_generation(&store);
        store.save("iroh_secret_key", "identity").unwrap();

        clear_pairing_store(&store).unwrap();

        assert!(!store.has_generation(active));
        assert!(!store.has_approval_key(active));
        assert_eq!(
            store.get("iroh_secret_key").unwrap().as_deref(),
            Some("identity")
        );
    }

    #[test]
    fn reset_removes_all_tracked_pairing_approval_keys() {
        let store = TestStore::default();
        let active = activate_initial_generation(&store);
        let pending = uuid::Uuid::new_v4();
        stage_and_commit(&store, pending);

        let retiring = uuid::Uuid::new_v4();
        store.add_approval_key(retiring);
        store
            .save(
                &pairing_generation_key(retiring),
                &serde_json::to_string(&PairingGeneration {
                    version: PAIRING_GENERATION_VERSION,
                    pairing_id: retiring,
                    approval_public_key_der: vec![0x44],
                    phone_share: [0x11; 32],
                    pin4_hash: PIN_HASH.to_owned(),
                    pin6_hash: PIN_HASH.to_owned(),
                    cli_node_id: [0x22; 32],
                    enrollment: None,
                    prepared: None,
                    recovery: None,
                    enrollment_complete: false,
                })
                .unwrap(),
            )
            .unwrap();
        save_generation_id(&store, RETIRING_PAIRING_GENERATION, retiring).unwrap();

        clear_pairing_store(&store).unwrap();

        for pairing_id in [active, pending, retiring] {
            assert!(!store.has_generation(pairing_id));
            assert!(!store.has_approval_key(pairing_id));
        }
    }

    #[test]
    fn pin_attempt_state_update_is_atomic_across_concurrent_failures() {
        const FAILURES: usize = 24;

        let update_lock = Arc::new(Mutex::new(()));
        let persisted = Arc::new(Mutex::new(PinAttemptState::default()));
        let mut threads = Vec::new();

        for _ in 0..FAILURES {
            let update_lock = update_lock.clone();
            let load_state = persisted.clone();
            let save_state = persisted.clone();
            let clear_state = persisted.clone();
            threads.push(thread::spawn(move || {
                update_pin_attempt_state_with(
                    &update_lock,
                    || Ok(*load_state.lock().unwrap()),
                    |state| {
                        thread::yield_now();
                        *save_state.lock().unwrap() = state;
                        Ok(())
                    },
                    || {
                        *clear_state.lock().unwrap() = PinAttemptState::default();
                        Ok(())
                    },
                    |state| {
                        let failed_attempts = state.failed_attempts.saturating_add(1);
                        thread::yield_now();
                        state.failed_attempts = failed_attempts;
                        (PinAttemptStateWrite::Save, ())
                    },
                )
                .unwrap();
            }));
        }

        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(persisted.lock().unwrap().failed_attempts, FAILURES as u8);
    }
}
