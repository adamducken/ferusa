use anyhow::Context;
use log::{debug, error, info, warn};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{command, AppHandle, Emitter, Manager, Runtime, State};
use tokio::{
    sync::{oneshot, Mutex},
    task,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{AppError, Result};
use crate::peer::{
    AppPeer, INBOUND_FRAME_TIMEOUT, INBOUND_IDLE_TIMEOUT, UNAUTHENTICATED_INBOUND_IDLE_TIMEOUT,
};
use crate::pin::{hash_pin, validate_pin, verify_pin};
use crate::state::{AppState, PinKind};
use crate::storage;
use ferusa_core::auth::{
    validate_auth_timestamp, AuthRequest, PairingActivateAck, PairingCommitAck,
};
use ferusa_core::crypto::canonical_approval_payload;
use ferusa_core::enrollment::{
    canonical_enrollment_activated, canonical_enrollment_ready, EnrollmentActivated,
    EnrollmentContext, EnrollmentHello, EnrollmentPrepared, EnrollmentReady,
};
use ferusa_core::recovery::{
    canonical_recovery_authorized, canonical_recovery_consent, canonical_recovery_finished,
    RecoveryAuthorized, RecoveryBegin, RecoveryConsent, RecoveryContext, RecoveryFinished,
    RecoveryPurpose, RecoveryRejectCode, RecoveryRejected,
};
use ferusa_core::transport::FerusaMessage;
use ferusa_core::types::VaultAction;
use ferusa_core::FerusaError;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingRequestPayload {
    pub request_id: String,
    pub correlation_code: u16,
    pub action: String,
    pub entry_title: Option<String>,
    pub pin_digits: u8,
}

const REQUEST_DISPLAY_FIELD_MAX_CHARS: usize = 120;

fn sanitize_request_display_field(value: &str) -> Option<String> {
    let normalized: String = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let trimmed = normalized.trim();

    if trimmed.is_empty() {
        None
    } else {
        Some(truncate_display_field(
            trimmed,
            REQUEST_DISPLAY_FIELD_MAX_CHARS,
        ))
    }
}

fn truncate_display_field(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }

    let keep_chars = max_chars.saturating_sub(3);
    let mut truncated = value.chars().take(keep_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

impl From<&AuthRequest> for PendingRequestPayload {
    fn from(r: &AuthRequest) -> Self {
        debug!(
            "[ferusa:app]: PendingRequestPayload::from AuthRequest id={} action={:?}",
            r.request_id, r.action
        );
        let (action, pin_digits) = match r.action {
            VaultAction::Unlock => ("unlock", 4u8),
            VaultAction::List => ("list", 4u8),
            VaultAction::Read => ("read", 4u8),
            VaultAction::Create => ("create", 6),
            VaultAction::Update => ("update", 6),
            VaultAction::Delete => ("delete", 6),
            // NOTE: protocol action is `Passwd` to match the CLI command; app UI expands it for clarity.
            VaultAction::Passwd => ("change_password", 6),
            VaultAction::Pair => ("replace_pairing", 6),
        };
        debug!(
            "[ferusa:app]: mapped action={} pin_digits={}",
            action, pin_digits
        );
        PendingRequestPayload {
            request_id: r.request_id.to_string(),
            correlation_code: r.correlation_code,
            action: action.into(),
            entry_title: r
                .entry_title
                .as_deref()
                .and_then(sanitize_request_display_field),
            pin_digits,
        }
    }
}

const PIN_FAILURES_BEFORE_COOLDOWN: u8 = 3;
const PIN_COOLDOWN_BASE: Duration = Duration::from_secs(30);
const PIN_COOLDOWN_MAX: Duration = Duration::from_secs(30 * 60);
const AUTH_SESSION_TTL: Duration = Duration::from_secs(10 * 60);
const PAIRING_REPLACEMENT_AUTHORIZATION_TTL: Duration = AUTH_SESSION_TTL;
const APPROVAL_KEY_AUTH_TTL: Duration = Duration::from_secs(120);
const PENDING_REQUEST_TTL: Duration = Duration::from_secs(65);
// Refuse excess requests instead of evicting IDs that could still be replayed.
const MAX_RECENT_REQUEST_IDS: usize = 4096;

fn remember_request_id(
    recent: &mut HashMap<uuid::Uuid, Instant>,
    request_id: uuid::Uuid,
    now: Instant,
) -> bool {
    recent.retain(|_, seen_at| now.saturating_duration_since(*seen_at) < AUTH_SESSION_TTL);
    if recent.contains_key(&request_id) || recent.len() >= MAX_RECENT_REQUEST_IDS {
        return false;
    }
    recent.insert(request_id, now);
    true
}

fn pin_retry_limit_reached(failed_attempts: u8) -> bool {
    failed_attempts >= PIN_FAILURES_BEFORE_COOLDOWN
}

fn pairing_replacement_authorization_is_current(created_at: Instant) -> bool {
    created_at.elapsed() <= PAIRING_REPLACEMENT_AUTHORIZATION_TTL
}

fn approval_key_auth_is_current(authenticated_at: Instant) -> bool {
    authenticated_at.elapsed() <= APPROVAL_KEY_AUTH_TTL
}

fn auth_session_is_current(unlocked_at: Instant) -> bool {
    unlocked_at.elapsed() <= AUTH_SESSION_TTL
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn pin_kind_for_action(action: VaultAction) -> PinKind {
    match action {
        VaultAction::Unlock | VaultAction::List | VaultAction::Read => PinKind::FourDigit,
        _ => PinKind::SixDigit,
    }
}

fn expected_pin_len(kind: PinKind) -> usize {
    match kind {
        PinKind::FourDigit => 4,
        PinKind::SixDigit => 6,
    }
}

fn cooldown_duration_ms(level: u8) -> u64 {
    if level == 0 {
        return 0;
    }
    let multiplier = 1u32.checked_shl((level - 1).into()).unwrap_or(u32::MAX);
    PIN_COOLDOWN_BASE
        .saturating_mul(multiplier)
        .min(PIN_COOLDOWN_MAX)
        .as_millis() as u64
}

fn active_cooldown_remaining_ms(
    state: &mut storage::PinAttemptState,
    clock: tauri_plugin_keystore::ClockSnapshot,
) -> Option<u64> {
    let duration_ms = state.cooldown_duration_ms.or_else(|| {
        state
            .cooldown_until_ms
            .map(|_| cooldown_duration_ms(state.cooldown_level))
    })?;

    if state.cooldown_boot_count != Some(clock.boot_count)
        || state.cooldown_started_elapsed_ms.is_none()
    {
        state.cooldown_boot_count = Some(clock.boot_count);
        state.cooldown_started_elapsed_ms = Some(clock.elapsed_realtime_ms);
        state.cooldown_duration_ms = Some(duration_ms);
        state.cooldown_until_ms = None;
        return Some(duration_ms);
    }

    let started = state.cooldown_started_elapsed_ms?;
    let remaining = started
        .saturating_add(duration_ms)
        .saturating_sub(clock.elapsed_realtime_ms);
    if remaining == 0 {
        state.cooldown_started_elapsed_ms = None;
        state.cooldown_boot_count = None;
        state.cooldown_duration_ms = None;
        state.cooldown_until_ms = None;
        None
    } else {
        Some(remaining)
    }
}

fn record_pin_failure_state(
    state: &mut storage::PinAttemptState,
    clock: tauri_plugin_keystore::ClockSnapshot,
) -> Option<u64> {
    state.failed_attempts = state.failed_attempts.saturating_add(1);
    if !pin_retry_limit_reached(state.failed_attempts) {
        return None;
    }

    state.failed_attempts = 0;
    state.cooldown_level = state.cooldown_level.saturating_add(1).max(1);
    let duration_ms = cooldown_duration_ms(state.cooldown_level);
    state.cooldown_until_ms = None;
    state.cooldown_started_elapsed_ms = Some(clock.elapsed_realtime_ms);
    state.cooldown_boot_count = Some(clock.boot_count);
    state.cooldown_duration_ms = Some(duration_ms);
    Some(duration_ms)
}

fn existing_setup_requires_replacement_authorization(
    persisted_setup: bool,
    state_setup: bool,
) -> bool {
    persisted_setup || state_setup
}

fn pending_request_is_expired(
    pending_identity: PendingIdentity,
    expected_identity: PendingIdentity,
    now: Instant,
) -> bool {
    pending_identity == expected_identity
        && now.saturating_duration_since(pending_identity.created_at) >= PENDING_REQUEST_TTL
}

fn pairing_generation_matches(expected: uuid::Uuid, actual: uuid::Uuid) -> bool {
    expected == actual
}

async fn current_approval_alias(state: &AppState) -> Option<String> {
    let secrets_guard = state.secrets.lock().await;
    secrets_guard
        .as_ref()
        .map(|secrets| secrets.approval_key_alias.clone())
}

async fn current_authenticated_approval_alias(state: &AppState) -> Option<String> {
    let authenticated = state
        .approval_key_authenticated_at
        .lock()
        .await
        .as_ref()
        .copied()
        .is_some_and(approval_key_auth_is_current);
    if authenticated {
        current_approval_alias(state).await
    } else {
        None
    }
}

async fn clear_approval_key_authenticated(state: &AppState) {
    *state.approval_key_authenticated_at.lock().await = None;
}

async fn refresh_approval_key_auth<R: Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    reason: &str,
    generation: u64,
) -> Result<()> {
    require_biometric(app, reason).await?;
    state.mark_approval_key_authenticated(generation).await
}

async fn ensure_approval_key_auth<R: Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    reason: &str,
) -> Result<()> {
    let current = state
        .approval_key_authenticated_at
        .lock()
        .await
        .as_ref()
        .copied()
        .is_some_and(approval_key_auth_is_current);
    if current {
        return Ok(());
    }

    let generation = state.authentication_generation().await?;
    refresh_approval_key_auth(app, state, reason, generation).await
}

fn approval_key_auth_error_details(details: &str) -> bool {
    details.contains("approval key authentication required or expired")
        || details.contains("UserNotAuthenticatedException")
}

fn map_approval_key_error(error: anyhow::Error, operation: &'static str) -> AppError {
    let details = error.to_string();
    if approval_key_auth_error_details(&details) {
        AppError::ApprovalKeyAuthRequired { details }
    } else {
        AppError::Keystore { operation, details }
    }
}

fn map_approval_sign_error(error: anyhow::Error) -> AppError {
    map_approval_key_error(error, "sign")
}

async fn handle_signed_response_error(state: &AppState, error: AppError) -> AppError {
    if matches!(error, AppError::ApprovalKeyAuthRequired { .. }) {
        clear_approval_key_authenticated(state).await;
    }
    error
}

async fn send_signed_response<R: Runtime + 'static>(
    app: AppHandle<R>,
    send: &mut iroh::endpoint::SendStream,
    alias: String,
    req: &AuthRequest,
    approved: bool,
    unlock_share: Option<&[u8; 32]>,
) -> Result<()> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut resp = crate::peer::build_response_for_signing(req, approved, unlock_share, timestamp)?;
    let payload = canonical_approval_payload(req, &resp).map_err(AppError::Core)?;
    resp.signature = storage::sign_approval_blocking(app, alias, payload)
        .await
        .map_err(map_approval_sign_error)?;
    AppPeer::send_response(send, resp).await.map_err(|e| {
        AppError::Core(FerusaError::Network {
            operation: "stream_write",
            details: e.to_string(),
        })
    })
}

async fn deny_pending_request<R: Runtime + 'static>(
    app: AppHandle<R>,
    mut pending_req: PendingRequest,
    approval_alias: Option<String>,
    reason: &str,
) {
    warn!(
        "[ferusa:app]: {}: clearing pending request id={}",
        reason, pending_req.request.request_id
    );

    if let Some(alias) = approval_alias {
        match send_signed_response(
            app,
            &mut pending_req.send,
            alias,
            &pending_req.request,
            false,
            None,
        )
        .await
        {
            Ok(()) => {
                debug!(
                    "[ferusa:app]: {}: signed denial sent for pending request",
                    reason
                );
                return;
            }
            Err(e) => {
                error!(
                    "[ferusa:app]: {}: signed denial send failed, closing connection: {}",
                    reason, e
                );
            }
        }
    } else {
        warn!(
            "[ferusa:app]: {}: approval key unavailable; closing pending request connection",
            reason
        );
    }

    pending_req
        .conn
        .close(0u32.into(), b"pending request cancelled");
}

async fn take_and_deny_pending<R: Runtime + 'static>(
    app: AppHandle<R>,
    pending: &PendingReq,
    approval_alias: Option<String>,
    reason: &str,
) {
    let pending_req = {
        let mut slot = pending.lock().await;
        slot.take()
    };

    let Some(pending_req) = pending_req else {
        debug!(
            "[ferusa:app]: {}: no pending request to deny or close",
            reason
        );
        return;
    };

    deny_pending_request(app, pending_req, approval_alias, reason).await;
}

async fn take_and_deny_expired_pending<R: Runtime + 'static>(
    app: AppHandle<R>,
    pending: &PendingReq,
    approval_alias: Option<String>,
    expected_identity: PendingIdentity,
    reason: &str,
) {
    let pending_req = {
        let mut slot = pending.lock().await;
        if slot.as_ref().is_some_and(|pending_req| {
            pending_request_is_expired(pending_req.identity, expected_identity, Instant::now())
        }) {
            slot.take()
        } else {
            None
        }
    };

    let Some(pending_req) = pending_req else {
        debug!(
            "[ferusa:app]: {}: pending request no longer matches expiry task",
            reason
        );
        return;
    };

    deny_pending_request(app, pending_req, approval_alias, reason).await;
}

fn schedule_pending_expiry<R: Runtime + 'static>(
    app_handle: AppHandle<R>,
    pending: PendingReq,
    identity: PendingIdentity,
) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(PENDING_REQUEST_TTL).await;

        let state = app_handle.state::<AppState>();
        let approval_alias = current_authenticated_approval_alias(state.inner()).await;
        take_and_deny_expired_pending(
            app_handle.clone(),
            &pending,
            approval_alias,
            identity,
            "pending_request_expiry",
        )
        .await;
    });
}

async fn emit_session_expired<R: Runtime>(app: &AppHandle<R>) {
    if let Err(e) = app.emit("ferusa://session-expired", ()) {
        error!("[ferusa:app]: session-expired emit failed: {}", e);
    }
}

async fn expire_session<R: Runtime + 'static>(
    app: AppHandle<R>,
    state: &AppState,
    pending: &PendingReq,
    reason: &str,
) {
    let recovery = app.state::<RecoveryReq>().inner().clone();
    cancel_recovery(&app, &recovery).await;
    let approval_alias = current_authenticated_approval_alias(state).await;
    take_and_deny_pending(app.clone(), pending, approval_alias, reason).await;
    state.lock().await;
    emit_session_expired(&app).await;
}

async fn ensure_active_session<R: Runtime + 'static>(
    app: AppHandle<R>,
    state: &AppState,
    pending: &PendingReq,
    reason: &str,
) -> Result<()> {
    if !state.is_foreground() {
        expire_session(app, state, pending, reason).await;
        return Err(AppError::SessionExpired);
    }
    let current = state
        .unlocked_at
        .lock()
        .await
        .as_ref()
        .copied()
        .is_some_and(auth_session_is_current);

    if current && state.secrets.lock().await.is_some() {
        return Ok(());
    }

    warn!(
        "[ferusa:app]: {}: biometric session expired or locked",
        reason
    );
    expire_session(app, state, pending, reason).await;
    Err(AppError::SessionExpired)
}

fn schedule_session_expiry<R: Runtime + 'static>(
    app: AppHandle<R>,
    pending: PendingReq,
    generation: u64,
) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(AUTH_SESSION_TTL).await;
        let state = app.state::<AppState>();

        let generation_current = *state.session_generation.lock().await == generation;
        let expired = state
            .unlocked_at
            .lock()
            .await
            .as_ref()
            .copied()
            .is_some_and(|unlocked_at| !auth_session_is_current(unlocked_at));

        if generation_current && expired {
            expire_session(app.clone(), state.inner(), &pending, "auth_session_expiry").await;
        }
    });
}

async fn consume_pairing_replacement_authorization(state: &AppState) -> bool {
    let mut authorized_at = state.pairing_replacement_authorized_at.lock().await;
    let is_authorized = authorized_at
        .as_ref()
        .copied()
        .is_some_and(pairing_replacement_authorization_is_current);
    *authorized_at = None;
    is_authorized
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinVerificationOutcome {
    Verified,
    Incorrect,
    CooldownStarted { retry_after_ms: u64 },
    CooldownActive { retry_after_ms: u64 },
}

async fn run_argon2_job<T, F>(state: &AppState, job: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    let permit = state
        .argon2_jobs()
        .acquire_owned()
        .await
        .map_err(|e| anyhow::anyhow!("Argon2 semaphore closed: {e}"))?;
    task::spawn_blocking(move || {
        let _permit = permit;
        job()
    })
    .await
    .map_err(|e| anyhow::anyhow!("Argon2 task failed: {e}"))?
}

async fn hash_pin_bounded(state: &AppState, pin: Zeroizing<String>) -> anyhow::Result<String> {
    run_argon2_job(state, move || hash_pin(&pin)).await
}

async fn verify_pin_with_cooldown<R: Runtime + 'static>(
    app: AppHandle<R>,
    state: &AppState,
    kind: PinKind,
    pin: Zeroizing<String>,
    pin_hash: Zeroizing<String>,
) -> Result<PinVerificationOutcome> {
    let _attempt_guard = state.pin_attempt_gate(kind).lock_owned().await;
    let clock = tauri_plugin_keystore::clock_snapshot(&app).map_err(|e| AppError::Keystore {
        operation: "get",
        details: format!("read monotonic clock: {e}"),
    })?;
    let retry_after_ms =
        storage::update_pin_attempt_state_blocking(app.clone(), kind, move |state| {
            let retry_after_ms = active_cooldown_remaining_ms(state, clock);
            (storage::PinAttemptStateWrite::Save, retry_after_ms)
        })
        .await
        .map_err(|e| AppError::Keystore {
            operation: "set",
            details: e.to_string(),
        })?;

    if let Some(retry_after_ms) = retry_after_ms {
        return Ok(PinVerificationOutcome::CooldownActive { retry_after_ms });
    }

    let pin_ok = run_argon2_job(state, move || verify_pin(&pin, &pin_hash))
        .await
        .map_err(|e| AppError::Pin {
            operation: "verify",
            details: e.to_string(),
        })?;

    if pin_ok {
        storage::update_pin_attempt_state_blocking(app, kind, |_| {
            (storage::PinAttemptStateWrite::Clear, ())
        })
        .await
        .map_err(|e| AppError::Keystore {
            operation: "delete",
            details: e.to_string(),
        })?;
        return Ok(PinVerificationOutcome::Verified);
    }

    let clock = tauri_plugin_keystore::clock_snapshot(&app).map_err(|e| AppError::Keystore {
        operation: "get",
        details: format!("read monotonic clock: {e}"),
    })?;
    let retry_after_ms = storage::update_pin_attempt_state_blocking(app, kind, move |state| {
        (
            storage::PinAttemptStateWrite::Save,
            record_pin_failure_state(state, clock),
        )
    })
    .await
    .map_err(|e| AppError::Keystore {
        operation: "set",
        details: e.to_string(),
    })?;

    Ok(match retry_after_ms {
        Some(retry_after_ms) => PinVerificationOutcome::CooldownStarted { retry_after_ms },
        None => PinVerificationOutcome::Incorrect,
    })
}

// We store the SendStream to write the response on the correct stream. Keep it
// pending until approval, denial, or retry exhaustion so the CLI always receives
// a terminal response instead of waiting for a timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingIdentity {
    request_id: uuid::Uuid,
    // Server-generated per instance; the request contents never change after admission.
    instance_id: uuid::Uuid,
    session_generation: u64,
    created_at: Instant,
}

impl PendingIdentity {
    fn is_current(self, expected: Self, now: Instant) -> bool {
        self == expected && now.saturating_duration_since(self.created_at) < PENDING_REQUEST_TTL
    }
}

pub struct PendingRequest {
    request: AuthRequest,
    send: iroh::endpoint::SendStream,
    conn: iroh::endpoint::Connection,
    identity: PendingIdentity,
}

pub type PendingReq = Arc<Mutex<Option<PendingRequest>>>;

#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPhase {
    Review,
    WaitingForLaptop,
    Verifying,
    WaitingForUsb,
    Confirmed,
    Denied,
    Expired,
    Disconnected,
    Failed,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RecoveryView {
    request_id: uuid::Uuid,
    instance_id: uuid::Uuid,
    purpose: RecoveryPurpose,
    correlation_code: u16,
    pairing_id: uuid::Uuid,
    phase: RecoveryPhase,
    remaining_ms: u64,
}

pub struct PendingRecovery {
    context: RecoveryContext,
    phase: RecoveryPhase,
    deadline: Instant,
    consent: Option<oneshot::Sender<bool>>,
    conn: iroh::endpoint::Connection,
    enrollment: bool,
}

impl PendingRecovery {
    fn view(&self) -> RecoveryView {
        RecoveryView {
            request_id: self.context.begin.request_id,
            instance_id: self.context.instance_id,
            purpose: self.context.begin.purpose,
            correlation_code: self.context.begin.correlation_code,
            pairing_id: self.context.begin.pairing_id,
            phase: self.phase,
            remaining_ms: self
                .deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
        }
    }
}

pub type RecoveryReq = Arc<Mutex<Option<PendingRecovery>>>;

async fn cancel_recovery<R: Runtime>(app: &AppHandle<R>, slot: &RecoveryReq) {
    if let Some(mut pending) = slot.lock().await.take() {
        pending.phase = RecoveryPhase::Disconnected;
        let _ = app.emit("ferusa://recovery-request", Some(pending.view()));
        if let Some(consent) = pending.consent.take() {
            let _ = consent.send(false);
        }
        pending.conn.close(0u32.into(), b"recovery cancelled");
        let _ = app.emit("ferusa://recovery-request", Option::<RecoveryView>::None);
    }
}

async fn recovery_is_current(
    state: &AppState,
    slot: &RecoveryReq,
    context: &RecoveryContext,
    deadline: Instant,
) -> bool {
    let generation = state.session_generation.lock().await;
    if *generation != context.phone_session_generation
        || !state.is_foreground()
        || Instant::now() >= deadline
    {
        return false;
    }
    let current = slot.lock().await;
    let Some(pending) = current.as_ref().filter(|p| {
        p.context == *context && p.deadline == deadline && p.conn.close_reason().is_none()
    }) else {
        return false;
    };
    if !pending.enrollment {
        if !state
            .unlocked_at
            .lock()
            .await
            .as_ref()
            .copied()
            .is_some_and(auth_session_is_current)
        {
            return false;
        }
        if !state.secrets.lock().await.as_ref().is_some_and(|s| {
            s.pairing_id == context.begin.pairing_id && s.cli_node_id == context.desktop_id
        }) {
            return false;
        }
    }
    true
}

async fn recovery_phase<R: Runtime>(
    app: &AppHandle<R>,
    slot: &RecoveryReq,
    context: &RecoveryContext,
    phase: RecoveryPhase,
) -> anyhow::Result<()> {
    let mut guard = slot.lock().await;
    let pending = guard
        .as_mut()
        .filter(|pending| pending.context == *context)
        .context("recovery request expired or cancelled")?;
    pending.phase = phase;
    app.emit("ferusa://recovery-request", Some(pending.view()))?;
    Ok(())
}

async fn write_recovery_frame(
    send: &mut iroh::endpoint::SendStream,
    message: FerusaMessage,
    deadline: Instant,
) -> anyhow::Result<()> {
    let bytes = message.encode()?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        anyhow::bail!("recovery request expired");
    }
    tokio::time::timeout(remaining.min(INBOUND_FRAME_TIMEOUT), send.write_all(&bytes))
        .await
        .context("recovery write timed out")??;
    Ok(())
}

// Validate lifecycle and immutable request before every poll that can queue bytes.
// No lifecycle mutex is held while waiting for network progress.
async fn write_current_recovery_frame(
    state: &AppState,
    slot: &RecoveryReq,
    context: &RecoveryContext,
    send: &mut iroh::endpoint::SendStream,
    message: FerusaMessage,
    deadline: Instant,
) -> anyhow::Result<()> {
    use std::future::Future;
    use std::task::Poll;
    let bytes = message.encode()?;
    let write_deadline = deadline.min(Instant::now() + INBOUND_FRAME_TIMEOUT);
    let mut write = std::pin::pin!(send.write_all(&bytes));
    loop {
        let generation = state.session_generation.lock().await;
        let current = slot.lock().await;
        let pending = current
            .as_ref()
            .filter(|p| p.context == *context && p.deadline == deadline)
            .context("recovery cancelled before publication")?;
        if *generation != context.phone_session_generation
            || !state.is_foreground()
            || Instant::now() >= write_deadline
            || pending.conn.close_reason().is_some()
            || (!pending.enrollment
                && !state
                    .unlocked_at
                    .lock()
                    .await
                    .as_ref()
                    .copied()
                    .is_some_and(auth_session_is_current))
        {
            anyhow::bail!("recovery cancelled or expired before publication");
        }
        let progress = std::future::poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await;
        drop(current);
        drop(generation);
        match progress {
            Poll::Ready(result) => {
                result?;
                return Ok(());
            }
            Poll::Pending => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
}

async fn read_recovery_frame(
    recv: &mut iroh::endpoint::RecvStream,
    deadline: Instant,
) -> anyhow::Result<FerusaMessage> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        anyhow::bail!("recovery request expired");
    }
    crate::peer::read_recovery_message(recv, remaining).await
}

async fn sign_recovery<R: Runtime + 'static>(
    app: &AppHandle<R>,
    alias: &str,
    payload: Zeroizing<Vec<u8>>,
) -> anyhow::Result<Vec<u8>> {
    storage::sign_approval_blocking(app.clone(), alias.to_owned(), payload).await
}

struct RecoveryStream<'a> {
    conn: iroh::endpoint::Connection,
    send: &'a mut iroh::endpoint::SendStream,
    recv: &'a mut iroh::endpoint::RecvStream,
}

async fn handle_recovery_begin<R: Runtime + 'static>(
    app: AppHandle<R>,
    normal: &PendingReq,
    slot: &RecoveryReq,
    stream: RecoveryStream<'_>,
    begin: RecoveryBegin,
    candidate: Option<(&EnrollmentPrepared, &storage::StoredSecrets, u64)>,
) -> anyhow::Result<RecoveryFinished> {
    let RecoveryStream { conn, send, recv } = stream;
    begin.validate()?;
    validate_auth_timestamp(begin.timestamp_ms, current_time_ms())?;
    let state = app.state::<AppState>();
    let (alias, pin4_hash, pin6_hash, phone_share, expected_generation) =
        if let Some((prepared, stored, token)) = candidate {
            if prepared.pairing_id != begin.pairing_id
                || prepared.context.desktop_id != *conn.remote_id().as_bytes()
                || begin.transaction_id != Some(prepared.context.transaction_id)
                || begin.purpose != prepared.context.purpose
                || begin.credential_revision != prepared.context.credential_revision
                || begin.vault_digest != prepared.vault_digest
                || stored.pairing_id != prepared.pairing_id
                || stored.cli_node_id != prepared.context.desktop_id
            {
                anyhow::bail!("candidate recovery capability mismatch");
            }
            (
                stored.approval_key_alias.clone(),
                Zeroizing::new(stored.pin4_hash.clone()),
                Zeroizing::new(stored.pin6_hash.clone()),
                Zeroizing::new(stored.phone_share),
                token,
            )
        } else {
            if !matches!(
                begin.purpose,
                RecoveryPurpose::Create
                    | RecoveryPurpose::ConfirmExisting
                    | RecoveryPurpose::PasswordChange
            ) || !is_authorized_auth_peer(&conn, &app).await
            {
                anyhow::bail!("recovery peer or purpose not authorized");
            }
            let generation = state.session_generation.lock().await;
            if !state.is_foreground()
                || !state
                    .unlocked_at
                    .lock()
                    .await
                    .as_ref()
                    .copied()
                    .is_some_and(auth_session_is_current)
            {
                anyhow::bail!("phone must be unlocked and foregrounded");
            }
            let secrets = state.secrets.lock().await;
            let current = secrets.as_ref().context("phone session is locked")?;
            if current.pairing_id != begin.pairing_id
                || current.cli_node_id != *conn.remote_id().as_bytes()
            {
                anyhow::bail!("recovery pairing identity mismatch");
            }
            (
                current.approval_key_alias.clone(),
                Zeroizing::new(current.pin4_hash.clone()),
                Zeroizing::new(current.pin6_hash.clone()),
                Zeroizing::new(current.phone_share),
                *generation,
            )
        };
    let mut challenge = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut challenge);
    let deadline = Instant::now() + PENDING_REQUEST_TTL;
    let (consent_tx, consent_rx) = oneshot::channel();
    let context = {
        let generation = state.session_generation.lock().await;
        let _gate = state.operation_gate.lock().await;
        if *generation != expected_generation
            || !state.is_foreground()
            || normal.lock().await.is_some()
            || slot.lock().await.is_some()
        {
            anyhow::bail!("another security request is pending");
        }
        let mut recent = state.recent_request_ids.lock().await;
        if !remember_request_id(&mut recent, begin.request_id, Instant::now()) {
            anyhow::bail!("reused recovery request ID");
        }
        let context = RecoveryContext {
            begin,
            instance_id: uuid::Uuid::new_v4(),
            desktop_id: *conn.remote_id().as_bytes(),
            phone_challenge: challenge,
            phone_session_generation: *generation,
        };
        *slot.lock().await = Some(PendingRecovery {
            context: context.clone(),
            phase: RecoveryPhase::Review,
            deadline,
            consent: Some(consent_tx),
            conn: conn.clone(),
            enrollment: candidate.is_some(),
        });
        context
    };
    let mut rejection = RecoveryRejectCode::Protocol;
    let mut retry_after_ms = None;
    let result = async {
        {
            let current = slot.lock().await;
            let pending = current
                .as_ref()
                .filter(|pending| pending.context == context)
                .context("missing recovery request")?;
            app.emit("ferusa://recovery-request", Some(pending.view()))?;
        }
        let approved = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            consent_rx,
        )
        .await??;
        if !approved {
            rejection = RecoveryRejectCode::Denied;
        }
        if !approved || !recovery_is_current(state.inner(), slot, &context, deadline).await {
            anyhow::bail!("recovery denied, expired, or cancelled");
        }
        ensure_approval_key_auth(&app, state.inner(), "Authorize recovery file").await?;
        let mut consent = RecoveryConsent {
            context: context.clone(),
            timestamp_ms: current_time_ms(),
            signature: Vec::new(),
        };
        consent.signature =
            sign_recovery(&app, &alias, canonical_recovery_consent(&consent)?).await?;
        if !recovery_is_current(state.inner(), slot, &context, deadline).await {
            anyhow::bail!("recovery consent expired during signing");
        }
        write_current_recovery_frame(
            state.inner(),
            slot,
            &context,
            send,
            FerusaMessage::RecoveryConsent(consent),
            deadline,
        )
        .await?;
        recovery_phase(&app, slot, &context, RecoveryPhase::WaitingForLaptop).await?;

        let mut pins = match read_recovery_frame(recv, deadline).await? {
            FerusaMessage::RecoveryPins(pins) => pins,
            _ => anyhow::bail!("expected recovery PIN submission"),
        };
        if pins.instance_id != context.instance_id
            || pins.request_id != context.begin.request_id
            || pins.challenge != context.phone_challenge
        {
            anyhow::bail!("recovery PIN submission does not match request");
        }
        if pins.pin4.len() != 4
            || !pins.pin4.bytes().all(|b| b.is_ascii_digit())
            || pins.pin6.len() != 6
            || !pins.pin6.bytes().all(|b| b.is_ascii_digit())
        {
            anyhow::bail!("invalid recovery PIN format");
        }
        if !recovery_is_current(state.inner(), slot, &context, deadline).await {
            anyhow::bail!("recovery cancelled before PIN verification");
        }
        recovery_phase(&app, slot, &context, RecoveryPhase::Verifying).await?;
        let pin4 = Zeroizing::new(std::mem::take(&mut pins.pin4));
        let pin6 = Zeroizing::new(std::mem::take(&mut pins.pin6));
        match verify_pin_with_cooldown(
            app.clone(),
            state.inner(),
            PinKind::FourDigit,
            pin4,
            pin4_hash,
        )
        .await?
        {
            PinVerificationOutcome::Verified => {}
            PinVerificationOutcome::Incorrect => {
                rejection = RecoveryRejectCode::Denied;
                anyhow::bail!("recovery PIN verification failed");
            }
            PinVerificationOutcome::CooldownActive {
                retry_after_ms: remaining,
            }
            | PinVerificationOutcome::CooldownStarted {
                retry_after_ms: remaining,
            } => {
                rejection = RecoveryRejectCode::Cooldown;
                retry_after_ms = Some(remaining);
                anyhow::bail!("recovery PIN cooldown");
            }
        }
        if !recovery_is_current(state.inner(), slot, &context, deadline).await {
            anyhow::bail!("recovery cancelled during PIN verification");
        }
        match verify_pin_with_cooldown(
            app.clone(),
            state.inner(),
            PinKind::SixDigit,
            pin6,
            pin6_hash,
        )
        .await?
        {
            PinVerificationOutcome::Verified => {}
            PinVerificationOutcome::Incorrect => {
                rejection = RecoveryRejectCode::Denied;
                anyhow::bail!("recovery PIN verification failed");
            }
            PinVerificationOutcome::CooldownActive {
                retry_after_ms: remaining,
            }
            | PinVerificationOutcome::CooldownStarted {
                retry_after_ms: remaining,
            } => {
                rejection = RecoveryRejectCode::Cooldown;
                retry_after_ms = Some(remaining);
                anyhow::bail!("recovery PIN cooldown");
            }
        }
        if !recovery_is_current(state.inner(), slot, &context, deadline).await {
            anyhow::bail!("recovery cancelled during PIN verification");
        }
        ensure_approval_key_auth(&app, state.inner(), "Authorize recovery file").await?;
        let mut authorized = RecoveryAuthorized {
            context: context.clone(),
            phone_share: *phone_share,
            timestamp_ms: current_time_ms(),
            signature: Vec::new(),
        };
        authorized.signature =
            sign_recovery(&app, &alias, canonical_recovery_authorized(&authorized)?).await?;
        if !recovery_is_current(state.inner(), slot, &context, deadline).await {
            anyhow::bail!("recovery cancelled during signing");
        }
        recovery_phase(&app, slot, &context, RecoveryPhase::WaitingForUsb).await?;
        write_current_recovery_frame(
            state.inner(),
            slot,
            &context,
            send,
            FerusaMessage::RecoveryAuthorized(authorized),
            deadline,
        )
        .await?;
        let finish = match read_recovery_frame(recv, deadline).await? {
            FerusaMessage::RecoveryFinish(finish) => finish,
            _ => anyhow::bail!("expected recovery finish"),
        };
        if finish.file_id.is_nil()
            || finish.instance_id != context.instance_id
            || finish.request_id != context.begin.request_id
            || finish.challenge != context.phone_challenge
            || context.begin.file_id.is_some_and(|id| id != finish.file_id)
            || context
                .begin
                .expected_envelope_digest
                .is_some_and(|digest| digest != finish.envelope_digest)
        {
            anyhow::bail!("recovery finish does not match request");
        }
        let mut finished = RecoveryFinished {
            context: context.clone(),
            file_id: finish.file_id,
            envelope_digest: finish.envelope_digest,
            timestamp_ms: current_time_ms(),
            signature: Vec::new(),
        };
        finished.signature =
            sign_recovery(&app, &alias, canonical_recovery_finished(&finished)?).await?;
        if !recovery_is_current(state.inner(), slot, &context, deadline).await {
            anyhow::bail!("recovery cancelled during final signing");
        }
        if candidate.is_some() {
            storage::store_enrollment_receipt_blocking(app.clone(), finished.clone()).await?;
            if !recovery_is_current(state.inner(), slot, &context, deadline).await {
                anyhow::bail!("recovery cancelled during receipt persistence");
            }
        }
        write_current_recovery_frame(
            state.inner(),
            slot,
            &context,
            send,
            FerusaMessage::RecoveryFinished(finished.clone()),
            deadline,
        )
        .await?;
        if candidate.is_none() {
            send.finish()?;
        }
        recovery_phase(&app, slot, &context, RecoveryPhase::Confirmed).await?;
        Ok::<RecoveryFinished, anyhow::Error>(finished)
    }
    .await;
    if result.is_err() {
        if Instant::now() >= deadline {
            rejection = RecoveryRejectCode::Expired;
        }
        let phase = match rejection {
            RecoveryRejectCode::Denied | RecoveryRejectCode::Cooldown => RecoveryPhase::Denied,
            RecoveryRejectCode::Expired => RecoveryPhase::Expired,
            RecoveryRejectCode::Disconnected => RecoveryPhase::Disconnected,
            _ => RecoveryPhase::Failed,
        };
        let _ = recovery_phase(&app, slot, &context, phase).await;
        if write_recovery_frame(
            send,
            FerusaMessage::RecoveryRejected(RecoveryRejected {
                request_id: context.begin.request_id,
                code: rejection,
                retry_after_ms,
            }),
            deadline,
        )
        .await
        .is_ok()
        {
            let _ = send.finish();
            // write_all only queues data. Wait for the peer's acknowledgement
            // before the caller closes the connection on this error path.
            let _ = tokio::time::timeout(Duration::from_secs(5), send.stopped()).await;
        }
    }
    let mut guard = slot.lock().await;
    if guard
        .as_ref()
        .is_some_and(|pending| pending.context.instance_id == context.instance_id)
    {
        guard.take();
        let _ = app.emit("ferusa://recovery-request", Option::<RecoveryView>::None);
    }
    drop(guard);
    result
}

async fn take_verified_pending(
    state: &AppState,
    pending: &PendingReq,
    expected: PendingIdentity,
) -> Result<PendingRequest> {
    let generation = state.session_generation.lock().await;
    if *generation != expected.session_generation || !state.is_foreground() {
        return Err(AppError::SessionExpired);
    }
    if !state
        .unlocked_at
        .lock()
        .await
        .as_ref()
        .copied()
        .is_some_and(auth_session_is_current)
    {
        return Err(AppError::SessionExpired);
    }
    let mut slot = pending.lock().await;
    let current = slot
        .as_ref()
        .ok_or(AppError::PendingRequest { kind: "missing" })?;
    if current.request.request_id != expected.request_id
        || !current.identity.is_current(expected, Instant::now())
    {
        return Err(AppError::PendingRequest { kind: "mismatch" });
    }
    Ok(slot.take().expect("verified pending request exists"))
}

async fn restore_pending_after_sign_error(
    state: &AppState,
    pending: &PendingReq,
    pending_req: PendingRequest,
) {
    let generation = state.session_generation.lock().await;
    if *generation == pending_req.identity.session_generation
        && state.is_foreground()
        && pending_req
            .identity
            .is_current(pending_req.identity, Instant::now())
    {
        let mut slot = pending.lock().await;
        if slot.is_none() {
            *slot = Some(pending_req);
            return;
        }
    }
    debug!("[ferusa:app]: discarding superseded pending request after sign error");
}

fn biometric_prompt_title(reason: &str) -> String {
    format!("{reason} ferusa vault")
}

#[cfg(target_os = "android")]
async fn require_biometric<R: Runtime>(app: &AppHandle<R>, reason: &str) -> Result<()> {
    use tauri_plugin_biometric::{AuthOptions, BiometricExt};

    debug!("[ferusa:app]: invoking biometric prompt for {}", reason);
    app.biometric()
        .authenticate(
            biometric_prompt_title(reason),
            AuthOptions {
                allow_device_credential: false,
                ..Default::default()
            },
        )
        .map_err(|e| {
            error!("[ferusa:app]: biometric failed: {}", e);
            AppError::Biometric {
                details: e.to_string(),
            }
        })?;
    debug!("[ferusa:app]: biometric prompt passed");

    Ok(())
}

#[cfg(not(target_os = "android"))]
async fn require_biometric<R: Runtime>(_app: &AppHandle<R>, reason: &str) -> Result<()> {
    Err(AppError::Biometric {
        details: format!(
            "{} is only available on Android",
            biometric_prompt_title(reason)
        ),
    })
}

async fn is_authorized_auth_peer<R: Runtime>(
    conn: &iroh::endpoint::Connection,
    app_handle: &AppHandle<R>,
) -> bool {
    let remote_id = conn.remote_id();
    let state = app_handle.state::<AppState>();

    if !*state.is_setup.lock().await {
        warn!(
            "[ferusa:app]: rejecting auth request from {}: app not setup",
            remote_id
        );
        return false;
    }

    let secrets_guard = state.secrets.lock().await;
    let Some(secrets) = secrets_guard.as_ref() else {
        warn!(
            "[ferusa:app]: rejecting auth request from {}: app locked",
            remote_id
        );
        return false;
    };

    if remote_id.as_bytes() != &secrets.cli_node_id {
        warn!(
            "[ferusa:app]: rejecting auth request from unpaired peer {}",
            remote_id
        );
        return false;
    }

    true
}

async fn is_authorized_pairing_recovery_peer<R: Runtime + 'static>(
    conn: &iroh::endpoint::Connection,
    app: AppHandle<R>,
    pairing_id: uuid::Uuid,
) -> bool {
    match storage::pairing_generation_cli_node_id_blocking(app, pairing_id).await {
        Ok(Some(cli_node_id)) if conn.remote_id().as_bytes() == &cli_node_id => true,
        Ok(_) => {
            warn!(
                "[ferusa:app]: rejecting pairing recovery for generation {} from {}",
                pairing_id,
                conn.remote_id()
            );
            false
        }
        Err(e) => {
            error!("[ferusa:app]: pairing recovery authorization failed: {}", e);
            false
        }
    }
}

async fn send_pairing_recovery_ack(
    send: &mut iroh::endpoint::SendStream,
    message: FerusaMessage,
) -> anyhow::Result<()> {
    let bytes = message.encode().map_err(anyhow::Error::from)?;
    tokio::time::timeout(INBOUND_FRAME_TIMEOUT, send.write_all(&bytes))
        .await
        .context("timed out sending pairing recovery acknowledgement")?
        .context("send pairing recovery acknowledgement")?;
    send.finish()
        .context("finish pairing recovery acknowledgement")
}

async fn send_pong(send: &mut iroh::endpoint::SendStream, timeout: Duration) -> anyhow::Result<()> {
    let bytes = FerusaMessage::Pong { path_info: None }
        .encode()
        .context("encode pong")?;
    tokio::time::timeout(timeout, send.write_all(&bytes))
        .await
        .context("timed out sending pong")?
        .context("send pong")?;
    send.finish().context("finish pong")
}

fn remaining_unauthenticated_timeout(deadline: Instant, maximum: Duration) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    (!remaining.is_zero()).then(|| remaining.min(maximum))
}

pub async fn serve_connection<R: Runtime + 'static>(
    conn: iroh::endpoint::Connection,
    pending: PendingReq,
    app_handle: AppHandle<R>,
) {
    let recovery_slot = app_handle.state::<RecoveryReq>().inner().clone();
    let mut authenticated = false;
    let authentication_deadline = Instant::now() + UNAUTHENTICATED_INBOUND_IDLE_TIMEOUT;

    loop {
        debug!("[ferusa:app]: accepting bi-directional stream...");
        let accept_timeout = if authenticated {
            Some(INBOUND_IDLE_TIMEOUT)
        } else {
            remaining_unauthenticated_timeout(
                authentication_deadline,
                UNAUTHENTICATED_INBOUND_IDLE_TIMEOUT,
            )
        };
        let Some(accept_timeout) = accept_timeout else {
            info!("[ferusa:app]: closing connection after authentication deadline");
            conn.close(0u32.into(), b"authentication deadline");
            break;
        };
        let (mut send, mut recv) =
            match tokio::time::timeout(accept_timeout, conn.accept_bi()).await {
                Ok(Ok(s)) => {
                    debug!("[ferusa:app]: stream accepted");
                    s
                }
                Ok(Err(e)) => {
                    warn!("[ferusa:app]: accept_bi ended: {}", e);
                    break;
                }
                Err(_) => {
                    info!("[ferusa:app]: closing idle inbound connection");
                    conn.close(0u32.into(), b"idle connection");
                    break;
                }
            };

        debug!("[ferusa:app]: reading request data...");
        let read_timeout = if authenticated {
            Some(INBOUND_FRAME_TIMEOUT)
        } else {
            remaining_unauthenticated_timeout(authentication_deadline, INBOUND_FRAME_TIMEOUT)
        };
        let Some(read_timeout) = read_timeout else {
            info!("[ferusa:app]: closing connection after authentication deadline");
            conn.close(0u32.into(), b"authentication deadline");
            break;
        };
        let message = match crate::peer::read_ferusa_message(&mut recv, read_timeout).await {
            Ok(message) => message,
            Err(e) => {
                error!("[ferusa:app]: read error: {}", e);
                if !authenticated {
                    conn.close(0u32.into(), b"invalid unauthenticated frame");
                    break;
                }
                continue;
            }
        };
        match message {
            FerusaMessage::Ping => {
                let paired_peer = if authenticated {
                    true
                } else if let Some(timeout) = remaining_unauthenticated_timeout(
                    authentication_deadline,
                    UNAUTHENTICATED_INBOUND_IDLE_TIMEOUT,
                ) {
                    tokio::time::timeout(timeout, is_authorized_auth_peer(&conn, &app_handle))
                        .await
                        .unwrap_or(false)
                } else {
                    false
                };
                if paired_peer {
                    authenticated = true;
                }
                debug!(
                    "[ferusa:app]: received ping; replying pong paired_peer={}",
                    paired_peer
                );
                let Some(write_timeout) = (if authenticated {
                    Some(INBOUND_FRAME_TIMEOUT)
                } else {
                    remaining_unauthenticated_timeout(
                        authentication_deadline,
                        INBOUND_FRAME_TIMEOUT,
                    )
                }) else {
                    conn.close(0u32.into(), b"authentication deadline");
                    break;
                };
                if let Err(e) = send_pong(&mut send, write_timeout).await {
                    warn!(
                        "[ferusa:app]: closing connection after pong failure: {:#}",
                        e
                    );
                    conn.close(0u32.into(), b"pong failed");
                    break;
                }
                if !paired_peer {
                    conn.close(0u32.into(), b"unauthenticated ping complete");
                    break;
                }
            }
            FerusaMessage::PairingCommit(commit) => {
                let authorization_timeout = if authenticated {
                    Some(INBOUND_FRAME_TIMEOUT)
                } else {
                    remaining_unauthenticated_timeout(
                        authentication_deadline,
                        UNAUTHENTICATED_INBOUND_IDLE_TIMEOUT,
                    )
                };
                let authorized = if let Some(timeout) = authorization_timeout {
                    tokio::time::timeout(
                        timeout,
                        is_authorized_pairing_recovery_peer(
                            &conn,
                            app_handle.clone(),
                            commit.pairing_id,
                        ),
                    )
                    .await
                    .unwrap_or(false)
                } else {
                    false
                };
                let authorized = authorized
                    && !storage::generation_requires_recovery_blocking(
                        app_handle.clone(),
                        commit.pairing_id,
                    )
                    .await
                    .unwrap_or(true);
                if !authorized {
                    conn.close(0u32.into(), b"unauthorized pairing recovery");
                    break;
                }
                authenticated = true;
                match storage::mark_pending_pairing_committed_blocking(
                    app_handle.clone(),
                    commit.pairing_id,
                )
                .await
                {
                    Ok(()) => {
                        if let Err(e) = send_pairing_recovery_ack(
                            &mut send,
                            FerusaMessage::PairingCommitAck(PairingCommitAck {
                                pairing_id: commit.pairing_id,
                            }),
                        )
                        .await
                        {
                            error!("[ferusa:app]: pairing commit ACK failed: {}", e);
                        }
                    }
                    Err(e) => error!("[ferusa:app]: pairing recovery commit failed: {}", e),
                }
            }
            FerusaMessage::PairingActivate(activate) => {
                let authorization_timeout = if authenticated {
                    Some(INBOUND_FRAME_TIMEOUT)
                } else {
                    remaining_unauthenticated_timeout(
                        authentication_deadline,
                        UNAUTHENTICATED_INBOUND_IDLE_TIMEOUT,
                    )
                };
                let authorized = if let Some(timeout) = authorization_timeout {
                    tokio::time::timeout(
                        timeout,
                        is_authorized_pairing_recovery_peer(
                            &conn,
                            app_handle.clone(),
                            activate.pairing_id,
                        ),
                    )
                    .await
                    .unwrap_or(false)
                } else {
                    false
                };
                let authorized = authorized
                    && !storage::generation_requires_recovery_blocking(
                        app_handle.clone(),
                        activate.pairing_id,
                    )
                    .await
                    .unwrap_or(true);
                if !authorized {
                    conn.close(0u32.into(), b"unauthorized pairing recovery");
                    break;
                }
                authenticated = true;
                match storage::activate_pairing_generation_blocking(
                    app_handle.clone(),
                    activate.pairing_id,
                )
                .await
                {
                    Ok(_) => {
                        let state = app_handle.state::<AppState>();
                        state.lock().await;
                        *state.is_setup.lock().await = true;
                        if let Err(e) = app_handle.emit("ferusa://setup-changed", ()) {
                            error!("[ferusa:app]: setup-changed emit failed: {}", e);
                        }
                        if let Err(e) = send_pairing_recovery_ack(
                            &mut send,
                            FerusaMessage::PairingActivateAck(PairingActivateAck {
                                pairing_id: activate.pairing_id,
                            }),
                        )
                        .await
                        {
                            error!("[ferusa:app]: pairing activate ACK failed: {}", e);
                        }
                    }
                    Err(e) => error!("[ferusa:app]: pairing recovery activation failed: {}", e),
                }
            }
            FerusaMessage::RecoveryBegin(begin) => {
                if let Err(error) = handle_recovery_begin(
                    app_handle.clone(),
                    &pending,
                    &recovery_slot,
                    RecoveryStream {
                        conn: conn.clone(),
                        send: &mut send,
                        recv: &mut recv,
                    },
                    begin,
                    None,
                )
                .await
                {
                    warn!("[ferusa:app]: recovery request ended: {error:#}");
                    conn.close(0u32.into(), b"recovery request ended");
                    break;
                }
                authenticated = true;
            }
            FerusaMessage::Request(req) => {
                let authorization_timeout = if authenticated {
                    Some(INBOUND_FRAME_TIMEOUT)
                } else {
                    remaining_unauthenticated_timeout(
                        authentication_deadline,
                        UNAUTHENTICATED_INBOUND_IDLE_TIMEOUT,
                    )
                };
                let authorized = if let Some(timeout) = authorization_timeout {
                    tokio::time::timeout(timeout, is_authorized_auth_peer(&conn, &app_handle))
                        .await
                        .unwrap_or(false)
                } else {
                    false
                };
                if !authorized {
                    conn.close(0u32.into(), b"unauthorized auth request");
                    break;
                }
                authenticated = true;

                if let Err(err) = validate_auth_timestamp(req.timestamp, current_time_ms()) {
                    warn!(
                        "[ferusa:app]: rejecting AuthRequest id={}: stale timestamp: {}",
                        req.request_id, err
                    );
                    conn.close(0u32.into(), b"stale auth timestamp");
                    break;
                }

                if ensure_active_session(
                    app_handle.clone(),
                    app_handle.state::<AppState>().inner(),
                    &pending,
                    "auth_request",
                )
                .await
                .is_err()
                {
                    conn.close(0u32.into(), b"expired auth session");
                    break;
                }

                let (approval_alias, pairing_id, approval_key_authenticated) = {
                    let state = app_handle.state::<AppState>();
                    let (approval_alias, pairing_id) = {
                        let secrets_guard = state.secrets.lock().await;
                        let Some(secrets) = secrets_guard.as_ref() else {
                            warn!(
                                "[ferusa:app]: rejecting auth request: app locked after peer check"
                            );
                            conn.close(0u32.into(), b"locked during auth request");
                            break;
                        };
                        (secrets.approval_key_alias.clone(), secrets.pairing_id)
                    };
                    let authenticated = state
                        .approval_key_authenticated_at
                        .lock()
                        .await
                        .as_ref()
                        .copied()
                        .is_some_and(approval_key_auth_is_current);
                    (approval_alias, pairing_id, authenticated)
                };

                if !pairing_generation_matches(pairing_id, req.pairing_id) {
                    warn!(
                        "[ferusa:app]: rejecting auth request id={}: stale pairing generation",
                        req.request_id
                    );
                    conn.close(0u32.into(), b"stale pairing generation");
                    break;
                }

                info!("[ferusa:app]: received AuthRequest id={}", req.request_id);
                debug!("[ferusa:app]: storing pending request...");
                let mut incoming_send = Some(send);
                let state = app_handle.state::<AppState>();
                let generation = state.session_generation.lock().await;
                let operation_gate = state.operation_gate.lock().await;
                if !state.is_foreground() {
                    conn.close(0u32.into(), b"expired auth session");
                    break;
                }
                let identity = PendingIdentity {
                    request_id: req.request_id,
                    instance_id: uuid::Uuid::new_v4(),
                    session_generation: *generation,
                    created_at: Instant::now(),
                };
                let mut reused_id = false;
                let existing_request_id = {
                    let mut slot = pending.lock().await;
                    if recovery_slot.lock().await.is_some() {
                        Some(req.request_id)
                    } else if let Some(existing) = slot.as_ref() {
                        Some(existing.request.request_id)
                    } else {
                        let mut recent = state.recent_request_ids.lock().await;
                        if remember_request_id(&mut recent, req.request_id, identity.created_at) {
                            *slot = Some(PendingRequest {
                                request: req.clone(),
                                send: incoming_send
                                    .take()
                                    .expect("incoming send stream is available"),
                                conn: conn.clone(),
                                identity,
                            });
                        } else {
                            reused_id = true;
                        }
                        None
                    }
                };
                drop(generation);
                drop(operation_gate);

                if reused_id || existing_request_id.is_some() {
                    warn!(
                        "[ferusa:app]: rejecting AuthRequest id={}: reused id or pending id={:?}",
                        req.request_id, existing_request_id
                    );
                    //NOTE: Ferusa intentionally allows only one live security prompt because the desktop UI, the pending request slot,
                    //and the CLI response stream form a single approval transaction.
                    //Accepting a second request here would either replace the first request and leave its CLI stream waiting forever,
                    //or show the user a prompt that no longer matches the response stream we later approve or deny.
                    //Denying the newer request is the safest deterministic behavior because it preserves the prompt the user is already reviewing
                    //and gives the newer CLI an explicit terminal response instead of a timeout.
                    let mut send = incoming_send
                        .take()
                        .expect("incoming send stream remains available when request is rejected");
                    if approval_key_authenticated {
                        if let Err(e) = send_signed_response(
                            app_handle.clone(),
                            &mut send,
                            approval_alias,
                            &req,
                            false,
                            None,
                        )
                        .await
                        {
                            error!("[ferusa:app]: rejected request denial send failed: {}", e);
                        }
                    } else {
                        warn!(
                            "[ferusa:app]: concurrent request denial skipped because approval key auth expired"
                        );
                    }
                    continue;
                }
                debug!("[ferusa:app]: pending request stored");
                schedule_pending_expiry(app_handle.clone(), pending.clone(), identity);

                let payload = PendingRequestPayload::from(&req);
                debug!(
                    "[ferusa:app]: built PendingRequestPayload action={}",
                    payload.action
                );

                info!("[ferusa:app]: emitting auth-request event to frontend");
                if let Err(e) = app_handle.emit("ferusa://auth-request", payload) {
                    error!("[ferusa:app]: emit error: {}", e);
                    let hidden_request = {
                        let mut slot = pending.lock().await;
                        if slot
                            .as_ref()
                            .is_some_and(|pending_req| pending_req.identity == identity)
                        {
                            slot.take()
                        } else {
                            None
                        }
                    };
                    if let Some(hidden_request) = hidden_request {
                        deny_pending_request(
                            app_handle.clone(),
                            hidden_request,
                            Some(approval_alias),
                            "auth_request_emit_failed",
                        )
                        .await;
                    }
                } else {
                    debug!("[ferusa:app]: auth-request event emitted successfully");
                }
            }
            other => {
                warn!("[ferusa:app]: unexpected message variant: {:?}", other);
                if !authenticated {
                    conn.close(0u32.into(), b"unexpected unauthenticated message");
                    break;
                }
            }
        }
    }
}

#[derive(Debug, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SetupPayload {
    pub pin4: String,
    pub pin6: String,
    pub cli_node_id_hex: String,
}

fn generate_pairing_code() -> u16 {
    rand::rng().random_range(0..=9999)
}

fn format_pairing_code(code: u16) -> String {
    format!("{code:04}")
}

#[command]
pub async fn setup_pairing_code(state: State<'_, AppState>) -> Result<String> {
    let code = generate_pairing_code();
    *state.setup_pairing_code.lock().await = Some(code);
    Ok(format_pairing_code(code))
}

async fn consume_setup_pairing_code(state: &AppState) -> Result<u16> {
    state
        .setup_pairing_code
        .lock()
        .await
        .take()
        .ok_or_else(|| AppError::SetupInput {
            details: "pairing verification code was not generated by the backend".into(),
        })
}

#[derive(serde::Serialize)]
pub struct SetupStatus {
    paired: bool,
    pending: bool,
}

#[command]
pub async fn setup_status<R: Runtime>(app: AppHandle<R>) -> Result<SetupStatus> {
    Ok(SetupStatus {
        paired: storage::is_setup_blocking(app.clone())
            .await
            .map_err(|e| map_approval_key_error(e, "get"))?,
        pending: storage::enrollment_pending_blocking(app)
            .await
            .map_err(|e| map_approval_key_error(e, "get"))?,
    })
}

#[derive(serde::Serialize)]
pub struct SetupEnrollment {
    resume: bool,
}

#[command]
pub async fn setup_enrollment<R: Runtime>(
    app: AppHandle<R>,
    enrollment_token: String,
) -> Result<SetupEnrollment> {
    let context = EnrollmentContext::parse_token(&enrollment_token)?;
    let resume = storage::enrollment_secrets_blocking(app, context)
        .await
        .map_err(|e| map_approval_key_error(e, "get"))?
        .is_some();
    Ok(SetupEnrollment { resume })
}

async fn check_enrollment_lifecycle(state: &AppState, token: u64) -> Result<()> {
    if state.authentication_generation().await? != token {
        return Err(AppError::SessionExpired);
    }
    Ok(())
}

async fn write_enrollment_frame(
    state: &AppState,
    token: u64,
    conn: &iroh::endpoint::Connection,
    send: &mut iroh::endpoint::SendStream,
    message: FerusaMessage,
) -> anyhow::Result<()> {
    use std::future::Future;
    use std::task::Poll;
    let bytes = message.encode()?;
    let deadline = Instant::now() + INBOUND_FRAME_TIMEOUT;
    let mut write = std::pin::pin!(send.write_all(&bytes));
    loop {
        let generation = state.session_generation.lock().await;
        if *generation != token
            || !state.is_foreground()
            || Instant::now() >= deadline
            || conn.close_reason().is_some()
        {
            anyhow::bail!("enrollment expired or cancelled");
        }
        let progress = std::future::poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await;
        drop(generation);
        match progress {
            Poll::Ready(result) => {
                result?;
                return Ok(());
            }
            Poll::Pending => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
}

async fn complete_enrollment<R: Runtime + 'static>(
    app: &AppHandle<R>,
    state: &AppState,
    context: EnrollmentContext,
    stored: &storage::StoredSecrets,
    code: u16,
    token: u64,
) -> anyhow::Result<()> {
    let endpoint = state
        .endpoint
        .lock()
        .await
        .as_ref()
        .context("phone endpoint not ready")?
        .clone();
    let desktop = iroh::PublicKey::from_bytes(&context.desktop_id)?;
    let conn = tokio::time::timeout(
        Duration::from_secs(120),
        endpoint.connect(
            iroh::EndpointAddr::new(desktop),
            ferusa_core::transport::FERUSA_ALPN,
        ),
    )
    .await??;
    let (mut send, mut recv) =
        tokio::time::timeout(INBOUND_FRAME_TIMEOUT, conn.open_bi()).await??;
    check_enrollment_lifecycle(state, token).await?;
    write_enrollment_frame(
        state,
        token,
        &conn,
        &mut send,
        FerusaMessage::EnrollmentHello(EnrollmentHello {
            context: context.clone(),
            hello: ferusa_core::auth::PairingHello {
                pairing_id: stored.pairing_id,
                approval_public_key_der: stored.approval_public_key_der.clone(),
                phone_share: stored.phone_share,
                verification_code: code,
            },
        }),
    )
    .await?;
    let prepared =
        match crate::peer::read_ferusa_message(&mut recv, Duration::from_secs(120)).await? {
            FerusaMessage::EnrollmentPrepared(prepared)
                if prepared.context == context && prepared.pairing_id == stored.pairing_id =>
            {
                prepared
            }
            _ => anyhow::bail!("enrollment preparation does not match transaction"),
        };
    check_enrollment_lifecycle(state, token).await?;
    storage::bind_enrollment_vault_blocking(app.clone(), prepared.clone()).await?;
    check_enrollment_lifecycle(state, token).await?;
    let signature = storage::sign_approval_blocking(
        app.clone(),
        stored.approval_key_alias.clone(),
        canonical_enrollment_ready(&prepared)?,
    )
    .await?;
    write_enrollment_frame(
        state,
        token,
        &conn,
        &mut send,
        FerusaMessage::EnrollmentReady(EnrollmentReady {
            prepared: prepared.clone(),
            signature,
        }),
    )
    .await?;
    let begin = match crate::peer::read_ferusa_message(&mut recv, Duration::from_secs(120)).await? {
        FerusaMessage::RecoveryBegin(begin) => begin,
        _ => anyhow::bail!("mandatory candidate recovery required before commit"),
    };
    let normal = app.state::<PendingReq>().inner().clone();
    let recovery = app.state::<RecoveryReq>().inner().clone();
    let finished = handle_recovery_begin(
        app.clone(),
        &normal,
        &recovery,
        RecoveryStream {
            conn: conn.clone(),
            send: &mut send,
            recv: &mut recv,
        },
        begin,
        Some((&prepared, stored, token)),
    )
    .await?;
    let reference = ferusa_core::enrollment::RecoveryReference::from_finished(&finished)?;
    let commit = match crate::peer::read_ferusa_message(&mut recv, Duration::from_secs(120)).await?
    {
        FerusaMessage::EnrollmentCommit(value)
            if value.pairing_id == stored.pairing_id && value.recovery == reference =>
        {
            value
        }
        _ => anyhow::bail!("commit recovery reference mismatch"),
    };
    check_enrollment_lifecycle(state, token).await?;
    storage::check_enrollment_transition_blocking(app.clone(), commit.clone(), context.desktop_id)
        .await?;
    check_enrollment_lifecycle(state, token).await?;
    storage::mark_pending_pairing_committed_blocking(app.clone(), stored.pairing_id).await?;
    write_enrollment_frame(
        state,
        token,
        &conn,
        &mut send,
        FerusaMessage::EnrollmentCommitAck(commit),
    )
    .await?;
    let activate =
        match crate::peer::read_ferusa_message(&mut recv, Duration::from_secs(120)).await? {
            FerusaMessage::EnrollmentActivate(value)
                if value.pairing_id == stored.pairing_id && value.recovery == reference =>
            {
                value
            }
            _ => anyhow::bail!("activation recovery reference mismatch"),
        };
    check_enrollment_lifecycle(state, token).await?;
    storage::check_enrollment_transition_blocking(
        app.clone(),
        activate.clone(),
        context.desktop_id,
    )
    .await?;
    check_enrollment_lifecycle(state, token).await?;
    storage::activate_pairing_generation_blocking(app.clone(), stored.pairing_id).await?;
    check_enrollment_lifecycle(state, token).await?;
    let signature = storage::sign_approval_blocking(
        app.clone(),
        stored.approval_key_alias.clone(),
        canonical_enrollment_activated(&activate)?,
    )
    .await?;
    write_enrollment_frame(
        state,
        token,
        &conn,
        &mut send,
        FerusaMessage::EnrollmentActivated(EnrollmentActivated {
            transition: activate,
            signature,
        }),
    )
    .await?;
    send.finish()?;
    tokio::time::timeout(INBOUND_FRAME_TIMEOUT, recv.read_to_end(0)).await??;
    storage::complete_enrollment_blocking(app.clone(), context, stored.pairing_id).await?;
    conn.close(
        ferusa_core::transport::PAIRING_COMPLETE_CLOSE_CODE.into(),
        ferusa_core::transport::PAIRING_COMPLETE_CLOSE_REASON,
    );
    Ok(())
}

#[command]
pub async fn setup_complete<R: Runtime + 'static>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    payload: SetupPayload,
) -> Result<()> {
    let _enrollment = state
        .enrollment_gate
        .try_lock()
        .map_err(|_| AppError::PendingRequest { kind: "busy" })?;
    let mut payload = payload;
    let context = EnrollmentContext::parse_token(&payload.cli_node_id_hex)?;
    let token = state.authentication_generation().await?;
    let resume = storage::enrollment_secrets_blocking(app.clone(), context.clone())
        .await
        .map_err(|e| map_approval_key_error(e, "get"))?;
    check_enrollment_lifecycle(state.inner(), token).await?;
    let persisted_setup = storage::is_setup_blocking(app.clone())
        .await
        .map_err(|e| map_approval_key_error(e, "get"))?;
    if resume.is_none()
        && existing_setup_requires_replacement_authorization(
            persisted_setup,
            *state.is_setup.lock().await,
        )
        && !consume_pairing_replacement_authorization(state.inner()).await
    {
        return Err(AppError::PairingReplacementAuthorization);
    }
    let pairing_code = consume_setup_pairing_code(state.inner()).await?;
    let stored = if let Some(stored) = resume {
        if !payload.pin4.is_empty() || !payload.pin6.is_empty() {
            return Err(AppError::SetupInput {
                details: "resume uses the original phone PINs; do not establish new PINs".into(),
            });
        }
        stored
    } else {
        validate_pin(&payload.pin4, 4).map_err(|e| AppError::Pin {
            operation: "validate",
            details: e.to_string(),
        })?;
        validate_pin(&payload.pin6, 6).map_err(|e| AppError::Pin {
            operation: "validate",
            details: e.to_string(),
        })?;
        let pin4 = Zeroizing::new(std::mem::take(&mut payload.pin4));
        let pin6 = Zeroizing::new(std::mem::take(&mut payload.pin6));
        let pin4_hash =
            Zeroizing::new(hash_pin_bounded(state.inner(), pin4).await.map_err(|e| {
                AppError::Pin {
                    operation: "hash",
                    details: e.to_string(),
                }
            })?);
        let pin6_hash =
            Zeroizing::new(hash_pin_bounded(state.inner(), pin6).await.map_err(|e| {
                AppError::Pin {
                    operation: "hash",
                    details: e.to_string(),
                }
            })?);
        check_enrollment_lifecycle(state.inner(), token).await?;
        let pairing_id = uuid::Uuid::new_v4();
        let alias = format!("ferusa_approval_{pairing_id}");
        storage::begin_pending_pairing_generation_blocking(app.clone(), pairing_id)
            .await
            .map_err(|e| map_approval_key_error(e, "set"))?;
        let public = storage::generate_approval_key_blocking(app.clone(), alias.clone())
            .await
            .map_err(|e| map_approval_key_error(e, "generate"))?;
        check_enrollment_lifecycle(state.inner(), token).await?;
        let mut share = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut *share);
        let stored_result = async {
            storage::store_pending_pairing_secrets_blocking(
                app.clone(),
                pairing_id,
                alias.clone(),
                public.clone(),
                *share,
                pin4_hash.to_string(),
                pin6_hash.to_string(),
                context.desktop_id,
            )
            .await?;
            storage::attach_enrollment_blocking(app.clone(), pairing_id, context.clone()).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = stored_result {
            let _ = storage::clear_pending_pairing_blocking(app.clone(), pairing_id).await;
            return Err(map_approval_key_error(error, "set"));
        }
        storage::StoredSecrets {
            pairing_id,
            approval_key_alias: alias,
            approval_public_key_der: public,
            phone_share: *share,
            pin4_hash: pin4_hash.to_string(),
            pin6_hash: pin6_hash.to_string(),
            cli_node_id: context.desktop_id,
        }
    };
    // A new connection gets fresh local authentication, even when resuming saved secrets.
    refresh_approval_key_auth(
        &app,
        state.inner(),
        "Confirm enrollment and recovery",
        token,
    )
    .await?;
    check_enrollment_lifecycle(state.inner(), token).await?;
    complete_enrollment(&app, state.inner(), context, &stored, pairing_code, token)
        .await
        .map_err(|e| {
            AppError::Core(FerusaError::Network {
                operation: "enrollment",
                details: format!("{e:#}; resume the same desktop enrollment token"),
            })
        })?;
    *state.is_setup.lock().await = true;
    state.lock().await;
    Ok(())
}

#[command]
pub async fn check_setup<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
) -> Result<bool> {
    debug!("[ferusa:app]: check_setup");
    let stored = storage::is_setup_blocking(app.clone()).await.map_err(|e| {
        error!("[ferusa:app]: check_setup storage failed: {}", e);
        AppError::Keystore {
            operation: "get",
            details: e.to_string(),
        }
    })?;
    debug!("[ferusa:app]: check_setup storage result: {}", stored);
    if stored {
        *state.is_setup.lock().await = true;
        debug!("[ferusa:app]: check_setup: is_setup synced to state");
    }
    Ok(stored)
}

#[derive(Debug, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PairingReplacementPayload {
    pub pin4: String,
    pub pin6: String,
}

#[command]
pub async fn authorize_pairing_replacement<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    pending: State<'_, PendingReq>,
    payload: PairingReplacementPayload,
) -> Result<()> {
    info!("[ferusa:app]: authorize_pairing_replacement: authorizing replacement");
    let mut payload = payload;
    let generation = state.begin_pairing_replacement().await?;

    validate_pin(&payload.pin4, 4).map_err(|e| {
        error!(
            "[ferusa:app]: authorize_pairing_replacement: invalid 4-pin: {}",
            e
        );
        AppError::Pin {
            operation: "validate",
            details: e.to_string(),
        }
    })?;

    validate_pin(&payload.pin6, 6).map_err(|e| {
        error!(
            "[ferusa:app]: authorize_pairing_replacement: invalid 6-pin: {}",
            e
        );
        AppError::Pin {
            operation: "validate",
            details: e.to_string(),
        }
    })?;

    refresh_approval_key_auth(&app, state.inner(), "Replace pairing", generation.0).await?;

    let mut stored = match storage::load_secrets_blocking(app.clone()).await {
        Ok(stored) => stored,
        Err(e) => {
            error!(
                "[ferusa:app]: authorize_pairing_replacement: load secrets failed: {}",
                e
            );
            let err = map_approval_key_error(e, "get");
            let err = handle_signed_response_error(state.inner(), err).await;
            return Err(err);
        }
    };

    let pin4 = Zeroizing::new(std::mem::take(&mut payload.pin4));
    let pin4_hash = Zeroizing::new(std::mem::take(&mut stored.pin4_hash));
    match verify_pin_with_cooldown(
        app.clone(),
        state.inner(),
        PinKind::FourDigit,
        pin4,
        pin4_hash,
    )
    .await?
    {
        PinVerificationOutcome::Verified => {}
        PinVerificationOutcome::Incorrect => {
            warn!("[ferusa:app]: authorize_pairing_replacement: incorrect 4-pin");
            return Err(AppError::Pin {
                operation: "incorrect",
                details: "4-digit pairing replacement PIN verification failed".into(),
            });
        }
        PinVerificationOutcome::CooldownStarted { retry_after_ms } => {
            warn!("[ferusa:app]: authorize_pairing_replacement: 4-pin cooldown started");
            expire_session(
                app.clone(),
                state.inner(),
                pending.inner(),
                "pairing_replacement_pin_cooldown",
            )
            .await;
            return Err(AppError::PinCooldown {
                retry_after_ms,
                details: "4-digit pairing replacement PIN verification failed".into(),
            });
        }
        PinVerificationOutcome::CooldownActive { retry_after_ms } => {
            return Err(AppError::PinCooldown {
                retry_after_ms,
                details: "4-digit pairing replacement PIN cooldown active".into(),
            });
        }
    }

    let pin6 = Zeroizing::new(std::mem::take(&mut payload.pin6));
    let pin6_hash = Zeroizing::new(std::mem::take(&mut stored.pin6_hash));
    match verify_pin_with_cooldown(
        app.clone(),
        state.inner(),
        PinKind::SixDigit,
        pin6,
        pin6_hash,
    )
    .await?
    {
        PinVerificationOutcome::Verified => {}
        PinVerificationOutcome::Incorrect => {
            warn!("[ferusa:app]: authorize_pairing_replacement: incorrect 6-pin");
            return Err(AppError::Pin {
                operation: "incorrect",
                details: "6-digit pairing replacement PIN verification failed".into(),
            });
        }
        PinVerificationOutcome::CooldownStarted { retry_after_ms } => {
            warn!("[ferusa:app]: authorize_pairing_replacement: 6-pin cooldown started");
            expire_session(
                app.clone(),
                state.inner(),
                pending.inner(),
                "pairing_replacement_pin_cooldown",
            )
            .await;
            return Err(AppError::PinCooldown {
                retry_after_ms,
                details: "6-digit pairing replacement PIN verification failed".into(),
            });
        }
        PinVerificationOutcome::CooldownActive { retry_after_ms } => {
            return Err(AppError::PinCooldown {
                retry_after_ms,
                details: "6-digit pairing replacement PIN cooldown active".into(),
            });
        }
    }

    state.complete_pairing_replacement(generation).await?;
    info!("[ferusa:app]: authorize_pairing_replacement: authorization passed");
    Ok(())
}

#[command]
pub async fn cancel_pairing_replacement(state: State<'_, AppState>) -> Result<()> {
    state.cancel_pairing_replacement().await;
    info!("[ferusa:app]: pairing replacement authorization cancelled");
    Ok(())
}

#[command]
pub async fn biometric_unlock<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    pending: State<'_, PendingReq>,
) -> Result<()> {
    info!("[ferusa:app]: biometric_unlock");
    let generation = state.authentication_generation().await?;
    refresh_approval_key_auth(&app, state.inner(), "Unlock", generation).await?;

    debug!("[ferusa:app]: loading secrets");
    let stored = match storage::load_secrets_blocking(app.clone()).await {
        Ok(stored) => stored,
        Err(e) => {
            error!("[ferusa:app]: load secrets failed: {}", e);
            let err = map_approval_key_error(e, "get");
            let err = handle_signed_response_error(state.inner(), err).await;
            return Err(err);
        }
    };
    debug!("[ferusa:app]: secrets loaded from storage");

    let generation = state
        .complete_unlock(generation, stored.into_state_secrets())
        .await?;
    debug!("[ferusa:app]: secrets written to app state");

    schedule_session_expiry(app.clone(), pending.inner().clone(), generation);
    debug!("[ferusa:app]: biometric_unlock: session timer started");

    *state.is_setup.lock().await = true;
    debug!("[ferusa:app]: biometric_unlock: is_setup synced to state");

    info!("[ferusa:app]: biometric_unlock success");
    Ok(())
}

#[command]
pub async fn lock<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    pending: State<'_, PendingReq>,
) -> Result<()> {
    let recovery = app.state::<RecoveryReq>().inner().clone();
    cancel_recovery(&app, &recovery).await;
    info!("[ferusa:app]: lock: denying pending request and clearing secrets from state");
    let approval_alias = current_authenticated_approval_alias(state.inner()).await;
    take_and_deny_pending(app, pending.inner(), approval_alias, "lock").await;
    state.lock().await;
    debug!("[ferusa:app]: lock: state cleared");
    Ok(())
}

#[command]
pub async fn set_app_foreground<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    pending: State<'_, PendingReq>,
    foreground: bool,
) -> Result<()> {
    state.set_foreground(foreground).await;
    if !foreground {
        let recovery = app.state::<RecoveryReq>().inner().clone();
        cancel_recovery(&app, &recovery).await;
        expire_session(app, state.inner(), pending.inner(), "app_backgrounded").await;
    }
    Ok(())
}

#[command]
pub async fn pending_recovery(pending: State<'_, RecoveryReq>) -> Result<Option<RecoveryView>> {
    Ok(pending.lock().await.as_ref().map(PendingRecovery::view))
}

#[command]
pub async fn confirm_recovery(
    state: State<'_, AppState>,
    pending: State<'_, RecoveryReq>,
    instance_id: uuid::Uuid,
) -> Result<()> {
    let generation = state.session_generation.lock().await;
    if !state.is_foreground() {
        return Err(AppError::SessionExpired);
    }
    let mut guard = pending.lock().await;
    let request = guard
        .as_mut()
        .ok_or(AppError::PendingRequest { kind: "missing" })?;
    if request.context.instance_id != instance_id
        || request.context.phone_session_generation != *generation
        || Instant::now() >= request.deadline
        || !matches!(request.phase, RecoveryPhase::Review)
    {
        return Err(AppError::PendingRequest { kind: "mismatch" });
    }
    request
        .consent
        .take()
        .ok_or(AppError::PendingRequest { kind: "mismatch" })?
        .send(true)
        .map_err(|_| AppError::PendingRequest { kind: "missing" })
}

#[command]
pub async fn deny_recovery<R: Runtime>(
    app: AppHandle<R>,
    pending: State<'_, RecoveryReq>,
    instance_id: uuid::Uuid,
) -> Result<()> {
    let mut guard = pending.lock().await;
    if !guard
        .as_ref()
        .is_some_and(|request| request.context.instance_id == instance_id)
    {
        return Err(AppError::PendingRequest { kind: "mismatch" });
    }
    if let Some(request) = guard.as_mut() {
        if matches!(request.phase, RecoveryPhase::Review) {
            if let Some(consent) = request.consent.take() {
                request.phase = RecoveryPhase::Denied;
                let view = request.view();
                drop(guard);
                let _ = app.emit("ferusa://recovery-request", Some(view));
                let _ = consent.send(false);
                return Ok(());
            }
        }
    }
    let mut request = guard.take().expect("checked recovery request");
    request.phase = RecoveryPhase::Denied;
    let _ = app.emit("ferusa://recovery-request", Some(request.view()));
    if let Some(consent) = request.consent.take() {
        let _ = consent.send(false);
    }
    request.conn.close(0u32.into(), b"recovery denied");
    let _ = app.emit("ferusa://recovery-request", Option::<RecoveryView>::None);
    drop(guard);
    Ok(())
}

#[command]
pub async fn pending_request(
    pending: State<'_, PendingReq>,
) -> Result<Option<PendingRequestPayload>> {
    debug!("[ferusa:app]: pending_request: acquiring lock");
    let guard = pending.lock().await;
    let has_pending = guard.is_some();
    debug!("[ferusa:app]: pending_request: has_pending={}", has_pending);
    Ok(guard
        .as_ref()
        .map(|pending| PendingRequestPayload::from(&pending.request)))
}

#[derive(Debug, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ApprovePayload {
    pub request_id: String,
    pub pin: String,
}

#[command]
pub async fn approve_request<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    pending: State<'_, PendingReq>,
    payload: ApprovePayload,
) -> Result<()> {
    let mut payload = payload;
    info!(
        "[ferusa:app]: approve_request: request_id={}",
        payload.request_id
    );
    ensure_active_session(
        app.clone(),
        state.inner(),
        pending.inner(),
        "approve_request",
    )
    .await?;

    let (pin_kind, expected_len, identity) = {
        let pend = pending.lock().await;
        let pending_req = pend.as_ref().ok_or_else(|| {
            warn!("[ferusa:app]: approve_request: no pending request found");
            AppError::PendingRequest { kind: "missing" }
        })?;

        debug!("[ferusa:app]: approve_request: validating request_id match");
        if pending_req.request.request_id.to_string() != payload.request_id {
            error!(
                "[ferusa:app]: request_id mismatch: expected={} got={}",
                pending_req.request.request_id, payload.request_id
            );
            return Err(AppError::PendingRequest { kind: "mismatch" });
        }
        if !pending_req
            .identity
            .is_current(pending_req.identity, Instant::now())
        {
            return Err(AppError::PendingRequest { kind: "mismatch" });
        }
        debug!("[ferusa:app]: approve_request: request_id matched");

        let pin_kind = pin_kind_for_action(pending_req.request.action);
        let expected_len = expected_pin_len(pin_kind);

        (pin_kind, expected_len, pending_req.identity)
    };

    let (approval_alias, pin_hash) = {
        let secrets_guard = state.secrets.lock().await;
        let secrets = secrets_guard.as_ref().ok_or_else(|| {
            warn!("[ferusa:app]: approve_request: app is locked, no secrets in state");
            AppError::PendingRequest { kind: "locked" }
        })?;

        let pin_hash = match pin_kind {
            PinKind::FourDigit => secrets.pin4_hash.clone(),
            PinKind::SixDigit => secrets.pin6_hash.clone(),
        };

        (secrets.approval_key_alias.clone(), Zeroizing::new(pin_hash))
    };

    validate_pin(&payload.pin, expected_len).map_err(|e| {
        let err = e.to_string();
        error!("[ferusa:app]: validate_pin failed: {}", err);
        AppError::Pin {
            operation: "validate",
            details: err,
        }
    })?;
    debug!("[ferusa:app]: approve_request: PIN format valid");

    let pin = Zeroizing::new(std::mem::take(&mut payload.pin));
    let pin_outcome =
        verify_pin_with_cooldown(app.clone(), state.inner(), pin_kind, pin, pin_hash).await?;

    if let PinVerificationOutcome::CooldownActive { retry_after_ms } = pin_outcome {
        ensure_approval_key_auth(&app, state.inner(), "Deny").await?;

        let mut pending_req =
            take_verified_pending(state.inner(), pending.inner(), identity).await?;

        warn!("[ferusa:app]: approve_request: PIN cooldown active; denying request");
        if let Err(e) = send_signed_response(
            app.clone(),
            &mut pending_req.send,
            approval_alias.clone(),
            &pending_req.request,
            false,
            None,
        )
        .await
        {
            error!("[ferusa:app]: active-cooldown denial send failed: {}", e);
            let err = handle_signed_response_error(state.inner(), e).await;
            if matches!(err, AppError::ApprovalKeyAuthRequired { .. }) {
                restore_pending_after_sign_error(state.inner(), pending.inner(), pending_req).await;
            }
            return Err(err);
        }

        state.lock().await;
        emit_session_expired(&app).await;

        return Err(AppError::PinCooldown {
            retry_after_ms,
            details: format!("{pin_kind:?} PIN cooldown active"),
        });
    }

    if pin_outcome == PinVerificationOutcome::Incorrect {
        return Err(AppError::Pin {
            operation: "incorrect",
            details: "PIN verification returned false".into(),
        });
    }

    if let PinVerificationOutcome::CooldownStarted { retry_after_ms } = pin_outcome {
        ensure_approval_key_auth(&app, state.inner(), "Deny").await?;

        let mut pending_req =
            take_verified_pending(state.inner(), pending.inner(), identity).await?;

        warn!("[ferusa:app]: approve_request: PIN cooldown started; denying request");
        if let Err(e) = send_signed_response(
            app.clone(),
            &mut pending_req.send,
            approval_alias.clone(),
            &pending_req.request,
            false,
            None,
        )
        .await
        {
            error!("[ferusa:app]: retry-limit denial send failed: {}", e);
            let err = handle_signed_response_error(state.inner(), e).await;
            if matches!(err, AppError::ApprovalKeyAuthRequired { .. }) {
                restore_pending_after_sign_error(state.inner(), pending.inner(), pending_req).await;
            }
            return Err(err);
        }

        state.lock().await;
        emit_session_expired(&app).await;

        return Err(AppError::PinCooldown {
            retry_after_ms,
            details: "PIN cooldown started".into(),
        });
    }

    debug!("[ferusa:app]: approve_request: PIN verified successfully");
    ensure_approval_key_auth(&app, state.inner(), "Approve").await?;

    let mut pending_req = take_verified_pending(state.inner(), pending.inner(), identity).await?;
    debug!("[ferusa:app]: approve_request: took ownership of pending request");

    if !state.is_foreground() {
        pending_req
            .conn
            .close(0u32.into(), b"app moved to background");
        state.lock().await;
        return Err(AppError::SessionExpired);
    }

    let phone_share = if pending_req.request.unlock_share_requested {
        let secrets_guard = state.secrets.lock().await;
        let Some(secrets) = secrets_guard.as_ref() else {
            warn!("[ferusa:app]: approve_request: app is locked before unlock-share copy");
            pending_req
                .conn
                .close(0u32.into(), b"app locked before approval");
            return Err(AppError::PendingRequest { kind: "locked" });
        };
        Some(Zeroizing::new(secrets.phone_share))
    } else {
        None
    };
    let unlock_share = phone_share.as_ref().map(|share| &**share);

    if !pending_req.identity.is_current(identity, Instant::now()) {
        pending_req
            .conn
            .close(0u32.into(), b"pending request expired");
        return Err(AppError::PendingRequest { kind: "mismatch" });
    }

    debug!("[ferusa:app]: sending approval response");
    if let Err(e) = send_signed_response(
        app,
        &mut pending_req.send,
        approval_alias,
        &pending_req.request,
        true,
        unlock_share,
    )
    .await
    {
        error!("[ferusa:app]: send_response failed: {}", e);
        let err = handle_signed_response_error(state.inner(), e).await;
        if matches!(err, AppError::ApprovalKeyAuthRequired { .. }) {
            restore_pending_after_sign_error(state.inner(), pending.inner(), pending_req).await;
        }
        return Err(err);
    }
    debug!("[ferusa:app]: approve_request: response written and stream finished");

    debug!("[ferusa:app]: approve_request: response sent; connection handler keeps session alive");

    info!("[ferusa:app]: approve_request done");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        active_cooldown_remaining_ms, auth_session_is_current,
        consume_pairing_replacement_authorization, cooldown_duration_ms,
        existing_setup_requires_replacement_authorization, pairing_generation_matches,
        pairing_replacement_authorization_is_current, pending_request_is_expired,
        pin_retry_limit_reached, record_pin_failure_state, remaining_unauthenticated_timeout,
        remember_request_id, run_argon2_job, sanitize_request_display_field, send_pong,
        take_verified_pending, AppState, PendingIdentity, PendingReq, PendingRequest,
        PendingRequestPayload, PinKind, PinVerificationOutcome, APPROVAL_KEY_AUTH_TTL,
        AUTH_SESSION_TTL, PAIRING_REPLACEMENT_AUTHORIZATION_TTL, PENDING_REQUEST_TTL,
        PIN_FAILURES_BEFORE_COOLDOWN, REQUEST_DISPLAY_FIELD_MAX_CHARS,
    };
    use crate::peer::{AppPeer, INBOUND_FRAME_TIMEOUT};
    use crate::storage::PinAttemptState;
    use ferusa_core::auth::{AuthRequest, AuthResponse};
    use ferusa_core::transport::{FerusaMessage, FERUSA_ALPN};
    use ferusa_core::types::VaultAction;
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };
    use tauri_plugin_keystore::ClockSnapshot;
    use tokio::sync::Mutex;

    async fn simulate_wrong_pin_attempt(
        app_state: Arc<AppState>,
        attempts: Arc<Mutex<PinAttemptState>>,
        kind: PinKind,
        clock: ClockSnapshot,
        argon2_runs: Arc<AtomicUsize>,
    ) -> PinVerificationOutcome {
        let _attempt_guard = app_state.pin_attempt_gate(kind).lock_owned().await;
        if let Some(retry_after_ms) =
            active_cooldown_remaining_ms(&mut *attempts.lock().await, clock)
        {
            return PinVerificationOutcome::CooldownActive { retry_after_ms };
        }

        run_argon2_job(&app_state, move || {
            argon2_runs.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();

        match record_pin_failure_state(&mut *attempts.lock().await, clock) {
            Some(retry_after_ms) => PinVerificationOutcome::CooldownStarted { retry_after_ms },
            None => PinVerificationOutcome::Incorrect,
        }
    }

    #[tokio::test]
    async fn paired_connection_supports_ping_then_approval_on_the_same_session() {
        let phone_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let cli_endpoint = Arc::new(
            iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                .alpns(vec![FERUSA_ALPN.to_vec()])
                .bind()
                .await
                .unwrap(),
        );

        let phone_server = phone_endpoint.clone();
        let server = tokio::spawn(async move {
            let incoming = phone_server.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();

            let (mut ping_send, mut ping_recv) = conn.accept_bi().await.unwrap();
            let ping = ping_recv.read_to_end(1024 * 1024).await.unwrap();
            assert!(matches!(
                FerusaMessage::decode(&ping).unwrap(),
                FerusaMessage::Ping
            ));
            send_pong(&mut ping_send, INBOUND_FRAME_TIMEOUT)
                .await
                .unwrap();

            let (mut approval_send, mut approval_recv) = conn.accept_bi().await.unwrap();
            let request = approval_recv.read_to_end(1024 * 1024).await.unwrap();
            let request = match FerusaMessage::decode(&request).unwrap() {
                FerusaMessage::Request(request) => request,
                other => panic!("expected approval request, got {other:?}"),
            };
            AppPeer::send_response(
                &mut approval_send,
                AuthResponse {
                    pairing_id: request.pairing_id,
                    request_id: request.request_id,
                    correlation_code: request.correlation_code,
                    action: request.action,
                    unlock_share: None,
                    approved: false,
                    timestamp: request.timestamp,
                    signature: Vec::new(),
                },
            )
            .await
            .unwrap();
            let _ = conn.closed().await;
        });

        let conn = cli_endpoint
            .connect(phone_endpoint.addr(), FERUSA_ALPN)
            .await
            .unwrap();
        let (mut ping_send, mut ping_recv) = conn.open_bi().await.unwrap();
        ping_send
            .write_all(&FerusaMessage::Ping.encode().unwrap())
            .await
            .unwrap();
        ping_send.finish().unwrap();
        let pong = ping_recv.read_to_end(1024 * 1024).await.unwrap();
        assert!(matches!(
            FerusaMessage::decode(&pong).unwrap(),
            FerusaMessage::Pong { .. }
        ));

        let request = AuthRequest {
            pairing_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            correlation_code: 1234,
            action: VaultAction::Read,
            entry_title: Some("example".into()),
            unlock_share_requested: false,
            timestamp: 42,
        };
        let (mut approval_send, mut approval_recv) = conn.open_bi().await.unwrap();
        approval_send
            .write_all(&FerusaMessage::Request(request.clone()).encode().unwrap())
            .await
            .unwrap();
        approval_send.finish().unwrap();
        let response = approval_recv.read_to_end(1024 * 1024).await.unwrap();
        let response = match FerusaMessage::decode(&response).unwrap() {
            FerusaMessage::Response(response) => response,
            other => panic!("expected approval response, got {other:?}"),
        };
        assert_eq!(response.request_id, request.request_id);

        conn.close(0u32.into(), b"test complete");
        server.await.unwrap();
        cli_endpoint.close().await;
        phone_endpoint.close().await;
    }

    async fn run_wrong_pin_burst(kind: PinKind) {
        const SUBMISSIONS: usize = 12;
        const CLOCK: ClockSnapshot = ClockSnapshot {
            elapsed_realtime_ms: 1_000,
            boot_count: 7,
        };

        let app_state = Arc::new(AppState::new());
        let attempts = Arc::new(Mutex::new(PinAttemptState::default()));
        let argon2_runs = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();

        for _ in 0..SUBMISSIONS {
            tasks.push(tokio::spawn(simulate_wrong_pin_attempt(
                app_state.clone(),
                attempts.clone(),
                kind,
                CLOCK,
                argon2_runs.clone(),
            )));
        }

        let mut outcomes = Vec::new();
        for task in tasks {
            outcomes.push(task.await.unwrap());
        }

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == PinVerificationOutcome::Incorrect)
                .count(),
            2
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PinVerificationOutcome::CooldownStarted { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PinVerificationOutcome::CooldownActive { .. }))
                .count(),
            SUBMISSIONS - PIN_FAILURES_BEFORE_COOLDOWN as usize
        );
        assert_eq!(argon2_runs.load(Ordering::SeqCst), 3);

        let attempts = *attempts.lock().await;
        assert_eq!(attempts.failed_attempts, 0);
        assert_eq!(attempts.cooldown_level, 1);
        assert_eq!(attempts.cooldown_until_ms, None);
        assert_eq!(attempts.cooldown_started_elapsed_ms, Some(1_000));
        assert_eq!(attempts.cooldown_boot_count, Some(7));
        assert_eq!(attempts.cooldown_duration_ms, Some(30_000));
    }

    #[test]
    fn pin_retry_limit_is_reached_on_configured_attempt_count() {
        assert!(!pin_retry_limit_reached(PIN_FAILURES_BEFORE_COOLDOWN - 1));
        assert!(pin_retry_limit_reached(PIN_FAILURES_BEFORE_COOLDOWN));
        assert!(pin_retry_limit_reached(PIN_FAILURES_BEFORE_COOLDOWN + 1));
    }

    #[test]
    fn auth_session_expires_after_ttl() {
        assert!(auth_session_is_current(Instant::now()));
        assert!(!auth_session_is_current(
            Instant::now() - AUTH_SESSION_TTL - Duration::from_secs(1)
        ));
    }

    #[test]
    fn unauthenticated_timeout_uses_one_absolute_deadline() {
        let deadline = Instant::now() + Duration::from_millis(100);
        assert!(
            remaining_unauthenticated_timeout(deadline, Duration::from_secs(3))
                .is_some_and(|remaining| remaining <= Duration::from_millis(100))
        );
        assert!(remaining_unauthenticated_timeout(
            Instant::now() - Duration::from_millis(1),
            Duration::from_secs(3),
        )
        .is_none());
    }

    #[test]
    fn approval_key_auth_expires_after_ttl() {
        assert!(super::approval_key_auth_is_current(Instant::now()));
        assert!(!super::approval_key_auth_is_current(
            Instant::now() - APPROVAL_KEY_AUTH_TTL - Duration::from_secs(1)
        ));
    }

    #[tokio::test]
    async fn approval_key_auth_marker_is_refreshed_and_cleared() {
        let state = AppState::new();

        assert!(state.approval_key_authenticated_at.lock().await.is_none());
        state.set_foreground(true).await;
        state.mark_approval_key_authenticated(0).await.unwrap();
        assert!(state
            .approval_key_authenticated_at
            .lock()
            .await
            .as_ref()
            .copied()
            .is_some_and(super::approval_key_auth_is_current));

        super::clear_approval_key_authenticated(&state).await;
        assert!(state.approval_key_authenticated_at.lock().await.is_none());
    }

    #[tokio::test]
    async fn lock_clears_approval_key_auth_marker() {
        let state = AppState::new();
        state.set_foreground(true).await;
        state.mark_approval_key_authenticated(0).await.unwrap();

        state.lock().await;

        assert!(state.approval_key_authenticated_at.lock().await.is_none());
    }

    #[tokio::test]
    async fn foreground_state_defaults_closed_and_tracks_lifecycle() {
        let state = AppState::new();
        assert!(!state.is_foreground());
        state.set_foreground(true).await;
        assert!(state.is_foreground());
        state.set_foreground(false).await;
        assert!(!state.is_foreground());
    }

    #[test]
    fn pin_cooldown_duration_exponentially_increases_and_caps() {
        assert_eq!(cooldown_duration_ms(1), 30_000);
        assert_eq!(cooldown_duration_ms(2), 60_000);
        assert_eq!(cooldown_duration_ms(7), 1_800_000);
        assert_eq!(cooldown_duration_ms(20), 1_800_000);
    }

    #[test]
    fn active_cooldown_reports_remaining_time() {
        let mut state = PinAttemptState {
            failed_attempts: 0,
            cooldown_level: 1,
            cooldown_until_ms: None,
            cooldown_started_elapsed_ms: Some(500),
            cooldown_boot_count: Some(7),
            cooldown_duration_ms: Some(1_500),
        };

        assert_eq!(
            active_cooldown_remaining_ms(
                &mut state,
                ClockSnapshot {
                    elapsed_realtime_ms: 1_000,
                    boot_count: 7,
                },
            ),
            Some(1_000)
        );
        assert_eq!(
            active_cooldown_remaining_ms(
                &mut state,
                ClockSnapshot {
                    elapsed_realtime_ms: 2_000,
                    boot_count: 7,
                },
            ),
            None
        );
    }

    #[test]
    fn cooldown_restarts_after_reboot_and_ignores_wall_clock() {
        let mut state = PinAttemptState {
            cooldown_level: 2,
            cooldown_started_elapsed_ms: Some(50_000),
            cooldown_boot_count: Some(7),
            cooldown_duration_ms: Some(60_000),
            ..PinAttemptState::default()
        };

        assert_eq!(
            active_cooldown_remaining_ms(
                &mut state,
                ClockSnapshot {
                    elapsed_realtime_ms: 2_000,
                    boot_count: 8,
                },
            ),
            Some(60_000)
        );
        assert_eq!(state.cooldown_started_elapsed_ms, Some(2_000));
        assert_eq!(state.cooldown_boot_count, Some(8));
    }

    #[test]
    fn pairing_replacement_authorization_expires_after_ttl() {
        assert!(pairing_replacement_authorization_is_current(Instant::now()));
        assert!(!pairing_replacement_authorization_is_current(
            Instant::now() - PAIRING_REPLACEMENT_AUTHORIZATION_TTL - Duration::from_secs(1)
        ));
    }

    #[test]
    fn setup_complete_requires_replacement_auth_for_any_existing_setup_state() {
        assert!(!existing_setup_requires_replacement_authorization(
            false, false
        ));
        assert!(existing_setup_requires_replacement_authorization(
            true, false
        ));
        assert!(existing_setup_requires_replacement_authorization(
            false, true
        ));
        assert!(existing_setup_requires_replacement_authorization(
            true, true
        ));
    }

    #[test]
    fn generated_setup_pairing_code_is_displayable_as_four_digits() {
        for _ in 0..100 {
            let code = super::generate_pairing_code();
            assert!(code <= 9999);
            assert_eq!(super::format_pairing_code(code).len(), 4);
        }
        assert_eq!(super::format_pairing_code(7), "0007");
    }

    #[tokio::test]
    async fn setup_pairing_code_is_backend_generated_and_consumed_once() {
        let state = AppState::new();
        *state.setup_pairing_code.lock().await = Some(1234);

        assert_eq!(
            super::consume_setup_pairing_code(&state).await.unwrap(),
            1234
        );
        assert!(super::consume_setup_pairing_code(&state).await.is_err());
    }

    #[tokio::test]
    async fn pairing_replacement_authorization_is_consumed_once() {
        let state = AppState::new();
        *state.pairing_replacement_authorized_at.lock().await = Some(Instant::now());

        assert!(consume_pairing_replacement_authorization(&state).await);
        assert!(!consume_pairing_replacement_authorization(&state).await);
    }

    #[tokio::test]
    async fn expired_pairing_replacement_authorization_is_rejected_and_consumed() {
        let state = AppState::new();
        *state.pairing_replacement_authorized_at.lock().await =
            Some(Instant::now() - PAIRING_REPLACEMENT_AUTHORIZATION_TTL - Duration::from_secs(1));

        assert!(!consume_pairing_replacement_authorization(&state).await);
        assert!(state
            .pairing_replacement_authorized_at
            .lock()
            .await
            .is_none());
    }

    #[test]
    fn pending_expiry_only_matches_same_request_after_ttl() {
        let now = Instant::now();
        let identity = PendingIdentity {
            request_id: uuid::Uuid::new_v4(),
            instance_id: uuid::Uuid::new_v4(),
            session_generation: 1,
            created_at: now,
        };
        let replacement = PendingIdentity {
            instance_id: uuid::Uuid::new_v4(),
            ..identity
        };

        assert!(!pending_request_is_expired(identity, identity, now));
        assert!(!pending_request_is_expired(
            replacement,
            identity,
            now + PENDING_REQUEST_TTL
        ));
        assert!(pending_request_is_expired(
            identity,
            identity,
            now + PENDING_REQUEST_TTL
        ));
        assert!(!identity.is_current(identity, now + PENDING_REQUEST_TTL));
        assert!(!replacement.is_current(identity, now));
    }

    #[test]
    fn request_id_reuse_is_rejected_during_session_lifetime() {
        let mut recent = HashMap::new();
        let now = Instant::now();
        let id = uuid::Uuid::new_v4();

        assert!(remember_request_id(&mut recent, id, now));
        assert!(!remember_request_id(
            &mut recent,
            id,
            now + PENDING_REQUEST_TTL
        ));
        assert!(remember_request_id(&mut recent, id, now + AUTH_SESSION_TTL));
    }

    #[tokio::test]
    async fn expired_read_verification_cannot_take_same_id_write_request() {
        let state = AppState::new();
        state.set_foreground(true).await;
        *state.unlocked_at.lock().await = Some(Instant::now());

        let phone_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let cli_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let accepting = {
            let endpoint = phone_endpoint.clone();
            tokio::spawn(async move {
                endpoint
                    .accept()
                    .await
                    .unwrap()
                    .accept()
                    .unwrap()
                    .await
                    .unwrap()
            })
        };
        let cli_conn = cli_endpoint
            .connect(phone_endpoint.addr(), FERUSA_ALPN)
            .await
            .unwrap();
        let phone_conn = accepting.await.unwrap();

        let request = AuthRequest {
            pairing_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            correlation_code: 1234,
            action: VaultAction::Read,
            entry_title: Some("entry".into()),
            unlock_share_requested: false,
            timestamp: 42,
        };
        let read_identity = PendingIdentity {
            request_id: request.request_id,
            instance_id: uuid::Uuid::new_v4(),
            session_generation: *state.session_generation.lock().await,
            created_at: Instant::now() - PENDING_REQUEST_TTL - Duration::from_secs(1),
        };
        let (mut cli_send, _) = cli_conn.open_bi().await.unwrap();
        cli_send.write_all(b"read").await.unwrap();
        cli_send.finish().unwrap();
        let (read_send, _) = phone_conn.accept_bi().await.unwrap();
        let pending: PendingReq = Arc::new(Mutex::new(Some(PendingRequest {
            request: request.clone(),
            send: read_send,
            conn: phone_conn.clone(),
            identity: read_identity,
        })));

        // PIN verification is suspended while expiry removes the read instance.
        let expired = pending.lock().await.take();
        drop(expired);
        let write_identity = PendingIdentity {
            instance_id: uuid::Uuid::new_v4(),
            created_at: Instant::now(),
            ..read_identity
        };
        let (mut cli_send, _) = cli_conn.open_bi().await.unwrap();
        cli_send.write_all(b"write").await.unwrap();
        cli_send.finish().unwrap();
        let (write_send, _) = phone_conn.accept_bi().await.unwrap();
        *pending.lock().await = Some(PendingRequest {
            request: AuthRequest {
                action: VaultAction::Update,
                unlock_share_requested: true,
                timestamp: 43,
                ..request
            },
            send: write_send,
            conn: phone_conn,
            identity: write_identity,
        });

        assert!(take_verified_pending(&state, &pending, read_identity)
            .await
            .is_err());
        let slot = pending.lock().await;
        let replacement = slot.as_ref().unwrap();
        assert_eq!(replacement.identity, write_identity);
        assert_eq!(replacement.request.action, VaultAction::Update);
        assert!(replacement.request.unlock_share_requested);
        drop(slot);
        state.lock().await;
        assert!(take_verified_pending(&state, &pending, write_identity)
            .await
            .is_err());
        drop(pending.lock().await.take());

        cli_conn.close(0u32.into(), b"test complete");
        cli_endpoint.close().await;
        phone_endpoint.close().await;
    }

    #[test]
    fn auth_request_pairing_generation_must_match_active_generation() {
        let active = uuid::Uuid::new_v4();

        assert!(pairing_generation_matches(active, active));
        assert!(!pairing_generation_matches(active, uuid::Uuid::new_v4()));
    }

    #[test]
    fn request_display_fields_are_sanitized_before_frontend_payload() {
        let req = AuthRequest {
            request_id: uuid::Uuid::new_v4(),
            pairing_id: uuid::Uuid::new_v4(),
            correlation_code: 1234,
            action: VaultAction::Read,
            entry_title: Some(format!("  Secret\nTitle\t{}  ", "x".repeat(200))),
            unlock_share_requested: false,
            timestamp: 1_000,
        };

        let payload = PendingRequestPayload::from(&req);
        let title = payload.entry_title.expect("display title is retained");

        assert_eq!(payload.action, "read");
        assert_eq!(payload.pin_digits, 4);
        assert_eq!(title.chars().count(), REQUEST_DISPLAY_FIELD_MAX_CHARS);
        assert!(title.starts_with("Secret Title"));
        assert!(title.ends_with("..."));
        assert!(!title.contains('\n'));
        assert!(!title.contains('\t'));
    }

    #[test]
    fn blank_request_display_fields_are_omitted() {
        assert_eq!(sanitize_request_display_field(" \n\t "), None);
    }

    #[tokio::test]
    async fn concurrent_approval_wrong_pins_reach_four_digit_cooldown() {
        run_wrong_pin_burst(PinKind::FourDigit).await;
    }

    #[tokio::test]
    async fn concurrent_replacement_wrong_pins_reach_six_digit_cooldown() {
        run_wrong_pin_burst(PinKind::SixDigit).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn argon2_jobs_are_globally_bounded_across_pin_kinds() {
        let state = Arc::new(AppState::new());
        let active_jobs = Arc::new(AtomicUsize::new(0));
        let max_active_jobs = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();

        for _ in [PinKind::FourDigit, PinKind::SixDigit] {
            let state = state.clone();
            let active_jobs = active_jobs.clone();
            let max_active_jobs = max_active_jobs.clone();
            tasks.push(tokio::spawn(async move {
                run_argon2_job(&state, move || {
                    let active = active_jobs.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active_jobs.fetch_max(active, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(25));
                    active_jobs.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .unwrap();
            }));
        }

        for task in tasks {
            task.await.unwrap();
        }

        assert_eq!(max_active_jobs.load(Ordering::SeqCst), 1);
    }
}

#[command]
pub async fn deny_request<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    pending: State<'_, PendingReq>,
    request_id: String,
) -> Result<()> {
    info!("[ferusa:app]: deny_request: request_id={}", request_id);
    ensure_active_session(app.clone(), state.inner(), pending.inner(), "deny_request").await?;

    let approval_alias = {
        let secrets_guard = state.secrets.lock().await;
        let secrets = secrets_guard.as_ref().ok_or_else(|| {
            warn!("[ferusa:app]: deny_request: app is locked, no secrets in state");
            AppError::PendingRequest { kind: "locked" }
        })?;
        secrets.approval_key_alias.clone()
    };

    ensure_approval_key_auth(&app, state.inner(), "Deny").await?;

    let mut pending_req = {
        let mut pend = pending.lock().await;
        pend.take().ok_or_else(|| {
            warn!("[ferusa:app]: deny_request: no pending request found");
            AppError::PendingRequest { kind: "missing" }
        })?
    };
    debug!("[ferusa:app]: deny_request: took ownership of pending request");

    debug!("[ferusa:app]: deny_request: validating request_id match");
    if pending_req.request.request_id.to_string() != request_id {
        error!(
            "[ferusa:app]: deny_request: request_id mismatch: expected={} got={}",
            pending_req.request.request_id, request_id
        );
        *pending.lock().await = Some(pending_req);
        return Err(AppError::PendingRequest { kind: "mismatch" });
    }
    debug!("[ferusa:app]: deny_request: request_id matched");

    if !state.is_foreground() {
        pending_req
            .conn
            .close(0u32.into(), b"app moved to background");
        state.lock().await;
        return Err(AppError::SessionExpired);
    }

    debug!("[ferusa:app]: sending denial response");
    if let Err(e) = send_signed_response(
        app,
        &mut pending_req.send,
        approval_alias,
        &pending_req.request,
        false,
        None,
    )
    .await
    {
        error!("[ferusa:app]: deny send failed: {}", e);
        let err = handle_signed_response_error(state.inner(), e).await;
        if matches!(err, AppError::ApprovalKeyAuthRequired { .. }) {
            *pending.lock().await = Some(pending_req);
        }
        return Err(err);
    }
    debug!("[ferusa:app]: deny_request: response written and stream finished");

    debug!("[ferusa:app]: deny_request: response sent; connection handler keeps session alive");

    info!("[ferusa:app]: deny_request done");
    Ok(())
}
