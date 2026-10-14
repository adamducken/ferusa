use crate::error::{AppError, Result};
use log::{debug, info};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};
use zeroize::ZeroizeOnDrop;

pub const MAX_CONCURRENT_ARGON2_JOBS: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinKind {
    FourDigit,
    SixDigit,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> Secrets {
        Secrets {
            pairing_id: uuid::Uuid::nil(),
            approval_key_alias: "test".into(),
            approval_public_key_der: Vec::new(),
            phone_share: [7; 32],
            pin4_hash: String::new(),
            pin6_hash: String::new(),
            cli_node_id: [0; 32],
        }
    }

    #[tokio::test]
    async fn lock_and_background_reject_paused_authentication_completions() {
        for background in [false, true] {
            for replacement in [false, true] {
                let state = Arc::new(AppState::new());
                state.set_foreground(true).await;
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
                let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
                let task_state = state.clone();
                let completion = tokio::spawn(async move {
                    let token = task_state.begin_pairing_replacement().await.unwrap();
                    task_state
                        .mark_approval_key_authenticated(token.0)
                        .await
                        .unwrap();
                    ready_tx.send(()).unwrap();
                    resume_rx.await.unwrap();
                    // A biometric callback must not restore its timestamp either.
                    assert!(task_state
                        .mark_approval_key_authenticated(token.0)
                        .await
                        .is_err());
                    if replacement {
                        task_state.complete_pairing_replacement(token).await
                    } else {
                        task_state
                            .complete_unlock(token.0, secrets())
                            .await
                            .map(|_| ())
                    }
                });
                ready_rx.await.unwrap();
                if background {
                    state.set_foreground(false).await;
                    // A quick foreground return must not revive the old operation.
                    state.set_foreground(true).await;
                } else {
                    state.lock().await;
                }
                resume_tx.send(()).unwrap();
                assert!(completion.await.unwrap().is_err());
                assert!(state.secrets.lock().await.is_none());
                assert!(state.unlocked_at.lock().await.is_none());
                assert!(state.approval_key_authenticated_at.lock().await.is_none());
                assert!(state
                    .pairing_replacement_authorized_at
                    .lock()
                    .await
                    .is_none());
            }
        }
    }

    #[tokio::test]
    async fn current_authentication_publishes_and_cancel_rejects_replacement() {
        let state = AppState::new();
        assert!(state.authentication_generation().await.is_err());
        state.set_foreground(true).await;
        let generation = state.authentication_generation().await.unwrap();
        state
            .mark_approval_key_authenticated(generation)
            .await
            .unwrap();
        let session = state.complete_unlock(generation, secrets()).await.unwrap();
        assert!(session > generation);
        assert!(state.secrets.lock().await.is_some());
        assert!(state.unlocked_at.lock().await.is_some());
        let replacement = state.begin_pairing_replacement().await.unwrap();
        state
            .complete_pairing_replacement(replacement)
            .await
            .unwrap();
        assert!(state
            .pairing_replacement_authorized_at
            .lock()
            .await
            .is_some());
        let replacement = state.begin_pairing_replacement().await.unwrap();
        state.cancel_pairing_replacement().await;
        assert!(state
            .complete_pairing_replacement(replacement)
            .await
            .is_err());
        assert!(state
            .pairing_replacement_authorized_at
            .lock()
            .await
            .is_none());
        // Replacement cancellation does not invalidate the live session timer.
        assert_eq!(*state.session_generation.lock().await, session);
    }

    #[tokio::test]
    async fn background_preserves_initial_enrollment_code() {
        let state = AppState::new();
        state.set_foreground(true).await;
        *state.setup_pairing_code.lock().await = Some(1234);

        state.set_foreground(false).await;
        state.lock().await; // set_app_foreground also expires the session.
        state.set_foreground(true).await;

        assert_eq!(*state.setup_pairing_code.lock().await, Some(1234));

        *state.is_setup.lock().await = true;
        state.lock().await;
        assert!(state.setup_pairing_code.lock().await.is_none());
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Secrets {
    #[zeroize(skip)]
    pub pairing_id: uuid::Uuid,
    #[zeroize(skip)]
    pub approval_key_alias: String,
    #[zeroize(skip)]
    pub approval_public_key_der: Vec<u8>,
    pub phone_share: [u8; 32],
    pub pin4_hash: String,
    pub pin6_hash: String,
    #[zeroize(skip)]
    pub cli_node_id: [u8; 32],
}

pub struct AppState {
    pub secrets: Arc<Mutex<Option<Secrets>>>,
    pub is_setup: Arc<Mutex<bool>>,
    pub endpoint: Arc<Mutex<Option<iroh::Endpoint>>>,
    pub pairing_replacement_authorized_at: Arc<Mutex<Option<Instant>>>,
    pub unlocked_at: Arc<Mutex<Option<Instant>>>,
    pub approval_key_authenticated_at: Arc<Mutex<Option<Instant>>>,
    pub setup_pairing_code: Arc<Mutex<Option<u16>>>,
    pub session_generation: Arc<Mutex<u64>>,
    pub recent_request_ids: Mutex<HashMap<uuid::Uuid, Instant>>,
    is_foreground: Arc<AtomicBool>,
    replacement_generation: AtomicU64,
    pin4_attempt_gate: Arc<Mutex<()>>,
    pin6_attempt_gate: Arc<Mutex<()>>,
    argon2_jobs: Arc<Semaphore>,
    pub operation_gate: Mutex<()>,
    pub enrollment_gate: Mutex<()>,
}

impl AppState {
    pub fn new() -> Self {
        debug!("[ferusa:app]: AppState::new");
        Self {
            secrets: Arc::new(Mutex::new(None)),
            is_setup: Arc::new(Mutex::new(false)),
            endpoint: Arc::new(Mutex::new(None)),
            pairing_replacement_authorized_at: Arc::new(Mutex::new(None)),
            unlocked_at: Arc::new(Mutex::new(None)),
            approval_key_authenticated_at: Arc::new(Mutex::new(None)),
            setup_pairing_code: Arc::new(Mutex::new(None)),
            session_generation: Arc::new(Mutex::new(0)),
            recent_request_ids: Mutex::new(HashMap::new()),
            is_foreground: Arc::new(AtomicBool::new(false)),
            replacement_generation: AtomicU64::new(0),
            pin4_attempt_gate: Arc::new(Mutex::new(())),
            pin6_attempt_gate: Arc::new(Mutex::new(())),
            argon2_jobs: Arc::new(Semaphore::new(MAX_CONCURRENT_ARGON2_JOBS)),
            operation_gate: Mutex::new(()),
            enrollment_gate: Mutex::new(()),
        }
    }

    pub fn pin_attempt_gate(&self, kind: PinKind) -> Arc<Mutex<()>> {
        match kind {
            PinKind::FourDigit => self.pin4_attempt_gate.clone(),
            PinKind::SixDigit => self.pin6_attempt_gate.clone(),
        }
    }

    pub fn argon2_jobs(&self) -> Arc<Semaphore> {
        self.argon2_jobs.clone()
    }

    pub fn is_foreground(&self) -> bool {
        self.is_foreground.load(Ordering::Acquire)
    }

    pub async fn set_foreground(&self, foreground: bool) {
        let mut generation = self.session_generation.lock().await;
        self.is_foreground.store(foreground, Ordering::Release);
        if !foreground {
            self.clear_session(&mut generation).await;
        }
    }

    pub async fn lock(&self) {
        info!("[ferusa:app]: AppState::lock clearing secrets");
        let mut generation = self.session_generation.lock().await;
        self.clear_session(&mut generation).await;
    }

    // Always acquire session_generation before any state-field mutex.
    async fn clear_session(&self, generation: &mut u64) {
        *generation = generation.saturating_add(1);
        *self.secrets.lock().await = None;
        *self.pairing_replacement_authorized_at.lock().await = None;
        *self.unlocked_at.lock().await = None;
        *self.approval_key_authenticated_at.lock().await = None;
        // Initial enrollment stays mounted across backgrounding. Its displayed
        // verification code must remain valid until setup consumes it.
        if *self.is_setup.lock().await {
            *self.setup_pairing_code.lock().await = None;
        }
        debug!("[ferusa:app]: AppState::lock secrets cleared");
    }

    pub async fn authentication_generation(&self) -> Result<u64> {
        let generation = self.session_generation.lock().await;
        self.check_authentication_generation(*generation, *generation)?;
        Ok(*generation)
    }

    fn check_authentication_generation(&self, expected: u64, current: u64) -> Result<()> {
        if expected != current || !self.is_foreground() {
            return Err(AppError::SessionExpired);
        }
        Ok(())
    }

    pub async fn mark_approval_key_authenticated(&self, expected: u64) -> Result<()> {
        let generation = self.session_generation.lock().await;
        self.check_authentication_generation(expected, *generation)?;
        *self.approval_key_authenticated_at.lock().await = Some(Instant::now());
        Ok(())
    }

    pub async fn complete_unlock(&self, expected: u64, secrets: Secrets) -> Result<u64> {
        let mut generation = self.session_generation.lock().await;
        self.check_authentication_generation(expected, *generation)?;
        *self.secrets.lock().await = Some(secrets);
        *self.unlocked_at.lock().await = Some(Instant::now());
        *generation = generation.saturating_add(1);
        Ok(*generation)
    }

    pub async fn begin_pairing_replacement(&self) -> Result<(u64, u64)> {
        let generation = self.session_generation.lock().await;
        self.check_authentication_generation(*generation, *generation)?;
        *self.pairing_replacement_authorized_at.lock().await = None;
        let replacement = self.replacement_generation.fetch_add(1, Ordering::Relaxed) + 1;
        Ok((*generation, replacement))
    }

    pub async fn complete_pairing_replacement(&self, expected: (u64, u64)) -> Result<()> {
        let generation = self.session_generation.lock().await;
        self.check_authentication_generation(expected.0, *generation)?;
        if self.replacement_generation.load(Ordering::Relaxed) != expected.1 {
            return Err(AppError::SessionExpired);
        }
        *self.pairing_replacement_authorized_at.lock().await = Some(Instant::now());
        Ok(())
    }

    pub async fn cancel_pairing_replacement(&self) {
        let _generation = self.session_generation.lock().await;
        self.replacement_generation.fetch_add(1, Ordering::Relaxed);
        *self.pairing_replacement_authorized_at.lock().await = None;
        *self.setup_pairing_code.lock().await = None;
    }
}
