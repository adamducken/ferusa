use crate::types::VaultAction;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const AUTH_TIMESTAMP_MAX_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTimestampError {
    TooOld {
        timestamp_ms: u64,
        now_ms: u64,
        max_skew_ms: u64,
    },
    TooFarInFuture {
        timestamp_ms: u64,
        now_ms: u64,
        max_skew_ms: u64,
    },
}

impl fmt::Display for AuthTimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooOld {
                timestamp_ms,
                now_ms,
                max_skew_ms,
            } => write!(
                f,
                "auth timestamp {timestamp_ms} is older than {max_skew_ms}ms from {now_ms}"
            ),
            Self::TooFarInFuture {
                timestamp_ms,
                now_ms,
                max_skew_ms,
            } => write!(
                f,
                "auth timestamp {timestamp_ms} is more than {max_skew_ms}ms after {now_ms}"
            ),
        }
    }
}

impl std::error::Error for AuthTimestampError {}

pub fn validate_auth_timestamp(timestamp_ms: u64, now_ms: u64) -> Result<(), AuthTimestampError> {
    if now_ms.saturating_sub(timestamp_ms) > AUTH_TIMESTAMP_MAX_SKEW_MS {
        return Err(AuthTimestampError::TooOld {
            timestamp_ms,
            now_ms,
            max_skew_ms: AUTH_TIMESTAMP_MAX_SKEW_MS,
        });
    }
    if timestamp_ms.saturating_sub(now_ms) > AUTH_TIMESTAMP_MAX_SKEW_MS {
        return Err(AuthTimestampError::TooFarInFuture {
            timestamp_ms,
            now_ms,
            max_skew_ms: AUTH_TIMESTAMP_MAX_SKEW_MS,
        });
    }
    Ok(())
}

pub fn validate_auth_exchange_timestamps(
    req: &AuthRequest,
    resp: &AuthResponse,
    now_ms: u64,
) -> Result<(), AuthTimestampError> {
    validate_auth_timestamp(req.timestamp, now_ms)?;
    validate_auth_timestamp(resp.timestamp, now_ms)
}

/// Sent CLI → phone over iroh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub pairing_id: Uuid,
    pub request_id: Uuid,
    pub correlation_code: u16,
    pub action: VaultAction,
    pub entry_title: Option<String>,
    pub unlock_share_requested: bool,
    // Signed freshness timestamp in milliseconds since Unix epoch.
    pub timestamp: u64,
}

/// Sent phone → CLI over iroh.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AuthResponse {
    #[zeroize(skip)]
    pub pairing_id: Uuid,
    #[zeroize(skip)]
    pub request_id: Uuid,
    #[zeroize(skip)]
    pub correlation_code: u16,
    #[zeroize(skip)]
    pub action: VaultAction,
    #[zeroize(skip)]
    pub approved: bool,
    pub unlock_share: Option<[u8; 32]>,
    // Signed freshness timestamp in milliseconds since Unix epoch.
    #[zeroize(skip)]
    pub timestamp: u64,
    #[zeroize(skip)]
    pub signature: Vec<u8>,
}

impl fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthResponse")
            .field("pairing_id", &self.pairing_id)
            .field("request_id", &self.request_id)
            .field("approved", &self.approved)
            .field("unlock_share", &"[redacted]")
            .finish()
    }
}

/// Sent phone → CLI during pairing.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PairingHello {
    #[zeroize(skip)]
    pub pairing_id: Uuid,
    #[zeroize(skip)]
    pub approval_public_key_der: Vec<u8>,
    pub phone_share: [u8; 32],
    #[zeroize(skip)]
    pub verification_code: u16,
}

impl fmt::Debug for PairingHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingHello")
            .field("pairing_id", &self.pairing_id)
            .field("phone_share", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingPrepared {
    pub pairing_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingReady {
    pub pairing_id: Uuid,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingCommit {
    pub pairing_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingCommitAck {
    pub pairing_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingActivate {
    pub pairing_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingActivateAck {
    pub pairing_id: Uuid,
}
