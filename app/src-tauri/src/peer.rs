use anyhow::{bail, Context, Result};
use ferusa_core::auth::{AuthRequest, AuthResponse};
use ferusa_core::recovery::checked_recovery_frame_len;
use ferusa_core::transport::FerusaMessage;
#[cfg(test)]
use ferusa_core::transport::{PAIRING_COMPLETE_CLOSE_CODE, PAIRING_COMPLETE_CLOSE_REASON};
#[cfg(test)]
use iroh::endpoint::{Connection, RecvStream, SendStream};
#[cfg(target_os = "android")]
use iroh::{endpoint::IncomingAddr, PublicKey};
use log::{debug, info};
#[cfg(any(target_os = "android", test))]
use std::collections::HashMap;
#[cfg(any(target_os = "android", test))]
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

pub const INBOUND_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "android")]
pub const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
pub const INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const UNAUTHENTICATED_INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(target_os = "android")]
pub const MAX_INBOUND_HANDSHAKES: usize = 8;
#[cfg(target_os = "android")]
pub const MAX_UNTRUSTED_CONNECTION_HANDLERS: usize = 8;
#[cfg(target_os = "android")]
pub const MAX_PAIRED_CONNECTION_HANDLERS: usize = 4;
#[cfg(target_os = "android")]
pub const MAX_INBOUND_CONNECTIONS_PER_PEER: usize = 4;
#[cfg(target_os = "android")]
pub const MAX_INBOUND_CONNECTIONS_PER_SOURCE: usize = 4;
#[cfg(test)]
const PAIRING_STEP_TIMEOUT: Duration = Duration::from_secs(120);

#[cfg(target_os = "android")]
pub fn inbound_source_key(addr: &IncomingAddr) -> String {
    match addr {
        IncomingAddr::Ip(socket) => format!("ip:{}", socket.ip()),
        IncomingAddr::Relay { url, .. } => format!("relay:{url:?}"),
        IncomingAddr::Custom(custom) => format!("custom:{custom:?}"),
        _ => format!("other:{addr:?}"),
    }
}

#[cfg(target_os = "android")]
pub fn inbound_claimed_endpoint_id(addr: &IncomingAddr) -> Option<PublicKey> {
    match addr {
        IncomingAddr::Relay { endpoint_id, .. } => Some(*endpoint_id),
        _ => None,
    }
}

#[cfg(any(target_os = "android", test))]
pub struct SourceAdmissionLimiter {
    max_per_source: usize,
    counts: Mutex<HashMap<String, usize>>,
}

#[cfg(any(target_os = "android", test))]
impl SourceAdmissionLimiter {
    pub fn new(max_per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            max_per_source,
            counts: Mutex::new(HashMap::new()),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, source: String) -> Option<SourceAdmissionPermit> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = counts.entry(source.clone()).or_insert(0);
        if *count >= self.max_per_source {
            return None;
        }
        *count += 1;
        Some(SourceAdmissionPermit {
            limiter: self.clone(),
            source,
        })
    }
}

#[cfg(any(target_os = "android", test))]
pub struct SourceAdmissionPermit {
    limiter: Arc<SourceAdmissionLimiter>,
    source: String,
}

#[cfg(any(target_os = "android", test))]
impl Drop for SourceAdmissionPermit {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(&self.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.source);
            }
        }
    }
}

pub struct AppPeer;

fn encode_secret_message(message: &FerusaMessage) -> Result<Zeroizing<Vec<u8>>> {
    let json = Zeroizing::new(serde_json::to_vec(message).context("encode secret message JSON")?);
    let len = json.len() as u32;
    let mut out = Zeroizing::new(Vec::with_capacity(4 + json.len()));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

#[cfg(test)]
async fn finish_pairing_connection(
    send: &mut SendStream,
    recv: &mut RecvStream,
    conn: &Connection,
) -> Result<()> {
    send.finish().context("finish pairing send")?;

    tokio::time::timeout(PAIRING_STEP_TIMEOUT, recv.read_to_end(0))
        .await
        .context("timed out waiting for CLI pairing completion")?
        .context("read CLI pairing completion")?;
    debug!("[ferusa:app]: CLI pairing completion observed");

    conn.close(
        PAIRING_COMPLETE_CLOSE_CODE.into(),
        PAIRING_COMPLETE_CLOSE_REASON,
    );
    Ok(())
}

pub fn build_response_for_signing(
    req: &AuthRequest,
    approved: bool,
    unlock_share: Option<&[u8; 32]>,
    timestamp: u64,
) -> Result<AuthResponse> {
    Ok(AuthResponse {
        pairing_id: req.pairing_id,
        request_id: req.request_id,
        correlation_code: req.correlation_code,
        action: req.action,
        approved,
        unlock_share: match (approved, req.unlock_share_requested) {
            (true, true) => {
                Some(*unlock_share.context("approved unlock response missing phone share")?)
            }
            _ => None,
        },
        timestamp,
        signature: Vec::new(),
    })
}

impl AppPeer {
    pub async fn send_response(
        send: &mut iroh::endpoint::SendStream,
        resp: AuthResponse,
    ) -> Result<()> {
        info!(
            "[ferusa:app]: send_response: request_id={} approved={}",
            resp.request_id, resp.approved
        );

        debug!("[ferusa:app]: send_response: timestamp={}", resp.timestamp);

        let message = FerusaMessage::Response(resp);
        let bytes = encode_secret_message(&message).context("encode response")?;
        drop(message);
        debug!(
            "[ferusa:app]: send_response: encoded response ({} bytes)",
            bytes.len()
        );

        // Write back on the same stream the CLI opened and is waiting on.
        tokio::time::timeout(INBOUND_FRAME_TIMEOUT, send.write_all(&bytes))
            .await
            .context("timed out sending response")?
            .context("send response")?;
        drop(bytes);
        debug!("[ferusa:app]: send_response: bytes written");

        send.finish().context("finish response")?;
        debug!("[ferusa:app]: send_response: stream finished");

        info!("[ferusa:app]: send_response: response sent successfully");

        Ok(())
    }
}

pub async fn read_ferusa_message(
    recv: &mut iroh::endpoint::RecvStream,
    timeout: Duration,
) -> Result<FerusaMessage> {
    tokio::time::timeout(timeout, read_ferusa_message_unbounded(recv))
        .await
        .context("timed out reading message")?
}

pub async fn read_recovery_message(
    recv: &mut iroh::endpoint::RecvStream,
    timeout: Duration,
) -> Result<FerusaMessage> {
    let started = std::time::Instant::now();
    let mut header = [0u8; 4];
    tokio::time::timeout(timeout, recv.read_exact(&mut header[..1]))
        .await
        .context("timed out waiting for recovery frame")?
        .context("read first recovery byte")?;
    tokio::time::timeout(
        timeout
            .saturating_sub(started.elapsed())
            .min(INBOUND_FRAME_TIMEOUT),
        async {
            recv.read_exact(&mut header[1..])
                .await
                .context("read recovery header")?;
            let len = checked_recovery_frame_len(header).context("check recovery frame size")?;
            let mut bytes = Zeroizing::new(vec![0u8; 4 + len]);
            bytes[..4].copy_from_slice(&header);
            recv.read_exact(&mut bytes[4..])
                .await
                .context("read recovery payload")?;
            FerusaMessage::decode(&bytes).context("decode recovery frame")
        },
    )
    .await
    .context("timed out transferring recovery frame")?
}

async fn read_ferusa_message_unbounded(
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<FerusaMessage> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header)
        .await
        .context("read message header")?;
    let len = u32::from_le_bytes(header) as usize;
    if len > 4096 {
        bail!("message too large: {len}");
    }
    let mut bytes = Zeroizing::new(vec![0u8; 4 + len]);
    bytes[..4].copy_from_slice(&header);
    recv.read_exact(&mut bytes[4..])
        .await
        .context("read message payload")?;
    FerusaMessage::decode(&bytes).context("decode message")
}

#[cfg(test)]
mod tests {
    use super::{build_response_for_signing, finish_pairing_connection, SourceAdmissionLimiter};
    use ferusa_core::auth::AuthRequest;
    use ferusa_core::transport::{
        FERUSA_ALPN, PAIRING_COMPLETE_CLOSE_CODE, PAIRING_COMPLETE_CLOSE_REASON,
    };
    use ferusa_core::types::VaultAction;
    use iroh::endpoint::{presets, ConnectionError};
    use std::time::Duration;
    use uuid::Uuid;

    fn request(unlock_share_requested: bool) -> AuthRequest {
        AuthRequest {
            pairing_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            correlation_code: 1234,
            action: VaultAction::Unlock,
            entry_title: None,
            unlock_share_requested,
            timestamp: 42,
        }
    }

    #[test]
    fn source_admission_cannot_be_bypassed_by_fresh_peer_identities() {
        let limiter = SourceAdmissionLimiter::new(2);
        let first = limiter.try_acquire("relay:https://relay.example".into());
        let second = limiter.try_acquire("relay:https://relay.example".into());
        let fresh_identity_same_relay = limiter.try_acquire("relay:https://relay.example".into());

        assert!(first.is_some());
        assert!(second.is_some());
        assert!(fresh_identity_same_relay.is_none());

        drop(first);
        assert!(limiter
            .try_acquire("relay:https://relay.example".into())
            .is_some());
    }

    #[test]
    fn approved_response_includes_requested_phone_share() {
        let phone_share = [0x22; 32];
        let req = request(true);

        let resp = build_response_for_signing(&req, true, Some(&phone_share), 100).unwrap();

        assert_eq!(resp.unlock_share, Some(phone_share));
        assert_eq!(resp.signature, Vec::<u8>::new());
    }

    #[test]
    fn approved_response_omits_unrequested_phone_share() {
        let phone_share = [0x22; 32];
        let req = request(false);

        let resp = build_response_for_signing(&req, true, Some(&phone_share), 100).unwrap();

        assert_eq!(resp.unlock_share, None);
        assert_eq!(resp.signature, Vec::<u8>::new());
    }

    #[test]
    fn denial_response_never_includes_phone_share() {
        let phone_share = [0x22; 32];
        let req = request(true);

        let resp = build_response_for_signing(&req, false, Some(&phone_share), 100).unwrap();

        assert_eq!(resp.unlock_share, None);
        assert_eq!(resp.signature, Vec::<u8>::new());
    }

    #[test]
    fn approved_requested_share_requires_phone_share() {
        let req = request(true);

        assert!(build_response_for_signing(&req, true, None, 100).is_err());
    }

    #[tokio::test]
    async fn pairing_close_waits_for_cli_completion_eof() {
        let phone = iroh::Endpoint::builder(presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let cli = iroh::Endpoint::builder(presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();

        let phone_accept = phone.clone();
        let phone_task = tokio::spawn(async move {
            let incoming = phone_accept.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut request = [0u8; 1];
            recv.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0xAA]);
            send.write_all(&[0xBB]).await.unwrap();
            finish_pairing_connection(&mut send, &mut recv, &conn)
                .await
                .unwrap();
            phone_accept.close().await;
        });

        let conn = cli.connect(phone.addr(), FERUSA_ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[0xAA]).await.unwrap();
        let mut response = [0u8; 1];
        recv.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0xBB]);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!phone_task.is_finished());

        send.finish().unwrap();
        let close_reason = conn.closed().await;
        match close_reason {
            ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code, PAIRING_COMPLETE_CLOSE_CODE.into());
                assert_eq!(close.reason.as_ref(), PAIRING_COMPLETE_CLOSE_REASON);
            }
            other => panic!("unexpected close reason: {other}"),
        }

        cli.close().await;
        tokio::time::timeout(Duration::from_secs(10), phone_task)
            .await
            .unwrap()
            .unwrap();
    }
}
