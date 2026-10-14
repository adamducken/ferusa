use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::endpoint::Connection;
use iroh::EndpointAddr;
use iroh::{Endpoint, SecretKey};
use log::{debug, error, info, warn};
use zeroize::Zeroizing;

use ferusa_core::auth::{AuthRequest, AuthResponse};
use ferusa_core::transport::{FerusaMessage, FERUSA_ALPN};

use super::iroh_path::{iroh_path_report, IrohPathReport};
use super::recv_all;
use crate::storage::paths::{restrict_private_file, write_private_file};

const CONNECT_PHASE_TIMEOUT: Duration = Duration::from_secs(15);
const STREAM_PHASE_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const AUTH_REQUEST_TOTAL_TIMEOUT: Duration = Duration::from_secs(75);

pub struct CliPeer {
    pub endpoint: Endpoint,
    pub phone_node_id: Option<iroh::PublicKey>,
}

impl CliPeer {
    /// Load secret key from `peer_id_path`, or generate + persist a new one.
    pub async fn init(peer_id_path: &Path) -> Result<Self> {
        info!(
            "[ferusa:cli]: CliPeer::init peer_id_path={:?}",
            peer_id_path
        );

        let secret_key = Self::prepare_identity(peer_id_path)?;

        debug!("[ferusa:cli]: CliPeer::init binding iroh endpoint");
        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .context("bind iroh endpoint")?;

        info!(
            "[ferusa:cli]: CliPeer::init endpoint bound node_id={}",
            endpoint.id()
        );
        Ok(Self {
            endpoint,
            phone_node_id: None,
        })
    }

    pub fn prepare_identity(peer_id_path: &Path) -> Result<SecretKey> {
        let secret_key = if peer_id_path.exists() {
            debug!("[ferusa:cli]: CliPeer::init loading existing secret key");
            restrict_private_file(peer_id_path).context("restrict peer.id permissions")?;
            let raw = Zeroizing::new(std::fs::read(peer_id_path).context("read peer.id")?);
            if raw.len() != 32 {
                error!(
                    "[ferusa:cli]: CliPeer::init peer.id corrupt ({} bytes)",
                    raw.len()
                );
                bail!("peer.id is corrupt (expected 32 bytes, got {})", raw.len());
            }
            let mut bytes = Zeroizing::new([0u8; 32]);
            bytes.copy_from_slice(&raw);
            SecretKey::from_bytes(&*bytes)
        } else {
            debug!("[ferusa:cli]: CliPeer::init generating new secret key");
            let key = SecretKey::generate();
            let key_bytes = Zeroizing::new(key.to_bytes());
            write_private_file(peer_id_path, &*key_bytes).context("write peer.id")?;
            debug!("[ferusa:cli]: CliPeer::init new peer.id written");
            key
        };

        Ok(secret_key)
    }

    /// Consume this `CliPeer` and return the underlying `Endpoint`.
    /// Use this when the caller wants to keep the endpoint alive beyond
    /// the `CliPeer`'s own lifetime (e.g. storing it in `SessionState`).
    pub fn into_endpoint(self) -> Endpoint {
        self.endpoint
    }

    /// Load the phone's PublicKey from a hex file at `phone_id_path`.
    pub fn load_phone_node_id(&mut self, phone_id_path: &Path) -> Result<()> {
        debug!("[ferusa:cli]: load_phone_node_id path={:?}", phone_id_path);
        if !phone_id_path.exists() {
            warn!("[ferusa:cli]: load_phone_node_id phone.id not found — not paired");
            bail!("not paired — run `ferusa pair` first");
        }
        let hex_str = std::fs::read_to_string(phone_id_path).context("read phone.id")?;
        let bytes = hex::decode(hex_str.trim()).context("decode phone.id hex")?;
        if bytes.len() != 32 {
            error!(
                "[ferusa:cli]: load_phone_node_id phone.id corrupt ({} bytes)",
                bytes.len()
            );
            bail!("phone.id is corrupt (expected 32 bytes)");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let pk = iroh::PublicKey::from_bytes(&arr).context("parse phone node id")?;
        self.phone_node_id = Some(pk);
        info!("[ferusa:cli]: load_phone_node_id phone_node_id={}", pk);
        Ok(())
    }

    /// Returns the EndpointAddr for this endpoint.
    pub fn node_addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Send an `AuthRequest` over an existing endpoint and wait up to
    /// 60 s for the response.
    ///
    /// This is a free-standing helper so that the session's persistent
    /// endpoint can be passed in without needing to hold a `CliPeer`.
    pub async fn send_auth_request_on(
        endpoint: &Endpoint,
        req: &AuthRequest,
        phone_node_id: iroh::PublicKey,
    ) -> Result<AuthResponse> {
        let (resp, _path_report) =
            Self::send_auth_request_on_with_path_report(endpoint, req, phone_node_id).await?;
        Ok(resp)
    }

    /// Send an `AuthRequest` and return both the signed response and iroh path report.
    pub async fn send_auth_request_on_with_path_report(
        endpoint: &Endpoint,
        req: &AuthRequest,
        phone_node_id: iroh::PublicKey,
    ) -> Result<(AuthResponse, IrohPathReport)> {
        info!(
            "[ferusa:cli]: send_auth_request_on request_id={} action={:?}",
            req.request_id, req.action
        );

        tokio::time::timeout(AUTH_REQUEST_TOTAL_TIMEOUT, async {
            let addr = EndpointAddr::new(phone_node_id);
            debug!("[ferusa:cli]: send_auth_request_on connecting to phone");
            let conn: Connection =
                tokio::time::timeout(CONNECT_PHASE_TIMEOUT, endpoint.connect(addr, FERUSA_ALPN))
                    .await
                    .context("timed out connecting to phone (15s)")??;
            debug!("[ferusa:cli]: send_auth_request_on connected");

            let (mut send, mut recv) = tokio::time::timeout(STREAM_PHASE_TIMEOUT, conn.open_bi())
                .await
                .context("timed out opening bidirectional stream (10s)")??;
            debug!("[ferusa:cli]: send_auth_request_on bidi stream opened");

            let msg = FerusaMessage::Request(req.clone());
            let bytes = msg.encode().context("encode AuthRequest")?;
            tokio::time::timeout(STREAM_PHASE_TIMEOUT, send.write_all(&bytes))
                .await
                .context("timed out sending AuthRequest (10s)")??;
            send.finish().context("finish send stream")?;
            debug!(
                "[ferusa:cli]: send_auth_request_on request sent ({} bytes)",
                bytes.len()
            );

            debug!("[ferusa:cli]: send_auth_request_on waiting for phone response (timeout 60s)");
            let response_bytes = tokio::time::timeout(RESPONSE_TIMEOUT, recv_all(&mut recv))
                .await
                .context("timed out waiting for phone response (60s)")??;

            debug!(
                "[ferusa:cli]: send_auth_request_on received {} response bytes",
                response_bytes.len()
            );

            match FerusaMessage::decode(&response_bytes).context("decode AuthResponse")? {
                FerusaMessage::Response(r) => {
                    info!(
                        "[ferusa:cli]: send_auth_request_on got Response approved={}",
                        r.approved
                    );
                    let path_report =
                        iroh_path_report(format!("2fa {:?} {}", req.action, req.request_id), &conn);
                    Ok((r, path_report))
                }
                _ => {
                    error!("[ferusa:cli]: send_auth_request_on phone sent a non-Response message");
                    bail!("phone sent a non-Response message")
                }
            }
        })
        .await
        .context("authentication request exceeded the total 75s deadline")?
    }

    /// Send an `AuthRequest` to the phone and wait up to 60 s for the
    /// response. Kept for backwards-compatibility and tests; prefer
    /// `send_auth_request_on` when you already have an `Arc<Endpoint>`.
    pub async fn send_auth_request(
        &self,
        req: &AuthRequest,
        phone_node_id: iroh::PublicKey,
    ) -> Result<AuthResponse> {
        Self::send_auth_request_on(&self.endpoint, req, phone_node_id).await
    }

    pub async fn close(self) {
        debug!("[ferusa:cli]: CliPeer::close closing endpoint");
        self.endpoint.close().await;
        info!("[ferusa:cli]: CliPeer::close endpoint closed");
    }
}
