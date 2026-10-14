mod commands;
mod error;
mod peer;
mod pin;
mod state;
mod storage;

use std::future::Future;
#[cfg(target_os = "android")]
use std::{collections::HashMap, sync::Arc};
#[cfg(target_os = "android")]
use tauri::Manager;

#[cfg(target_os = "android")]
fn android_boot_log(message: &str) {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    const ANDROID_LOG_INFO: c_int = 4;

    unsafe extern "C" {
        fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
    }

    let Ok(tag) = CString::new("ferusa_boot") else {
        return;
    };
    let Ok(fmt) = CString::new("%s") else {
        return;
    };
    let Ok(msg) = CString::new(message) else {
        return;
    };

    unsafe {
        __android_log_print(ANDROID_LOG_INFO, tag.as_ptr(), fmt.as_ptr(), msg.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
fn android_boot_log(_message: &str) {}

fn install_panic_logger() {
    std::panic::set_hook(Box::new(|panic_info| {
        let message = format!("[ferusa:panic]: {panic_info}");
        android_boot_log(&message);
        log::error!("{message}");
        eprintln!("{message}");
    }));
}
#[cfg(target_os = "android")]
use tokio::sync::{Mutex, Semaphore};

#[cfg(target_os = "android")]
use commands::{PendingReq, RecoveryReq};
#[cfg(target_os = "android")]
use ferusa_core::transport::FERUSA_ALPN;
use iroh::SecretKey;
#[cfg(target_os = "android")]
use iroh::{Endpoint, PublicKey};
use log::info;
#[cfg(target_os = "android")]
use log::{debug, error, warn};
#[cfg(target_os = "android")]
use peer::{
    inbound_claimed_endpoint_id, inbound_source_key, SourceAdmissionLimiter,
    INBOUND_HANDSHAKE_TIMEOUT, MAX_INBOUND_CONNECTIONS_PER_PEER,
    MAX_INBOUND_CONNECTIONS_PER_SOURCE, MAX_INBOUND_HANDSHAKES, MAX_PAIRED_CONNECTION_HANDLERS,
    MAX_UNTRUSTED_CONNECTION_HANDLERS,
};
#[cfg(target_os = "android")]
use state::AppState;

#[cfg(target_os = "android")]
async fn is_referenced_pairing_peer<R: tauri::Runtime + 'static>(
    app: &tauri::AppHandle<R>,
    endpoint_id: PublicKey,
) -> bool {
    let state = app.state::<AppState>();
    if state
        .secrets
        .lock()
        .await
        .as_ref()
        .is_some_and(|secrets| endpoint_id.as_bytes() == &secrets.cli_node_id)
    {
        return true;
    }
    match tokio::time::timeout(
        INBOUND_HANDSHAKE_TIMEOUT,
        storage::is_referenced_pairing_cli_node_id_blocking(app.clone(), *endpoint_id.as_bytes()),
    )
    .await
    {
        Ok(Ok(referenced)) => referenced,
        Ok(Err(e)) => {
            warn!("[ferusa:app]: persisted peer classification failed: {e}");
            false
        }
        Err(_) => {
            warn!("[ferusa:app]: persisted peer classification timed out");
            false
        }
    }
}

async fn resolve_iroh_secret_key<L, LFut, S, SFut>(
    mut load: L,
    mut store: S,
) -> anyhow::Result<SecretKey>
where
    L: FnMut() -> LFut,
    LFut: Future<Output = anyhow::Result<Option<SecretKey>>>,
    S: FnMut(SecretKey) -> SFut,
    SFut: Future<Output = anyhow::Result<()>>,
{
    use anyhow::{bail, Context};

    if let Some(secret_key) = load().await.context("load iroh secret key")? {
        info!("[ferusa:app]: loaded existing iroh secret key from storage");
        return Ok(secret_key);
    }

    info!("[ferusa:app]: no iroh secret key on disk, generating new one");
    let generated = SecretKey::generate();
    store(generated.clone())
        .await
        .context("persist generated iroh secret key")?;

    let stored = load()
        .await
        .context("read back generated iroh secret key")?
        .context("generated iroh secret key missing after store")?;
    if stored.public() != generated.public() {
        bail!("generated iroh secret key changed during store");
    }

    info!("[ferusa:app]: generated iroh secret key persisted and verified");
    Ok(stored)
}

#[cfg(target_os = "android")]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    install_panic_logger();
    android_boot_log("[ferusa:boot]: run() entered before tauri logger init");
    info!("[ferusa:app]: starting Ferusa app run()...");

    let app_state = AppState::new();
    debug!("[ferusa:app]: AppState created");
    let pending_req: PendingReq = Arc::new(Mutex::new(None));
    let recovery_req: RecoveryReq = Arc::new(Mutex::new(None));
    debug!("[ferusa:app]: PendingReq slot created");
    android_boot_log("[ferusa:boot]: state initialized");

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_keystore::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .target(tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::Stdout,
                ))
                .target(tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::LogDir {
                        file_name: Some("ferusa".into()),
                    },
                ))
                .build(),
        );
    android_boot_log("[ferusa:boot]: tauri log and keystore plugins added");

    info!("[ferusa:app]: initializing barcode scanner plugin (Android)...");
    builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    debug!("[ferusa:app]: barcode scanner plugin registered");
    android_boot_log("[ferusa:boot]: barcode scanner plugin registered");

    info!("[ferusa:app]: initializing biometric plugin (Android)...");
    builder = builder.plugin(tauri_plugin_biometric::init());
    debug!("[ferusa:app]: biometric plugin registered");
    android_boot_log("[ferusa:boot]: biometric plugin registered");

    info!("[ferusa:app]: configuring Tauri builder...");
    android_boot_log("[ferusa:boot]: configuring tauri builder and entering run()");
    builder = builder
        .manage(app_state)
        .manage(pending_req.clone())
        .manage(recovery_req)
        .invoke_handler(tauri::generate_handler![
            commands::setup_pairing_code,
            commands::setup_complete,
            commands::setup_enrollment,
            commands::setup_status,
            commands::check_setup,
            commands::biometric_unlock,
            commands::lock,
            commands::set_app_foreground,
            commands::pending_request,
            commands::pending_recovery,
            commands::confirm_recovery,
            commands::deny_recovery,
            commands::approve_request,
            commands::deny_request,
            commands::authorize_pairing_replacement,
            commands::cancel_pairing_replacement,
        ])
        .setup(move |app| {
            android_boot_log("[ferusa:boot]: setup hook entered");
            info!("[ferusa:app]: inside Tauri setup hook");
            let app_handle = app.handle().clone();
            let pending = pending_req.clone();

            tauri::async_runtime::spawn(async move {
                android_boot_log("[ferusa:boot]: endpoint async task started");
                // Load or generate the iroh secret key so our Node ID is
                // stable across restarts. The CLI records this Node ID during
                // `ferusa pair`; if it changes the CLI can never reach us again.
                info!("[ferusa:app]: resolving iroh secret key...");
                let secret_key = match resolve_iroh_secret_key(
                    || storage::load_iroh_secret_key_blocking(app_handle.clone()),
                    |secret_key| {
                        storage::store_iroh_secret_key_blocking(app_handle.clone(), secret_key)
                    },
                )
                .await
                {
                    Ok(secret_key) => secret_key,
                    Err(e) => {
                        let message = format!(
                            "[ferusa:boot]: iroh identity unavailable; endpoint disabled: {e}"
                        );
                        android_boot_log(&message);
                        error!("[ferusa:app]: iroh identity unavailable; endpoint disabled: {e}");
                        return;
                    }
                };

                debug!("[ferusa:app]: iroh node id = {}", secret_key.public());

                info!("[ferusa:app]: binding iroh endpoint...");
                let endpoint = match Endpoint::builder(iroh::endpoint::presets::N0)
                    .secret_key(secret_key)
                    .alpns(vec![FERUSA_ALPN.to_vec()])
                    .bind()
                    .await
                {
                    Ok(ep) => {
                        android_boot_log("[ferusa:boot]: iroh endpoint bound successfully");
                        info!("[ferusa:app]: iroh endpoint bound successfully");
                        ep
                    }
                    Err(e) => {
                        android_boot_log(&format!(
                            "[ferusa:boot]: failed to bind iroh endpoint: {e}"
                        ));
                        error!("[ferusa:app]: failed to bind iroh endpoint: {}", e);
                        return;
                    }
                };

                // Store the endpoint in AppState so setup_complete can borrow
                // it for pairing without creating a second, conflicting endpoint.
                {
                    let state: tauri::State<'_, AppState> = app_handle.state();
                    *state.endpoint.lock().await = Some(endpoint.clone());
                    debug!("[ferusa:app]: endpoint stored in AppState");
                }

                debug!("[ferusa:app]: entering connection accept loop");
                let inbound_handshakes = Arc::new(Semaphore::new(MAX_INBOUND_HANDSHAKES));
                let paired_handlers =
                    Arc::new(Semaphore::new(MAX_PAIRED_CONNECTION_HANDLERS));
                let untrusted_handlers =
                    Arc::new(Semaphore::new(MAX_UNTRUSTED_CONNECTION_HANDLERS));
                let source_limiter =
                    SourceAdmissionLimiter::new(MAX_INBOUND_CONNECTIONS_PER_SOURCE);
                let inbound_peer_counts = Arc::new(Mutex::new(HashMap::<PublicKey, usize>::new()));
                loop {
                    debug!("[ferusa:app]: waiting for incoming iroh connection...");

                    let incoming = match endpoint.accept().await {
                        Some(inc) => {
                            info!("[ferusa:app]: incoming connection detected");
                            inc
                        }
                        None => {
                            error!("[ferusa:app]: iroh endpoint closed, exiting accept loop");
                            break;
                        }
                    };

                    let pending_clone = pending.clone();
                    let app_handle_c = app_handle.clone();
                    let inbound_peer_counts_c = inbound_peer_counts.clone();
                    let remote_addr = incoming.remote_addr();
                    let source = inbound_source_key(&remote_addr);
                    let claims_referenced_peer = if let Some(endpoint_id) =
                        inbound_claimed_endpoint_id(&remote_addr)
                    {
                        is_referenced_pairing_peer(&app_handle, endpoint_id).await
                    } else {
                        false
                    };
                    // A relay supplies the authenticated endpoint id before the QUIC handshake.
                    // Do not let fresh identities consume the paired peer's source allowance.
                    let source_permit = if claims_referenced_peer {
                        None
                    } else {
                        match source_limiter.try_acquire(source.clone()) {
                            Some(permit) => Some(permit),
                            None => {
                                warn!(
                                    "[ferusa:app]: rejecting inbound connection: source limit reached for {}",
                                    source
                                );
                                incoming.refuse();
                                continue;
                            }
                        }
                    };
                    let handshake_permit = match inbound_handshakes.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(
                                "[ferusa:app]: rejecting inbound connection: handshake limit reached"
                            );
                            incoming.refuse();
                            continue;
                        }
                    };
                    let paired_handlers_c = paired_handlers.clone();
                    let untrusted_handlers_c = untrusted_handlers.clone();

                    debug!("[ferusa:app]: spawning task to handle incoming connection");
                    tauri::async_runtime::spawn(async move {
                        let _source_permit = source_permit;
                        let handshake_permit = handshake_permit;
                        debug!("[ferusa:app]: handling incoming connection...");
                        let conn = match incoming.accept() {
                            Ok(acc) => {
                                match tokio::time::timeout(INBOUND_HANDSHAKE_TIMEOUT, acc).await {
                                    Ok(Ok(c)) => {
                                        info!("[ferusa:app]: connection handshake successful");
                                        c
                                    }
                                    Ok(Err(e)) => {
                                        error!("[ferusa:app]: handshake error: {}", e);
                                        return;
                                    }
                                    Err(_) => {
                                        warn!("[ferusa:app]: inbound handshake timed out");
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("[ferusa:app]: accept error: {}", e);
                                return;
                            }
                        };
                        drop(handshake_permit);

                        let remote_id = conn.remote_id();
                        let is_referenced_peer =
                            is_referenced_pairing_peer(&app_handle_c, remote_id).await;
                        let handler_permit = if is_referenced_peer {
                            paired_handlers_c.try_acquire_owned()
                        } else {
                            untrusted_handlers_c.try_acquire_owned()
                        };
                        let _handler_permit = match handler_permit {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(
                                    "[ferusa:app]: rejecting inbound connection from {}: {} handler capacity exhausted",
                                    remote_id,
                                    if is_referenced_peer { "paired" } else { "untrusted" }
                                );
                                conn.close(0u32.into(), b"connection handler capacity exhausted");
                                return;
                            }
                        };
                        let peer_slot_accepted = {
                            let mut counts = inbound_peer_counts_c.lock().await;
                            let count = counts.entry(remote_id).or_insert(0);
                            if *count >= MAX_INBOUND_CONNECTIONS_PER_PEER {
                                false
                            } else {
                                *count += 1;
                                true
                            }
                        };
                        if !peer_slot_accepted {
                            warn!(
                                "[ferusa:app]: rejecting inbound connection from {}: per-peer limit reached",
                                remote_id
                            );
                            conn.close(0u32.into(), b"per-peer connection limit");
                            return;
                        }

                        commands::serve_connection(conn, pending_clone, app_handle_c).await;

                        let mut counts = inbound_peer_counts_c.lock().await;
                        if let Some(count) = counts.get_mut(&remote_id) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                counts.remove(&remote_id);
                            }
                        }
                    });
                }

                warn!("[ferusa:app]: accept loop exited");
            });

            android_boot_log("[ferusa:boot]: setup hook returning Ok");
            Ok(())
        });

    android_boot_log("[ferusa:boot]: calling builder.run()");
    if let Err(e) = builder.run(tauri::generate_context!()) {
        android_boot_log(&format!("[ferusa:boot]: builder.run returned error: {e}"));
        panic!("error while running ferusa: {e}");
    }
    android_boot_log("[ferusa:boot]: builder.run returned Ok; app is exiting");
}

#[cfg(not(target_os = "android"))]
pub fn run() {
    panic!("ferusa app runtime is Android-only");
}

#[cfg(test)]
mod tests {
    use super::resolve_iroh_secret_key;
    use anyhow::{anyhow, Result};
    use iroh::SecretKey;
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        future::ready,
    };

    #[tokio::test]
    async fn existing_identity_is_used_without_store() {
        let existing = SecretKey::generate();
        let store_called = Cell::new(false);

        let resolved = resolve_iroh_secret_key(
            || ready(Ok(Some(existing.clone()))),
            |_| {
                store_called.set(true);
                ready(Ok(()))
            },
        )
        .await
        .unwrap();

        assert_eq!(resolved.public(), existing.public());
        assert!(!store_called.get());
    }

    #[tokio::test]
    async fn load_failure_disables_identity_instead_of_generating_one() {
        let store_called = Cell::new(false);

        let err = resolve_iroh_secret_key(
            || ready(Err(anyhow!("keystore unavailable"))),
            |_| {
                store_called.set(true);
                ready(Ok(()))
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("load iroh secret key"));
        assert!(!store_called.get());
    }

    #[tokio::test]
    async fn generated_identity_requires_successful_store() {
        let err =
            resolve_iroh_secret_key(|| ready(Ok(None)), |_| ready(Err(anyhow!("write failed"))))
                .await
                .unwrap_err();

        assert!(err
            .to_string()
            .contains("persist generated iroh secret key"));
    }

    #[tokio::test]
    async fn generated_identity_requires_read_back() {
        let err = resolve_iroh_secret_key(|| ready(Ok(None)), |_| ready(Ok(())))
            .await
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("generated iroh secret key missing after store"));
    }

    #[tokio::test]
    async fn generated_identity_requires_matching_read_back() {
        let other = SecretKey::generate();
        let loads = RefCell::new(VecDeque::from([None, Some(other)]));

        let err = resolve_iroh_secret_key(
            || ready(Ok(loads.borrow_mut().pop_front().unwrap())),
            |_| ready(Ok(())),
        )
        .await
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("generated iroh secret key changed during store"));
    }

    #[tokio::test]
    async fn generated_identity_is_used_after_verified_read_back() -> Result<()> {
        let stored = RefCell::new(None);

        let resolved = resolve_iroh_secret_key(
            || ready(Ok(stored.borrow().clone())),
            |generated| {
                *stored.borrow_mut() = Some(generated);
                ready(Ok(()))
            },
        )
        .await?;

        assert_eq!(
            resolved.public(),
            stored.borrow().as_ref().unwrap().public()
        );
        Ok(())
    }
}
