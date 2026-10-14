use anyhow::Result;
#[cfg(feature = "dev-2fa-stub")]
mod legacy {
    use std::io::{self, Write};

    use anyhow::{Context, Result};
    use log::{debug, info, warn};

    use ferusa_core::crypto::{combine_vault_key, derive_keys, encrypt_vault, new_salt};
    use ferusa_core::types::Vault;
    use zeroize::Zeroizing;

    use crate::commands::pair::reconcile_pairing_transaction;
    #[cfg(not(feature = "dev-2fa-stub"))]
    use crate::commands::pair::{
        begin_pair_with_phone, commit_and_activate_pairing, confirm_pairing_ready,
    };
    use crate::interface::ui;
    #[cfg(not(feature = "dev-2fa-stub"))]
    use crate::net::cli_peer::CliPeer;
    use crate::password::{validate_master_password, MIN_MASTER_PASSWORD_CHARS};
    #[cfg(not(feature = "dev-2fa-stub"))]
    use crate::storage::paths::PairingData;
    use crate::storage::paths::{write_private_file, Paths};

    #[cfg(feature = "dev-2fa-stub")]
    pub async fn cmd_init() -> Result<()> {
        info!("[ferusa:cli]: cmd_init start");

        // — load paths —
        ui::execute("loading config paths");
        let paths = Paths::load()?;
        ui::success("paths loaded");
        debug!(
            "[ferusa:cli]: cmd_init paths loaded data_dir={:?}",
            paths.data_dir
        );

        // — ensure data dir exists —
        ui::execute("creating data directory");
        paths.ensure_data_dir().map_err(|e| {
            ui::failed("could not create data directory");
            e
        })?;
        ui::success(&format!("data directory ready at {:?}", paths.data_dir));
        debug!("[ferusa:cli]: cmd_init data dir ensured");

        let _vault_lock = paths.acquire_vault_lock().context("lock vault")?;
        reconcile_pairing_transaction(&paths)
            .await
            .context("recover pairing transaction")?;

        #[cfg(not(feature = "dev-2fa-stub"))]
        paths.ensure_not_dev_2fa_stub_vault().map_err(|e| {
            ui::failed("dev 2FA stub vaults are not production-compatible");
            e
        })?;

        // — check vault does not already exist —
        ui::execute("checking for existing vault");
        if paths.vault_exists() {
            ui::failed("a vault already exists at this location");
            ui::info(&format!("location: {:?}", paths.vault_enc));
            ui::info("use `ferusa passwd` to change the password");
            ui::info("or delete the data directory to start fresh");
            warn!(
                "[ferusa:cli]: cmd_init vault already exists at {:?}",
                paths.vault_enc
            );
            return Err(anyhow::anyhow!("vault already exists"));
        }
        ui::success("no existing vault found — safe to initialise");

        // — collect master password —
        println!();
        ui::info("your master password encrypts the vault ");
        ui::info(&format!(
            "choose a unique passphrase (minimum {MIN_MASTER_PASSWORD_CHARS} characters)"
        ));
        ui::info("it is never stored anywhere, only you know it");

        let pw1 = Zeroizing::new(
            rpassword::prompt_password("\x1b[1minput:\x1b[0m new master password: ")
                .context("read password")?,
        );

        ui::execute("checking password strength requirements");
        if let Err(e) = validate_master_password(&pw1) {
            ui::failed(&e.to_string());
            warn!(
                "[ferusa:cli]: cmd_init master password rejected ({}) characters",
                pw1.chars().count()
            );
            return Err(e);
        }
        ui::success("password meets strength requirements");

        let pw2 = Zeroizing::new(
            rpassword::prompt_password("\x1b[1minput:\x1b[0m confirm master password: ")
                .context("read password confirm")?,
        );

        ui::execute("verifying passwords match");
        if pw1.as_str() != pw2.as_str() {
            ui::failed("passwords do not match — please run `ferusa init` again");
            warn!("[ferusa:cli]: cmd_init passwords do not match");
            return Err(anyhow::anyhow!("passwords do not match"));
        }
        ui::success("passwords match");
        debug!("[ferusa:cli]: cmd_init password confirmed");

        // — derive keys —
        println!();
        ui::info("we now derive your local password factor using Argon2");
        ui::info("this is intentionally slow to resist brute-force attacks");
        ui::execute("deriving local factor from master password");
        let salt = new_salt();
        let keys = derive_keys(pw1.as_bytes(), &salt).map_err(|e| {
            ui::failed("key derivation failed");
            e
        })?;
        drop(pw1);
        drop(pw2);
        ui::success("keys derived");
        debug!("[ferusa:cli]: cmd_init keys derived");

        #[cfg(feature = "dev-2fa-stub")]
        let phone_share = {
            ui::warn("DEV 2FA STUB ENABLED — using deterministic test phone share");
            crate::twofa::stub::dev_phone_share()?
        };

        #[cfg(not(feature = "dev-2fa-stub"))]
        let exchange = {
            ui::execute("initialising p2p identity");
            let peer = CliPeer::init(&paths.peer_id).await.map_err(|e| {
                ui::failed("could not initialise p2p identity");
                e
            })?;
            let endpoint = std::sync::Arc::new(peer.into_endpoint());
            begin_pair_with_phone(&paths, endpoint).await?
        };

        #[cfg(not(feature = "dev-2fa-stub"))]
        let phone_share = exchange.secrets.phone_share;

        let vault_key =
            combine_vault_key(&keys.local_secret, &phone_share).context("combine vault key")?;

        // — encrypt vault —
        ui::execute("encrypting empty vault");
        let vault = Vault::default();
        let plaintext = Zeroizing::new(serde_json::to_vec(&vault).context("serialize vault")?);
        let blob = encrypt_vault(&vault_key, salt, plaintext.as_slice()).map_err(|e| {
            ui::failed("vault encryption failed");
            e
        })?;
        ui::success("vault encrypted");
        debug!("[ferusa:cli]: cmd_init vault encrypted");

        // — write to disk (atomic) —
        ui::execute("writing vault to disk (atomic)");

        #[cfg(feature = "dev-2fa-stub")]
        {
            write_private_file(&paths.vault_enc, &blob.to_bytes()).context("write vault.enc")?;
            write_private_file(&paths.vault_salt, &salt).context("write legacy vault.salt")?;
            paths
                .write_dev_2fa_stub_marker()
                .context("write dev 2FA stub marker")?;
        }

        #[cfg(not(feature = "dev-2fa-stub"))]
        {
            let persist_result = async {
                write_private_file(&paths.pending_vault_enc(), &blob.to_bytes())
                    .context("write pending vault.enc")?;
                write_private_file(&paths.vault_salt, &salt).context("write legacy vault.salt")?;
                let pairing = PairingData {
                    pairing_id: exchange.secrets.pairing_id,
                    phone_node_id: exchange.secrets.phone_node_id,
                    approval_public_key_der: exchange.secrets.approval_public_key_der.clone(),
                    created_at_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };
                paths.write_pending_pairing_data(&pairing).map_err(|e| {
                    ui::failed("could not write pending pairing data");
                    e
                })?;
                debug!("[ferusa:cli]: cmd_init pending pairing written to disk");

                let commit_transport = confirm_pairing_ready(exchange.transport, &pairing).await?;
                commit_and_activate_pairing(&paths, commit_transport, pairing.pairing_id).await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;

            if let Err(e) = persist_result {
                if paths.pairing_transaction_state().exists() {
                    return Err(e).context("init transaction retained for automatic recovery");
                }
                paths
                    .clear_pending_pairing()
                    .context("clear aborted init pairing")?;
                return Err(e);
            }
        }

        ui::success("vault written to disk");
        debug!("[ferusa:cli]: cmd_init atomic write complete");

        info!(
            "[ferusa:cli]: cmd_init vault initialised at {:?}",
            paths.data_dir
        );

        // — done —
        println!();
        ui::success("vault initialised");
        ui::info(&format!("stored at {:?}", paths.data_dir));

        ui::info("clipboard command is bring-your-own and receives passwords on stdin");
        ui::info("examples: wl-copy, xclip -selection clipboard, pbcopy");
        print!("\x1b[1minput:\x1b[0m configure clipboard command now? [y/N]: ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            print!("\x1b[1minput:\x1b[0m clipboard command: ");
            io::stdout().flush()?;
            let mut command = String::new();
            io::stdin().read_line(&mut command)?;
            crate::commands::config::cmd_config_set(command.trim(), 30)?;
        }

        println!();
        ui::info("next steps:");
        ui::info("run \"ferusa config set --clear-after 30 <clipboard command>\" if clipboard is not configured");
        ui::info("run \"ferusa add\" to add your first entry");
        ui::info("run \"ferusa get <title>\" to retrieve an entry");

        Ok(())
    }
}
#[cfg(feature = "dev-2fa-stub")]
pub use legacy::cmd_init;

#[cfg(all(target_os = "linux", not(feature = "dev-2fa-stub")))]
pub async fn cmd_init() -> Result<()> {
    super::enroll::cmd_init_with_recovery(None).await
}

pub async fn cmd_init_with_recovery(selected: Option<&std::path::Path>) -> Result<()> {
    #[cfg(feature = "dev-2fa-stub")]
    {
        let _ = selected;
        return cmd_init().await;
    }
    #[cfg(all(target_os = "linux", not(feature = "dev-2fa-stub")))]
    {
        super::enroll::cmd_init_with_recovery(selected).await
    }
    #[cfg(all(not(target_os = "linux"), not(feature = "dev-2fa-stub")))]
    {
        anyhow::bail!("mandatory recovery requires the Linux storage topology resolver")
    }
}

#[cfg(all(not(target_os = "linux"), not(feature = "dev-2fa-stub")))]
pub async fn cmd_init() -> Result<()> {
    cmd_init_with_recovery(None).await
}
