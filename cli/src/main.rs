use clap::Parser;
use cli::args::{Commands, ConfigCommand, FerusaCli, RecoveryCommand};
use cli::interface::error::{CliError, Result};
use cli::session::SharedState;
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

const LOG_TARGET: &str = "ferusa::lifecycle";

/// Initialise a file-only logger writing to `~/.local/share/ferusa/ferusa.log`.
/// Only redacted lifecycle records are captured; nothing goes to stdout/stderr.
fn init_logger() -> Result<()> {
    use cli::storage::paths::open_private_append_file;
    use simplelog::{ConfigBuilder, LevelFilter, WriteLogger};

    let log_path = cli::storage::paths::Paths::load()
        .map_err(CliError::from)?
        .data_dir
        .join("ferusa.log");

    let file = match open_private_append_file(&log_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("[ferusa:cli]: logger file open failed: {e}");
            return Ok(());
        }
    };

    let config = ConfigBuilder::new()
        .add_filter_allow_str(LOG_TARGET)
        .build();
    if let Err(e) = WriteLogger::init(LevelFilter::Debug, config, file) {
        eprintln!("[ferusa:cli]: logger init failed: {e}");
        return Ok(());
    }

    // Log the startup line *after* the logger is live.
    info!(target: LOG_TARGET, "[ferusa:cli]: logger initialized");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = FerusaCli::parse();
    // Offline verification must work with only the two selected files and a
    // terminal, even if local installation metadata is missing or read-only.
    if !matches!(&cli.command, Some(Commands::Recovery { .. })) {
        init_logger()?;
    }
    let state: SharedState = Arc::new(Mutex::new(None));

    let command = match cli.command {
        Some(command) => command,
        None => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching Repl");
            return cli::interface::repl::run().await.map_err(CliError::from);
        }
    };

    let result: Result<()> = match command {
        Commands::Recovery { action } => match action {
            RecoveryCommand::Create { to, confirm } => match (to, confirm) {
                (Some(to), None) => cli::commands::recovery::cmd_create(&to)
                    .await
                    .map_err(CliError::from),
                (None, Some(from)) => cli::commands::recovery::cmd_confirm(&from)
                    .await
                    .map_err(CliError::from),
                _ => unreachable!("clap requires exactly one recovery create target"),
            },
            RecoveryCommand::Verify { from, vault } => {
                cli::commands::recovery::cmd_verify(&from, &vault).map_err(CliError::from)
            }
        },
        Commands::Init => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching Init");
            cli::commands::init::cmd_init()
                .await
                .map_err(CliError::from)
        }
        Commands::Add { title } => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching Add");
            cli::commands::add::cmd_add(state, &title)
                .await
                .map_err(CliError::from)
        }
        Commands::Get { title } => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching Get");
            cli::commands::get::cmd_get(state, &title)
                .await
                .map_err(CliError::from)
        }
        Commands::Edit { title } => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching Edit");
            cli::commands::edit::cmd_edit(state, &title)
                .await
                .map_err(CliError::from)
        }
        Commands::Remove { title } => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching Remove");
            cli::commands::remove::cmd_remove(state, &title)
                .await
                .map_err(CliError::from)
        }
        Commands::List => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching List");
            cli::commands::list::cmd_list(state)
                .await
                .map_err(CliError::from)
        }
        Commands::Passwd => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching Passwd");
            cli::commands::passwd::cmd_passwd(state)
                .await
                .map_err(CliError::from)
        }
        Commands::Pair => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching Pair");
            cli::commands::pair::cmd_pair(state)
                .await
                .map_err(CliError::from)
        }
        Commands::Config { action } => {
            info!(target: LOG_TARGET, "[ferusa:cli]: dispatching Config");
            match action {
                ConfigCommand::Get => {
                    cli::commands::config::cmd_config_get().map_err(CliError::from)
                }
                ConfigCommand::Set {
                    clear_after,
                    command,
                } => cli::commands::config::cmd_config_set(&command.join(" "), clear_after)
                    .map_err(CliError::from),
            }
        }
        Commands::ClipboardClearHelper { after_secs } => {
            cli::clipboard::run_clear_helper(after_secs).map_err(CliError::from)
        }
    };

    match &result {
        Ok(()) => info!(target: LOG_TARGET, "[ferusa:cli]: command completed successfully"),
        Err(e) => e.render(),
    }

    result
}
