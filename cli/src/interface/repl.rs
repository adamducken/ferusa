use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use log::{info, warn};
use tokio::sync::Mutex;

use crate::commands;
use crate::interface::ui;
use crate::session::{ensure_unlocked_for, lock_session, SharedState};
use crate::session_conn::connect_to_phone;
use crate::storage::paths::Paths;
use ferusa_core::types::VaultAction;

// const PROMPT: &str = "\x1b[1mferusa ➜\x1b[0m ";
const PROMPT: &str = "\x1b[1mferusa:\x1b[0m ";

pub async fn run() -> Result<()> {
    ui::info(&format!("ferusa v{}", env!("CARGO_PKG_VERSION")));

    let state: SharedState = Arc::new(Mutex::new(None));
    let paths = Paths::load()?;

    ensure_unlocked_for(&state, &paths, VaultAction::Unlock, None).await?;

    match connect_to_phone(&state, &paths, Duration::from_secs(5)).await {
        Ok(_) => {}
        Err(e) => {
            warn!("[ferusa:cli]: initial phone connection failed: {:#}", e);
            ui::failed(&format!("phone not reachable — 2FA unavailable: {e}"));
        }
    }

    repl_loop(state, paths).await
}

async fn repl_loop(state: SharedState, paths: Paths) -> Result<()> {
    let mut rl = rustyline::DefaultEditor::new()?;

    loop {
        let line = match rl.readline(PROMPT) {
            Ok(line) => line,
            Err(
                rustyline::error::ReadlineError::Interrupted | rustyline::error::ReadlineError::Eof,
            ) => break,
            Err(e) => return Err(e.into()),
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let _ = rl.add_history_entry(line);

        let result: Result<()> = match parse(line) {
            ReplCommand::Exit | ReplCommand::Lock => break,
            ReplCommand::Help => {
                print_help();
                Ok(())
            }
            ReplCommand::Ping => {
                ping(&state).await;
                Ok(())
            }
            ReplCommand::Reconnect => {
                close_phone_connection(&state).await;
                if let Err(e) = connect_to_phone(&state, &paths, Duration::from_secs(10)).await {
                    ui::failed(&format!("reconnect failed: {e}"));
                }
                Ok(())
            }
            ReplCommand::Add(title) => commands::add::cmd_add(Arc::clone(&state), &title).await,
            ReplCommand::Get(title) => commands::get::cmd_get(Arc::clone(&state), &title).await,
            ReplCommand::Edit(title) => commands::edit::cmd_edit(Arc::clone(&state), &title).await,
            ReplCommand::Remove(title) => {
                commands::remove::cmd_remove(Arc::clone(&state), &title).await
            }
            ReplCommand::List => commands::list::cmd_list(Arc::clone(&state)).await,
            ReplCommand::Pair => commands::pair::cmd_pair(Arc::clone(&state)).await,
            ReplCommand::Passwd => commands::passwd::cmd_passwd(Arc::clone(&state)).await,
            ReplCommand::RecoveryCreate => {
                #[cfg(target_os = "linux")]
                {
                    let directory = commands::enroll::recovery_directory(None)?;
                    commands::recovery::cmd_create_in_session(&directory, &state).await
                }
                #[cfg(not(target_os = "linux"))]
                {
                    anyhow::bail!("recovery creation requires Linux storage validation")
                }
            }
            ReplCommand::ConfigGet => commands::config::cmd_config_get(),
            ReplCommand::ConfigSet(command) => commands::config::cmd_config_set(&command, 30),
            ReplCommand::Unknown(s) => {
                ui::failed(&format!("unknown command: {s}"));
                Ok(())
            }
        };

        if let Err(e) = result {
            warn!("[ferusa:cli]: repl command failed: {:#}", e);
        }
    }

    close_phone_connection(&state).await;
    lock_session(&state).await;
    ui::info("vault locked. goodbye.");
    info!("[ferusa:cli]: repl exited");
    Ok(())
}

async fn ping(state: &SharedState) {
    let conn = {
        let guard = state.lock().await;
        guard
            .as_ref()
            .and_then(|session| session.phone_conn.clone())
    };
    match conn {
        Some(c) => match c.ping().await {
            Ok(report) => ui::success(&format!("pong — {}", report.human_summary())),
            Err(e) => ui::failed(&format!("no response: {e}")),
        },
        None => ui::info("not connected to phone — use `reconnect`"),
    }
}

async fn close_phone_connection(state: &SharedState) {
    let conn = {
        let mut guard = state.lock().await;
        guard.as_mut().and_then(|session| session.phone_conn.take())
    };
    if let Some(conn) = conn {
        conn.close().await;
    }
}

fn parse(line: &str) -> ReplCommand {
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else {
        return ReplCommand::Help;
    };
    match cmd {
        "exit" | "quit" => ReplCommand::Exit,
        "lock" => ReplCommand::Lock,
        "help" | "?" => ReplCommand::Help,
        "ping" => ReplCommand::Ping,
        "reconnect" => ReplCommand::Reconnect,
        "add" => one_arg(parts, "add")
            .map(ReplCommand::Add)
            .unwrap_or_else(ReplCommand::Unknown),
        "list" | "ls" => ReplCommand::List,
        "pair" => ReplCommand::Pair,
        "passwd" => ReplCommand::Passwd,
        "recovery" if parts.next() == Some("create") && parts.next().is_none() => {
            ReplCommand::RecoveryCreate
        }
        "get" => one_arg(parts, "get")
            .map(ReplCommand::Get)
            .unwrap_or_else(ReplCommand::Unknown),
        "edit" => one_arg(parts, "edit")
            .map(ReplCommand::Edit)
            .unwrap_or_else(ReplCommand::Unknown),
        "remove" | "rm" => one_arg(parts, "remove")
            .map(ReplCommand::Remove)
            .unwrap_or_else(ReplCommand::Unknown),
        "config" => config_command(parts),
        _ => ReplCommand::Unknown(cmd.to_string()),
    }
}

fn config_command<'a>(mut parts: impl Iterator<Item = &'a str>) -> ReplCommand {
    match parts.next() {
        Some("get") => ReplCommand::ConfigGet,
        Some("set") => {
            let command = parts.collect::<Vec<_>>().join(" ");
            if command.is_empty() {
                ReplCommand::Unknown("usage: config set <clipboard command>".to_string())
            } else {
                ReplCommand::ConfigSet(command)
            }
        }
        _ => ReplCommand::Unknown("usage: config get | config set <clipboard command>".to_string()),
    }
}

fn one_arg<'a>(mut parts: impl Iterator<Item = &'a str>, name: &str) -> Result<String, String> {
    let Some(value) = parts.next() else {
        return Err(format!("usage: {name} <title>"));
    };
    let mut title = value.to_string();
    for part in parts {
        title.push(' ');
        title.push_str(part);
    }
    if title.is_empty() {
        Err("empty title".to_string())
    } else {
        Ok(title)
    }
}

fn print_help() {
    ui::info("commands: add <title>, get <title>, edit <title>, remove <title>, list, pair, recovery create, config get, config set <cmd>, ping, reconnect, passwd, lock, exit, help");
}

enum ReplCommand {
    Add(String),
    ConfigGet,
    ConfigSet(String),
    Edit(String),
    Exit,
    Get(String),
    Help,
    List,
    Lock,
    Pair,
    Passwd,
    Ping,
    Reconnect,
    RecoveryCreate,
    Remove(String),
    Unknown(String),
}
