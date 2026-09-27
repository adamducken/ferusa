use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ferusa", about = "A 2FA-gated password vault", version)]
pub struct FerusaCli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Verify that a recovery file can open a separate encrypted vault, offline
    Recovery {
        #[command(subcommand)]
        action: RecoveryCommand,
    },
    /// Initialise a new vault (~/.local/share/ferusa/)
    Init,
    /// Add a new entry
    Add { title: String },
    /// Get a password by title
    Get { title: String },
    /// Edit an existing entry
    Edit { title: String },
    /// Remove an entry
    Remove { title: String },
    /// List all entries (titles + URLs, no passwords)
    List,
    /// Change the master password (re-encrypts vault; pairing is preserved)
    Passwd,
    /// Safely replace the phone pairing while preserving the encrypted vault
    Pair,
    /// Configure CLI behavior
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
    },
    #[command(name = "clipboard-clear-helper", hide = true)]
    ClipboardClearHelper {
        #[arg(long)]
        after_secs: u64,
    },
}

#[derive(Subcommand)]
pub enum RecoveryCommand {
    /// Create a phone-approved recovery file on a separate mounted USB drive
    Create {
        #[arg(
            long,
            value_name = "DIR",
            conflicts_with = "confirm",
            required_unless_present = "confirm"
        )]
        to: Option<PathBuf>,
        /// Freshly confirm one exact existing recovery file after an uncertain outcome
        #[arg(long, value_name = "FILE", conflicts_with = "to")]
        confirm: Option<PathBuf>,
    },
    /// Check the file, credentials, and vault compatibility without contacting a phone
    Verify {
        #[arg(long = "from", value_name = "FILE")]
        from: PathBuf,
        #[arg(long, value_name = "VAULT")]
        vault: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Print the configured clipboard command
    Get,
    /// Set the clipboard command that receives passwords on stdin
    Set {
        /// Clear the clipboard after this many seconds (0 disables clearing)
        #[arg(long, default_value_t = 30)]
        clear_after: u64,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

pub fn parse_from<I, T>(args: I) -> Result<FerusaCli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    FerusaCli::try_parse_from(args)
}
