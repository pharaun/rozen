use std::path::PathBuf;
use serde::Deserialize;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "Rozen")]
#[command(about = "Whole file dedup backup to a remote (AWS S3)")]
#[command(author, version, long_about = None)]
pub struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Lists all known snapshots
    List,

    /// Appends a new snapshot
    Append {
        /// Set a custom name, otherwise datetime is the default
        #[arg(short, long)]
        name: Option<String>
    },

    /// Fetch a snapshot from remote
    Fetch {
        /// The name of the snapshot to fetch
        name: String
    }
}

// Configuration
// At a later time honor: https://aws.amazon.com/blogs/security/a-new-and-standardized-way-to-manage-credentials-in-the-aws-sdks/
// envy = "0.4.2" - for grabbing the env vars via serde
#[derive(Deserialize, Debug)]
pub struct Config {
    pub symlink: bool,
    pub same_fs: bool,

    pub sources: Vec<Source>,
}

#[derive(Deserialize, Debug)]
pub struct Source {
    pub include: Vec<String>,
    pub exclude: Vec<String>,

    #[serde(rename = "type")]
    pub source_type: SourceType,
}

#[derive(Deserialize, Debug, Clone, Copy)]
pub enum SourceType {
    AppendOnly,
}

