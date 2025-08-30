use serde::Deserialize;
use serde::Serialize;

use std::path::PathBuf;

use clap::{ArgGroup, Parser, Subcommand};

use rozen::rcore::key::DiskKey;

#[derive(Parser)]
#[command(name = "Rozen")]
#[command(about = "Whole file dedup backup to a remote (AWS S3)")]
#[command(author, version, long_about = None)]
pub struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    // /// Verbose, use multiples to increase level
    // #[arg(short, long, action = clap::ArgAction::Count)]
    // verbose: u8,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Init the repo
    #[command(group(ArgGroup::new("aws")
                        .args(["aws_region", "aws_bucket"])
                        .conflicts_with("sqlite_file")
                        .multiple(true)
                   ))]
    Init {
        /// AWS Region
        #[arg(long, requires = "aws_bucket")]
        aws_region: Option<String>,

        /// AWS Bucket
        #[arg(long, requires = "aws_region")]
        aws_bucket: Option<String>,

        /// Local Sqlite file
        #[arg(long)]
        sqlite_file: Option<PathBuf>,
    },

    /// Lists all known snapshots
    List,

    /// Appends a new snapshot
    Append {
        /// Set a custom name, otherwise datetime is the default
        #[arg(short, long)]
        tag: Option<String>,
    },

    /// Fetch a snapshot from remote
    Fetch {
        /// The timestamp of the snapshot
        timestamp: i64,

        /// The tag of the snapshot to fetch
        tag: Option<String>,

        /// Directory to download snapshot files to
        dir: PathBuf,
    },

    /// Test the entire lifecycle
    Test,
}

// Configuration
// At a later time honor: https://aws.amazon.com/blogs/security/a-new-and-standardized-way-to-manage-credentials-in-the-aws-sdks/
// envy = "0.4.2" - for grabbing the env vars via serde
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub symlink: bool,
    pub same_fs: bool,

    pub sources: Vec<Source>,

    // credentials
    pub disk_key: Option<DiskKey>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Source {
    pub include: Vec<String>,
    pub exclude: Vec<String>,

    #[serde(rename = "type")]
    pub source_type: SourceType,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
pub enum SourceType {
    AppendOnly,
}
