use ignore::WalkBuilder;

use std::error::Error;
use std::io::{Read, Write};
use std::path::Path;
use tempfile::TempDir;

use clap::Parser as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use log::info;

mod cli;
use crate::cli::Commands;

use rozen::rcore::crypto;
use rozen::rcore::key;

use rozen::remote;
use rozen::remote::Remote;
use rozen::remote::Typ;

use rozen::snapshot;

// TODO: should name various things like Index getting its own hashkey
//  * I-<timestamp> = index
//  * P-<rng>  = packfile (only one that isn't hash)
//  * B-<hash> = raw blob (big files)
// TODO: how to handle files larger than X size (ie S3 only allow file up to X for eg)
//  * Do we want to support chunking, could possibly do it via
//  * B-<hash>.p0
//  * B-<hash>.p1
//  * B-<hash>.p? - I'm not sure, could have B-<hash> -> metadata -> B-<hash>.p? but could
//      also just always have the B-<hash> xor B-<hash>.p?
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    crypto::init()?;

    // Parse the cli
    let cli = cli::Cli::parse();

    // In memory remote for data storage
    #[cfg(all(feature = "sql", not(feature = "s3")))]
    let mut remote = remote::sql::SqlVFS::new(Some("test.sqlite"))?;

    // Build a s3 remote here - Overrides the sql feature
    #[cfg(feature = "s3")]
    let mut remote = remote::s3::S3::new_endpoint("test", "http://localhost:8333")?;

    // TODO: should use a user given password, hardcode for ease of test right now
    let password = "ThisIsAPassword";

    match &cli.command {
        Some(Commands::Init { .. }) => {
            // Dump config to a TEST typ
            let mut config_content = remote.write_multi_filename(Typ::TEST, "CONFIG")?;

            // For now just focus on figuring out some sort of key management/generation here
            init(&mut config_content, password)?;
            Ok(())
        }
        Some(Commands::List) => list(&remote),
        Some(Commands::Append { tag }) => {
            let timestamp = OffsetDateTime::now_utc();

            let mut config_content = remote.read_filename(Typ::TEST, "CONFIG")?;
            let mut config_str = String::new();
            config_content.read_to_string(&mut config_str)?;
            let config: cli::Config = toml::from_str(&config_str)?;

            append(&config, password, &mut remote, timestamp, tag.clone())
        }
        Some(Commands::Fetch {
            timestamp,
            tag,
            dir,
        }) => {
            let timestamp = OffsetDateTime::parse(timestamp, &Rfc3339)?;
            let target = dir.as_path();

            let mut config_content = remote.read_filename(Typ::TEST, "CONFIG")?;
            let mut config_str = String::new();
            config_content.read_to_string(&mut config_str)?;
            let config: cli::Config = toml::from_str(&config_str)?;

            fetch(
                &config,
                password,
                &mut remote,
                timestamp,
                tag.clone(),
                target,
            )
        }
        Some(Commands::Test) => {
            println!("TEST ONLY");
            let timestamp = OffsetDateTime::now_utc();
            let tag = Some("TEST".to_owned());
            let target = TempDir::new()?;

            let mut config_content = remote.write_multi_filename(Typ::TEST, "CONFIG")?;
            init(&mut config_content, password)?;

            let mut config_content = remote.read_filename(Typ::TEST, "CONFIG")?;
            let mut config_str = String::new();
            config_content.read_to_string(&mut config_str)?;
            let config: cli::Config = toml::from_str(&config_str)?;

            append(&config, password, &mut remote, timestamp, tag.clone())?;
            fetch(
                &config,
                password,
                &mut remote,
                timestamp,
                tag.clone(),
                target.path(),
            )?;
            list(&remote)?;

            // TODO: add support to picking an target/combo and verifying
            verify(&config, password, &mut remote, timestamp, tag)
        }
        None => Ok(()),
    }
}

fn init(config_content: &mut Box<dyn Write>, password: &str) -> Result<(), Box<dyn Error>> {
    // TODO: make all of this much beter, ie maybe make it generate all of the needed
    // stuff at the top then generate commented out sample section and then go from there
    let mut sample_config: cli::Config = toml::from_str(
        r#"
        symlink = true
        same_fs = true

        [[sources]]
            include = ["docs"]
            exclude = ["*.pyc"]
            type = "AppendOnly"

        "#,
    )?;
    info!("CONFIG: {sample_config:?}");

    // Generate a new MemKey and convert it to DiskKey to store in the config
    let key = key::MemKey::new();
    let disk_key = key.to_disk_key(password)?;
    sample_config.disk_key = Some(disk_key);

    info!("CONFIG2: {sample_config:?}");
    let toml = toml::to_string(&sample_config)?;

    // Dump to output stream
    config_content.write_all(toml.as_bytes())?;
    config_content.flush()?;
    Ok(())
}

fn list<B: Remote>(remote: &B) -> Result<(), Box<dyn Error>> {
    // TODO: add the following fields/option
    // 1. timestamp
    // 2. size (of stored backup?)
    // 3. Prefix name - I-{timestamp}-{name}
    for key in remote.list_keys(Typ::Index)? {
        let (typ, odt, tag) = from_key(&key)?;
        println!(
            "Typ: {}, odt: {}, tag: {:?}",
            typ,
            odt.format(&Rfc3339)?,
            tag
        );
    }
    Ok(())
}

fn append<B: Remote>(
    config: &cli::Config,
    password: &str,
    remote: &mut B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
) -> Result<(), Box<dyn Error>> {
    // Config bits
    let target = config
        .sources
        .first()
        .ok_or("config")?
        .include
        .first()
        .ok_or("config")?;
    let _xclude = config
        .sources
        .first()
        .ok_or("config")?
        .exclude
        .first()
        .ok_or("config")?;
    let _stype = config.sources.first().ok_or("config")?.typ;
    let key = config
        .disk_key
        .as_ref()
        .ok_or("config")?
        .to_mem_key(password)?;

    // Store indexer + Map
    let (mut index_content, mut map_content) = write_snapshot(remote, timestamp, tag)?;

    // Perform an appending snapshot
    snapshot::append(
        &key,
        remote,
        &mut index_content,
        &mut map_content,
        WalkBuilder::new(target)
            .follow_links(config.symlink)
            .standard_filters(false)
            .same_file_system(config.same_fs)
            .sort_by_file_name(Ord::cmp)
            .build(),
    )
}

fn fetch<B: Remote>(
    config: &cli::Config,
    password: &str,
    remote: &mut B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
    target: &Path,
) -> Result<(), Box<dyn Error>> {
    let (mut index_content, mut map_content) = read_snapshot(remote, timestamp, tag.clone())?;
    let (_, mut map_content_2) = read_snapshot(remote, timestamp, tag)?;
    let key = config
        .disk_key
        .as_ref()
        .ok_or("dadf")?
        .to_mem_key(password)?;

    snapshot::fetch(
        &key,
        remote,
        &mut index_content,
        &mut map_content,
        &mut map_content_2,
        target,
    )
}

// TODO: add a verify_all to validate the entire backup archive
fn verify<B: Remote>(
    config: &cli::Config,
    password: &str,
    remote: &mut B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let (mut index_content, mut map_content) = read_snapshot(remote, timestamp, tag)?;
    let key = config
        .disk_key
        .as_ref()
        .ok_or("Asdf")?
        .to_mem_key(password)?;

    snapshot::verify(&key, remote, &mut index_content, &mut map_content)
}

#[expect(clippy::type_complexity)]
fn read_snapshot<B: Remote>(
    remote: &mut B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
) -> Result<(Box<dyn Read>, Box<dyn Read>), Box<dyn Error>> {
    let index_content = remote.read_filename(Typ::Index, &to_key("I", timestamp, tag.clone()))?;
    let map_content = remote.read_filename(Typ::Map, &to_key("M", timestamp, tag))?;

    Ok((index_content, map_content))
}

#[expect(clippy::type_complexity)]
fn write_snapshot<B: Remote>(
    remote: &B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
) -> Result<(Box<dyn Write>, Box<dyn Write>), Box<dyn Error>> {
    let index_content =
        remote.write_multi_filename(Typ::Index, &to_key("I", timestamp, tag.clone()))?;

    let map_content = remote.write_multi_filename(Typ::Map, &to_key("M", timestamp, tag))?;

    Ok((index_content, map_content))
}

fn to_key(typ: &str, timestamp: OffsetDateTime, tag: Option<String>) -> String {
    match tag {
        Some(tag) => format!("{}-{}-{}", typ, timestamp.unix_timestamp(), tag),
        None => format!("{}-{}", typ, timestamp.unix_timestamp()),
    }
}

fn from_key(key: &str) -> Result<(&str, OffsetDateTime, Option<&str>), Box<dyn Error>> {
    let items: Vec<&str> = key.split('-').collect();

    match items[..] {
        [ty, ts, tag] => Ok((
            ty,
            OffsetDateTime::from_unix_timestamp(ts.parse::<i64>()?)?,
            Some(tag),
        )),
        [ty, ts] => Ok((
            ty,
            OffsetDateTime::from_unix_timestamp(ts.parse::<i64>()?)?,
            None,
        )),
        _ => panic!("Wrong length split!"),
    }
}
