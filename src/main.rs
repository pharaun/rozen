use ignore::WalkBuilder;

use std::io::{Read, Write};
use std::path::Path;
use tempfile::TempDir;

use clap::Parser;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use log::info;

mod cli;
use crate::cli::Commands;

use rcore::crypto;
use rcore::key;

use remote;
use remote::Remote;
use remote::Typ;

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
fn main() {
    env_logger::init();
    crypto::init().unwrap();

    // Parse the cli
    let cli = cli::Cli::parse();

    // In memory remote for data storage
    #[cfg(all(feature = "sql", not(feature = "s3")))]
    let mut remote = remote::sql::SqlVFS::new(Some("test.sqlite"));

    // Build a s3 remote here - Overrides the sql feature
    #[cfg(feature = "s3")]
    let mut remote = remote::s3::S3::new_endpoint("test", "http://localhost:8333").unwrap();

    // TODO: should use a user given password, hardcode for ease of test right now
    let password = "ThisIsAPassword";

    match &cli.command {
        Some(Commands::Init { .. }) => {
            // Dump config to a TEST typ
            let mut config_content = remote.write_multi_filename(Typ::TEST, "CONFIG").unwrap();

            // For now just focus on figuring out some sort of key management/generation here
            init(&mut config_content, password);
        }
        Some(Commands::List) => {
            list(&mut remote);
        }
        Some(Commands::Append { tag }) => {
            let timestamp = OffsetDateTime::now_utc();

            let mut config_content = remote.read_filename(Typ::TEST, "CONFIG").unwrap();
            let mut config_str = String::new();
            config_content.read_to_string(&mut config_str).unwrap();
            let config: cli::Config = toml::from_str(&config_str).unwrap();

            append(&config, password, &mut remote, timestamp, tag.clone());
        }
        Some(Commands::Fetch {
            timestamp,
            tag,
            dir,
        }) => {
            let timestamp = OffsetDateTime::from_unix_timestamp(*timestamp).unwrap();
            let target = dir.as_path();

            let mut config_content = remote.read_filename(Typ::TEST, "CONFIG").unwrap();
            let mut config_str = String::new();
            config_content.read_to_string(&mut config_str).unwrap();
            let config: cli::Config = toml::from_str(&config_str).unwrap();

            fetch(
                &config,
                password,
                &mut remote,
                timestamp,
                tag.clone(),
                target,
            );
        }
        Some(Commands::Test) => {
            println!("TEST ONLY");
            let timestamp = OffsetDateTime::now_utc();
            let tag = Some("TEST".to_string());
            let target = TempDir::new().unwrap();

            let mut config_content = remote.write_multi_filename(Typ::TEST, "CONFIG").unwrap();
            init(&mut config_content, password);

            let mut config_content = remote.read_filename(Typ::TEST, "CONFIG").unwrap();
            let mut config_str = String::new();
            config_content.read_to_string(&mut config_str).unwrap();
            let config: cli::Config = toml::from_str(&config_str).unwrap();

            append(&config, password, &mut remote, timestamp, tag.clone());
            fetch(
                &config,
                password,
                &mut remote,
                timestamp,
                tag.clone(),
                target.path(),
            );
            list(&mut remote);

            // TODO: add support to picking an target/combo and verifying
            verify(&config, password, &mut remote, timestamp, tag);
        }
        None => (),
    }
}

fn init(config_content: &mut Box<dyn Write>, password: &str) {
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
    )
    .unwrap();
    info!("CONFIG: {:?}", sample_config);

    // Generate a new MemKey and convert it to DiskKey to store in the config
    let key = key::MemKey::new();
    let disk_key = key.to_disk_key(password);
    sample_config.disk_key = Some(disk_key);

    info!("CONFIG2: {:?}", sample_config);
    let toml = toml::to_string(&sample_config).unwrap();

    // Dump to output stream
    config_content.write_all(toml.as_bytes()).unwrap();
    config_content.flush().unwrap();
}

fn list<B: Remote>(remote: &mut B) {
    // TODO: add the following fields/option
    // 1. timestamp
    // 2. size (of stored backup?)
    // 3. Prefix name - I-{timestamp}-{name}
    for key in remote.list_keys(Typ::Index).unwrap() {
        let (typ, odt, tag) = from_key(&key);
        println!(
            "Typ: {}, odt: {}, tag: {:?}",
            typ,
            odt.format(&Rfc3339).unwrap(),
            tag
        );
    }
}

fn append<B: Remote>(
    config: &cli::Config,
    password: &str,
    remote: &mut B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
) {
    // Config bits
    let target = config.sources.get(0).unwrap().include.get(0).unwrap();
    let _xclude = config.sources.get(0).unwrap().exclude.get(0).unwrap();
    let _stype = config.sources.get(0).unwrap().source_type;
    let key = config.disk_key.as_ref().unwrap().to_mem_key(password);

    // Store indexer + Map
    let (mut index_content, mut map_content) = write_snapshot(remote, timestamp, tag);

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
            .sort_by_file_name(|a, b| a.cmp(b))
            .build(),
    );
}

fn fetch<B: Remote>(
    config: &cli::Config,
    password: &str,
    remote: &mut B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
    target: &Path,
) {
    let (mut index_content, mut map_content) = read_snapshot(remote, timestamp, tag.clone());
    let (_, mut map_content_2) = read_snapshot(remote, timestamp, tag);
    let key = config.disk_key.as_ref().unwrap().to_mem_key(password);

    snapshot::fetch(
        &key,
        remote,
        &mut index_content,
        &mut map_content,
        &mut map_content_2,
        target,
    );
}

// TODO: add a verify_all to validate the entire backup archive
fn verify<B: Remote>(
    config: &cli::Config,
    password: &str,
    remote: &mut B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
) {
    let (mut index_content, mut map_content) = read_snapshot(remote, timestamp, tag);
    let key = config.disk_key.as_ref().unwrap().to_mem_key(password);

    snapshot::verify(&key, remote, &mut index_content, &mut map_content);
}

fn read_snapshot<B: Remote>(
    remote: &mut B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
) -> (Box<dyn Read>, Box<dyn Read>) {
    let index_content = remote
        .read_filename(Typ::Index, &to_key("I", timestamp, tag.clone()))
        .unwrap();
    let map_content = remote
        .read_filename(Typ::Map, &to_key("M", timestamp, tag))
        .unwrap();

    (index_content, map_content)
}

fn write_snapshot<B: Remote>(
    remote: &mut B,
    timestamp: OffsetDateTime,
    tag: Option<String>,
) -> (Box<dyn Write>, Box<dyn Write>) {
    let index_content = remote
        .write_multi_filename(Typ::Index, &to_key("I", timestamp, tag.clone()))
        .unwrap();

    let map_content = remote
        .write_multi_filename(Typ::Map, &to_key("M", timestamp, tag))
        .unwrap();

    (index_content, map_content)
}

fn to_key(typ: &str, timestamp: OffsetDateTime, tag: Option<String>) -> String {
    match tag {
        Some(tag) => format!("{}-{}-{}", typ, timestamp.unix_timestamp(), tag),
        None => format!("{}-{}", typ, timestamp.unix_timestamp()),
    }
}

fn from_key(key: &str) -> (&str, OffsetDateTime, Option<&str>) {
    let items: Vec<&str> = key.split('-').collect();

    match items[..] {
        [ty, ts, tag] => (
            ty,
            OffsetDateTime::from_unix_timestamp(ts.parse::<i64>().unwrap()).unwrap(),
            Some(tag),
        ),
        [ty, ts] => (
            ty,
            OffsetDateTime::from_unix_timestamp(ts.parse::<i64>().unwrap()).unwrap(),
            None,
        ),
        _ => panic!("Wrong length split!"),
    }
}
