use ignore::WalkBuilder;

use clap::Parser;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use rozen::cli;
use rozen::cli::Commands;
use rozen::crypto;
use rozen::key;
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
fn main() {
    crypto::init().unwrap();

    // Per run key
    // TODO: bad news, should have separate key, one for encryption, and one for hmac
    let key = key::gen_key();

    // Parse the cli
    let cli = cli::Cli::parse();

    let config: cli::Config = if cli.config.is_none() {
        toml::from_str(
            r#"
            symlink = true
            same_fs = true

            [[sources]]
                include = ["docs"]
                exclude = ["*.pyc"]
                type = "AppendOnly"

        "#,
        )
        .unwrap()
    } else {
        panic!("Config file was set, not supported yet");
    };
    println!("CONFIG:");
    println!("\t{:?}", config);

    // In memory remote for data storage
    let mut remote = remote::mem::MemoryVFS::new(Some("test.sqlite"));
    let mut _remote = remote::mem::MemoryVFS::new(None);

    // Build a s3 remote here
    let mut _remote = remote::s3::S3::new_endpoint("test", "http://localhost:8333").unwrap();

    match &cli.command {
        Some(Commands::List) => {
            list(&mut remote);
        }
        Some(Commands::Append { name }) => {
            append(&key, &config, &mut remote, name.clone());
        }
        Some(Commands::Fetch { name }) => {
            fetch(&key, &mut remote, name.to_string());
        }
        Some(Commands::Test) => {
            println!("TEST ONLY");
            let name = "TEST".to_string();

            append(&key, &config, &mut remote, Some(name.clone()));
            fetch(&key, &mut remote, name);
            list(&mut remote);
        }
        None => (),
    }
}

fn list<B: Remote>(remote: &mut B) {
    for key in remote.list_keys(Typ::Index).unwrap() {
        println!("Key: {:?}", key);
    }
}

fn append<B: Remote>(key: &key::Key, config: &cli::Config, remote: &mut B, name: Option<String>) {
    let filename = match name {
        Some(x) => x,
        None => {
            let datetime = OffsetDateTime::now_utc();
            datetime.format(&Rfc3339).unwrap()
        }
    };

    // Config bits
    let target = config.sources.get(0).unwrap().include.get(0).unwrap();
    let _xclude = config.sources.get(0).unwrap().exclude.get(0).unwrap();
    let _stype = config.sources.get(0).unwrap().source_type;

    // Store indexer + Map
    let index_filename = format!("INDEX-{}.sqlite.zst", filename);
    let mut index_content = remote
        .write_multi_filename(Typ::Index, &index_filename)
        .unwrap();

    let map_filename = format!("MAP-{}.sqlite.zst", filename);
    let mut map_content = remote
        .write_multi_filename(Typ::Map, &map_filename)
        .unwrap();

    // Perform an appending snapshot
    snapshot::append(
        key,
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

fn fetch<B: Remote>(key: &key::Key, remote: &mut B, name: String) {
    let index_filename = format!("INDEX-{}.sqlite.zst", name);
    let mut index_content = remote.read_filename(Typ::Index, &index_filename).unwrap();

    let map_filename = format!("MAP-{}.sqlite.zst", name);
    let mut map_content = remote.read_filename(Typ::Map, &map_filename).unwrap();

    snapshot::fetch(key, remote, &mut index_content, &mut map_content);
}
