use ignore::WalkBuilder;

use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

mod remote;
use crate::remote::Remote;

mod buf;
mod cas;
mod crypto;
mod hash;
mod ltvc;
mod pack;
mod snapshot;
mod sql;

// Configuration
// At a later time honor: https://aws.amazon.com/blogs/security/a-new-and-standardized-way-to-manage-credentials-in-the-aws-sdks/
// envy = "0.4.2" - for grabbing the env vars via serde
#[derive(Deserialize, Debug)]
struct Config {
    symlink: bool,
    same_fs: bool,

    sources: Vec<Source>,
}

#[derive(Deserialize, Debug)]
struct Source {
    include: Vec<String>,
    exclude: Vec<String>,

    #[serde(rename = "type")]
    source_type: SourceType,
}

#[derive(Deserialize, Debug, Clone, Copy)]
enum SourceType {
    AppendOnly,
}

fn main() {
    crypto::init().unwrap();

    // Per run key
    // TODO: bad news, should have separate key, one for encryption, and one for hmac
    let key = crypto::gen_key();

    let config: Config = toml::from_str(
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

    println!("CONFIG:");
    println!("{:?}", config);

    let target = config.sources.get(0).unwrap().include.get(0).unwrap();
    let _xclude = config.sources.get(0).unwrap().exclude.get(0).unwrap();
    let _stype = config.sources.get(0).unwrap().source_type;

    // In memory remote for data storage
    //let mut remote = remote::mem::MemoryVFS::new(Some("test.sqlite"));
    let mut remote = remote::mem::MemoryVFS::new(None);

    // Build a s3 remote here
    let mut _remote = remote::s3::S3::new_endpoint("http://localhost:8333").unwrap();

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
    let datetime = OffsetDateTime::now_utc();
    let dt_fmt = datetime.format(&Rfc3339).unwrap();

    // Store indexer + Map
    let index_filename = format!("INDEX-{}.sqlite.zst", dt_fmt);
    println!("Write INDEX: {:?}", index_filename);
    let mut index_content = remote.write_multi_filename(&index_filename).unwrap();

    let map_filename = format!("MAP-{}.sqlite.zst", dt_fmt);
    println!("Write MAP: {:?}", map_filename);
    let mut map_content = remote.write_multi_filename(&map_filename).unwrap();

    // Perform an appending snapshot
    snapshot::append(
        &key,
        &mut remote,
        &mut index_content,
        &mut map_content,
        WalkBuilder::new(target)
            .follow_links(config.symlink)
            .standard_filters(false)
            .same_file_system(config.same_fs)
            .sort_by_file_name(|a, b| a.cmp(b))
            .build(),
    );

    // Indexer
    let mut index_content = remote.read_filename(&index_filename).unwrap();
    let mut map_content = remote.read_filename(&map_filename).unwrap();

    snapshot::fetch(&key, &mut remote, &mut index_content, &mut map_content);
}
