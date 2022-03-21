use ignore::WalkBuilder;

use zstd::stream::read::Decoder;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use std::collections::HashMap;

mod backend;
use crate::backend::Backend;

mod crypto;
mod append;
mod index;
mod pack;
mod buf;
mod hash;
use crate::index::Index;

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

    let config: Config = toml::from_str(r#"
        symlink = true
        same_fs = true

        [[sources]]
            include = ["docs"]
            exclude = ["*.pyc"]
            type = "AppendOnly"

    "#).unwrap();

    println!("CONFIG:");
    println!("{:?}", config);

    let target  = config.sources.get(0).unwrap().include.get(0).unwrap();
    let _xclude = config.sources.get(0).unwrap().exclude.get(0).unwrap();
    let _stype  = config.sources.get(0).unwrap().source_type;


    // In memory backend for data storage
    let mut backend = backend::mem::MemoryVFS::new();

    // Build a s3 backend here
    let mut _backend = backend::s3::S3::new_endpoint("http://localhost:8333").unwrap();

    // TODO: should name various things like Index getting its own hashkey
    //  * I-<timestamp> = index
    //  * P-<rng>  = packfile (only one that isn't hash)
    //  * B-<hash> = raw blob (big files)
    let datetime = OffsetDateTime::now_utc();
    append::snapshot(
        &key,
        &mut backend,
        datetime,
        WalkBuilder::new(target)
            .follow_links(config.symlink)
            .standard_filters(false)
            .same_file_system(config.same_fs)
            .sort_by_file_name(|a, b| a.cmp(b))
            .build(),
    );

    // Grab db out of backend and put it to a temp handle
    let dt_fmt = datetime.format(&Rfc3339).unwrap();
    let filename = format!("INDEX-{}.sqlite.zst", dt_fmt);
    let mut index_content = Backend::read_filename(&mut backend, &filename).unwrap();
    let mut dec = crypto::decrypt(&key, &mut index_content).unwrap();
    let mut und = Decoder::new(&mut dec).unwrap();
    let index = Index::load(&mut und);

    // Cached packfile refs
    let mut pack_cache = HashMap::new();

    // Dump the sqlite db data so we can view what it is
    println!("\nINDEX Dump + ARCHIVE Dump + PACK Dump");
    index.walk_files(|path, perm, pack, hash| {
        let pack = pack.unwrap();
        println!("HASH: {:?}", hash);
        println!("\tPACK: {:?}", pack);
        println!("\tPERM: {:?}", perm);
        println!("\tPATH: {:?}", path);

        // Find or load the packfile
        if !pack_cache.contains_key(&pack) {
            println!("Loading: {:?}", pack);

            let mut pack_read = Backend::read(&mut backend, &hash::from_hex(&pack).unwrap()).unwrap();
            let pack_file = pack::PackOut::load(&mut pack_read, &key);

            pack_cache.insert(
                pack.clone(),
                pack_file,
            );
        }

        // Read from the packfile
        let data = pack_cache.get(&pack).unwrap().find(hash::from_hex(hash).unwrap()).unwrap();

        // Process the data
        let mut dec = crypto::decrypt(&key, &data[..]).unwrap();
        let mut und = Decoder::new(&mut dec).unwrap();
        let content_hash = hash::hash(&key, &mut und).unwrap();

        match hash::from_hex(hash.clone()) {
            Ok(data_hash) => {
                let is_same = data_hash == content_hash;

                println!("\tSAME: {:5}", is_same);
                println!("\tSIZE: {:5}", "-----");
            },
            Err(_) => {
                println!("\tSAME: {:5}", "-----");
                println!("\tSIZE: {:5}", "-----");
            },
        }
    });
    index.close();
}
