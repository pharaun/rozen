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
mod ltvc;
mod chunk;
mod mapper;
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
    //let mut backend = backend::mem::MemoryVFS::new(Some("test.sqlite"));
    let mut backend = backend::mem::MemoryVFS::new(None);

    // Build a s3 backend here
    let mut _backend = backend::s3::S3::new_endpoint("http://localhost:8333").unwrap();

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

    // TODO: mapper load here + switch logic below to read from mapper, and then delete
    // pack_id from index

    // Dump the sqlite db data so we can view what it is
    println!("\nINDEX Dump + ARCHIVE Dump + PACK Dump");
    index.walk_files(|path, perm, packs, hash| {
        println!("HASH: {:?}", hash);

        // Iterate over the packfile to assemble the chunk data
        let mut chunk_pack = vec![];
        for pack in packs {
            println!("\tPACK: {:?}", pack);

            // Find or load the packfile
            if !pack_cache.contains_key(&pack) {
                println!("\t\tLoading: {:?}", pack);

                let mut pack_read = Backend::read(&mut backend, &pack).unwrap();
                let pack_file = pack::PackOut::load(&mut pack_read, &key);

                pack_cache.insert(
                    pack.clone(),
                    pack_file,
                );
            }

            for chunk in (pack_cache.get(&pack).unwrap()).list_chunks(hash.clone()).unwrap() {
                chunk_pack.push((chunk, pack.clone()));
            }
        }

        // Sort the chunk_pack
        chunk_pack.sort_by(|(ca, _), (cb, _)| ca.cmp(cb));

        // TODO: make this into a streaming read but for now copy data
        let mut data: Vec<u8> = vec![];

        // Assume no gaps in chunks
        for (chunk, pack) in chunk_pack {
            let mut dat = pack_cache.get(&pack).unwrap().find_chunk(hash.clone(), chunk).unwrap();
            data.append(&mut dat);
        }

        // Process the data
        let mut dec = crypto::decrypt(&key, &data[..]).unwrap();
        let mut und = Decoder::new(&mut dec).unwrap();
        let content_hash = hash::hash(&key, &mut und).unwrap();

        println!("\tPATH: {:?}", path);
        println!("\tPERM: {:?}", perm);

        let is_same = hash == content_hash;
        println!("\tSAME: {:5}", is_same);
    });
    index.close();
}
