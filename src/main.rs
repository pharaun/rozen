use ignore::WalkBuilder;

use std::io::{copy, Read};
use blake3::Hasher;
use blake3::Hash;
use zstd::stream::read::Decoder;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

mod backend;
use crate::backend::Backend;

mod crypto;
mod engine;
mod index;
mod pack;
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

#[derive(Deserialize, Debug)]
enum SourceType {
    AppendOnly,
}

fn main() {
    crypto::init().unwrap();

    // Per run key
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

    let target = config.sources.get(0).unwrap().include.get(0).unwrap();

    // Build a s3 backend here
    //let mut backend = backend::s3::S3::new_endpoint("http://localhost:8333").unwrap();

    // In memory backend for data storage
    let mut backend = backend::mem::MemoryVFS::new();

    // TODO: should name various things like Index getting its own hashkey
    //  * I<hash> = index
    //  * B<hash> = raw blob (big files)
    //  * P<rng>  = packfile (only one that isn't hash)
    let datetime = OffsetDateTime::now_utc();
    engine::append_only::snapshot(
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
    let mut index_content = Backend::read(&mut backend, &filename).unwrap();
    let mut dec = crypto::decrypt(&key, &mut index_content).unwrap();
    let mut und = Decoder::new(&mut dec).unwrap();
    let index = Index::load(&mut und);

    // Load a packfile "packfile-1" then consult it to pull out the
    // relevant files needed
    let mut pack_read = Backend::read(&mut backend, "packfile-1").unwrap();
    let pack = pack::Pack::read(&mut pack_read);

    // Dump the sqlite db data so we can view what it is
    println!("\nINDEX Dump + ARCHIVE Dump");
    index.walk_files(|path, perm, hash| {
        println!("HASH: {:?}", hash);
        println!("\tPERM: {:?}", perm);
        println!("\tPATH: {:?}", path);

        // Read from the packfile
        let data = pack.find(&hash).unwrap();
        let mut dec = crypto::decrypt(&key, &data[..]).unwrap();
        let mut und = Decoder::new(&mut dec).unwrap();
        let content_hash = test_hash(&key, &mut und).unwrap();

        match Hash::from_hex(hash.clone()) {
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


// copy pasted into appendonly for now
fn test_hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}
