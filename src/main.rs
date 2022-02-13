use ignore::WalkBuilder;

use std::io::{Seek, SeekFrom, copy, Read};
use blake3::Hasher;
use blake3::Hash;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;
use serde::Deserialize;

mod backend;
use crate::backend::mem::Backend;

mod crypto;
mod engine;
mod index;
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

    // In memory backend for data storage
    let mut backend = backend::mem::MemoryVFS::new();

    engine::append_only::archive(
        &key,
        &mut backend,
        WalkBuilder::new(target)
            .follow_links(config.symlink)
            .standard_filters(false)
            .same_file_system(config.same_fs)
            .sort_by_file_name(|a, b| a.cmp(b))
            .build(),
    );

    let index = Index::new();
    println!("\nARCHIVE Dump");
    for k in backend.list_keys().unwrap() {
        let mut read_from = backend.read(&k).unwrap();
        let mut dec = crypto::decrypt(&key, &mut read_from).unwrap();
        let mut und = Decoder::new(&mut dec).unwrap();
        let content_hash = hash(&key, &mut und).unwrap();

        match Hash::from_hex(k.clone()) {
            Ok(data_hash) => {
                let is_same = data_hash == content_hash;

                println!("SAME: {:5} SIZE: {:5}, NAME: {}", is_same, "-----", k);
            },
            Err(_) => {
                println!("SAME: {:5} SIZE: {:5}, NAME: {}", "----", "-----", k);
            },
        }
    }

    // Grab db out of backend and put it to a temp handle
    let mut index_content = backend.read("INDEX.sqlite.zst").unwrap();
    let mut dec = crypto::decrypt(&key, &mut index_content).unwrap();
    let mut und = Decoder::new(&mut dec).unwrap();

    let index = Index::load(&mut und);

    // Dump the sqlite db data so we can view what it is
    println!("\nINDEX Dump");
    index.walk_files(|path, perm, hash| {
        println!("HASH: {:?}, PERM: {:?}, PATH: {:?}", hash, perm, path);
    });

    index.close();
}


// copy pasted into appendonly for now
fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}
