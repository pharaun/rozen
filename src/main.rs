use rusqlite as rs;

use ignore::WalkBuilder;

use std::io::{Seek, SeekFrom, copy, Read};
use blake3::Hasher;
use blake3::Hash;
use rusqlite::Connection;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;
use serde::Deserialize;

mod backend;
use crate::backend::mem::Backend;

mod crypto;
mod engine;


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


struct Index {
    file: std::fs::File,
    // Don't use this but we need to keep it around till we are done with the db
    path: tempfile::TempPath,
    conn: Connection,
}

impl Index {
    fn new() -> Self {
        let (file, path) = tempfile::NamedTempFile::new().unwrap().into_parts();
        let conn = Connection::open(&path).unwrap();
        // TODO: can't remove file path (sqlite seems to depend on it)
        //s_path.close().unwrap();

        // Setup the db
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE files (
                path VARCHAR NOT NULL,
                permission INTEGER NOT NULL,
                content_hash VARCHAR NOT NULL
             );
             COMMIT;"
        ).unwrap();

        Index {
            file,
            path,
            conn
        }
    }

    // TODO: improve the types
    fn insert_file(&self, path: &std::path::Path, hash: &str) {
        let mut file_stmt = self.conn.prepare_cached(
            "INSERT INTO files
             (path, permission, content_hash)
             VALUES
             (?, ?, ?)"
        ).unwrap();

        // Load file into index
        file_stmt.execute(rs::params![
            format!("{}", path.display()),
            0000,
            hash,
        ]).unwrap();
    }

    fn close(mut self) {
        self.conn.close().unwrap();
    }

    fn unload(mut self) -> std::fs::File {
        // Spool the sqlite file into the backend as index
        self.conn.close().unwrap();
        // TODO: not sure we need the seek here since we never touched this handle
        self.file.seek(SeekFrom::Start(0)).unwrap();

        self.file
    }

    fn load<R: Read>(reader: &mut R) -> Self {
        let (mut file, path) = tempfile::NamedTempFile::new().unwrap().into_parts();

        // Copy from filehandler to tempfile
        copy(reader, &mut file).unwrap();

        let conn = Connection::open(&path).unwrap();
        // TODO: can't remove file path (sqlite seems to depend on it)
        //s_path.close().unwrap();

        Index {
            file,
            path,
            conn
        }
    }
}


fn main() {
    crypto::init();

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

    let index = Index::new();
    {
        // Sort filename for determistic order
        for entry in WalkBuilder::new(target)
            .follow_links(config.symlink)
            .standard_filters(false)
            .same_file_system(config.same_fs)
            .sort_by_file_name(|a, b| a.cmp(b))
            .build() {

            match entry {
                Ok(e) => {
                    match e.file_type() {
                        None => println!("NONE: {}", e.path().display()),
                        Some(ft) => {
                            if ft.is_file() {
                                println!("COMP: {}", e.path().display());

                                let mut file_data = std::fs::File::open(e.path()).unwrap();

                                // Hasher
                                let content_hash = hash(
                                    &key,
                                    &mut file_data
                                ).unwrap().to_hex().to_string();

                                // Streaming compressor
                                file_data.seek(SeekFrom::Start(0)).unwrap();

                                let comp = Encoder::new(
                                    &mut file_data,
                                    21
                                ).unwrap();

                                // Encrypt the stream
                                let mut enc = crypto::encrypt(&key, comp).unwrap();

                                // Stream the data into the backend
                                let mut write_to = backend.write(content_hash.as_str()).unwrap();
                                copy(&mut enc, &mut write_to).unwrap();

                                // Load file info into index
                                index.insert_file(e.path(), content_hash.as_str());
                            } else {
                                println!("SKIP: {}", e.path().display());
                            }
                        },
                    }
                },
                Err(e) => println!("ERRR: {:?}", e),
            }
        }

        // Spool the sqlite file into the backend as index
        let mut s_file = index.unload();

        let comp = Encoder::new(
            &mut s_file,
            21
        ).unwrap();

        // Encrypt the stream
        let mut enc = crypto::encrypt(&key, comp).unwrap();

        // Stream the data into the backend
        let mut write_to = backend.write("INDEX.sqlite.zst").unwrap();
        copy(&mut enc, &mut write_to).unwrap();
    }

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
    {
        let mut dump_stmt = index.conn.prepare(
            "SELECT path, permission, content_hash FROM files"
        ).unwrap();
        let mut rows = dump_stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let path: String = row.get(0).unwrap();
            let perm: u32 = row.get(1).unwrap();
            let hash: String = row.get(2).unwrap();

            println!("HASH: {:?}, PERM: {:?}, PATH: {:?}", hash, perm, path);
        }
    }
    index.close();
}


fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}
