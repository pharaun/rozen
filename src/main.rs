use rusqlite as rs;

use ignore::WalkBuilder;

use std::io::{Seek, SeekFrom, copy, Cursor, Read};
use blake3::Hasher;
use rusqlite::Connection;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;
use serde::Deserialize;

mod backend_mem;
use crate::backend_mem::Backend;

use sodiumoxide::crypto::secretstream::gen_key;
use sodiumoxide::crypto::secretbox;


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
    Worm,
}

fn main() {
    sodiumoxide::init().unwrap();

    // Per run key
    let key = gen_key();

    let config: Config = toml::from_str(r#"
        symlink = true
        same_fs = true

        [[sources]]
            include = ["docs"]
            exclude = ["*.pyc"]
            type = "Worm"

    "#).unwrap();

    println!("CONFIG:");
    println!("{:?}", config);

    let target = config.sources.get(0).unwrap().include.get(0).unwrap();

    // In memory backend for data storage
    let mut backend = backend_mem::MemoryVFS::new();

    {
        // Temp file for rusqlite
        let (mut s_file, s_path) = tempfile::NamedTempFile::new().unwrap().into_parts();
        let conn = Connection::open(&s_path).unwrap();
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

        {
            let mut file_stmt = conn.prepare(
                "INSERT INTO files
                 (path, permission, content_hash)
                 VALUES
                 (?, ?, ?)"
            ).unwrap();

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
                                    let mut hash = Hasher::new_keyed(&key.0);
                                    copy(&mut file_data, &mut hash).unwrap();
                                    let content_hash = hash.finalize().to_hex();

                                    // Streaming compressor
                                    file_data.seek(SeekFrom::Start(0)).unwrap();

                                    let mut comp = Encoder::new(
                                        &mut file_data,
                                        21
                                    ).unwrap();

                                    let mut vec_comp = Vec::new();
                                    copy(&mut comp, &mut vec_comp).unwrap();
                                    comp.finish();

                                    // Encrypt the stream
                                    let fkey = secretbox::gen_key();
                                    let fnonce = secretbox::gen_nonce();

                                    let ciphertext = secretbox::seal(
                                        &vec_comp[..],
                                        &fnonce,
                                        &fkey
                                    );

                                    // Stream the data into the backend
                                    let mut write_to = backend.write(content_hash.as_str()).unwrap();

                                    // Write the key and nonce to the stream
                                    write_to.write_all(&fkey.0).unwrap();
                                    write_to.write_all(&fnonce.0).unwrap();

                                    let mut cursor = Cursor::new(ciphertext);
                                    copy(&mut cursor, &mut write_to).unwrap();

                                    // Load file info into index
                                    file_stmt.execute(rs::params![
                                        format!("{}", e.path().display()),
                                        0000,
                                        content_hash.as_str(),
                                    ]).unwrap();

                                } else {
                                    println!("SKIP: {}", e.path().display());
                                }
                            },
                        }
                    },
                    Err(e) => println!("ERRR: {:?}", e),
                }
            }
        }

        // Spool the sqlite file into the backend as index
        conn.close().unwrap();

        // TODO: not sure we need the seek here since we never touched this handle
        s_file.seek(SeekFrom::Start(0)).unwrap();

        {
            let mut comp = Encoder::new(
                &mut s_file,
                21
            ).unwrap();

            let mut vec_comp = Vec::new();
            copy(&mut comp, &mut vec_comp).unwrap();
            comp.finish();

            // Encrypt the stream
            let fkey = secretbox::gen_key();
            let fnonce = secretbox::gen_nonce();

            let ciphertext = secretbox::seal(
                &vec_comp[..],
                &fnonce,
                &fkey
            );

            // Write to the backend
            let mut write_to = backend.write("INDEX.sqlite.zst").unwrap();

            // Write the key and nonce to the stream
            write_to.write_all(&fkey.0).unwrap();
            write_to.write_all(&fnonce.0).unwrap();

            let mut cursor = Cursor::new(ciphertext);
            copy(&mut cursor, &mut write_to).unwrap();
        }
    }

    println!("\nARCHIVE Dump");
    for k in backend.list_keys().unwrap() {
        // Get key, pull file, re-hash it and verify
        let mut content: Vec<u8> = Vec::new();
        let mut read_from = backend.read(&k).unwrap();
        copy(&mut read_from, &mut content).unwrap();

        let len = content.len();

        // Decrypt the stream
        // read the key then nonce then stream
        let mut dkey: [u8; 32] = [0; 32];
        let mut dnonce: [u8; 24] = [0; 24];
        let mut dciphertext = Vec::new();

        let mut cursor = Cursor::new(content);
        cursor.read_exact(&mut dkey).unwrap();
        cursor.read_exact(&mut dnonce).unwrap();
        cursor.read_to_end(&mut dciphertext).unwrap();

        let fkey = secretbox::Key::from_slice(&dkey).unwrap();
        let fnonce = secretbox::Nonce::from_slice(&dnonce).unwrap();

        let plaintext = secretbox::open(
            &dciphertext[..],
            &fnonce,
            &fkey
        ).unwrap();

        // Validate the hash now.
        let mut hash = Hasher::new_keyed(&key.0);
        let mut cursor = Cursor::new(plaintext);
        let mut dec = Decoder::new(&mut cursor).unwrap();
        copy(&mut dec, &mut hash).unwrap();
        let content_hash = hash.finalize().to_hex();

        let is_same = content_hash.as_str() == k;

        println!("SAME: {:5} SIZE: {:5}, NAME: {}", is_same, len, k);
    }

    // Grab db out of backend and put it to a temp handle
    let mut index_content = backend.read("INDEX.sqlite.zst").unwrap();

    // Decrypt the stream
    // read the key then nonce then stream
    let mut dkey: [u8; 32] = [0; 32];
    let mut dnonce: [u8; 24] = [0; 24];
    let mut dciphertext = Vec::new();

    index_content.read_exact(&mut dkey).unwrap();
    index_content.read_exact(&mut dnonce).unwrap();
    index_content.read_to_end(&mut dciphertext).unwrap();

    let fkey = secretbox::Key::from_slice(&dkey).unwrap();
    let fnonce = secretbox::Nonce::from_slice(&dnonce).unwrap();

    let plaintext = secretbox::open(
        &dciphertext[..],
        &fnonce,
        &fkey
    ).unwrap();

    // Setup decompression stream
    let mut cursor = Cursor::new(plaintext);
    let mut dec = Decoder::new(&mut cursor).unwrap();

    let (mut d_file, d_path) = tempfile::NamedTempFile::new().unwrap().into_parts();
    copy(&mut dec, &mut d_file).unwrap();
    let conn = Connection::open(&d_path).unwrap();

    // Dump the sqlite db data so we can view what it is
    println!("\nINDEX Dump");
    {
        let mut dump_stmt = conn.prepare(
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
    conn.close().unwrap();
}
