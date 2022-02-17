use std::io::{Seek, SeekFrom, copy, Read};
use blake3::Hasher;
use blake3::Hash;
use zstd::stream::read::Encoder;
use chrono::Utc;
use chrono::DateTime;
use chrono::SecondsFormat;

use crate::index::Index;
use crate::crypto;
use crate::backend::mem::Backend;


pub fn snapshot<B: Backend>(
    key: &crypto::Key,
    backend: &mut B,
    datetime: DateTime<Utc>,
    walker: ignore::Walk,
) {
    let index = Index::new();

    {
        for entry in walker {
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
        let filename = format!("INDEX-{}.sqlite.zst", datetime.to_rfc3339_opts(SecondsFormat::Secs, true));
        println!("INDEX: {:?}", filename);
        let mut write_to = backend.write(&filename).unwrap();
        copy(&mut enc, &mut write_to).unwrap();
    }
}

// copy paste from main.rs for now
fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}
