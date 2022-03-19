use std::io::{Seek, SeekFrom, copy, Read};
use blake3::Hasher;
use blake3::Hash;
use zstd::stream::read::Encoder;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::index::Index;
use crate::crypto;
use crate::backend::Backend;
use crate::pack::PackIn;

pub fn snapshot<B: Backend>(
    key: &crypto::Key,
    backend: &mut B,
    datetime: OffsetDateTime,
    walker: ignore::Walk,
) {
    let index = Index::new();

    // Trivial case to start with
    let mut pack = PackIn::new();

    // Begin a multipart upload here
    let mut multipart = backend.multi_write(
        &pack.id,
    ).unwrap();

    {
        for entry in walker {
            match entry {
                Ok(e) => {
                    let meta = e.metadata().unwrap();
                    println!("len: {:?}", meta.len());

                    match e.file_type() {
                        None => println!("NONE: {}", e.path().display()),
                        Some(ft) => {
                            if ft.is_file() {
                                println!("COMP: {}", e.path().display());

                                let mut file_data = std::fs::File::open(e.path()).unwrap();

                                // Hasher
                                // TODO: stop passing around hash strings, pass around hash
                                // result, then switch to string/bytes when needed at the
                                // destination
                                let content_hash = hash(
                                    &key,
                                    &mut file_data
                                ).unwrap().to_hex().to_string();

                                // TODO: need to make sure that each stage always calls
                                // some form of finalize on its into_inner reader object
                                // so that it can flush it up the pipeline into the output.

                                // Streaming compressor
                                file_data.seek(SeekFrom::Start(0)).unwrap();

                                let comp = Encoder::new(
                                    &mut file_data,
                                    21
                                ).unwrap();

                                // Encrypt the stream
                                let mut enc = crypto::encrypt(&key, comp).unwrap();

                                // Stream the data into the pack
                                let mut chunk = pack.begin_write(content_hash.as_str(), &mut enc);

                                // Spool the pack content to this point into multiwrite
                                // TODO: fraught, the transition into chunk mode should carry the
                                // buffer over from pack, and drain that first
                                multipart.write(&mut pack).unwrap();
                                multipart.write(&mut chunk).unwrap();

                                // Finalize the chunk write
                                pack.finish_write(chunk);
                                multipart.write(&mut pack).unwrap();

                                // Load file info into index
                                // Snapshot will be '<packfile-id>:<hash-id>' to pull out
                                //  the content or can just be a list of <hash-id> then another
                                //  list of <packfile-id> with <hash-id>s
                                index.insert_file(e.path(), Some(&pack.id), content_hash.as_str());
                            } else {
                                println!("SKIP: {}", e.path().display());
                            }
                        },
                    }
                },
                Err(e) => println!("ERRR: {:?}", e),
            }
        }

        // Finalize packfile and spool it into the backend
        pack.finalize(&key);

        multipart.write(
            &mut pack,
        ).unwrap();

        // Complete the multipart upload
        multipart.finalize().unwrap();


        // Spool the sqlite file into the backend as index
        // TODO: update this to support the archive file format defined in pack.rs
        let mut s_file = index.unload();

        let comp = Encoder::new(
            &mut s_file,
            21
        ).unwrap();

        // Encrypt the stream
        let mut enc = crypto::encrypt(&key, comp).unwrap();

        // Stream the data into the backend
        let dt_fmt = datetime.format(&Rfc3339).unwrap();
        let filename = format!("INDEX-{}.sqlite.zst", dt_fmt);
        println!("INDEX: {:?}", filename);
        backend.write(&filename, &mut enc).unwrap();
    }
}

// copy paste from main.rs for now
fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}
