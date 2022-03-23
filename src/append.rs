use std::io::{Seek, SeekFrom};
use zstd::stream::read::Encoder;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::index::Index;
use crate::crypto;
use crate::backend::Backend;
use crate::pack::PackBuilder;
use crate::pack;
use crate::hash;

pub fn snapshot<B: Backend>(
    key: &crypto::Key,
    backend: &mut B,
    datetime: OffsetDateTime,
    walker: ignore::Walk,
) {
    let index = Index::new();

    // Trivial write pack
    let pack_id = pack::generate_pack_id();

    // Write multipart upload
    let multiwrite = backend.write_multi(
        &pack_id,
    ).unwrap();

    let mut wpack = PackBuilder::new(pack_id, multiwrite);

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
                                let content_hash = hash::hash(
                                    &key,
                                    &mut file_data
                                ).unwrap();

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
                                wpack.append(
                                    content_hash.clone(),
                                    &mut enc
                                );

                                // Load file info into index
                                // Snapshot will be '<packfile-id>:<hash-id>' to pull out
                                //  the content or can just be a list of <hash-id> then another
                                //  list of <packfile-id> with <hash-id>s
                                index.insert_file(
                                    e.path(),
                                    Some(&wpack.id),
                                    &content_hash
                                );
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
        wpack.finalize(&key);

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
        backend.write_filename(&filename, &mut enc).unwrap();
    }
}

