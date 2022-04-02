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

// TODO: can probs make the snapshot be strictly focused on snapshot concerns such as
// - deciding what files needs to be stored in a snapshot
// - deciding what file to skip/move/etc
// - once it has decided that a file or block of data needs to go into a packfile it can then
//      submit it to a queue that then get processed/packed up for shipping to the backend.
// - Open question: what about backups that does delta/diff and chunking and all of that, would
//      be instead submitting data/blocks. but could still see this section being only concerned
//      with what data should be backed up
//      then the queue can then manage "whole" or "chunked" or "chunked+delta" for processing
//      before it ships it into the packfile possibly
pub fn snapshot<B: Backend>(
    key: &crypto::Key,
    backend: &mut B,
    datetime: OffsetDateTime,
    walker: ignore::Walk,
) {
    let index = Index::new();
    let mut wpack = None;

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
                                let t_wpack = wpack.get_or_insert_with(|| {
                                    let pack_id = pack::generate_pack_id();
                                    let multiwrite = backend.write_multi(&pack_id).unwrap();
                                    PackBuilder::new(pack_id, multiwrite)
                                });
                                let tmp_pack_id = t_wpack.id.clone();

                                if t_wpack.append(
                                    content_hash.clone(),
                                    &mut enc
                                ) {
                                    wpack.take().unwrap().finalize(&key);
                                }

                                // Load file info into index
                                // Snapshot will be '<packfile-id>:<hash-id>' to pull out
                                //  the content or can just be a list of <hash-id> then another
                                //  list of <packfile-id> with <hash-id>s
                                // TODO: better to just store content-id because it can be moved
                                // around in packfile after compaction
                                index.insert_file(
                                    e.path(),
                                    Some(tmp_pack_id),
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

        // Force an finalize if its not already finalized
        if wpack.is_some() {
            wpack.take().unwrap().finalize(&key);
        }

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
