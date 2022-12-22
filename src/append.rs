use std::io::{Seek, SeekFrom};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zstd::stream::read::Encoder;

use crate::remote::Remote;
use crate::cas::ObjectStore;
use crate::crypto;
use crate::hash;
use crate::sql::Index;

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
pub fn snapshot<B: Remote>(
    key: &crypto::Key,
    remote: &mut B,
    datetime: OffsetDateTime,
    walker: ignore::Walk,
) {
    let index = Index::new();
    let mut cas = ObjectStore::new(remote);

    {
        for entry in walker {
            match entry {
                Ok(e) => {
                    match e.file_type() {
                        None => println!("NONE: {}", e.path().display()),
                        Some(ft) => {
                            if ft.is_file() {
                                println!("COMP: {}", e.path().display());

                                let meta = e.metadata().unwrap();
                                println!("len: {:?}", meta.len());

                                let mut file_data = std::fs::File::open(e.path()).unwrap();

                                // Hasher
                                let content_hash = hash::hash(key, &mut file_data).unwrap();

                                // TODO: need to make sure that each stage always calls
                                // some form of finalize on its into_inner reader object
                                // so that it can flush it up the pipeline into the output.

                                // Streaming compressor
                                file_data.seek(SeekFrom::Start(0)).unwrap();

                                let comp = Encoder::new(&mut file_data, 21).unwrap();

                                // Encrypt the stream
                                let mut enc = crypto::encrypt(key, comp).unwrap();

                                // Stream the data into the CAS system
                                cas.append(&content_hash, key, &mut enc, meta.len());

                                // Load file info into index
                                // Snapshot will be '<packfile-id>:<hash-id>' to pull out
                                //  the content or can just be a list of <hash-id> then another
                                //  list of <packfile-id> with <hash-id>s
                                // TODO: better to just store content-id because it can be moved
                                // around in packfile after compaction
                                index.insert_file(e.path(), &content_hash);
                            } else {
                                println!("SKIP: {}", e.path().display());
                            }
                        }
                    }
                }
                Err(e) => println!("ERRR: {:?}", e),
            }
        }

        // Finalize the CAS
        cas.finalize(datetime, key);

        // Unload the sqlite file into remote as snapshot
        let dt_fmt = datetime.format(&Rfc3339).unwrap();
        let filename = format!("INDEX-{}.sqlite.zst", dt_fmt);
        println!("INDEX: {:?}", filename);

        let multiwrite = remote.write_multi_filename(&filename).unwrap();
        index.unload(key, multiwrite);
    }
}
