use std::io::{Seek, SeekFrom};
use zstd::stream::read::Encoder;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use std::collections::HashSet;

use crate::index::Index;
use crate::crypto;
use crate::backend::Backend;
use crate::pack::PackBuilder;
use crate::pack;
use crate::hash;
use crate::chunk;
use crate::mapper;
use crate::mapper::MapBuilder;

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
    let mut cas = ObjectStore::new(backend);

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

                                // Stream the data into the CAS system
                                let pack_id = cas.append(
                                    content_hash.clone(),
                                    &key,
                                    &mut enc
                                );

                                // Load file info into index
                                // Snapshot will be '<packfile-id>:<hash-id>' to pull out
                                //  the content or can just be a list of <hash-id> then another
                                //  list of <packfile-id> with <hash-id>s
                                // TODO: better to just store content-id because it can be moved
                                // around in packfile after compaction
                                index.insert_file(
                                    e.path(),
                                    pack_id,
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

        // Finalize the CAS
        cas.finalize(&key);

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


use std::io::Read;
use std::io::Write;

// This manages the under laying layer
// - chunking
// - packfiles
// - hash -> packfile+chunks
//
// This then presents a nice view to the user of this, which let them give a hash and a stream to
// write or a hash and a read to read from
//
// TODO:
// - I wonder if its better to separate the chunk from the packfile + backend system
// - Separting would enable alternative ways of chunking, right now its size based
// - Open question of what key/how to handle the key for the chunking
// - Changing requirement/idea may lead to merit of tagged data type/CBOR kind of headers
//
// Layering:
//  - Decide what needs backup and what doesn't
//  - Process data however way it needs to be
//      * Compress
//      * Encrypt
//      * Chunking?
//  - Present the data to be stored into backend
//      * Pack up small data into efficient packfiles
//      * Handle large streams (either chunk or just ingest as it is)
//          - Have 2 api, one is for most files, and second for large files (?)
//          - Small files get stuffed into packfiles as it is, large files gets its own packfile
//          - Could just handle it as it is in the api but 'ask for more info ahead of time' or
//          enforce certain minium size of buffer before it diverges to large blob files
//  - Backend
//      * Stream key -> value data stream to backend
//      * Fetch sub-parts of the data stream (ranged get)
//      * Fetch whole thing
//      * Manage s3/glacier/deep-freeze lifecycle (adjecent system, not in backend directly)
//
pub struct ObjectStore<'a, B: Backend + 'a> {
    w_backend: &'a B,

    w_pack: Option<PackBuilder<Box<dyn Write>>>,
    w_map: MapBuilder<Box<dyn Write>>,
}

impl<'a, B: Backend> ObjectStore<'a, B> {
    pub fn new(backend: &'a mut B) -> Self {
        let map = {
            let map_id = mapper::generate_map_id();
            let multiwrite = backend.write_multi(&map_id).unwrap();
            MapBuilder::new(map_id, multiwrite)
        };

        ObjectStore {
            w_backend: backend,
            w_pack: None,
            w_map: map,
        }
    }

    pub fn append<R: Read>(&mut self, hash: hash::Hash, key: &crypto::Key, reader: &mut R) -> HashSet<hash::Hash> {
        // Stream the data into the pack
        // TODO:
        //  1. compression complicates things for things below a certain
        //     size don't bother compressing?
        //  2. for things above a size try compressing
        //  3. See if i can't do fast bail out but would require
        //     spooling....
        //  4. If below certain size go ahead and pack it up
        //  5. if above certain size just send it as its own archive to
        //     backend
        let mut chunker = chunk::Chunk::new(reader);
        let mut pack_id: HashSet<hash::Hash> = HashSet::new();

        while let Some((mut chunk, part)) = chunker.next() {
            let t_pack = self.w_pack.get_or_insert_with(|| {
                let pack_id = pack::generate_pack_id();
                let multiwrite = self.w_backend.write_multi(&pack_id).unwrap();
                PackBuilder::new(pack_id, multiwrite)
            });
            pack_id.insert(t_pack.id.clone());

            if t_pack.append(
                hash.clone(),
                part,
                &mut chunk
            ) {
                self.w_pack.take().unwrap().finalize(&mut self.w_map, &key);
            }
        }

        pack_id
    }

    pub fn finalize(mut self, key: &crypto::Key) {
        // Force an finalize if its not already finalized
        if self.w_pack.is_some() {
            self.w_pack.take().unwrap().finalize(&mut self.w_map, &key);
        }

        self.w_map.finalize(&key);
    }

    // TODO:
    // 1. Implement a way to fetch by content_hash
    // 2. returns packfiles involved + chunks involved
    // 3. fetch needed packfiles + chunks and reassembly then stream it out
}
