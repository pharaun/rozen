use std::io::{copy, Read, Seek, SeekFrom, Write};
use std::path::Path;
use zstd::stream::read::Decoder;
use zstd::stream::read::Encoder;

use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs::create_dir_all;
use std::fs::File;

use rcore::crypto;
use rcore::hash;
use rcore::key;

use rarc::pack::PackOut;

use remote::Remote;
use remote::Typ;

use crate::cas::ObjectFetch;
use crate::cas::ObjectStore;

use crate::sql::walk_files;
use crate::sql::Index;
use crate::sql::Map;

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
pub fn append<B: Remote, W: Write>(
    key: &key::MemKey,
    remote: &mut B,
    index_content: W,
    map_content: W,
    walker: ignore::Walk,
) {
    let index = Index::new();
    let mut cas = ObjectStore::new(remote);

    {
        for entry in walker {
            match entry {
                Ok(e) => {
                    match e.file_type() {
                        None => info!("NONE: {}", e.path().display()),
                        Some(ft) => {
                            if ft.is_file() {
                                info!("COMP: {}", e.path().display());

                                let meta = e.metadata().unwrap();
                                debug!("len: {:?}", meta.len());

                                let mut file_data = std::fs::File::open(e.path()).unwrap();

                                // Hasher
                                let content_hash = hash::hash(key, &mut file_data).unwrap();
                                file_data.seek(SeekFrom::Start(0)).unwrap();

                                // TODO: need to make sure that each stage always calls
                                // some form of finalize on its into_inner reader object
                                // so that it can flush it up the pipeline into the output.

                                let comp = Encoder::new(&mut file_data, 21).unwrap();
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
                                info!("SKIP: {}", e.path().display());
                            }
                        }
                    }
                }
                Err(e) => warn!("ERRR: {:?}", e),
            }
        }

        // Finalize the CAS
        cas.finalize(map_content, key);
        index.unload(key, index_content);
    }
}

// TODO: hack of map_content_2 to deal with walk_files
// TODO: add concurrent hash verification along with writing it to disk
pub fn fetch<B: Remote, R: Read>(
    key: &key::MemKey,
    remote: &mut B,
    index_content: &mut R,
    map_content: &mut R,
    map_content_2: &mut R,
    target: &Path,
) {
    let map = Map::load(map_content, key);
    let mut cas = ObjectFetch::new(remote, map);
    walk_files(index_content, map_content_2, key, |path, _, _, hash| {
        let data = cas.get_content(key, &hash).unwrap();

        // Verify the data
        let mut dec = crypto::decrypt(key, data).unwrap();
        let mut und = Decoder::new(&mut dec).unwrap();

        // TODO: make this concurrent, for now, write to disk, then read and hash from disk.
        let target_path = target.join(path);
        create_dir_all(target_path.parent().unwrap()).unwrap();
        let mut target_file = File::create(&target_path).unwrap();
        copy(&mut und, &mut target_file).unwrap();
        target_file.sync_data().unwrap();

        let mut hash_file = File::open(&target_path).unwrap();
        let content_hash = hash::hash(key, &mut hash_file).unwrap();

        let is_same = hash == content_hash;
        info!("\tSAME: {:5} - PATH: {:?}", is_same, target_path);
    });
}

pub fn verify<B: Remote, R: Read>(
    key: &key::MemKey,
    remote: &mut B,
    index_content: &mut R,
    map_content: &mut R,
) {
    // Cached packfile refs
    let mut pack_cache = HashMap::new();

    // Dump the sqlite db data so we can view what it is
    println!("VERIFYING:");
    walk_files(index_content, map_content, key, |path, perm, pack, hash| {
        println!("\tHASH: {:?}", hash);
        println!("\t\tPACK: {:?}", pack);

        // Find or load the packfile
        if !pack_cache.contains_key(&pack) {
            let mut pack_read = remote.read(Typ::Pack, &pack).unwrap();
            let pack_file = PackOut::load(&mut pack_read, key);

            pack_cache.insert(pack.clone(), pack_file);

            // TODO: make this into a streaming read but for now copy data
            let data: Vec<u8> = pack_cache
                .get(&pack)
                .unwrap()
                .find_hash(hash.clone())
                .unwrap();

            // Process the data
            let mut dec = crypto::decrypt(key, &data[..]).unwrap();
            let mut und = Decoder::new(&mut dec).unwrap();
            let content_hash = hash::hash(key, &mut und).unwrap();

            println!("\tPATH: {:?}", path);
            println!("\tPERM: {:?}", perm);

            let is_same = hash == content_hash;
            println!("\tSAME: {:5}", is_same);
        }
    });
}
