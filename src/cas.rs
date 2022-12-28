use crate::hash;
use crate::key;
use crate::pack;
use crate::pack::PackBuilder;
use crate::remote::Remote;
use crate::remote::Typ;
use crate::sql::Map;
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
pub struct ObjectStore<'a, B: Remote + 'a> {
    remote: &'a B,
    current_pack: Option<PackBuilder<Box<dyn Write>>>,
    map: Map,
}

impl<'a, B: Remote> ObjectStore<'a, B> {
    pub fn new(remote: &'a mut B) -> Self {
        // TODO: later do something like fetch the latest cache and use that
        ObjectStore {
            remote,
            current_pack: None,
            map: Map::new(),
        }
    }

    pub fn append<R: Read>(
        &mut self,
        hash: &hash::Hash,
        key: &key::Key,
        reader: &mut R,
        size: u64,
    ) {
        let pack_id = if size > (3 * 1024) {
            self.append_big(hash, key, reader)
        } else {
            self.append_small(hash, key, reader)
        };

        self.map.insert_chunk(hash, &pack_id);
    }

    fn append_big<R: Read>(
        &mut self,
        hash: &hash::Hash,
        key: &key::Key,
        reader: &mut R,
    ) -> hash::Hash {
        // This one focuses on reading in one single big file into its own packfile and uploading
        // it as it is
        let mut temp_pack = {
            let pack_id = pack::generate_pack_id();
            let multiwrite = self.remote.write_multi(Typ::Pack, &pack_id).unwrap();
            PackBuilder::new(pack_id, multiwrite)
        };
        let pack_id = temp_pack.id.clone();

        temp_pack.append(hash.clone(), reader);

        temp_pack.finalize(key);

        pack_id
    }

    fn append_small<R: Read>(
        &mut self,
        hash: &hash::Hash,
        key: &key::Key,
        reader: &mut R,
    ) -> hash::Hash {
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
        let temp_pack = self.current_pack.get_or_insert_with(|| {
            let pack_id = pack::generate_pack_id();
            let multiwrite = self.remote.write_multi(Typ::Pack, &pack_id).unwrap();
            PackBuilder::new(pack_id, multiwrite)
        });
        let pack_id = temp_pack.id.clone();

        if temp_pack.append(hash.clone(), reader) {
            self.current_pack.take().unwrap().finalize(key);
        }

        pack_id
    }

    pub fn finalize<W: Write>(mut self, map_content: W, key: &key::Key) {
        // Force an finalize if its not already finalized
        if self.current_pack.is_some() {
            self.current_pack.take().unwrap().finalize(key);
        }

        // Unload the sqlite file into remote as snapshot
        self.map.unload(key, map_content);
    }

    // TODO:
    // 1. Implement a way to fetch by content_hash
    // 2. returns packfiles involved + chunks involved
    // 3. fetch needed packfiles + chunks and reassembly then stream it out
}
