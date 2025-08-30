use log::debug;
use std::collections::HashMap;
use std::io::{copy, Read, Write};
use zstd::stream::read::Decoder;

use crate::rcore::crypto;
use crate::rcore::hash;
use crate::rcore::key;

use crate::rarc::ltvc::indexing::HeaderIdx;
use crate::rarc::ltvc::indexing::LtvcIndexing;
use crate::rarc::ltvc::linear::EdatStream;
use crate::rarc::ltvc::linear::Header;
use crate::rarc::ltvc::linear::LtvcLinear;

// TODO: set to 1gb at some point
const PACK_SIZE: usize = 4 * 1024;

pub struct PackBuilder<W: Write> {
    pub id: hash::Hash,
    inner: LtvcIndexing<W>,
}

// TODO: implement drop to call finalize
// TODO: implement some form of split for too large files here
//  * Allow the archive to go over x% (or) allow chunks/file to go over xMB
//  * if they go over, they get split. All parts start with 'part count 0'
//  * If there's more then it becomes <hash>.p1....???
//  * Need to figure out a good way to handle the indexing or might just delegate
//  to higher layer and just index on 'hash + part -> idx + len'
impl<W: Write> PackBuilder<W> {
    pub fn new(id: hash::Hash, writer: W) -> Self {
        PackBuilder {
            id,
            inner: LtvcIndexing::new(writer),
        }
    }

    pub fn append<R: Read>(&mut self, hash: hash::Hash, reader: &mut R) -> bool {
        self.inner.append_file(hash, reader);
        self.inner.get_size() >= PACK_SIZE
    }

    // TODO: should hash+hmac various data bits in a packfile
    // Store the hmac hash of the packfile in packfile + snapshot itself.
    pub fn finalize(self, key: &key::MemKey) {
        self.inner.finalize(true, key);
    }
}

// TODO: for now have this PackOut be a streaming validating pack reader, it stream reads
// and then cache the idx+data then use that info to validate the aidx and aend
// TODO: make it into an actual streaming/indexing packout but for now just buffer in ram
pub struct PackOut {
    idx: HashMap<hash::Hash, Vec<u8>>,
    _idx: Vec<HeaderIdx>,
}

impl PackOut {
    pub fn load<R: Read>(reader: &mut R, key: &key::MemKey) -> Self {
        let ltvc = LtvcLinear::new(reader);
        let mut idx: HashMap<hash::Hash, Vec<u8>> = HashMap::new();
        let mut chunk_idx: Vec<HeaderIdx> = vec![];

        for EdatStream { header, mut data } in ltvc {
            match header {
                Header::Fhdr { hash } => {
                    debug!("FHDR - EDAT");

                    let mut out_data = vec![];
                    copy(&mut data, &mut out_data).unwrap();

                    idx.insert(hash, out_data);
                }
                Header::Aidx => {
                    debug!("AIDX - EDAT");
                    let mut idx_buf: Vec<u8> = Vec::new();
                    let mut dec = crypto::decrypt(key, &mut data).unwrap();
                    let mut und = Decoder::new(&mut dec).unwrap();
                    copy(&mut und, &mut idx_buf).unwrap();

                    // Deserialize the index
                    let config = bincode::config::standard().with_little_endian().with_variable_int_encoding();
                    chunk_idx = bincode::serde::decode_from_slice(&idx_buf, config).unwrap().0;
                    debug!("AIDX - EDAT - length: {}", chunk_idx.len());
                }

                // Skip header we don't care for
                _ => (),
            }
        }

        PackOut {
            idx,
            _idx: chunk_idx,
        }
    }

    pub fn find_hash(&self, hash: hash::Hash) -> Option<Vec<u8>> {
        self.idx.get(&hash).cloned()
    }
}
