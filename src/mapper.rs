use std::io::{copy, Read, Write};
use serde::Serialize;
use serde::Deserialize;
use bincode;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;

use crate::crypto;
use crate::hash;
use crate::ltvc::builder::LtvcBuilder;
use crate::ltvc::reader::{LtvcReader, LtvcEntry};

// TODO: do this better - should be a typed pseudo hash instead of a fake hash
pub fn generate_map_id() -> hash::Hash {
    // Use a crypto grade random key for the map-id
    let id = crypto::gen_key();
    hash::Hash::from(id.0)
}

pub struct MapBuilder<W: Write> {
    pub id: hash::Hash,
    idx: Vec<PackIdx>,
    inner: LtvcBuilder<W>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PackIdx {
    hash: hash::Hash,
    chunk: u16,
    pack: hash::Hash,
}

// TODO: dump when the vec gets too large a chunk to the file?
// TODO: drop call on finalize?
impl<W: Write> MapBuilder<W> {
    pub fn new(id: hash::Hash, writer: W) -> Self {
        let mut mapper = MapBuilder {
            id,
            idx: Vec::new(),
            inner: LtvcBuilder::new(writer),
        };

        // Start with the Archive Header (kinda serves as a magic bits)
        let _ = mapper.inner.write_ahdr(0x01).unwrap();
        mapper
    }

    pub fn append(&mut self, hash: hash::Hash, chunk: u16, pack: hash::Hash) {
        self.idx.push(PackIdx {
            hash,
            chunk,
            pack,
        });
    }

    // TODO: should hash+hmac various data bits in a mapfile
    // Store the hmac hash of the packfile in packfile + snapshot itself.
    pub fn finalize(mut self, key: &crypto::Key) {
        let _ = self.inner.write_pidx().unwrap();

        let index = bincode::serialize(&self.idx).unwrap();
        let comp = Encoder::new(
            &index[..],
            21
        ).unwrap();
        let mut enc = crypto::encrypt(&key, comp).unwrap();

        let _ = self.inner.write_edat(&mut enc).unwrap();
        let _ = self.inner.write_aend(0x00_00_00_00).unwrap();

        // Flush to signal to the backend that its done
        self.inner.to_inner().flush().unwrap();
    }
}
