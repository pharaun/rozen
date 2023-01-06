use serde::Deserialize;
use serde::Serialize;
use std::io::{Read, Write};
use zstd::stream::read::Encoder;

use crate::crypto;
use crate::hash;
use crate::key;
use crate::ltvc::builder::LtvcBuilder;

// TODO: add header type, for initial impl this is Fidx only
#[derive(Serialize, Deserialize, Debug)]
pub struct HeaderIdx {
    pub typ: [u8; 4],
    pub hash: hash::Hash,
    pub start_idx: usize,
    pub length: usize,
}

pub struct LtvcIndexing<W: Write> {
    inner: LtvcBuilder<W>,
    h_idx: Vec<HeaderIdx>,
    idx: usize,
}

// This is the high level writer interface
impl<W: Write> LtvcIndexing<W> {
    pub fn new(writer: W) -> Self {
        let mut indexer = LtvcIndexing {
            inner: LtvcBuilder::new(writer),
            h_idx: Vec::new(),
            idx: 0,
        };

        // Start with the Archive Header (kinda serves as a magic bits)
        indexer.idx += indexer.inner.write_ahdr(0x01).unwrap();
        indexer
    }

    pub fn get_size(&self) -> usize {
        self.idx
    }

    pub fn append_file<R: Read>(&mut self, hash: hash::Hash, reader: &mut R) {
        let f_idx = self.idx;

        self.idx += self.inner.write_fhdr(&hash).unwrap();
        self.idx += self.inner.write_edat(reader).unwrap();

        self.h_idx.push(HeaderIdx {
            typ: *b"FHDR",
            hash,
            start_idx: f_idx,
            length: self.idx - f_idx,
        });
    }

    pub fn append_snapshot<R: Read>(&mut self, hash: hash::Hash, reader: &mut R) {
        let s_idx = self.idx;

        self.idx += self.inner.write_shdr().unwrap();
        self.idx += self.inner.write_edat(reader).unwrap();

        self.h_idx.push(HeaderIdx {
            typ: *b"SHDR",
            hash,
            start_idx: s_idx,
            length: self.idx - s_idx,
        });
    }

    pub fn append_pack_index<R: Read>(&mut self, hash: hash::Hash, reader: &mut R) {
        let p_idx = self.idx;

        self.idx += self.inner.write_pidx().unwrap();
        self.idx += self.inner.write_edat(reader).unwrap();

        self.h_idx.push(HeaderIdx {
            typ: *b"PIDX",
            hash,
            start_idx: p_idx,
            length: self.idx - p_idx,
        });
    }

    pub fn finalize(mut self, append_aidx: bool, key: &key::MemKey) {
        if append_aidx {
            let a_idx = self.idx;

            self.idx += self.inner.write_aidx().unwrap();

            let index = bincode::serialize(&self.h_idx).unwrap();
            let comp = Encoder::new(&index[..], 21).unwrap();
            let mut enc = crypto::encrypt(key, comp).unwrap();

            self.idx += self.inner.write_edat(&mut enc).unwrap();
            self.idx += self.inner.write_aend(a_idx).unwrap();
        } else {
            self.idx += self.inner.write_aend(0x00_00_00_00).unwrap();
        }

        // Flush to signal to the backend that its done
        self.inner.into_inner().flush().unwrap();
    }
}
