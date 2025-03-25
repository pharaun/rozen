use serde::Deserialize;
use serde::Serialize;
use std::io::{Read, Write};
use zstd::stream::read::Encoder;

use rcore::crypto;
use rcore::hash;
use rcore::key;

use crate::ltvc::builder::LtvcBuilder;

// Test imports
use integer_encoding::VarIntReader;
use integer_encoding::VarIntWriter;
use binrw::binrw;

// TODO: add header type, for initial impl this is Fidx only
#[binrw]
#[brw(little)]
#[derive(Serialize, Deserialize, Debug)]
pub struct HeaderIdx {
    pub typ: [u8; 4],

    #[bw(map = |x| x.as_bytes())]
    #[br(map = |x: [u8; 32]| x.into())]
    pub hash: hash::Hash,

    #[br(parse_with = varint_parser)]
    #[bw(write_with = varint_writer)]
    pub start_idx: usize,

    #[br(parse_with = varint_parser)]
    #[bw(write_with = varint_writer)]
    pub length: usize,
}

// Test type for varint
#[binrw::parser(reader)]
fn varint_parser() -> binrw::BinResult<usize> {
    let ret: u32 = reader.read_varint()?;
    binrw::BinResult::Ok(ret as usize)
}

#[binrw::writer(writer)]
fn varint_writer(integer: &usize) -> binrw::BinResult<()> {
    writer.write_varint(*integer)?;
    binrw::BinResult::Ok(())
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

            let config = bincode::config::standard().with_little_endian().with_variable_int_encoding();
            let index = bincode::serde::encode_to_vec(&self.h_idx, config).unwrap();
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

#[cfg(test)]
mod serialize {
    use super::HeaderIdx;

    use std::io::Cursor;
    use binrw::BinWrite;

    use rcore::key::MemKey;

    fn file_gen(start: usize, length: usize) -> HeaderIdx {
        let key = MemKey::new();
        HeaderIdx {
            typ: *b"FHDR",
            hash: key.gen_id(),
            start_idx: start,
            length,
        }
    }

    fn snapshot_gen(start: usize, length: usize) -> HeaderIdx {
        let key = MemKey::new();
        HeaderIdx {
            typ: *b"SHDR",
            hash: key.gen_id(),
            start_idx: start,
            length,
        }
    }

    fn pack_idx_gen(start: usize, length: usize) -> HeaderIdx {
        let key = MemKey::new();
        HeaderIdx {
            typ: *b"PIDX",
            hash: key.gen_id(),
            start_idx: start,
            length,
        }
    }

    fn data_gen() -> Vec<HeaderIdx> {
        vec![
            file_gen(0, 10),
            file_gen(20, u32::MAX as usize),
            file_gen(u32::MAX as usize, u64::MAX as usize),
            snapshot_gen(123, 0),
            pack_idx_gen(100, 1),
        ]
    }

    #[test]
    fn small_data_bincode() {
        let idx = data_gen();

        // Test encode options
        let config = bincode::config::standard().with_little_endian().with_variable_int_encoding();
        let index = bincode::serde::encode_to_vec(&idx, config).unwrap();

        println!("{}", hex::encode(&index));

        assert!(false);
    }

    #[test]
    fn small_data_binrw() {
        let idx = data_gen();

        // Test encode options
        let mut index = Cursor::new(Vec::new());
        idx.write(&mut index).unwrap();

        println!("{}", hex::encode(index.into_inner()));

        assert!(false);
    }
}
