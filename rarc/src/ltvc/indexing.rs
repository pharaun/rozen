use serde::Deserialize;
use serde::Serialize;
use std::io::{Read, Write};
use zstd::stream::read::Encoder;

use rcore::crypto;
use rcore::hash;
use rcore::key;

use crate::ltvc::builder::LtvcBuilder;

// Test imports
use binrw::binrw;
use borsh::BorshDeserialize;
use borsh::BorshSerialize;

// TODO: add header type, for initial impl this is Fidx only
#[binrw]
#[brw(little)]
#[derive(Serialize, Deserialize, Debug)]
#[derive(BorshSerialize, BorshDeserialize)]
pub struct HeaderIdx {
    pub typ: [u8; 4],

    #[bw(map = |x| x.as_bytes())]
    #[br(map = |x: [u8; 32]| x.into())]
    #[borsh(deserialize_with = "deserialize_hash", serialize_with = "serialize_hash")]
    pub hash: hash::Hash,

    #[bw(map = |x| *x as u32)]
    #[br(map = |x: u32| x as usize)]
    pub start_idx: usize,

    #[bw(map = |x| *x as u32)]
    #[br(map = |x: u32| x as usize)]
    pub length: usize,
}

// Borsh
fn deserialize_hash<R: borsh::io::Read>(reader: &mut R) -> Result<hash::Hash, borsh::io::Error> {
    let hash: [u8; 32] = borsh::BorshDeserialize::deserialize_reader(reader)?;
    Ok(hash.into())
}

fn serialize_hash<W: borsh::io::Write>(hash: &hash::Hash, writer: &mut W) -> Result<(), borsh::io::Error> {
    let hash: &[u8; 32] = hash.as_bytes();
    borsh::BorshSerialize::serialize(hash, writer)?;
    Ok(())
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
    use bcs::to_bytes;

    use rcore::key::MemKey;

    fn data_gen() -> Vec<HeaderIdx> {
        let key = MemKey::new();

        vec![
            HeaderIdx {
                typ: *b"FHDR",
                hash: key.gen_id(),
                start_idx: 0,
                length: 10,
            }
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
    fn small_data_cbor() {
        let idx = data_gen();

        // Test encode options
        let mut index = Vec::new();
        ciborium::into_writer(&idx, &mut index).unwrap();

        println!("{}", hex::encode(&index));

        assert!(false);
    }

    #[test]
    fn small_data_msgpack() {
        let idx = data_gen();

        // Test encode options
        let index = rmp_serde::to_vec(&idx).unwrap();

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

    #[test]
    fn small_data_bcs() {
        let idx = data_gen();

        // Test encode options
        let index = to_bytes(&idx).unwrap();

        println!("{}", hex::encode(index));

        assert!(false);
    }

    #[test]
    fn small_data_borsh() {
        let idx = data_gen();

        // Test encode options
        let index = borsh::to_vec(&idx).unwrap();

        println!("{}", hex::encode(index));

        assert!(false);
    }
}
