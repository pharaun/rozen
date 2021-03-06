use std::io::{copy, Read, Write};
use std::collections::HashMap;
use serde::Serialize;
use serde::Deserialize;
use bincode;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;

use crate::crypto;
use crate::hash;
use crate::ltvc::builder::LtvcBuilder;
use crate::ltvc::reader::{LtvcReader, LtvcEntry};
use crate::mapper;

// TODO: set to 1gb at some point
const PACK_SIZE: usize = 4 * 1024;

// TODO: do this better - should be a typed pseudo hash instead of a fake hash
pub fn generate_pack_id() -> hash::Hash {
    // Use a crypto grade random key for the packfile-id
    let id = crypto::gen_key();
    hash::Hash::from(id.0)
}

pub struct PackBuilder<W: Write> {
    pub id: hash::Hash,
    idx: Vec<ChunkIdx>,
    inner: LtvcBuilder<W>,

    // State bits
    p_idx: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct ChunkIdx {
    start_idx: usize,
    length: usize,
    chunk: u16,
    hash: hash::Hash,
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
        let mut pack = PackBuilder {
            id,
            idx: Vec::new(),
            inner: LtvcBuilder::new(writer),
            p_idx: 0
        };

        // Start with the Archive Header (kinda serves as a magic bits)
        pack.p_idx += pack.inner.write_ahdr(0x01).unwrap();
        pack
    }

    pub fn append<R: Read>(&mut self, hash: hash::Hash, chunk: u16, reader: &mut R) -> bool {
        let f_idx = self.p_idx;

        self.p_idx += self.inner.write_fhdr(&hash, chunk).unwrap();
        self.p_idx += self.inner.write_edat(reader).unwrap();

        self.idx.push(ChunkIdx {
            start_idx: f_idx,
            length: self.p_idx - f_idx,
            chunk: chunk,
            hash: hash,
        });

        if self.p_idx >= PACK_SIZE {
            true
        } else {
            false
        }
    }

    // TODO: should hash+hmac various data bits in a packfile
    // Store the hmac hash of the packfile in packfile + snapshot itself.
    pub fn finalize<MW: Write>(mut self, map: &mut mapper::MapBuilder<MW>, key: &crypto::Key) {
        let f_idx = self.p_idx;

        self.p_idx += self.inner.write_fidx().unwrap();

        let index = bincode::serialize(&self.idx).unwrap();
        let comp = Encoder::new(
            &index[..],
            21
        ).unwrap();
        let mut enc = crypto::encrypt(&key, comp).unwrap();

        self.p_idx += self.inner.write_edat(&mut enc).unwrap();
        self.p_idx += self.inner.write_aend(f_idx).unwrap();

        // Flush to signal to the backend that its done
        self.inner.to_inner().flush().unwrap();

        // TODO: decide on what is a good ordering, but for now record the index data to the mapper
        for i in self.idx {
            map.append(
                i.hash,
                i.chunk,
                self.id.clone(),
            )
        }
    }
}


// TODO: for now have this PackOut be a streaming validating pack reader, it stream reads
// and then cache the idx+data then use that info to validate the fidx and aend
// TODO: make it into an actual streaming/indexing packout but for now just buffer in ram
pub struct PackOut {
    idx: HashMap<hash::Hash, Vec<(u16, Vec<u8>)>>,
    _idx: Vec<ChunkIdx>,
}

#[derive(Debug)]
enum Spo {
    Start,
    Ahdr,
    Fhdr { hash: hash::Hash, chunk: u16 },
    FhdrEdat,
    Fidx,
    FidxEdat,
    Aend,
}

impl PackOut {
    pub fn load<R: Read>(reader: &mut R, key: &crypto::Key) -> Self {
        let mut ltvc = LtvcReader::new(reader);
        let mut idx: HashMap<hash::Hash, Vec<(u16, Vec<u8>)>> = HashMap::new();
        let mut chunk_idx: Vec<ChunkIdx> = vec![];
        let mut state = Spo::Start;

        loop {
            match (state, ltvc.next()) {
                // Assert that the first entry is an Ahdr with 0x01 as version
                (Spo::Start, Some(Ok(LtvcEntry::Ahdr { version }))) if version == 0x01 => {
                    println!("\t\t\tAHDR 0x01");
                    state = Spo::Ahdr;
                },

                // Assert that Fhdr follows the Ahdr, FhdrEdat
                (Spo::Ahdr, Some(Ok(LtvcEntry::Fhdr { hash, chunk }))) |
                (Spo::FhdrEdat, Some(Ok(LtvcEntry::Fhdr { hash, chunk }))) => {
                    println!("\t\t\tFhdr <hash>");
                    state = Spo::Fhdr { hash, chunk };
                },

                // Assert that Fhdr Edat follows the Fhdr
                (Spo::Fhdr { hash, chunk }, Some(Ok(LtvcEntry::Edat { mut data }))) => {
                    println!("\t\t\tFhdr Edat - {:?}", chunk);
                    let mut out_data = vec![];
                    copy(&mut data, &mut out_data).unwrap();

                    if let Some(dat) = idx.get_mut(&hash) {
                        dat.push((chunk, out_data));
                    } else {
                        idx.insert(hash, vec![(chunk, out_data)]);
                    }
                    state = Spo::FhdrEdat;
                },

                // Assert that Fidx follows FhdrEdat
                (Spo::FhdrEdat, Some(Ok(LtvcEntry::Fidx))) => {
                    println!("\t\t\tFidx");
                    state = Spo::Fidx;
                },

                // Assert that Fidx Edat follows Fidx
                (Spo::Fidx, Some(Ok(LtvcEntry::Edat { mut data }))) => {
                    println!("\t\t\tFidx Edat");
                    let mut idx_buf: Vec<u8> = Vec::new();
                    let mut dec = crypto::decrypt(&key, &mut data).unwrap();
                    let mut und = Decoder::new(&mut dec).unwrap();
                    copy(&mut und, &mut idx_buf).unwrap();

                    // Deserialize the index
                    chunk_idx = bincode::deserialize(&idx_buf).unwrap();
                    println!("\t\t\t\tChunk len: {:?}", chunk_idx.len());
                    state = Spo::FidxEdat;
                },

                // Assert that Aend follows FidxEdat
                (Spo::FidxEdat, Some(Ok(LtvcEntry::Aend { idx: _ }))) => {
                    println!("\t\t\tAend");
                    state = Spo::Aend;
                },

                // Asserts that the iterator is terminated
                (Spo::Aend, None) => break,

                // Unhandled states
                // TODO: improve debuggability
                (s, None)         => panic!("In state: {:?} unexpected end of iterator", s),
                (s, Some(Err(_))) => panic!("In state: {:?} error on iterator", s),
                (s, Some(Ok(_)))  => panic!("In state: {:?} unknown LtvcEntry", s),
            }
        }

        PackOut {
            idx: idx,
            _idx: chunk_idx,
        }
    }

    pub fn find_chunk(&self, hash: hash::Hash, chunk: u16) -> Option<Vec<u8>> {
        self.idx.get(&hash).and_then(
            |chunks| chunks.into_iter().find(
                |(vec_chunk, _)| *vec_chunk == chunk
            ).map(
                |(_, dat)| dat.clone()
            )
        )
    }

    pub fn list_chunks(&self, hash: hash::Hash) -> Option<Vec<u16>> {
        self.idx.get(&hash).map(
            |chunks| chunks.into_iter().map(
                |(chunk, _)| *chunk
            ).collect()
        )
    }
}
