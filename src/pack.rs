//! Collection of Blobs
//!
//! # Top Level
//!
//! | Type    | Name  | Description |
//! | :-----: | ----- | ----------- |
//! | [u8; 4] | magic | b"pack" |
//! | [u8; N] | chunk | See [Blobs](#blobs) |
//! | [u8; N] | index | See [Index](#index) |
//!
//!
//! Consider it from 2 PoV
//!     - Streaming (Beginning to end)
//!     - Fetch+seek (read trailing pointer to fIDX)
//!         * Fetch fIDX -> eof-8
//!         * Use this to fetch all EDAT data desired
//!
//! PNG is the big inspiration
//!     length, type, [data], crc
//!     crc - https://docs.rs/twox-hash/latest/twox_hash/ - 32 or 64bit xxhash (this is only for
//!     integrity)
//!
//! Encryption
//!     - Investigate padding (PADME?) for anonomyizing file size to reduce identification
//!     - Chunk/file size is information leak
//!          One way to consider information leak is pack file is purely an optimization for
//!          glacier store in which the index can be stored in S3 + packfile, and the specified
//!          byte range be fetched out of glacier. This leads me to interpret any information leak
//!          is also the same as a stand-alone blob in glacier store so... treat both the same.
//!          packfile == packed blobs
//!
//!          Now mind you there *is* information leak via the length cos of compression/plaintext
//!          but blob storage would have this as well so resolving blob storage + etc will be good
//!          to have also this is more for chunked data ala borg/restic/etc
//!
//!     - Use the phash (file HMAC) for additional data with the encryption to ensure that
//!     the encrypted data matches the phash
//!
//! File format family:
//!     - Packfile: AHDR, FHDR, EDAT, FHDR, EDAT, fIDX, EDAT, AEND (-> fIDX)
//!     - Singlet: AHDR, FHDR, EDAT, AEND (-> 0x0000)
//!     - Snapshot: Same as Singlet
//!
//!     Layers:
//!         input file -> FHDR + FILE
//!         file_hash + packfile id -or- file_hash -> snapshot -> FHDR + FILE
//!         multiple FHDR -> chunk_idx -> fIDX + FILE
//!
//!         FILE -> compression -> crypto -> EDAT
//!
//!     mvp-chunk:
//!         AHDR
//!             - Section header
//!             - Version 1 so a magic byte would be
//!             - 00 00 00 01 b'S' b'H' b'D' b'R' 01 [checksum]
//!         FHDR
//!             - File data (1 followed by 1 more more EDAT)
//!             - phash => keyed hmac of plaintext data
//!         FIDX
//!             - File data index (if more than 1 FHDR) (1 followed by 1 or more EDAT)
//!             - vec<(phash, pointer to start of FDAT, length (to end of last FDAT))>
//!             - optional, is for efficient seek in a packfile, encouraged
//!         EDAT
//!             - Encrypted Data Chunks
//!             - EDAT == 1 or more EDAT in sequence
//!             - Ends when any other chunk is seen
//!         FSNP
//!             - file snapshot
//!             - Not sure, its more to mark what a sequence of EDAT is for.
//!                 * May end up having fHDR/fIDX/fSNP being marker chunks to mark what
//!                 the following sequence of EDAT are for
//!             - EDAT that contains the sqlite db that holds the relevant snapshot+metadata
//!         AEND
//!             - Archive sector file end (only there to terminate a sequence of EDAT)
//!             - Contains the trailer-pointer (without chunk checksum)
//!             - 4, AEND, ptr
//!             - trailer-pointer
//!                 * points to fIDX
//!                 * None
//!                     - Fetch 16 bytes at end of file
//!                     - If last 4 bytes == AEND, there is no trailer pointer
//!                         * What if it is 4, AEND, AEND (for pointer) so better validate
//!                         * last 8 byte is 0, AEND, if there is AEND, AEND then its a pointer to
//!                             AEND bytes
//!                     - Otherwise validate that first 8 bytes is 4 + AEND before using pointer
//!
//!         Rules:
//!             - lower case first letter for optional (5th bit)
//!             - Mandatory upper for other 3, bit meaning to be determited
//!
//! magic = [137, R, O, Z, 13, 10, 26, 10]
//!
//! # Blobs
//!
//! This is basically [`crypto::Crypter<R, E>`]
//!
//! # Index
//!
//! | Type              | Name   | Description |
//! | :---------------: | ------ | ----------- |
//! | [[`ChunkIdx`]; N] | index  | Hash -> offset+length of each chunk in the packfile |
//! | u32               | offset | Pointer to the start of the index |
//! | u32               | length | Length of the index |
//! | [u8; 64]          | hmac   | Index HMAC </br> HMAC(index \|\| offset \|\| length) |
//!

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
    hash: hash::Hash,
}

// TODO: implement drop to call finalize
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

    pub fn append<R: Read>(&mut self, hash: hash::Hash, reader: &mut R) {
        let f_idx = self.p_idx;

        self.p_idx += self.inner.write_fhdr(&hash).unwrap();
        self.p_idx += self.inner.write_edat(reader).unwrap();

        self.idx.push(ChunkIdx {
            start_idx: f_idx,
            length: self.p_idx - f_idx,
            hash: hash,
        });
    }

    // TODO: should hash+hmac various data bits in a packfile
    // Store the hmac hash of the packfile in packfile + snapshot itself.
    pub fn finalize(mut self, key: &crypto::Key) {
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
    }
}


// TODO: for now have this PackOut be a streaming validating pack reader, it stream reads
// and then cache the idx+data then use that info to validate the fidx and aend
// TODO: make it into an actual streaming/indexing packout but for now just buffer in ram
pub struct PackOut {
    idx: HashMap<hash::Hash, Vec<u8>>,
    _idx: Vec<ChunkIdx>,
}

#[derive(Debug)]
enum Spo {
    Start,
    Ahdr,
    Fhdr { hash: hash::Hash },
    FhdrEdat,
    Fidx,
    FidxEdat,
    Aend,
}

impl PackOut {
    pub fn load<R: Read>(reader: &mut R, key: &crypto::Key) -> Self {
        let mut ltvc = LtvcReader::new(reader);
        let mut idx = HashMap::new();
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
                (Spo::Ahdr, Some(Ok(LtvcEntry::Fhdr { hash }))) |
                (Spo::FhdrEdat, Some(Ok(LtvcEntry::Fhdr { hash }))) => {
                    println!("\t\t\tFhdr <hash>");
                    state = Spo::Fhdr { hash };
                },

                // Assert that Fhdr Edat follows the Fhdr
                (Spo::Fhdr { hash }, Some(Ok(LtvcEntry::Edat { mut data }))) => {
                    println!("\t\t\tFhdr Edat");
                    let mut out_data = vec![];
                    copy(&mut data, &mut out_data).unwrap();

                    idx.insert(hash, out_data);
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

    pub fn find(&self, hash: hash::Hash) -> Option<Vec<u8>> {
        self.idx.get(&hash).map(|x| x.clone())
    }
}
