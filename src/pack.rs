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
//!     - Packfile: magic, FHDR, EDAT, FHDR, EDAT, fIDX, EDAT, trailer (-> fIDX)
//!     - Singlet: magic, FHDR, EDAT, trailer (-> 0x0000)
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
//!         REND
//!             - Rozen file end (only there to terminate a sequence of EDAT)
//!             - Contains the trailer-pointer (without chunk checksum)
//!             - 4, REND, ptr
//!             - trailer-pointer
//!                 * points to fIDX
//!                 * None
//!                     - Fetch 16 bytes at end of file
//!                     - If last 4 bytes == REND, there is no trailer pointer
//!                         * What if it is 4, REND, REND (for pointer) so better validate
//!                         * last 8 byte is 0, REND, if there is REND, REND then its a pointer to
//!                             REND bytes
//!                     - Otherwise validate that first 8 bytes is 4 + REND before using pointer
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

use std::io::{copy, Read};
use std::cmp;
use std::convert::TryInto;
use std::str::from_utf8;
use hex;
use serde::Serialize;
use serde::Deserialize;
use bincode;
use twox_hash::XxHash32;
use std::hash::Hasher;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;

use crate::crypto;
use crate::buf::flush_buf;
use crate::buf::fill_buf;

// Selected via https://datatracker.ietf.org/doc/html/draft-main-magic-00
const MAGIC: [u8; 8] = [0x65, 0x86, 0x89, 0xd8, 0x27, 0xb0, 0xbb, 0x9b];


// Attempt to on the fly write chunks into a packfile to a backend
pub struct PackIn {
    pub id: String,
    idx: Vec<ChunkIdx>,

    // TODO: Not sure how to hold state bits yet
    t_buf: Option<Vec<u8>>,
    finalized: bool,
    p_idx: usize,
}

// TODO: Make sure we understand security/validation of the serialization deserialization of
// various chunks here
#[derive(Serialize, Deserialize, Debug)]
struct ChunkIdx {
    start_idx: usize,
    length: usize,
    hash: String,
}

// TODO: Evaulate the need for a hash
// Length, Type, Value, xxhash32 of Type+Value
// u32, u32, [u8; N], u32
fn ltvc(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut hash = XxHash32::with_seed(0);
    hash.write(chunk_type);
    hash.write(data);

    let mut buf: Vec<u8> = Vec::new();

    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(chunk_type);
    buf.extend_from_slice(data);
    buf.extend_from_slice(&(hash.finish() as u32).to_le_bytes());

    if let Ok(out_str) = from_utf8(chunk_type) {
        println!("Serializing: {:?}", out_str);
    }

    buf
}

impl PackIn {
    // Use a crypto grade random key for the packfile-id
    pub fn new() -> Self {
        let id = crypto::gen_key();
        let mut pack = PackIn {
            id: hex::encode(id),
            idx: Vec::new(),
            // Start with the magic bits for the file format, inspired by PNG
            t_buf: None,
            finalized: false,
            p_idx: 0,
        };
        pack.write_buf(MAGIC.to_vec());
        pack
    }

    fn write_buf(&mut self, data: Vec<u8>) {
        self.p_idx += data.len();

        println!("write_buf: {:?}", data.len());

        match &mut self.t_buf {
            None    => self.t_buf = Some(data),
            Some(b) => b.extend(&data),
        }
    }

    // TODO: should have integrity check to make sure the current reader is
    // done (aka unset otherwise it errors)
    pub fn begin_write<R: Read>(&mut self, hash: &str, reader: R) -> ChunkState<R> {
        if !self.finalized {
            // Dump the FHDR chunk
            self.write_buf(
                ltvc(
                    b"FHDR",
                    hash.to_string().as_bytes()
                )
            );

            // EDAT chunk size
            let in_buf = [0u8; CHUNK_SIZE];
            let out_buf = Vec::with_capacity(CHUNK_SIZE);

            ChunkState {
                hash: hash.to_string(),
                inner: reader,
                len: 0,
                idx: self.p_idx,
                finished: false,
                in_buf: Box::new(in_buf),
                out_buf,
            }
        } else {
            panic!("SYSTEM-ERROR, this is finalized and got more ChunkState");
        }
    }

    pub fn finish_write<R: Read>(&mut self, chunk: ChunkState<R>) {
        if !self.finalized {
            self.idx.push(ChunkIdx {
                start_idx: chunk.idx,
                length: chunk.len,
                hash: chunk.hash.clone(),
            });
            self.p_idx += chunk.len;
        } else {
            panic!("SYSTEM-ERROR, this is finalized and got more ChunkState");
        }
    }

    // TODO: should hash+hmac various data bits in a packfile
    // Store the hmac hash of the packfile in packfile + snapshot itself.
    // TODO: should consume self, and return the final blob of data to read out then terminate
    // for now we set finalized flag and refuse more blob additions
    pub fn finalize(&mut self, key: &crypto::Key) {
        if self.finalized {
            panic!("SYSTEM-ERROR, already finalized once, this is invalid");
        }

        // Dump the FIDX chunk
        let cached_p_idx = self.p_idx;
        self.write_buf(
            ltvc(b"FIDX", &[])
        );

        // Dump IDX into 1 large EDAT for now
        // TODO: in real implementation it should chunk
        let index = bincode::serialize(&self.idx).unwrap();

        let comp = Encoder::new(
            &index[..],
            21
        ).unwrap();

        let mut enc = crypto::encrypt(&key, comp).unwrap();

        let mut buf: Vec<u8> = Vec::new();
        copy(&mut enc, &mut buf).unwrap();

        self.write_buf(
            ltvc(b"EDAT", &buf[..])
        );

        // Dump the REND chunk
        self.write_buf(ltvc(b"REND", &(cached_p_idx as u32).to_le_bytes()));
        self.finalized = true;
    }
}

impl Read for PackIn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(t_buf) = self.t_buf.as_mut() {
            if t_buf.is_empty() {
                self.t_buf = None;
                Ok(0)
            } else {
                // Write out what we can
                let dat_len = flush_buf(t_buf, buf);
                Ok(dat_len)
            }
        } else {
            if self.finalized {
                println!("We are done for good on the PackIn, refuse more data");
            }
            Ok(0)
        }
    }
}


// 1Kb EDAT frame buffer
const CHUNK_SIZE: usize = 1 * 1024;

// TODO: if parent has any remaining data in buffer, put it here so that it
// can finish reading out of the buffer before reading form the inner
pub struct ChunkState<R: Read> {
    hash: String,
    inner: R,
    len: usize,
    idx: usize,
    finished: bool,

    // TODO: can probs improve the effency of this and not double buffer or etc
    in_buf: Box<[u8]>,
    out_buf: Vec<u8>,
}

// Read from pack till EoF then time for next chunk to be added
// TODO: to force ourself to handle sequence of EDAT for now use small
// chunk size such as 1024
impl<R: Read> Read for ChunkState<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut buf_write: usize = 0;

        // 1. If buf_write == buf.len() return
        while buf_write < buf.len() {
            if !self.out_buf.is_empty() {
                // 2. If data in out_buf, flush into buf first
                buf_write += flush_buf(&mut self.out_buf, &mut buf[buf_write..]);

            } else {
                // 3. Read till there is 1Kb of data in in_buf
                match fill_buf(&mut self.inner, &mut self.in_buf)? {
                    // 4a. Nothing left in in_buf, is EoF, and is not finalize, finalize
                    (true, 0) if !self.finished => {
                        println!("Finalizing EDAT");
                        self.finished = true;
                    },

                    // 4b. Nothing left in [in_buf, out_buf] and is EoF, exit
                    (true, 0) if self.out_buf.is_empty() => {
                        self.len += buf_write;
                        return Ok(buf_write);
                    },

                    // 4c. Copy in_buf -> out_buf
                    // 4d. Final read, finalize
                    (_eof, in_len) => {
                        self.out_buf = ltvc(b"EDAT", &mut self.in_buf[..in_len]);
                        println!("dump2 - out: {:?}, in: {:?}", self.out_buf.len(), self.in_buf.len());
                    },
                }
            }
        }

        self.len += buf_write;
        Ok(buf_write)
    }
}



// TODO: have 2 ways to read the packfile, one via the index, in a seek manner, other via start to
// end
// Attempt to read a packfile from the backend in a streaming manner
// TODO: make it into an actual streaming/indexing packout but for now just buffer in ram
pub struct PackOut {
    idx: Vec<ChunkIdx>,
    buf: Vec<u8>,
}


// Read the buffer to convert to a LTVC and validate
// TODO: consider a iterator/streaming option where it takes a buffer
// that begins on a chunk and then it streams the chunk+data one block at a time
// TODO: make sure to reject too large chunk size for preventing out of memory bugs
fn read_ltvc(buf: &[u8]) -> Option<(usize, [u8; 4], &[u8])> {
    let len_buf: [u8; 4] = buf[0..4].try_into().unwrap();
    let typ_buf: [u8; 4] = buf[4..8].try_into().unwrap();

    let len: usize = u32::from_le_bytes(len_buf) as usize;

    // TODO: this is bad, do this better, don't trust length
    let dat_buf: &[u8]   = buf[8..(8+len)].try_into().unwrap();
    let has_buf: [u8; 4] = buf[(8+len)..(8+len+4)].try_into().unwrap();

    let old_hash: u32 = u32::from_le_bytes(has_buf);

    // Validate the hash
    let mut hash = XxHash32::with_seed(0);
    hash.write(&typ_buf);
    hash.write(dat_buf);

    let whole_len = 4 + 4 + len + 4;

    if (hash.finish() as u32) == old_hash {
        Some((whole_len, typ_buf, dat_buf))
    } else {
        None
    }
}


impl PackOut {
    pub fn load<R: Read>(reader: &mut R, key: &crypto::Key) -> Self {
        let mut buf: Vec<u8> = Vec::new();
        copy(reader, &mut buf).unwrap();

        println!("Buf.len: {:?}", buf.len());

        // Current REND is 16 bytes
        // TODO: make this more intelligent
        let (_, typ, rend_dat) = read_ltvc(&buf[buf.len()-16..buf.len()]).unwrap();
        if &typ == b"REND" {
            println!("REND parsing");
        }

        let i_idx = {
            let idx_buf:  [u8; 4]  = rend_dat[0..4].try_into().unwrap();
            u32::from_le_bytes(idx_buf) as usize
        };

        println!("Index offset: {:?}", i_idx);
        println!("buf-len: {:?}", buf.len());

        // FIDX is 12 bytes, ingest that
        let (_, typ, _) = read_ltvc(&buf[i_idx..(i_idx+12)]).unwrap();
        if &typ == b"FIDX" {
            println!("FIDX parsing");
        }

        // Fetch the EDAT
        let (_, typ, edat) = read_ltvc(&buf[(i_idx+12)..]).unwrap();
        if &typ == b"EDAT" {
            println!("EDAT parsing");
        }
        let mut dec = crypto::decrypt(&key, edat).unwrap();
        let mut und = Decoder::new(&mut dec).unwrap();

        let mut idx_buf: Vec<u8> = Vec::new();
        copy(&mut und, &mut idx_buf).unwrap();

        // Deserialize the index
        let chunk_idx: Vec<ChunkIdx> = bincode::deserialize(&idx_buf).unwrap();

        println!("Chunk len: {:?}", chunk_idx.len());
        println!("Chunk Idx: {:#?}", chunk_idx);

        PackOut {
            idx: chunk_idx,
            buf: buf,
        }
    }

    pub fn find(&self, hash: &str) -> Option<Vec<u8>> {
        for c in self.idx.iter() {
            if c.hash == hash {
                let mut buf: Vec<u8> = Vec::new();
                buf.extend_from_slice(&self.buf[c.start_idx..(c.start_idx+c.length)]);

                println!("Found!");
                println!("\tCached idx: {:?}, length: {:?}", c.start_idx, c.length);
                println!("\tActual idx: {:?}, End idx: {:?}", c.start_idx, (c.start_idx+c.length));
                println!("\tbuf: {:?}", buf.len());

                println!("\tunpack EDAT");
                let mut out_buf: Vec<u8> = Vec::new();
                let mut out_idx: usize = 0;

                while out_idx != buf.len() {
                    let (read_len, _typ, edat_dat) = read_ltvc(&buf[out_idx..]).unwrap();
                    out_idx += read_len;
                    out_buf.extend(edat_dat);

                    println!(
                        "\tEDAT read: rlen: {:?}, left: {:?}, total: {:?}, cur_out_len: {:?}",
                        read_len, buf.len()-out_idx, buf.len(), out_buf.len());
                }

                return Some(out_buf);
            }
        }
        None
    }
}
