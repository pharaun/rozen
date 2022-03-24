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
use std::convert::TryInto;
use serde::Serialize;
use serde::Deserialize;
use bincode;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;

use crate::crypto;
use crate::buf::fill_buf;
use crate::hash;

// 1Kb EDAT frame buffer
const CHUNK_SIZE: usize = 1 * 1024;

// TODO: Evaulate the need for a hash
// Length, Type, Value, xxhash32 of Type+Value
// u32, u32, [u8; N], u32
fn ltvc(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut hash = hash::Checksum::new();
    hash.update(chunk_type);
    hash.update(data);

    let mut buf: Vec<u8> = Vec::new();

    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(chunk_type);
    buf.extend_from_slice(data);
    buf.extend_from_slice(&hash.finalize().to_le_bytes());

    buf
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
    let mut hash = hash::Checksum::new();
    hash.update(&typ_buf);
    hash.update(dat_buf);

    let whole_len = 4 + 4 + len + 4;

    if hash.finalize()  == old_hash {
        Some((whole_len, typ_buf, dat_buf))
    } else {
        None
    }
}


// TODO: do this better - should be a typed pseudo hash instead of a fake hash
pub fn generate_pack_id() -> hash::Hash {
    // Use a crypto grade random key for the packfile-id
    let id = crypto::gen_key();
    hash::Hash::from(id.0)
}

// Packfile builder
pub struct PackBuilder<W: Write> {
    pub id: hash::Hash,
    idx: Vec<ChunkIdx>,
    inner: W,

    // State bits
    p_idx: usize,
}

// TODO: Make sure we understand security/validation of the serialization deserialization of
// various chunks here
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
            inner: writer,
            p_idx: 0
        };

        // Start with the Archive Header (kinda serves as a magic bits)
        pack.write(&ltvc(b"AHDR", &[0x01])).unwrap();
        pack
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        self.p_idx += data.len();
        self.inner.write(data)
    }

    // Read from pack till EoF then time for next chunk to be added
    // TODO: to force ourself to handle sequence of EDAT for now use small
    // chunk size such as 1024
    pub fn append<R: Read>(&mut self, hash: hash::Hash, reader: &mut R) {
        // Dump the FHDR chunk first
        self.write(&ltvc(b"FHDR", hash.as_bytes())).unwrap();

        // EDAT chunk size
        let mut in_buf = [0u8; CHUNK_SIZE];
        let chunk_idx = self.p_idx;

        loop {
            let (eof, len) = fill_buf(reader, &mut in_buf).unwrap();
            self.write(&ltvc(b"EDAT", &in_buf[..len])).unwrap();

            if eof {
                break;
            }
        }

        self.idx.push(ChunkIdx {
            start_idx: chunk_idx,
            length: self.p_idx - chunk_idx,
            hash: hash,
        });
    }

    // TODO: should hash+hmac various data bits in a packfile
    // Store the hmac hash of the packfile in packfile + snapshot itself.
    pub fn finalize(mut self, key: &crypto::Key) {
        let f_idx = self.p_idx;
        self.write(&ltvc(b"FIDX", &[])).unwrap();

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

        self.write(&ltvc(b"EDAT", &buf[..])).unwrap();

        // Dump the AEND chunk
        self.write(&ltvc(b"AEND", &(f_idx as u32).to_le_bytes())).unwrap();

        // Flush to signal to the backend that its done
        self.inner.flush().unwrap();
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

impl PackOut {
    pub fn load<R: Read>(reader: &mut R, key: &crypto::Key) -> Self {
        let mut buf: Vec<u8> = Vec::new();
        copy(reader, &mut buf).unwrap();

        println!("\t\t\tBuf.len: {:?}", buf.len());

        // Current AEND is 16 bytes
        // TODO: make this more intelligent
        let (_, typ, aend_dat) = read_ltvc(&buf[buf.len()-16..buf.len()]).unwrap();
        if &typ == b"AEND" {
            println!("\t\t\tAEND parsing");
        }

        let i_idx = {
            let idx_buf:  [u8; 4]  = aend_dat[0..4].try_into().unwrap();
            u32::from_le_bytes(idx_buf) as usize
        };

        println!("\t\t\tIndex offset: {:?}", i_idx);
        println!("\t\t\tbuf-len: {:?}", buf.len());

        // FIDX is 12 bytes, ingest that
        let (_, typ, _) = read_ltvc(&buf[i_idx..(i_idx+12)]).unwrap();
        if &typ == b"FIDX" {
            println!("\t\t\tFIDX parsing");
        }

        // Fetch the EDAT
        let (_, typ, edat) = read_ltvc(&buf[(i_idx+12)..]).unwrap();
        if &typ == b"EDAT" {
            println!("\t\t\tEDAT parsing");
        }
        let mut dec = crypto::decrypt(&key, edat).unwrap();
        let mut und = Decoder::new(&mut dec).unwrap();

        let mut idx_buf: Vec<u8> = Vec::new();
        copy(&mut und, &mut idx_buf).unwrap();

        // Deserialize the index
        let chunk_idx: Vec<ChunkIdx> = bincode::deserialize(&idx_buf).unwrap();

        println!("\t\t\tChunk len: {:?}", chunk_idx.len());

        PackOut {
            idx: chunk_idx,
            buf: buf,
        }
    }

    pub fn find(&self, hash: hash::Hash) -> Option<Vec<u8>> {
        for c in self.idx.iter() {
            if c.hash == hash {
                let mut buf: Vec<u8> = Vec::new();
                buf.extend_from_slice(&self.buf[c.start_idx..(c.start_idx+c.length)]);

                println!("\t\tFound! for {:?}", hash::to_hex(&hash));
                println!("\t\t\tCached idx: {:?}, length: {:?}", c.start_idx, c.length);
                println!("\t\t\tActual idx: {:?}, End idx: {:?}", c.start_idx, (c.start_idx+c.length));
                println!("\t\t\tbuf: {:?}", buf.len());

                println!("\t\t\tunpack EDAT");
                let mut out_buf: Vec<u8> = Vec::new();
                let mut out_idx: usize = 0;

                while out_idx != buf.len() {
                    let (read_len, _typ, edat_dat) = read_ltvc(&buf[out_idx..]).unwrap();
                    out_idx += read_len;
                    out_buf.extend(edat_dat);

                    println!(
                        "\t\t\tEDAT read: rlen: {:?}, left: {:?}, total: {:?}, cur_out_len: {:?}",
                        read_len, buf.len()-out_idx, buf.len(), out_buf.len());
                }

                return Some(out_buf);
            }
        }
        None
    }
}
