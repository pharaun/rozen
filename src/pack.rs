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
//! TODO: ideally it would be like
//!
//! header, chunk, index, trailer
//!
//! TODO: Do we want version in trailer and header? if version is in trailer can
//! read trailer bytes to verify the version+index, then proceed to unpack the pack using
//! seeks for s3 without having to read the header then the trailer
//!
//! TODO: Consider it from 2 pov, streaming (read front to end) where you read
//! the header, then process each chunk one by one, also from fetch pov where you
//! read trailer then fetch just the chunk's data you care about. support both case
//!
//! Magic
//! Pack Header - first chunk
//! data header - second chunk onward
//! index header - second to last chunk
//! trailer header - last chunk
//!
//! PNG is for each chunk:
//!     length, type, [data], crc
//!     Probs can employ the same png chunking/etc for other file format (ie stand alone blobs etc)
//!
//!     todo: understand the encryption bit it might become:
//!     Enc len (4096, type, data, checksum) for all except last which is less than 4096?
//!     Do we want to pad so its always 4 kilobytes, may want to consider 64 kilobytes instead?
//!         - can we turn it into a const gentrics that let the N be defined to a const such as 4096
//!     Is this information leak?
//!     do we always mandate reading from index first then streaming from the index? (requires
//!     seekability storage) possible to reconstruct index upon truncation or data stream damage?
//!     Could always just fix the chunk at some chunk size for streamability and allow things to
//!     cross boundaries.
//!
//!     I think i want to use the file HMAC for additional data with encryption so we can ensure
//!     that the encrypted data is also assocated with the correct plaintext keyed hmac
//!
//!     One way to consider information leak is pack file is purely an optimization for glacier
//!     store in which the index can be stored in S3 + packfile, and the specified byte range be
//!     fetched out of glacier. This leads me to interpret any information leak is also the same
//!     as a stand-alone blob in glacier store so... treat both the same. packfile == packed blobs
//!
//!     Now mind you there *is* information leak via the length cos of compression/plaintext but
//!     blob storage would have this as well so resolving blob storage + etc will be good to have
//!     also this is more for chunked data ala borg/restic/etc
//!
//!
//! header = magic || version
//!     magic = b"rozen-pack" (consider rozepack -> u64)
//! chunk = data (has encryption tags to validate + compression and inner hashes)
//! index = hmac? || enc+comp(data) (need hmac if encryption+compression validates?)
//! trailer = index offset
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
use blake3::Hasher;
use blake3::Hash;
use std::convert::TryInto;
use std::str::from_utf8;
use hex;
use serde::Serialize;
use serde::Deserialize;
use bincode;

use crate::crypto;

// Attempt to on the fly write chunks into a packfile to a backend
pub struct PackIn {
    pub id: String,
    idx: Vec<ChunkIdx>,

    // TODO: Not sure how to hold state bits yet
    finalized: Option<Vec<u8>>,
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

impl PackIn {
    // Use a crypto grade random key for the packfile-id
    pub fn new() -> Self {
        let id = crypto::gen_key();
        PackIn {
            id: hex::encode(id),
            idx: Vec::new(),
            finalized: None,
            p_idx: 0,
        }
    }

    // TODO: should have integrity check to make sure the current reader is
    // done (aka unset otherwise it errors)
    pub fn begin_write<R: Read>(&mut self, hash: &str, reader: R) -> ChunkState<R> {
        ChunkState {
            hash: hash.to_string(),
            inner: reader,
            len: 0,
            idx: self.p_idx,
            finished: false,
        }
    }

    pub fn finish_write<R: Read>(&mut self, chunk: ChunkState<R>) {
        self.idx.push(ChunkIdx {
            start_idx: chunk.idx,
            length: chunk.len,
            hash: chunk.hash.clone(),
        });
        self.p_idx += chunk.len;
    }

    // TODO: should hash+hmac various data bits in a packfile
    // Store the hmac hash of the packfile in packfile + snapshot itself.
    pub fn finalize(&mut self, key: &crypto::Key) {
        // [ChunkIdx..] idx_pointer, len, hash
        let mut buf: Vec<u8> = Vec::new();
        let index = bincode::serialize(&self.idx).unwrap();
        buf.extend_from_slice(&index[..]);

        // Write pointer + len + hash
        buf.extend_from_slice(
            &(self.p_idx as u32).to_le_bytes()
        );
        buf.extend_from_slice(
            &(index.len() as u32).to_le_bytes()
        );

        let mut hash_buf = &index[..];
        buf.extend_from_slice(
            hash(key, &mut hash_buf).unwrap().to_hex().to_string().as_bytes()
        );

        self.finalized = Some(buf);
    }
}

impl Read for PackIn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(f_buf) = self.finalized.as_mut() {
            if f_buf.is_empty() {
                // Its done, go home
                Ok(0)
            } else {
                // Write out what we can
                let split_at = cmp::min(f_buf.len(), buf.len());
                let dat: Vec<u8> = f_buf.drain(0..split_at).collect();
                buf[0..split_at].copy_from_slice(&dat[..]);

                Ok(dat.len())
            }
        } else {
            Ok(0)
        }
    }
}

pub struct ChunkState<R: Read> {
    hash: String,
    inner: R,
    len: usize,
    idx: usize,
    finished: bool,
}

// Read from pack till EoF then time for next chunk to be added
// TODO: add chunk header+trailer
impl<R: Read> Read for ChunkState<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.finished {
            // Read from chunk reader till done
            let c_len = self.inner.read(buf).unwrap();

            // Manage the len and update p_idx
            self.len += c_len;

            // Check if we hit EOF?
            if c_len == 0 {
                // We hit eof of the underlaying file
                self.finished = true;
            }

            Ok(c_len)
        } else {
            // We aren't finalized but we don't have further data yet
            Ok(0)
        }
    }
}


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

        println!("Buf.len: {:?}", buf.len());

        // Index, index length, index hash
        let (i_idx, i_len, i_hash) = {
            let idx_buf:  [u8; 4]  = (&buf[(buf.len()-(64 + 8))..(buf.len()-(64 + 4))]).try_into().unwrap();
            let len_buf:  [u8; 4]  = (&buf[(buf.len()-(64 + 4))..(buf.len()-(64 + 0))]).try_into().unwrap();
            let hash_buf: [u8; 64] = (&buf[(buf.len()-(64 + 0))..]).try_into().unwrap();

            (
                u32::from_le_bytes(idx_buf) as usize,
                u32::from_le_bytes(len_buf) as usize,
                from_utf8(&hash_buf).unwrap().to_string(),
            )
        };

        println!("Index offset: {:?}", i_idx);
        println!("Index length: {:?}", i_len);
        println!("Index hash: {:?}", i_hash);

        // Ingest the index then validate the hash
        let mut idx_buf: &[u8] = &buf[i_idx..(i_idx+i_len)];

        // TODO: convert both back to actual hash
        let new_i_hash = hash(key, &mut idx_buf).unwrap().to_hex().to_string();

        println!("New Index hash: {:?}", new_i_hash);
        println!("Equal hash: {:?}", i_hash == new_i_hash);

        // Deserialize the index
        let mut idx_buf: &[u8] = &buf[i_idx..(i_idx+i_len)];
        let chunk_idx: Vec<ChunkIdx> = bincode::deserialize(idx_buf).unwrap();

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
                return Some(buf);
            }
        }
        None
    }
}

// copy paste from main.rs for now
// TODO: can probs make it into a hash struct so we dont need to pass the key around
fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}
