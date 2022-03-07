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
