use std::io::{copy, Read};
use blake3::Hasher;
use blake3::Hash;
use std::convert::TryInto;

use crate::crypto;


// TODO: do better index and avoid (?) the buffering here
// 1. Have one for on the fly reading from S3 via range request/etc
// 2. Have one for on the fly writing to S3/backend via whatever
pub struct Pack {
    chunk: Vec<Chunk>
}

struct Chunk {
    buf: Vec<u8>,
    hash: String,
}

impl Pack {
    pub fn new() -> Self {
        Pack {
            chunk: Vec::new(),
        }
    }

    pub fn finalize(self, key: &crypto::Key) -> (String, Vec<u8>) {
        let mut buf: Vec<u8> = Vec::new();
        let mut idx: Vec<(String, u32)> = Vec::new();

        for v in self.chunk.into_iter() {
            // Simple header, Length then data
            let len = v.buf.len() as u32;
            let chunk_idx = buf.len() as u32;

            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&v.buf[..]);

            // Register index
            idx.push((v.hash, chunk_idx));
        }

        // We are done, now dump the index
        let count = idx.len() as u32;
        let index_idx = buf.len() as u32;

        buf.extend_from_slice(&count.to_le_bytes());
        for (ih, ip) in idx.into_iter() {
            // Dump the hash then u32 pointer
            buf.extend_from_slice(&ih.as_bytes());
            buf.extend_from_slice(&ip.to_le_bytes());

            println!("len hash: {:?}", &ih.as_bytes().len());
        }

        // Dump the last pointer to the index start
        buf.extend_from_slice(&index_idx.to_le_bytes());

        // We need a hash to return - use whole file for now
        // should probs look into merkle tree of hashes stuff
        // TODO: not very good, this is cloning the whole thing bah
        let mut buf_copy = &(buf.clone())[..];
        let ret_hash = hash(key, &mut buf_copy).unwrap().to_hex().to_string();

        // Return it
        (ret_hash, buf)
    }

    pub fn write<R: Read>(&mut self, hash: &str, reader: &mut R) {
        let mut buf: Vec<u8> = Vec::new();
        copy(reader, &mut buf).unwrap();

        self.chunk.push(Chunk {
            buf: buf,
            hash: hash.to_string()
        });
    }

    pub fn read<R: Read>(reader: &mut R) -> Self {
        let mut buf: Vec<u8> = Vec::new();
        copy(reader, &mut buf).unwrap();

        println!("Buf.len: {:?}", buf.len());

        // Index Idx
        let index_idx: usize = {
            let idx_buf: [u8; 4] = (&buf[(buf.len()-4)..]).try_into().unwrap();
            u32::from_le_bytes(idx_buf) as usize
        };

        println!("Index idx: {:?}", index_idx);

        // Read the count of index
        let count: u32 = {
            let count_buf: [u8; 4] = (&buf[index_idx..index_idx+4]).try_into().unwrap();
            u32::from_le_bytes(count_buf)
        };

        println!("Index count: {:?}", count);

        // Read in the actual index
        let mut index: Vec<(String, usize)> = Vec::new();

        // TODO:
        // 1. read in the index string+offset
        // 2. read in each chunk into Chunk
        // 3. stuff it into the pack and then use it

        // Now to parse it out to an actual Pack + Chunk
        Pack {
            chunk: Vec::new()
        }
    }
}

// copy paste from main.rs for now
fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}
