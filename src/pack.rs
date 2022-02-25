use std::io::{copy, Read};
use blake3::Hasher;
use blake3::Hash;
use std::convert::TryInto;
use std::str::from_utf8;

use crate::crypto;


// TODO: do better index and avoid (?) the buffering here
// 1. Have one for on the fly reading from S3 via range request/etc
// 2. Have one for on the fly writing to S3/backend via whatever
// 3. Make sure we understand security/validation of the serialization
//  deserialization of various chunks here
// 4. For on the fly pack writing out could do some sort of bounded queue
//  where if its still below some target number it admits more reads to be
//  added, otherwise it stops and then finalize the stream. Not sure how
//  to do this in a single thread context may have to go multithread here
//  - Main issue is we need an hash of all content hashes before for the name
//  - https://docs.rs/tempfile/3.3.0/tempfile/fn.spooled_tempfile.html
//  - There *IS* a way to do it without spooling, is a tad unorthodox
//      * Hash + size various files, collect them into the pack
//      * Finalize pool (start to read all files refs stored in pack)
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
        for (ih, ip) in idx.iter() {
            // Dump the hash then u32 pointer
            buf.extend_from_slice(&ih.as_bytes());
            buf.extend_from_slice(&ip.to_le_bytes());

            println!("len hash: {:?}", &ih.as_bytes().len());
        }

        // Dump the last pointer to the index start
        buf.extend_from_slice(&index_idx.to_le_bytes());

        // Perform a merkle tree hash (take all content hash, sort it then hash that)
        // TODO: One simple fix is defined in Certificate Transparency: when computing leaf node
        // hashes, a 0x00 byte is prepended to the hash data, while 0x01 is prepended when
        // computing internal node hashes.
        // Data = 0x0, packfile: 0x1, snapshot: 0x2 (snapshot contains hash of all packfiles used)
        // etc...
        let mut hashes: Vec<String> = Vec::new();

        for (h, _) in idx.iter() {
            hashes.push(h.to_string());
        }
        hashes.sort();

        let mut hash_buf: Vec<u8> = Vec::new();
        for h in hashes.iter() {
            hash_buf.extend_from_slice(&h.as_bytes());
        }
        let mut hash_buf = &hash_buf[..];
        let ret_hash = hash(key, &mut hash_buf).unwrap().to_hex().to_string();

        println!("merkle pack hash: {:?}", ret_hash);

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

        for i in (0..count) {
            let i_idx = index_idx+4 + (((64 + 4) * i) as usize);
            println!("i idx: {:?}", i_idx);

            let hash_buf: [u8; 64] = (&buf[i_idx..i_idx+64]).try_into().unwrap();
            let hash = from_utf8(&hash_buf).unwrap();

            let hash_idx: [u8; 4] = (&buf[i_idx+64..i_idx+68]).try_into().unwrap();
            let h_idx = u32::from_le_bytes(hash_idx) as usize;

            println!("hash: {:?}, idx: {:?}", hash.to_string(), h_idx);
            index.push((hash.to_string(), h_idx));
        }

        // Time to use the index to read data into each chunk
        let mut chunk: Vec<Chunk> = Vec::new();

        for (h,i) in index.into_iter() {
            // Index points to size, read it in
            // then read the remaining to a buffer
            let size_buf: [u8; 4] = (&buf[i..i+4]).try_into().unwrap();
            let size = u32::from_le_bytes(size_buf) as usize;

            let data_buf = &buf[i+4..i+4+size];

            println!("size: {:?}, data.len: {:?}", size, data_buf.len());

            chunk.push(Chunk {
                buf: data_buf.to_vec(),
                hash: h,
            });
        }

        Pack {
            chunk: chunk,
        }
    }

    pub fn find(&self, hash: &str) -> Option<Vec<u8>> {
        for c in self.chunk.iter() {
            if c.hash == hash {
                return Some(c.buf.clone())
            }
        }

        None
    }
}

// copy paste from main.rs for now
fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}
