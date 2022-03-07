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


// TODO: do better index and avoid (?) the buffering here
// 1. Have one for on the fly reading from S3 via range request/etc
// 2. Have one for on the fly writing to S3/backend via whatever
// 3. Make sure we understand security/validation of the serialization
//  deserialization of various chunks here
// 4. For on the fly pack writing have the packfile read in as far as it can
//  on each file then once it hits an capacity threshold it stops and asks to
//  be finalized for shipping off to S3
//      - Use a crypto grade random key for the packfile-id
//      - Store the hmac hash of the packfile in packfile + snapshot itself.
//      - We need a identifier for the packfile but we don't need it to be a hash
//      - Snapshot will be '<packfile-id>:<hash-id>' to pull out the content or
//          can just be a list of <hash-id> then another list of <packfile-id> with <hash-id>s
//  * Need to use some non-hash identifier cos of S3 and avoiding buffing/spooling to disk
//  * https://docs.rs/tempfile/3.3.0/tempfile/fn.spooled_tempfile.html
pub struct PackIn<R: Read> {
    pub id: String,
    idx: Vec<ChunkIdx>,

    // TODO: Not sure how to hold state bits yet
    finalized: Option<Vec<u8>>,
    p_idx: usize,

    // TODO: probs should be its own data structure to manage the chunk bits
    cur_chunk: Option<ChunkState<R>>,
}

struct ChunkState<R: Read> {
    hash: String,
    inner: R,
    len: usize,
    idx: usize,
}

#[derive(Serialize, Deserialize)]
struct ChunkIdx {
    start_idx: usize,
    length: usize,
    hash: String,
}

impl<R: Read> PackIn<R> {
    pub fn new() -> Self {
        let id = crypto::gen_key();
        PackIn {
            id: hex::encode(id),
            idx: Vec::new(),
            finalized: None,
            p_idx: 0,
            cur_chunk: None,
        }
    }

    // TODO: should have integrity check to make sure the current reader is
    // done (aka unset otherwise it errors)
    pub fn write(&mut self, hash: &str, reader: R) {
        self.cur_chunk = Some(ChunkState {
            hash: hash.to_string(),
            inner: reader,
            len: 0,
            idx: self.p_idx,
        });
    }

    // TODO: should hash+hmac various data bits in a packfile
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

// Read from pack till EoF then time for next chunk to be added
// TODO: add chunk header+trailer
impl<R: Read> Read for PackIn<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(chunk) = self.cur_chunk.as_mut() {
            // Read from chunk reader till done
            let c_len = chunk.inner.read(buf).unwrap();

            // Manage the len and update p_idx
            self.p_idx += c_len;
            chunk.len += c_len;

            // Check if we hit EOF?
            if c_len == 0 {
                // We hit eof of the underlaying file
                self.idx.push(ChunkIdx {
                    start_idx: chunk.idx,
                    length: chunk.len,
                    hash: chunk.hash.clone(),
                });
                self.cur_chunk = None;
            }

            Ok(c_len)
        } else if let Some(f_buf) = self.finalized.as_mut() {
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
            // We aren't finalized but we don't have further data yet
            // Return EOF
            Ok(0)
        }
    }
}


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
            let idx_buf: [u8; 4]   = (&buf[(buf.len()-(64 + 8))..]).try_into().unwrap();
            let len_buf: [u8; 4]   = (&buf[(buf.len()-(64 + 4))..]).try_into().unwrap();
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
        let chunk_idx: Vec<ChunkIdx> = bincode::deserialize(idx_buf).unwrap();

        println!("Chunk len: {:?}", chunk_idx.len());

        PackOut {
            idx: chunk_idx,
            buf: buf,
        }
    }

    pub fn find(&self, hash: &str) -> Option<Vec<u8>> {
        for c in self.idx.iter() {
            if c.hash == hash {
                let mut buf: Vec<u8> = Vec::new();
                buf.copy_from_slice(&self.buf[c.start_idx..(c.start_idx+c.length)]);
                return Some(buf);
            }
        }
        None
    }
}


















pub struct Pack {
    id: String,
    chunk: Vec<Chunk>
}

struct Chunk {
    buf: Vec<u8>,
    hash: String,
}

impl Pack {
    pub fn new() -> Self {
        let id = crypto::gen_key();
        Pack {
            id: hex::encode(id),
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
        // TODO; improve the index, it should list the hash + start+end offset of the data
        // This will then avoid another indirection (ie eof -> index -> chunk-eof -> chunk data)
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

        // TODO: should record the hash after the index offpoint so that it can validate everything
        println!("merkle pack hash: {:?}", ret_hash);

        // Return it
        (self.id, buf)
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

        for i in 0..count {
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

        // TODO: should get the pack id
        let id = crypto::gen_key();
        Pack {
            id: hex::encode(id),
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
// TODO: can probs make it into a hash struct so we dont need to pass the key around
fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}
