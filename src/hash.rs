use std::io::{Read, copy};

use blake3::Hasher;
use blake3::Hash;
use blake3::HexError;

use twox_hash::XxHash32;
use std::hash::Hasher as StdHasher;
use crate::crypto;

pub fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}

pub fn from_hex(hash: &str) -> Result<Hash, HexError> {
    Hash::from_hex(hash)
}

pub struct XxHash {
    hash: XxHash32,
}

impl XxHash {
    pub fn new() -> XxHash {
        XxHash {
            hash: XxHash32::with_seed(0),
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.hash.write(data);
    }

    pub fn finish(mut self) -> u32 {
        self.hash.finish() as u32
    }
}
