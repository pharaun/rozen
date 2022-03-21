use std::io::{Read, copy};

use blake3::Hasher;
use blake3::Hash;
use blake3::HexError;

use twox_hash::XxHash32;
use std::hash::Hasher as StdHasher;
use crate::crypto;


// Make the checksum api be similiar to blake3's
pub struct Checksum (XxHash32);

impl Checksum {
    pub fn new() -> Checksum {
        Checksum(XxHash32::with_seed(0))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.write(data);
    }

    pub fn finalize(self) -> u32 {
        self.0.finish() as u32
    }
}


// TODO: Should require a 'hash type' here so that we can know
// the providence of the hash (file, blob, etc...)
pub fn hash<R: Read>(key: &crypto::Key, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key.0);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}

// To encapsulate the hash engine used
pub fn from_hex(hash: &str) -> Result<Hash, HexError> {
    Hash::from_hex(hash)
}
