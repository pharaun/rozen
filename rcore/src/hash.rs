use std::convert::TryInto;
use std::fmt;
use std::io::{copy, Read};

use std::hash::Hash as StdHash;
use std::hash::Hasher as StdHasher;
use twox_hash::XxHash32;

use serde::de::{self, Unexpected, Visitor};
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::key;

// Make the checksum api be similiar to blake3's
pub struct Checksum(XxHash32);

impl Checksum {
    pub fn new() -> Checksum {
        // TODO: Evaulate seed of 0, might be better to start with a non-zero seed
        // (verify that feeding a sequence of 0 doesn't end up with the checksum being 0)
        // (Check ordering ie 0x00 + 0x01 vs 0x01 + 0x00 == same checksum for eg)
        Checksum(XxHash32::with_seed(0))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.write(data);
    }

    pub fn finalize(self) -> u32 {
        self.0.finish() as u32
    }
}

// TODO: improve the blake hash wrap
#[derive(PartialEq, Eq, Clone, Debug, StdHash)]
pub struct Hash(blake3::Hash);

// TODO: Should require a 'hash type' here so that we can know
// the providence of the hash (file, blob, etc...)
// 1. File - F type
// 2. Index - I type
// 3. Packfile - P Type
// 4. Mapper - M Type
pub fn hash<R: Read>(key: &key::MemKey, data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = blake3::Hasher::new_keyed(&key.hmac_key().0);
    copy(data, &mut hash)?;
    Ok(Hash(hash.finalize()))
}

// To encapsulate the hash engine used
pub fn from_hex(hash: &str) -> Result<Hash, blake3::HexError> {
    blake3::Hash::from_hex(hash).map(Hash)
}

pub fn to_hex(hash: &Hash) -> String {
    hash.0.to_hex().to_string()
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(blake3::Hash::from(bytes))
    }
}

impl Hash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

// Serde impls
impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

struct HashVisitor;

impl<'de> Visitor<'de> for HashVisitor {
    type Value = Hash;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a byte array containing 32 bytes")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        if v.len() == 32 {
            let mut hash_bytes: [u8; 32] = [0; 32];
            hash_bytes.clone_from_slice(v);
            Ok(Hash::from(hash_bytes))
        } else {
            Err(de::Error::invalid_value(Unexpected::Bytes(v), &self))
        }
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        v.try_into().map_or_else(
            |v: Vec<u8>| Err(de::Error::invalid_value(Unexpected::Bytes(&v), &self)),
            |hash_bytes: [u8; 32]| Ok(Hash::from(hash_bytes)),
        )
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Hash, D::Error> {
        deserializer.deserialize_byte_buf(HashVisitor)
    }
}
