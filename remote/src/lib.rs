#[cfg(feature = "sql")]
pub mod sql;

#[cfg(feature = "s3")]
pub mod s3;

use std::fmt;
use std::io::{Read, Write};

use rcore::hash;

// Main types of files being stored
#[derive(Clone, Copy)]
pub enum Typ {
    Map,
    Index,
    Pack,

    // Test only, for storing testing related stuff
    // TODO: REMOVE
    TEST,
}

impl fmt::Display for Typ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Typ::Map => write!(f, "map"),
            Typ::Index => write!(f, "index"),
            Typ::Pack => write!(f, "pack"),
            Typ::TEST => write!(f, "TEST"),
        }
    }
}

pub trait Remote {
    fn list_keys(&self, typ: Typ) -> Result<Box<dyn Iterator<Item = String>>, String>;

    // Api for reading/writing filenames
    fn write_filename<R: Read>(&self, typ: Typ, filename: &str, reader: R) -> Result<(), String>;
    fn read_filename(&mut self, typ: Typ, filename: &str) -> Result<Box<dyn Read>, String>;

    // Api for reading/Writing hashes to the remote
    fn write<R: Read>(&self, typ: Typ, key: &hash::Hash, reader: R) -> Result<(), String> {
        self.write_filename(typ, &hash::to_hex(key), reader)
    }
    fn read(&mut self, typ: Typ, key: &hash::Hash) -> Result<Box<dyn Read>, String> {
        self.read_filename(typ, &hash::to_hex(key))
    }

    // Write Multipart, give a write handle and it will handle the streaming
    // TODO: consider if finalize on a trait is better than 'flush' for our purposes
    fn write_multi_filename(&self, typ: Typ, key: &str) -> Result<Box<dyn Write>, String>;

    fn write_multi(&self, typ: Typ, key: &hash::Hash) -> Result<Box<dyn Write>, String> {
        self.write_multi_filename(typ, &hash::to_hex(key))
    }
}
