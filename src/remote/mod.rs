pub mod mem;
pub mod s3;

use std::io::{Read, Write};

use crate::hash;

pub trait Remote {
    fn list_keys(&self) -> Result<Box<dyn Iterator<Item = String>>, String>;

    // Api for reading/writing filenames
    fn write_filename<R: Read>(&self, filename: &str, reader: R) -> Result<(), String>;
    fn read_filename(&mut self, filename: &str) -> Result<Box<dyn Read>, String>;

    // Api for reading/Writing hashes to the remote
    fn write<R: Read>(&self, key: &hash::Hash, reader: R) -> Result<(), String> {
        self.write_filename(&hash::to_hex(key), reader)
    }
    fn read(&mut self, key: &hash::Hash) -> Result<Box<dyn Read>, String> {
        self.read_filename(&hash::to_hex(key))
    }

    // Write Multipart, give a write handle and it will handle the streaming
    // TODO: consider if finalize on a trait is better than 'flush' for our purposes
    fn write_multi_filename(&self, key: &str) -> Result<Box<dyn Write>, String>;

    fn write_multi(&self, key: &hash::Hash) -> Result<Box<dyn Write>, String> {
        self.write_multi_filename(&hash::to_hex(key))
    }
}
