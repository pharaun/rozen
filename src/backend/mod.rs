pub mod mem;
pub mod s3;

use std::io::Read;

use crate::hash;

pub trait Backend {
    fn list_keys(&self) -> Result<Box<dyn Iterator<Item = String>>, String>;

    // Api for reading/writing filenames
    fn write_filename<R: Read>(&self, filename: &str, reader: R) -> Result<(), String>;
    fn read_filename(&mut self, filename: &str) -> Result<Box<dyn Read>, String>;

    // Api for reading/Writing hashes to the backend
    fn write<R: Read>(&self, key: &hash::Hash, reader: R) -> Result<(), String>;
    fn read(&mut self, key: &hash::Hash) -> Result<Box<dyn Read>, String>;

    // Multipart writes - This should begin a multipart
    fn multi_write(&self, key: &hash::Hash) -> Result<Box<dyn MultiPart>, String>;
}

pub trait MultiPart {
    fn write(&mut self, reader: &mut dyn Read) -> Result<(), String>;
    fn finalize(self: Box<Self>) -> Result<(), String>;
}
