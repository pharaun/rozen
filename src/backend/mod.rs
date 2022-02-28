pub mod mem;
pub mod s3;

use std::io::Read;

pub trait Backend {
    fn list_keys(&self) -> Result<Box<dyn Iterator<Item = String>>, String>;
    fn write<R: Read>(&self, key: &str, reader: R) -> Result<(), String>;
    fn read(&mut self, key: &str) -> Result<Box<dyn Read>, String>;

    // Multipart writes - This should begin a multipart
    fn multi_write(&self, key: &str) -> Result<Box<dyn MultiPart>, String>;
}

pub trait MultiPart {
    fn write(&mut self, reader: &mut dyn Read) -> Result<(), String>;
    fn finalize(self: Box<Self>) -> Result<(), String>;
}
