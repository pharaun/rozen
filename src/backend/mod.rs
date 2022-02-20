pub mod mem;
pub mod s3;

use std::io::Write;
use std::io::Read;

pub trait Backend {
    fn list_keys(&self) -> Result<Box<dyn Iterator<Item = String>>, String>;
    fn write(&self, key: &str) -> Result<Box<dyn Write>, String>;
    fn read(&mut self, key: &str) -> Result<Box<dyn Read>, String>;
}
