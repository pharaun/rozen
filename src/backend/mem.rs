use std::io::{Read, Write, copy};
use vfs::{VfsPath, MemoryFS};

use crate::backend::Backend;
use crate::backend::MultiPart;
use crate::hash;

pub struct MemoryVFS {
    root: VfsPath
}

pub struct MemoryWrite {
    inner: Box<dyn Write>
}

impl MemoryVFS {
    pub fn new() -> Self {
        let root: VfsPath = MemoryFS::new().into();
        root.join("data").unwrap()
            .create_dir().unwrap();

        MemoryVFS {
            root: root,
        }
    }
}

impl Backend for MemoryVFS {
    fn list_keys(&self) -> Result<Box<dyn Iterator<Item = String>>, String>{
        Ok(Box::new(
            self.root
                .join("data").expect("data-dir")
                .read_dir()
                .unwrap()
                .map(move |path| path.as_str().to_string().replace("/data/", ""))
        ))
    }

    fn write_filename<R: Read>(&self, filename: &str, mut reader: R) -> Result<(), String> {
        let path = self.root
            .join("data").expect("data-dir")
            .join(filename).expect("data-dir/key-file");

        let mut write_to = path.create_file().map_err(|err| err.to_string())?;
        copy(&mut reader, &mut write_to).unwrap();
        Ok(())
    }

    fn read_filename(&mut self, filename: &str) -> Result<Box<dyn Read>, String> {
        let path = self.root
            .join("data").expect("data-dir")
            .join(filename).expect("data-dir/key-file");

        match path.open_file() {
            Ok(f)  => Ok(Box::new(f)),
            Err(e) => Err(e.to_string()),
        }
    }

    fn write<R: Read>(&self, key: &hash::Hash, reader: R) -> Result<(), String> {
        self.write_filename(
            &hash::to_hex(key),
            reader
        )
    }

    fn read(&mut self, key: &hash::Hash) -> Result<Box<dyn Read>, String> {
        self.read_filename(
            &hash::to_hex(key),
        )
    }

    fn multi_write(&self, key: &hash::Hash) -> Result<Box<dyn MultiPart>, String> {
        let path = self.root
            .join("data").expect("data-dir")
            .join(&hash::to_hex(key)).expect("data-dir/key-file");

        let write_to = path.create_file().map_err(|err| err.to_string())?;

        Ok(Box::new(MemoryWrite {
            inner: Box::new(write_to)
        }))
    }

    fn write_multi(&self, key: &hash::Hash) -> Result<Box<dyn Write>, String> {
        let path = self.root
            .join("data").expect("data-dir")
            .join(&hash::to_hex(key)).expect("data-dir/key-file");

        let write_to = path.create_file().map_err(|err| err.to_string())?;

        Ok(Box::new(write_to))
    }
}

impl MultiPart for MemoryWrite {
    fn write(&mut self, reader: &mut dyn Read) -> Result<(), String> {
        copy(reader, &mut self.inner).unwrap();
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<(), String> {
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use crate::backend::mem::MemoryVFS;
    use crate::backend::mem::Backend;
    use std::io::Cursor;

    #[test]
    fn basic_read_write() {
        let mut back = MemoryVFS::new();
        let key = "test-key";

        let data: &[u8; 9] = b"Test Data";
        let b = Cursor::new(data);
        back.write(key, b).unwrap();

        let mut val = String::new();
        back.read(key).unwrap()
            .read_to_string(&mut val).unwrap();

        assert_eq!(val, "Test Data");
    }

    #[test]
    fn overwrite_read_write() {
        let mut back = MemoryVFS::new();
        let key = "test-key";

        let data: &[u8; 9] = b"Test Data";
        let b = Cursor::new(data);
        back.write(key, b).unwrap();

        let data: &[u8; 9] = b"Data Test";
        let b = Cursor::new(data);
        back.write(key, b).unwrap();

        let mut val = String::new();
        back.read(key).unwrap()
            .read_to_string(&mut val).unwrap();

        assert_eq!(val, "Data Test");
    }
}
