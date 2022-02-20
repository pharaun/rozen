use std::io::{Read, copy};
use vfs::{VfsPath, MemoryFS};

use crate::backend::Backend;

pub struct MemoryVFS {
    root: VfsPath
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

    fn write<R: Read>(&self, key: &str, mut reader: R) -> Result<(), String> {
        let path = self.root
            .join("data").expect("data-dir")
            .join(key).expect("data-dir/key-file");

        let mut write_to = path.create_file().map_err(|err| err.to_string())?;
        copy(&mut reader, &mut write_to).unwrap();
        Ok(())
    }

    fn read(&mut self, key: &str) -> Result<Box<dyn Read>, String> {
        let path = self.root
            .join("data").expect("data-dir")
            .join(key).expect("data-dir/key-file");

        match path.open_file() {
            Ok(f)  => Ok(Box::new(f)),
            Err(e) => Err(e.to_string()),
        }
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
