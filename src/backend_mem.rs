use std::io::{Read, Write};

pub trait Backend {
    fn list_keys(&self) -> Result<Box<dyn Iterator<Item = String>>, String>;
    fn write(&self, key: &str) -> Result<Box<dyn Write>, String>;
    fn read(&mut self, key: &str) -> Result<Box<dyn Read>, String>;
}


use vfs::{VfsPath, MemoryFS};

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

    fn write(&self, key: &str) -> Result<Box<dyn Write>, String> {
        let path = self.root
            .join("data").expect("data-dir")
            .join(key).expect("data-dir/key-file");

        path.create_file().map_err(|err| err.to_string())
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
    use crate::backend_mem::MemoryVFS;
    use crate::backend_mem::Backend;

    #[test]
    fn basic_read_write() {
        let mut back = MemoryVFS::new();
        let key = "test-key";

        back.write(key).unwrap()
            .write_all(b"Test Data").unwrap();

        let mut val = String::new();
        back.read(key).unwrap()
            .read_to_string(&mut val).unwrap();

        assert_eq!(val, "Test Data");
    }

    #[test]
    fn overwrite_read_write() {
        let mut back = MemoryVFS::new();
        let key = "test-key";

        back.write(key).unwrap()
            .write_all(b"Test Data").unwrap();

        back.write(key).unwrap()
            .write_all(b"Data Test").unwrap();

        let mut val = String::new();
        back.read(key).unwrap()
            .read_to_string(&mut val).unwrap();

        assert_eq!(val, "Data Test");
    }
}
