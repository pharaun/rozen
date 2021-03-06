use rusqlite as rs;
use rusqlite::Connection;
use iter_read::IterRead;
use std::io::{Read, Write, Cursor};

// Single threaded but we are on one thread here for now
use std::rc::Rc;

use crate::backend::Backend;
use crate::hash;
use crate::buf::fill_buf;

const CHUNK_SIZE: usize = 1 * 1024;

pub struct MemoryVFS {
    conn: Rc<Connection>,
}

impl MemoryVFS {
    pub fn new(filename: Option<&str>) -> Self {
        let conn = match filename {
            None    => Connection::open_in_memory().unwrap(),
            Some(f) => Connection::open(f).unwrap(),
        };

        // Setup the db
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE blob (
                key VARCHAR NOT NULL,
                chunk INTEGER NOT NULL,
                content BLOB NOT NULL,
                UNIQUE(key, chunk)
             );
             COMMIT;"
        ).unwrap();

        MemoryVFS {
            conn: Rc::new(conn)
        }
    }
}

impl Backend for MemoryVFS {
    fn list_keys(&self) -> Result<Box<dyn Iterator<Item = String>>, String>{
        let mut stmt = self.conn.prepare("SELECT DISTINCT key FROM blob").unwrap();
        Ok(Box::new(stmt.query_map([], |row| {
                let x: String = row.get(0).unwrap();
                Ok(x)
            }).unwrap().map(|item| {
                item.unwrap()
            }).collect::<Vec<String>>().into_iter()
        ))
    }

    fn write_filename<R: Read>(&self, filename: &str, reader: R) -> Result<(), String> {
        write_filename(
            self.conn.clone(),
            filename,
            reader
        )
    }

    fn read_filename(&mut self, filename: &str) -> Result<Box<dyn Read>, String> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT content
             FROM blob
             WHERE key = ?
             ORDER BY chunk ASC"
        ).unwrap();

        Ok(Box::new(IterRead::new(
            stmt.query_map(rs::params![filename], |row| {
                let x: Vec<u8> = row.get(0).unwrap();
                Ok(x)
            }).unwrap().map(|item| {
                item.unwrap()
            }).flatten().collect::<Vec<u8>>().into_iter()
        )))
    }

    fn write_multi(&self, key: &hash::Hash) -> Result<Box<dyn Write>, String> {
        Ok(Box::new(VFSWrite {
            conn: self.conn.clone(),
            key: key.clone(),
            t_buf: Vec::new(),
        }))
    }
}

struct VFSWrite {
    conn: Rc<Connection>,
    key: hash::Hash,
    t_buf: Vec<u8>,
}

impl Write for VFSWrite {
    fn write(&mut self, in_buf: &[u8]) -> Result<usize, std::io::Error> {
        self.t_buf.extend(in_buf);
        Ok(in_buf.len())
    }

    // TODO: not sure if this is proper use of flush or if we should have a finalize call instead
    fn flush(&mut self) -> Result<(), std::io::Error> {
        let data = Cursor::new(self.t_buf.clone());
        write_filename(
            self.conn.clone(),
            &hash::to_hex(&self.key),
            data
        ).unwrap();
        Ok(())
    }
}

fn write_filename<R: Read>(conn: Rc<Connection>, filename: &str, mut reader: R) -> Result<(), String> {
    // Delete any key chunks that exists before
    conn.prepare_cached(
        "DELETE FROM blob WHERE key = ?"
    ).unwrap().execute(rs::params![filename]).unwrap();

    // Insert new data
    let mut chunk_idx: i64 = 0;

    loop {
        let mut in_buf = [0u8; CHUNK_SIZE];
        match fill_buf(&mut reader, &mut in_buf).unwrap() {
            (true, 0) => break,
            (_, len)  => {
                // Write a new chunk to the db
                let mut file_stmt = conn.prepare_cached(
                    "INSERT INTO blob
                     (key, chunk, content)
                     VALUES
                     (?, ?, ?)"
                ).unwrap();

                file_stmt.execute(rs::params![
                    filename,
                    chunk_idx,
                    &in_buf[..len],
                ]).unwrap();

                chunk_idx += 1;
            },
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use crate::backend::mem::MemoryVFS;
    use crate::backend::mem::Backend;
    use std::io::Cursor;

    #[test]
    fn basic_read_write() {
        let mut back = MemoryVFS::new(None);
        let key = "test-key";

        let data: &[u8; 9] = b"Test Data";
        let b = Cursor::new(data);
        back.write_filename(key, b).unwrap();

        let mut val = String::new();
        back.read_filename(key).unwrap()
            .read_to_string(&mut val).unwrap();

        assert_eq!(val, "Test Data");
    }

    #[test]
    fn overwrite_read_write() {
        let mut back = MemoryVFS::new(None);
        let key = "test-key";

        let data: &[u8; 9] = b"Test Data";
        let b = Cursor::new(data);
        back.write_filename(key, b).unwrap();

        let data: &[u8; 9] = b"Data Test";
        let b = Cursor::new(data);
        back.write_filename(key, b).unwrap();

        let mut val = String::new();
        back.read_filename(key).unwrap()
            .read_to_string(&mut val).unwrap();

        assert_eq!(val, "Data Test");
    }
}
