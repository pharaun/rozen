use rusqlite as rs;

use std::io::{Seek, SeekFrom, copy, Read};
use rusqlite::Connection;
use std::collections::HashSet;

use crate::hash;

pub struct Index {
    file: std::fs::File,
    // Don't use this but we need to keep it around till we are done with the db
    _path: tempfile::TempPath,
    conn: Connection,
}

impl Index {
    pub fn new() -> Self {
        let (file, path) = tempfile::NamedTempFile::new().unwrap().into_parts();
        let conn = Connection::open(&path).unwrap();
        // TODO: can't remove file path (sqlite seems to depend on it)
        //s_path.close().unwrap();

        // Setup the db
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE files (
                path VARCHAR NOT NULL,
                permission INTEGER NOT NULL,
                pack_hash VARCHAR NOT NULL,
                content_hash VARCHAR NOT NULL
             );
             COMMIT;"
        ).unwrap();

        Index {
            file,
            _path: path,
            conn
        }
    }

    // TODO: improve the types
    pub fn insert_file(
        &self,
        path: &std::path::Path,
        packs: HashSet<hash::Hash>,
        hash: &hash::Hash
    ) {
        let mut file_stmt = self.conn.prepare_cached(
            "INSERT INTO files
             (path, permission, pack_hash, content_hash)
             VALUES
             (?, ?, ?, ?)"
        ).unwrap();

        // Load file into index
        file_stmt.execute(rs::params![
            format!("{}", path.display()),
            0000,
            packs.into_iter().map(|h| hash::to_hex(&h)).collect::<Vec<String>>().join(","),
            hash::to_hex(hash),
        ]).unwrap();
    }

    pub fn walk_files<F>(&self, mut f: F)
    where
        F: FnMut(&str, u32, HashSet<hash::Hash>, hash::Hash)
    {
        let mut dump_stmt = self.conn.prepare_cached(
            "SELECT path, permission, pack_hash, content_hash FROM files"
        ).unwrap();
        let mut rows = dump_stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let path: String = row.get(0).unwrap();
            let perm: u32 = row.get(1).unwrap();
            let pack: String = row.get(2).unwrap();
            let hash: String = row.get(3).unwrap();

            // convert packs into hashset
            let packs: HashSet<hash::Hash> = pack
                .split(",")
                .map(|x| hash::from_hex(x).unwrap())
                .collect();

            f(path.as_str(), perm, packs, hash::from_hex(&hash).unwrap())
        }
    }

    pub fn close(self) {
        self.conn.close().unwrap();
    }

    pub fn unload(mut self) -> std::fs::File {
        // Spool the sqlite file into the backend as index
        self.conn.close().unwrap();
        // TODO: not sure we need the seek here since we never touched this handle
        self.file.seek(SeekFrom::Start(0)).unwrap();

        self.file
    }

    pub fn load<R: Read>(reader: &mut R) -> Self {
        let (mut file, path) = tempfile::NamedTempFile::new().unwrap().into_parts();

        // Copy from filehandler to tempfile
        copy(reader, &mut file).unwrap();

        let conn = Connection::open(&path).unwrap();
        // TODO: can't remove file path (sqlite seems to depend on it)
        //s_path.close().unwrap();

        Index {
            file,
            _path: path,
            conn
        }
    }
}
