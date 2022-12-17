use rusqlite as rs;

use std::io::{Seek, SeekFrom, copy, Read};
use rusqlite::Connection;

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
                content_hash VARCHAR NOT NULL
             );
             CREATE TABLE packfiles (
                content_hash VARCHAR NOT NULL,
                pack_hash VARCHAR NOT NULL
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
        pack: &hash::Hash,
        hash: &hash::Hash
    ) {
        let mut file_stmt = self.conn.prepare_cached(
            "INSERT INTO files
             (path, permission, content_hash)
             VALUES
             (?, ?, ?)"
        ).unwrap();

        let mut pack_stmt = self.conn.prepare_cached(
            "INSERT INTO packfiles
             (content_hash, pack_hash)
             VALUES
             (?, ?)"
        ).unwrap();

        // Load file into index
        file_stmt.execute(rs::params![
            format!("{}", path.display()),
            0000,
            hash::to_hex(hash),
        ]).unwrap();

        // TODO: move this packfile stuff out of index and into its own cache layer in CAS
        pack_stmt.execute(rs::params![
            hash::to_hex(hash),
            hash::to_hex(pack),
        ]).unwrap();
    }

    pub fn walk_files<F>(&self, mut f: F)
    where
        F: FnMut(&str, u32, hash::Hash, hash::Hash)
    {
        let mut query_packfile = self.conn.prepare_cached(
            "SELECT pack_hash FROM packfiles where content_hash = ?"
        ).unwrap();

        // TODO: these could be a join to also get pack hash too...
        // - do we want to have a sql module that handles loading/unloading sql db
        // - then give indivual modules access to a table (ie CAS the pack_hash table?)
        // - Probs can do a typeclass or something which does all of the support needed for sqlite
        //      Then for each things (ie file index, and cas) they hook into that support system
        //      it feels like
        let mut dump_stmt = self.conn.prepare_cached(
            "SELECT path, permission, content_hash FROM files"
        ).unwrap();
        let mut rows = dump_stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let path: String = row.get(0).unwrap();
            let perm: u32 = row.get(1).unwrap();
            let hash: String = row.get(2).unwrap();

            // We have a content hash, query for packfile hash
            let mut pack_rows = query_packfile.query([&hash]).unwrap();

            // Should be only one row....
            while let Ok(Some(pack_row)) = pack_rows.next() {
                let pack: String = pack_row.get(0).unwrap();

                f(path.as_str(), perm, hash::from_hex(&pack).unwrap(), hash::from_hex(&hash).unwrap())
            }
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
