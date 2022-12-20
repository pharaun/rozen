use rusqlite as rs;

use std::io::{copy, Read, Write};
use serde::Serialize;
use serde::Deserialize;
use bincode;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;

use rusqlite::Connection;
use std::fs::File;

use crate::ltvc::builder::LtvcBuilder;
use crate::ltvc::reader::{LtvcReader, LtvcEntry};

use crate::crypto;
use crate::hash;


// TODO:
// - Figure out a better implementation, the sqlite is a shared resource, but we want
//   to have multiple databases for various parts and these parts will want to own their
//   tables
pub struct IndexMap {
    db_dir: tempfile::TempDir,
    conn: Connection,
}

impl IndexMap {
    pub fn new() -> Self {
        let base_dir = tempfile::TempDir::new().unwrap();

        // Create the index db as 'main'
        let index_path = base_dir.path().join("index.sqlite");
        let conn = Connection::open(&index_path).unwrap();

        // Attach Map
        let map_path = base_dir.path().join("map.sqlite");
        conn.execute_batch(&format!("ATTACH DATABASE '{}' AS map;", &(&map_path.display()))).unwrap();

        // Setup the database
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE main.files (
                path VARCHAR NOT NULL,
                permission INTEGER NOT NULL,
                content_hash VARCHAR NOT NULL
             );
             CREATE TABLE map.packfiles (
                content_hash VARCHAR NOT NULL,
                pack_hash VARCHAR NOT NULL
             );
             COMMIT;"
        ).unwrap();

        IndexMap {
            db_dir: base_dir,
            conn: conn,
        }
    }

    // TODO: for now just load both index + map at same time, in future
    // this will be more complicated
    // TODO: deal with encryption + compression
    pub fn load<R: Read>(index: &mut R, map: &mut R) -> Self {
        let base_dir = tempfile::TempDir::new().unwrap();

        let index_path = base_dir.path().join("index.sqlite");
        let mut index_file = File::create(&index_path).unwrap();

        let map_path = base_dir.path().join("map.sqlite");
        let mut map_file = File::create(&map_path).unwrap();

        // Copy from filehandler to tmpfile
        copy(index, &mut index_file).unwrap();
        copy(map, &mut map_file).unwrap();

        // Setup sql session
        let conn = Connection::open(&index_path).unwrap();
        conn.execute_batch(&format!("ATTACH DATABASE '{}' AS map;", &(&map_path.display()))).unwrap();

        IndexMap {
            db_dir: base_dir,
            conn: conn,
        }
    }

    pub fn close(self) {
        self.conn.execute_batch("DETACH DATABASE map;").unwrap();
        self.conn.close().unwrap();
    }

    // TODO: deal with encryption + compression
    pub fn unload(mut self) -> (File, File) {
        self.conn.execute_batch("DETACH DATABASE map;").unwrap();
        self.conn.close().unwrap();

        // Spool the sqlite file into the backend as index
        let index_path = self.db_dir.path().join("index.sqlite");
        let mut index = File::open(index_path).unwrap();

        let map_path = self.db_dir.path().join("map.sqlite");
        let mut map = File::open(map_path).unwrap();

        // TODO: handle encryption + compression here
        (index, map)
    }

    // TODO: improve the types
    pub fn insert_file(
        &self,
        path: &std::path::Path,
        pack: &hash::Hash,
        hash: &hash::Hash
    ) {
        let mut file_stmt = self.conn.prepare_cached(
            "INSERT INTO main.files
             (path, permission, content_hash)
             VALUES
             (?, ?, ?)"
        ).unwrap();

        let mut pack_stmt = self.conn.prepare_cached(
            "INSERT INTO map.packfiles
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
        // TODO: these could be a join to also get pack hash too...
        // - do we want to have a sql module that handles loading/unloading sql db
        // - then give indivual modules access to a table (ie CAS the pack_hash table?)
        // - Probs can do a typeclass or something which does all of the support needed for sqlite
        //      Then for each things (ie file index, and cas) they hook into that support system
        //      it feels like
        let mut dump_stmt = self.conn.prepare_cached(
            "SELECT f.path, f.permission, m.pack_hash, f.content_hash
             FROM main.files f
             INNER JOIN map.packfiles m ON
                m.content_hash = f.content_hash;
            "
        ).unwrap();
        let mut rows = dump_stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let path: String = row.get(0).unwrap();
            let perm: u32 = row.get(1).unwrap();
            let pack: String = row.get(2).unwrap();
            let hash: String = row.get(3).unwrap();

            f(path.as_str(), perm, hash::from_hex(&pack).unwrap(), hash::from_hex(&hash).unwrap())
        }
    }
}


struct MapBuilder<W: Write> {
    inner: LtvcBuilder<W>,
}

// TODO: copy the finalize idea to the unload impl for IndexMap
impl<W: Write> MapBuilder<W> {
    fn new(writer: W) -> Self {
        let mut mapper = MapBuilder {
            inner: LtvcBuilder::new(writer),
        };

        // Start with the Archive Header (kinda serves as a magic bits)
        let _ = mapper.inner.write_ahdr(0x01).unwrap();
        mapper
    }

    // TODO: should hash+hmac various data bits in a mapfile
    // Store the hmac hash of the packfile in packfile + snapshot itself.
    fn finalize(mut self, key: &crypto::Key) {
        let _ = self.inner.write_pidx().unwrap();
        let idx = vec![1, 2, 3, 4];

        let index = bincode::serialize(&idx).unwrap();
        let comp = Encoder::new(
            &index[..],
            21
        ).unwrap();
        let mut enc = crypto::encrypt(&key, comp).unwrap();

        let _ = self.inner.write_edat(&mut enc).unwrap();
        let _ = self.inner.write_aend(0x00_00_00_00).unwrap();

        // Flush to signal to the backend that its done
        self.inner.to_inner().flush().unwrap();
    }
}
