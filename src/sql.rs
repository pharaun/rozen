use rusqlite as rs;

use std::io::{copy, Read, Write};
use std::path::Path;
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
// - The Map should probs not need to be encrypted since its just a cache map of hash ->
//   packfile...
// TODO: these could be a join to also get pack hash too...
// - do we want to have a sql module that handles loading/unloading sql db
// - then give indivual modules access to a table (ie CAS the pack_hash table?)
// - Probs can do a typeclass or something which does all of the support needed for sqlite
//      Then for each things (ie file index, and cas) they hook into that support system
//      it feels like
//
// Sql mapper
// 1. Have it being separate for the building and inserting
// 2. Have a separate function that takes the given sql stuff and builds a query out
// 3. Have a generic implementation that takes care of packing it into a ltvc record and unpacking it then specific end user impl that uses this.
struct SqlDb {
    db_tmp: tempfile::NamedTempFile,
    conn: Connection,
}

impl SqlDb {
    fn new() -> Self {
        let db_tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(db_tmp.path()).unwrap();
        SqlDb {
            db_tmp,
            conn
        }
    }

    fn attach(&self, db: &Path, name: &str) {
        self.conn.execute_batch(
            &format!(
                "ATTACH DATABASE '{}' as {};",
                &(db.display()),
                name
            )
        ).unwrap();
    }

    fn detach(&self, name: &str) {
        self.conn.execute_batch(
            &format!(
                "DETACH DATABASE {};",
                name
            )
        ).unwrap();
    }

    // TODO: deal with encryption + compression
    fn load<R: Read>(reader: &mut R) -> Self {
        let mut db_tmp = tempfile::NamedTempFile::new().unwrap();
        copy(reader, &mut db_tmp).unwrap();
        let conn = Connection::open(db_tmp.path()).unwrap();

        SqlDb {
            db_tmp,
            conn
        }
    }

    fn unload(mut self) -> File {
        self.conn.close().unwrap();
        self.db_tmp.into_file()
    }
}


pub struct Index {
    db: SqlDb,
}

impl Index {
    pub fn new() -> Self {
        let mut db = SqlDb::new();

        db.conn.execute_batch(
            "CREATE TABLE files (
                path VARCHAR NOT NULL,
                permission INTEGER NOT NULL,
                content_hash VARCHAR NOT NULL
             );"
        ).unwrap();

        Index { db }
    }

    pub fn load<R: Read>(index: &mut R) -> Self {
        Index {
            db: SqlDb::load(index)
        }
    }

    pub fn unload(mut self) -> File {
        self.db.unload()
    }

    // TODO: improve the types
    pub fn insert_file(
        &self,
        path: &std::path::Path,
        hash: &hash::Hash
    ) {
        let mut file_stmt = self.db.conn.prepare_cached(
            "INSERT INTO files
             (path, permission, content_hash)
             VALUES
             (?, ?, ?)"
        ).unwrap();

        file_stmt.execute(rs::params![
            format!("{}", path.display()),
            0000,
            hash::to_hex(hash),
        ]).unwrap();
    }
}


pub struct Map {
    db: SqlDb,
}

impl Map {
    pub fn new() -> Self {
        let mut db = SqlDb::new();

        db.conn.execute_batch(
            "CREATE TABLE packfiles (
                content_hash VARCHAR NOT NULL,
                pack_hash VARCHAR NOT NULL
            );"
        ).unwrap();

        Map { db }
    }

    pub fn load<R: Read>(index: &mut R) -> Self {
        Map {
            db: SqlDb::load(index)
        }
    }

    pub fn unload(mut self) -> File {
        self.db.unload()
    }

    // TODO: improve the types
    pub fn insert_chunk(
        &self,
        chunk: &hash::Hash,
        pack: &hash::Hash
    ) {
        let mut pack_stmt = self.db.conn.prepare_cached(
            "INSERT INTO packfiles
             (content_hash, pack_hash)
             VALUES
             (?, ?)"
        ).unwrap();

        pack_stmt.execute(rs::params![
            hash::to_hex(chunk),
            hash::to_hex(pack),
        ]).unwrap();
    }
}


pub fn walk_files<R, F>(index: &mut R, map: &mut R, mut f: F)
where
    F: FnMut(&str, u32, hash::Hash, hash::Hash),
    R: Read
{
    // Load up the index db
    let mut idx = Index::load(index).db;
    let map_file = {
        let m = Map::load(map).db;
        m.conn.close();
        m.db_tmp
    };
    idx.attach(map_file.path(), "map");

    // Do query stuff
    {
        let mut dump_stmt = idx.conn.prepare_cached(
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

    // Cleanup
    idx.detach("map");
    idx.conn.close();
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
