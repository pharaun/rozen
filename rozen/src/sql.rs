use rusqlite as rs;

use log::debug;
use std::io::{copy, Read, Seek, SeekFrom, Write};
use std::path::Path;
use zstd::stream::read::Decoder;
use zstd::stream::read::Encoder;

use rusqlite::Connection;

use rcore::crypto;
use rcore::hash;
use rcore::key;

use rarc::ltvc::indexing::LtvcIndexing;
use rarc::ltvc::linear::EdatStream;
use rarc::ltvc::linear::Header;
use rarc::ltvc::linear::LtvcLinear;

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

enum UnloadType {
    Shdr,
    Pidx,
}

impl SqlDb {
    fn new() -> Self {
        let db_tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(db_tmp.path()).unwrap();
        SqlDb { db_tmp, conn }
    }

    fn attach(&self, db: &Path, name: &str) {
        self.conn
            .execute_batch(&format!(
                "ATTACH DATABASE '{}' as {};",
                &(db.display()),
                name
            ))
            .unwrap();
    }

    fn detach(&self, name: &str) {
        self.conn
            .execute_batch(&format!("DETACH DATABASE {};", name))
            .unwrap();
    }

    fn load<R: Read>(reader: &mut R, key: &key::MemKey) -> Self {
        let ltvc = LtvcLinear::new(reader);

        for EdatStream { header, data } in ltvc {
            match header {
                Header::Shdr | Header::Pidx => {
                    let mut db_tmp = tempfile::NamedTempFile::new().unwrap();

                    let mut dec = crypto::decrypt(key, data).unwrap();
                    let mut und = Decoder::new(&mut dec).unwrap();
                    copy(&mut und, &mut db_tmp).unwrap();

                    let conn = Connection::open(db_tmp.path()).unwrap();
                    return SqlDb { db_tmp, conn };
                }

                // Skip header we don't care for
                _ => (),
            }
        }

        // Shouldn't reach here, we didn't find what we needed
        panic!("Did not find Shdr or Pidx in the stream!");
    }

    fn unload<W: Write>(self, header: UnloadType, key: &key::MemKey, writer: W) {
        self.conn.close().unwrap();

        let mut ltvc = LtvcIndexing::new(writer);

        let mut db_file = self.db_tmp.into_file();

        let content_hash = hash::hash(key, &mut db_file).unwrap();
        db_file.seek(SeekFrom::Start(0)).unwrap();

        let comp = Encoder::new(&mut db_file, 21).unwrap();
        let mut enc = crypto::encrypt(key, comp).unwrap();

        match header {
            UnloadType::Shdr => ltvc.append_snapshot(content_hash, &mut enc),
            UnloadType::Pidx => ltvc.append_pack_index(content_hash, &mut enc),
        }

        ltvc.finalize(false, key);
    }
}

pub struct Index {
    db: SqlDb,
}

impl Index {
    pub fn new() -> Self {
        let db = SqlDb::new();

        db.conn
            .execute_batch(
                "CREATE TABLE files (
                    path VARCHAR NOT NULL,
                    permission INTEGER NOT NULL,
                    content_hash VARCHAR NOT NULL
                 );",
            )
            .unwrap();

        Index { db }
    }

    pub fn load<R: Read>(index: &mut R, key: &key::MemKey) -> Self {
        Index {
            db: SqlDb::load(index, key),
        }
    }

    pub fn unload<W: Write>(self, key: &key::MemKey, writer: W) {
        self.db.unload(UnloadType::Shdr, key, writer);
    }

    // TODO: improve the types
    pub fn insert_file(&self, path: &std::path::Path, hash: &hash::Hash) {
        let mut file_stmt = self
            .db
            .conn
            .prepare_cached(
                "INSERT INTO files
                 (path, permission, content_hash)
                 VALUES
                 (?, ?, ?)",
            )
            .unwrap();

        file_stmt
            .execute(rs::params![
                format!("{}", path.display()),
                0000,
                hash::to_hex(hash),
            ])
            .unwrap();
    }
}

pub struct Map {
    db: SqlDb,
}

impl Map {
    pub fn new() -> Self {
        let db = SqlDb::new();

        db.conn
            .execute_batch(
                "CREATE TABLE packfiles (
                    content_hash VARCHAR NOT NULL,
                    pack_hash VARCHAR NOT NULL
                );",
            )
            .unwrap();

        Map { db }
    }

    pub fn load<R: Read>(index: &mut R, key: &key::MemKey) -> Self {
        Map {
            db: SqlDb::load(index, key),
        }
    }

    pub fn unload<W: Write>(self, key: &key::MemKey, writer: W) {
        self.db.unload(UnloadType::Pidx, key, writer);
    }

    // TODO: improve the types
    pub fn insert_chunk(&self, chunk: &hash::Hash, pack: &hash::Hash) {
        let mut pack_stmt = self
            .db
            .conn
            .prepare_cached(
                "INSERT INTO packfiles
                 (content_hash, pack_hash)
                 VALUES
                 (?, ?)",
            )
            .unwrap();

        pack_stmt
            .execute(rs::params![hash::to_hex(chunk), hash::to_hex(pack),])
            .unwrap();
    }

    pub fn find_pack(&self, chunk: &hash::Hash) -> Option<hash::Hash> {
        let mut query_stmt = self
            .db
            .conn
            .prepare_cached(
                "SELECT pack_hash
             FROM packfiles
             WHERE content_hash = ?",
            )
            .unwrap();

        query_stmt
            .query_row(rs::params![hash::to_hex(chunk)], |row| {
                let hash: String = row.get(0).unwrap();
                Ok(hash::from_hex(&hash).unwrap())
            })
            .ok()
    }
}

pub fn walk_files<R, F>(index: &mut R, map: &mut R, key: &key::MemKey, mut f: F)
where
    F: FnMut(&str, u32, hash::Hash, hash::Hash),
    R: Read,
{
    // Load up the index db
    debug!("Loading INDEX db");
    let idx = Index::load(index, key).db;
    let map_file = {
        debug!("Loading MAP db");
        let m = Map::load(map, key).db;
        let _ = m.conn.close();
        m.db_tmp
    };
    idx.attach(map_file.path(), "map");

    // Do query stuff
    {
        let mut dump_stmt = idx
            .conn
            .prepare_cached(
                "SELECT f.path, f.permission, m.pack_hash, f.content_hash
                 FROM main.files f
                 INNER JOIN map.packfiles m ON
                    m.content_hash = f.content_hash;",
            )
            .unwrap();
        let mut rows = dump_stmt.query([]).unwrap();
        while let Ok(Some(row)) = rows.next() {
            let path: String = row.get(0).unwrap();
            let perm: u32 = row.get(1).unwrap();
            let pack: String = row.get(2).unwrap();
            let hash: String = row.get(3).unwrap();

            f(
                path.as_str(),
                perm,
                hash::from_hex(&pack).unwrap(),
                hash::from_hex(&hash).unwrap(),
            )
        }
    }

    // Cleanup
    idx.detach("map");
    let _ = idx.conn.close();
}
