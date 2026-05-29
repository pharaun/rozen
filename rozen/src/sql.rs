use rusqlite as rs;

use log::debug;
use std::error::Error;
use std::io::{Read, Seek as _, SeekFrom, Write, copy};
use std::path::Path;
use zstd::stream::read::Decoder;
use zstd::stream::read::Encoder;

use rusqlite::Connection;

use crate::rcore::crypto;
use crate::rcore::hash;
use crate::rcore::key;

use crate::rarc::ltvc::indexing::LtvcIndexing;
use crate::rarc::ltvc::linear::EdatStream;
use crate::rarc::ltvc::linear::Header;
use crate::rarc::ltvc::linear::LtvcLinear;

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

#[derive(Clone, Copy)]
enum UnloadType {
    Shdr,
    Pidx,
}

impl SqlDb {
    fn new() -> Result<Self, Box<dyn Error>> {
        let db_tmp = tempfile::NamedTempFile::new()?;
        let conn = Connection::open(db_tmp.path())?;
        Ok(Self { db_tmp, conn })
    }

    fn attach(&self, db: &Path, name: &str) -> Result<(), Box<dyn Error>> {
        self.conn.execute_batch(&format!(
            "ATTACH DATABASE '{}' as {};",
            &(db.display()),
            name
        ))?;
        Ok(())
    }

    fn detach(&self, name: &str) -> Result<(), Box<dyn Error>> {
        self.conn
            .execute_batch(&format!("DETACH DATABASE {name};"))?;
        Ok(())
    }

    fn load<R: Read>(reader: &mut R, key: &key::MemKey) -> Result<Self, Box<dyn Error>> {
        let ltvc = LtvcLinear::new(reader);

        for EdatStream { header, data } in ltvc {
            match header {
                Header::Shdr | Header::Pidx => {
                    let mut db_tmp = tempfile::NamedTempFile::new()?;

                    let mut dec = crypto::decrypt(key, data)?;
                    let mut und = Decoder::new(&mut dec)?;
                    copy(&mut und, &mut db_tmp)?;

                    let conn = Connection::open(db_tmp.path())?;
                    return Ok(Self { db_tmp, conn });
                }

                // Skip header we don't care for
                _ => (),
            }
        }

        // Shouldn't reach here, we didn't find what we needed
        Err("Did not find Shdr or Pidx in the stream!".into())
    }

    fn unload<W: Write>(
        self,
        header: UnloadType,
        key: &key::MemKey,
        writer: W,
    ) -> Result<(), Box<dyn Error>> {
        let _ = self.conn.close();

        let mut ltvc = LtvcIndexing::new(writer)?;

        let mut db_file = self.db_tmp.into_file();

        let content_hash = hash::hash(key, &mut db_file)?;
        db_file.seek(SeekFrom::Start(0))?;

        let comp = Encoder::new(&mut db_file, 21)?;
        let mut enc = crypto::encrypt(key, comp)?;

        match header {
            UnloadType::Shdr => ltvc.append_snapshot(content_hash, &mut enc)?,
            UnloadType::Pidx => ltvc.append_pack_index(content_hash, &mut enc)?,
        };

        ltvc.finalize(false, key)?;
        Ok(())
    }
}

pub(crate) struct Index {
    db: SqlDb,
}

impl Index {
    pub(crate) fn new() -> Result<Self, Box<dyn Error>> {
        let db = SqlDb::new()?;

        db.conn.execute_batch(
            "CREATE TABLE files (
                    path VARCHAR NOT NULL,
                    permission INTEGER NOT NULL,
                    content_hash VARCHAR NOT NULL
                 );",
        )?;

        Ok(Self { db })
    }

    pub(crate) fn load<R: Read>(index: &mut R, key: &key::MemKey) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            db: SqlDb::load(index, key)?,
        })
    }

    pub(crate) fn unload<W: Write>(
        self,
        key: &key::MemKey,
        writer: W,
    ) -> Result<(), Box<dyn Error>> {
        self.db.unload(UnloadType::Shdr, key, writer)?;
        Ok(())
    }

    // TODO: improve the types
    pub(crate) fn insert_file(&self, path: &Path, hash: &hash::Hash) -> Result<(), Box<dyn Error>> {
        let mut file_stmt = self.db.conn.prepare_cached(
            "INSERT INTO files
                 (path, permission, content_hash)
                 VALUES
                 (?, ?, ?)",
        )?;

        file_stmt.execute(rs::params![
            format!("{}", path.display()),
            0000,
            hash::to_hex(hash),
        ])?;
        Ok(())
    }
}

pub(crate) struct Map {
    db: SqlDb,
}

impl Map {
    pub(crate) fn new() -> Result<Self, Box<dyn Error>> {
        let db = SqlDb::new()?;

        db.conn.execute_batch(
            "CREATE TABLE packfiles (
                    content_hash VARCHAR NOT NULL,
                    pack_hash VARCHAR NOT NULL
                );",
        )?;

        Ok(Self { db })
    }

    pub(crate) fn load<R: Read>(index: &mut R, key: &key::MemKey) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            db: SqlDb::load(index, key)?,
        })
    }

    pub(crate) fn unload<W: Write>(
        self,
        key: &key::MemKey,
        writer: W,
    ) -> Result<(), Box<dyn Error>> {
        self.db.unload(UnloadType::Pidx, key, writer)?;
        Ok(())
    }

    // TODO: improve the types
    pub(crate) fn insert_chunk(
        &self,
        chunk: &hash::Hash,
        pack: &hash::Hash,
    ) -> Result<(), Box<dyn Error>> {
        let mut pack_stmt = self.db.conn.prepare_cached(
            "INSERT INTO packfiles
                 (content_hash, pack_hash)
                 VALUES
                 (?, ?)",
        )?;

        pack_stmt.execute(rs::params![hash::to_hex(chunk), hash::to_hex(pack),])?;
        Ok(())
    }

    pub(crate) fn find_pack(&self, chunk: &hash::Hash) -> Result<hash::Hash, Box<dyn Error>> {
        let mut query_stmt = self.db.conn.prepare_cached(
            "SELECT pack_hash
             FROM packfiles
             WHERE content_hash = ?",
        )?;

        Ok(
            query_stmt.query_row(rs::params![hash::to_hex(chunk)], |row| {
                let hash: String = row.get(0)?;
                Ok(hash::from_hex(&hash).expect("don't want to deal with hex conversion error"))
            })?,
        )
    }
}

pub(crate) fn walk_files<R, F>(
    index: &mut R,
    map: &mut R,
    key: &key::MemKey,
    mut f: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnMut(&str, u32, hash::Hash, hash::Hash) -> Result<(), Box<dyn Error>>,
    R: Read,
{
    // Load up the index db
    debug!("Loading INDEX db");
    let idx = Index::load(index, key)?.db;
    let map_file = {
        debug!("Loading MAP db");
        let m = Map::load(map, key)?.db;
        let _ = m.conn.close();
        m.db_tmp
    };
    idx.attach(map_file.path(), "map")?;

    // Do query stuff
    {
        let mut dump_stmt = idx.conn.prepare_cached(
            "SELECT f.path, f.permission, m.pack_hash, f.content_hash
                 FROM main.files f
                 INNER JOIN map.packfiles m ON
                    m.content_hash = f.content_hash;",
        )?;
        let mut rows = dump_stmt.query([])?;
        while let Ok(Some(row)) = rows.next() {
            let path: String = row.get(0)?;
            let perm: u32 = row.get(1)?;
            let pack: String = row.get(2)?;
            let hash: String = row.get(3)?;

            f(
                path.as_str(),
                perm,
                hash::from_hex(&pack)?,
                hash::from_hex(&hash)?,
            )?;
        }
    }

    // Cleanup
    idx.detach("map")?;
    let _ = idx.conn.close();
    Ok(())
}
