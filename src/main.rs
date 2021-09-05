use rusqlite as rs;

use ignore::WalkBuilder;

use std::io::{Cursor, Seek, SeekFrom, copy};
use blake3::Hasher;
use rusqlite::Connection;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;

fn main() {
    let target_dir = "docs";
    let follow_symlink = true;
    let same_file_system = true;

    // Zipfile in memory to prove concept
    let mut buf_zip = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf_zip);

        // Options
        let options = zip::write::FileOptions::default().compression_method(
            zip::CompressionMethod::Stored
        );

        // Temp file for rusqlite
        let (mut s_file, s_path) = tempfile::NamedTempFile::new().unwrap().into_parts();
        let conn = Connection::open(&s_path).unwrap();
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
             COMMIT;"
        ).unwrap();

        {
            let mut file_stmt = conn.prepare(
                "INSERT INTO files
                 (path, permission, content_hash)
                 VALUES
                 (?, ?, ?)"
            ).unwrap();

            // Sort filename for determistic order
            for entry in WalkBuilder::new(target_dir)
                .follow_links(follow_symlink)
                .standard_filters(false)
                .same_file_system(same_file_system)
                .sort_by_file_name(|a, b| a.cmp(b))
                .build() {

                match entry {
                    Ok(e) => {
                        match e.file_type() {
                            None => println!("NONE: {}", e.path().display()),
                            Some(ft) => {
                                if ft.is_file() {
                                    println!("COMP: {}", e.path().display());

                                    let mut file_data = std::fs::File::open(e.path()).unwrap();

                                    // Hasher
                                    let mut hash = Hasher::new();
                                    copy(&mut file_data, &mut hash).unwrap();
                                    let content_hash = hash.finalize().to_hex();

                                    // Streaming compressor
                                    file_data.seek(SeekFrom::Start(0)).unwrap();

                                    let mut comp = Encoder::new(
                                        &mut file_data,
                                        21
                                    ).unwrap();

                                    // Setup a zip and slurp in the data
                                    zip.start_file(
                                        content_hash.as_str(),
                                        options
                                    ).unwrap();
                                    copy(&mut comp, &mut zip).unwrap();
                                    comp.finish();

                                    // Load file info into index
                                    file_stmt.execute(rs::params![
                                        format!("{}", e.path().display()),
                                        0000,
                                        content_hash.as_str(),
                                    ]).unwrap();

                                } else {
                                    println!("SKIP: {}", e.path().display());
                                }
                            },
                        }
                    },
                    Err(e) => println!("ERRR: {:?}", e),
                }
            }
        }

        // Spool the sqlite file into the zip as index
        conn.close().unwrap();

        // TODO: not sure we need the seek here since we never touched this handle
        s_file.seek(SeekFrom::Start(0)).unwrap();

        {
            let mut comp = Encoder::new(
                &mut s_file,
                21
            ).unwrap();

            // Setup a zip and slurp in the data
            zip.start_file(
                "INDEX.sqlite.zst",
                options
            ).unwrap();
            copy(&mut comp, &mut zip).unwrap();
            comp.finish();
        }

        // wrap up zip file
        zip.finish().unwrap();
    }

    // Reread to output debug info
    buf_zip.set_position(0);

    println!("\nARCHIVE Dump");
    let mut zip_read = zip::ZipArchive::new(&mut buf_zip).unwrap();
    for i in 0..zip_read.len() {
        let file = zip_read.by_index(i).unwrap();
        println!("SIZE: {:5}, NAME: {}", file.size(), file.name());
    }

    // Grab db out of zip and put it to a temp handle
    let mut index_content = zip_read.by_name("INDEX.sqlite.zst").unwrap();

    // Setup decompression stream
    let mut dec = Decoder::new(&mut index_content).unwrap();

    let (mut d_file, d_path) = tempfile::NamedTempFile::new().unwrap().into_parts();
    copy(&mut dec, &mut d_file).unwrap();
    let conn = Connection::open(&d_path).unwrap();

    // Dump the sqlite db data so we can view what it is
    println!("\nINDEX Dump");
    {
        let mut dump_stmt = conn.prepare(
            "SELECT path, permission, content_hash FROM files"
        ).unwrap();
        let mut rows = dump_stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let path: String = row.get(0).unwrap();
            let perm: u32 = row.get(1).unwrap();
            let hash: String = row.get(2).unwrap();

            println!("HASH: {:?}, PERM: {:?}, PATH: {:?}", hash, perm, path);
        }
    }
    conn.close().unwrap();
}
