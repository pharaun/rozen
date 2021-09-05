use ignore::WalkBuilder;

use std::io::{Cursor, Seek, SeekFrom, copy};
use blake3::Hasher;
use zstd::stream::read::Encoder;

fn main() {
    let target_dir = "target";
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

                            } else {
                                println!("SKIP: {}", e.path().display());
                            }
                        },
                    }
                },
                Err(e) => println!("ERRR: {:?}", e),
            }
        }

        // wrap up zip file
        zip.finish().unwrap();
    }

    // Reread to output debug info
    buf_zip.set_position(0);

    let mut zip_read = zip::ZipArchive::new(&mut buf_zip).unwrap();
    for i in 0..zip_read.len() {
        let file = zip_read.by_index(i).unwrap();
        println!("NAME: {}", file.name());
    }
}
