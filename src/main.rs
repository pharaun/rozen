use ignore::WalkBuilder;

use std::fs::File;
use tar::{Builder, Header};
use std::io::Read;

fn main() {
    let target_dir = "tmp";
    let follow_symlink = true;
    let same_file_system = true;


    // Enclosuring tarfile
    let tar_file = File::create("test.tar").unwrap();
    let mut enc_tar = Builder::new(tar_file);


    // Chunked tarfile
    let limit = 1024 * 1024 * 10;
    let mut chunk_len = 0;
    let mut chunk_idx: u32 = 0;

    let mut chunk_tar = Builder::new(Vec::new());


    // Compare this to each file get a zstd compressed
    let cmp_tar_file = File::create("test2.tar").unwrap();
    let mut cmp_tar = Builder::new(cmp_tar_file);


    // Do we want sort by filename? it will allow determistic order
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
                            // 1. ingest it into chunk_tar
                            {
                                println!("EATS: {}", e.path().display());

                                let file_data: Vec<u8> = {
                                    let mut content = Vec::new();

                                    std::fs::File::open(e.path())
                                        .unwrap()
                                        .read_to_end(&mut content)
                                        .unwrap();
                                    content
                                };
                                chunk_len += file_data.len();

                                // Header for each file into the chunk
                                let mut header = Header::new_gnu();
                                header.set_size(file_data.len() as u64);
                                header.set_cksum();

                                // stuff it into the tar now
                                chunk_tar.append_data(
                                    &mut header,
                                    e.path(),
                                    &file_data[..]
                                ).unwrap();


                                // COMPARE
                                {
                                    header = Header::new_gnu();
                                    header.set_size(file_data.len() as u64);
                                    header.set_cksum();

                                    let comp_data: Vec<u8> = zstd::encode_all(
                                        &file_data[..],
                                        21
                                    ).unwrap();

                                    // stuff it into the tar now
                                    cmp_tar.append_data(
                                        &mut header,
                                        e.path(),
                                        &comp_data[..]
                                    ).unwrap();
                                }
                            }

                            // 2. check if chunk_tar is greater than limit
                            if chunk_len > limit {
                                println!("STOW: {} chunk", chunk_idx);

                                // 3. if so, finalize it.
                                let chunk = chunk_tar.into_inner().unwrap();

                                // 4. compress it with zstd
                                let comp_data: Vec<u8> = zstd::encode_all(
                                    &chunk[..],
                                    21
                                ).unwrap();

                                // 5. ingest the compressed chunk into enc_tar
                                let chunk_name = format!("{}.tar.zst", chunk_idx);

                                // Header for the new chunk
                                let mut header = Header::new_gnu();
                                header.set_size(comp_data.len() as u64);
                                header.set_path(chunk_name).unwrap();
                                header.set_cksum();

                                // stuff it into the tar now
                                enc_tar.append(&header, &comp_data[..]).unwrap();

                                // 6. re-make the chunk+chunk_tar for next batch
                                chunk_len = 0;
                                chunk_tar = Builder::new(Vec::new());
                                chunk_idx += 1;
                            }
                        } else {
                            println!("SKIP: {}", e.path().display());
                        }
                    },
                }
            },
            Err(e) => println!("ERRR: {:?}", e),
        }
    }

    // 7. on completion if there is data in chunk, finalize it
    if chunk_len > 0 {
        println!("TRAILER: {} chunk", chunk_idx);

        // 3. if so, finalize it.
        let chunk = chunk_tar.into_inner().unwrap();

        // 4. compress it with zstd
        let comp_data: Vec<u8> = zstd::encode_all(
            &chunk[..],
            21
        ).unwrap();

        // 5. ingest the compressed chunk into enc_tar
        let chunk_name = format!("{}.tar.zst", chunk_idx);

        // Header for the new chunk
        let mut header = Header::new_gnu();
        header.set_size(comp_data.len() as u64);
        header.set_path(chunk_name).unwrap();
        header.set_cksum();

        // stuff it into the tar now
        enc_tar.append(&header, &comp_data[..]).unwrap();
    }

    // Wrap up the tar file
    let _ = enc_tar.into_inner().unwrap();

    // Wrap compare tar file
    let _ = cmp_tar.into_inner().unwrap();
}
