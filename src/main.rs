use ignore::WalkBuilder;

use std::fs::File;
use tar::{Builder, Header};
use std::io::Read;
use std::io::Write;

fn main() {
    let target_dir = "tmp";
    let follow_symlink = true;
    let same_file_system = true;

    let tar_file = File::create("test.tar").unwrap();
    let mut tar = Builder::new(tar_file);

    let mut test_file = File::create("test.file").unwrap();

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
                            // In memory compression, fine for now
                            let file_data: Vec<u8> = {
                                let mut content = Vec::new();

                                std::fs::File::open(e.path())
                                    .unwrap()
                                    .read_to_end(&mut content)
                                    .unwrap();
                                content
                            };
                            let comp_data: Vec<u8> = zstd::encode_all(&file_data[..], 21).unwrap();

                            if file_data.len() < comp_data.len() {
                                // Pull in raw
                                println!("RAWW: {}", e.path().display());

                                // Header for the tar pack
                                let mut header = Header::new_gnu();
                                header.set_size(file_data.len() as u64);
                                header.set_cksum();

                                // stuff it into the tar now
                                tar.append_data(&mut header, e.path(), &file_data[..]).unwrap();

                                // Dump it to the file too
                                test_file.write(&file_data[..]);

                            } else {
                                // Pull in COMP
                                println!("COMP: {}", e.path().display());

                                // Header for the tar pack
                                let mut header = Header::new_gnu();
                                header.set_size(comp_data.len() as u64);
                                header.set_cksum();

                                // stuff it into the tar now
                                tar.append_data(&mut header, e.path(), &comp_data[..]).unwrap();

                                // Dump it to the file too
                                test_file.write(&comp_data[..]);
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

    // Wrap up the tar file
    let data = tar.into_inner().unwrap();
}
