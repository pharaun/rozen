use ignore::WalkBuilder;

fn main() {
    let target_dir = "tmp";
    let follow_symlink = true;
    let same_file_system = true;


    // Do we want sort by filename? it will allow determistic order
    for entry in WalkBuilder::new(target_dir)
        .follow_links(follow_symlink)
        .standard_filters(false)
        .same_file_system(same_file_system)
        .sort_by_file_name(|a, b| a.cmp(b))
        .build() {

        match entry {
            Ok(e) => println!("{}", e.path().display()),
            Err(e) => println!("{:?}", e),
        }
    }
}
