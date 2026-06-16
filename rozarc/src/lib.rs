pub mod logical;
pub mod compress;

use std::io;

// Trait for sharing contextual information to be passed down the layer
// regarding a incoming member, such as its total expected size.
pub trait EventWrite: io::Write {
    fn member_write_start(&mut self, member_size: u64) -> io::Result<()>;
}
