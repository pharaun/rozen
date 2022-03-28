pub mod builder;
pub mod reader;
mod raw;

// 1Kb EDAT frame buffer
// TODO: to force ourself to handle sequence of EDAT for now use small
// chunk size such as 1024
const CHUNK_SIZE: usize = 1 * 1024;
const MAX_CHUNK_SIZE: usize = 10 * 1024;
