//! Length-Tag-Value-Checksum file format
//!
//! This is inspired by the PNG file format and is designed to be a
//! flexible and extensible filr format for any data being stored in
//! the backup repository.
//!
//! <div class="example-wrap" style="display:inline-block">
//! <pre class="compile_fail" style="white-space:normal;font:inherit;">
//!
//! **Warning**: This file format is not yet considered stable, the
//! semantics or even layout may vary. Please use with care.
//!
//! </pre>
//! </div>
//!
//! # Top Level
//!
//! This file format needs to support several use cases such as:
//! - Streaming (I.E. writing to S3 without caching locally)
//! - Fetch+Seek (I.E. reading a index then fetching specific data)
//!
//! A file is a collection of chunks (see: [`raw::LtvcEntryRaw`]). With the
//! following on disk format. Unless other wise noted everything is stored
//! in Little Endian format.
//!
//! | Type    | Name     | Description |
//! | ------: | -------- | ----------- |
//! | u32     | length   | The length of the value section of a chunk, is allowed to be 0 bytes |
//! | [u8; 4] | type     | The type of the chunk, usually ASCII such as `AHDR` but is not required |
//! | u16     | header checksum | The checksum of <code>length \|\| type</code> concated together |
//! | [u8; N] | value    | The content of the chunk, interpret according to the chunk type |
//! | u32     | checksum | The checksum of `value` |
//!
//! # Chunk Types
//!
//! In the table below is the list of supported types for chunks. These types will be further
//! detailed in their own sub-sections.
//!
//! | Chunk Type | Name              | Description |
//! | :--------: | ----------------- | ----------- |
//! | AHDR       | Archive Header    | The first chunk, holds archive wide metadata |
//! | FHDR       | File Header       | Holds per-file metadata |
//! | SHDR       | Snapshot Header   | Holds snapshot metadata |
//! | AIDX       | Archive Index     | Offset+length index of all records in the archive |
//! | PIDX       | Pack Index        | Chunk to Packfile index |
//! | EDAT       | Encrypted Data    | Encrypted blobs. `AIDX/FHDR` before defines the content |
//! | AEND       | Archive Ending    | Terminates the archive begun by a `AHDR` |
//!
//! ## AHDR
//!
//! This is the chunk that begins an archive block in a file. This currently only holds the archive
//! block version since we are still evolving the precise format so this is used to handle file
//! format versoning. In the future there may be additional metadata within. This chunk must be
//! followed by one of these following chunks: `FHDR`, `AIDX`, `AEND`
//!
//! | Type | Name    | Description |
//! | ---: | ------- | ----------- |
//! | u8   | version | The archive block version |
//!
//! ## FHDR
//!
//! This is the chunk that defines what the `EDAT` that follows contains. This is specifically for
//! file data. Each file is hashed by a keyed HMAC hash that then becomes the file content
//! identifier. This information is stored within a `FHDR`. This chunk must be followed by 1 or
//! more `EDAT` chunks that contains the compressed and encrypted content of the file that belong
//! to this HMAC.
//!
//! | Type     | Name    | Description |
//! | -------: | ------- | ----------- |
//! | [u8; 32] | hash    | The keyed HMAC hash of the file content |
//!
//! ## SHDR
//!
//! This is the chunk that defines what the `EDAT` that follows contains. This is specifically for
//! snapshot data. Each snapshot's metadata is stored in the `EDAT` that follows this header.
//! Similiar rules as `FHDR` itself.
//!
//! There is currently no data held within the value field of this chunk.
//!
//! ## AIDX
//!
//! This like the `FHDR` chunk also defines what the content inside the `EDAT` that follows. This
//! is specifically for holding the index of all of the archive blocks within this archive block. See:
//! [`crate::pack::ChunkIdx`]. This is an optional chunk but is highly encouraged to support seeks in an
//! archive block that contains more than 1 `FHDR`. This chunk must be followed by an `EDAT`
//!
//! There is currently no data held within the value field of this chunk.
//!
//! ## PIDX
//!
//! This is like `AIDX` chunk, except that its the tag for what kind of content is in the `EDAT`
//! that follows. This is specifically for holding the mapping of all file hash -> packfile ids.
//! This is to allow us to do lookup by hash+chunk and get which packfile it was stored in.
//!
//! There is currently no data held within the value field of this chunk.
//!
//! ## EDAT
//!
//! Encrypted data chunk. This must be preceeded by an; `FHDR`, `SHDR`, `AIDX`, or `PIDX`  at this
//! point in time. This contains the encrypted and compressed datastream.
//!
//! There must be 1 or more chunk to hold the entire datastream. To support the streaming usecase
//! the content of each `EDAT` is appended to the preceeding one. The LTVC reader is allowed to
//! reject an chunk that is too large to prevent out of memory exhaustion attacks. Must be followed
//! by an `FHDR`, `AIDX`, or `AEND` to mark the end of an stream of data. Can be followed by more
//! `EDAT` if the data stream cannot be contained within one chunk.
//!
//! | Type    | Name    | Description |
//! | ------: | ------- | ----------- |
//! | [u8; N] | data    | The encrypted data chunk. See [`crate::crypto::Crypter<R, E>`] |
//!
//! ## AEND
//!
//! Terminates an archive block opened by the `AHDR` and contains an optional pointer to the
//! `AIDX` for easy seek-ability within an archive block.
//!
//! | Type | Name    | Description |
//! | ---: | ------- | ----------- |
//! | u32  | idx_ptr | The offset (from start of the archive block) pointer to the `AIDX` |
//!
//! The standard strategy for doing a seek in an archive block which contains a `AIDX` is to
//! fetch the last 16 bytes (4 byte length, 4 byte type, 4 byte offset, 4 byte checksum). Once
//! the `AEND` block is fetched, parse out the `AIDX` pointer, and then do a second fetch of
//! `AIDX.offset - AEND.offset`. After the `AIDX` is parsed the user can now use this index to
//! do ranged seek within the entire archive block.
//!
//! **TODO**: Need to decide how to handle archive block without a `AIDX`. The pointer might be
//! set to `0x00_00_00_00`
mod builder;
pub mod indexing;
pub mod linear;
mod raw;
mod reader;

// 1Kb EDAT frame buffer
// TODO: to force ourself to handle sequence of EDAT for now use small
// chunk size such as 1024
#[allow(clippy::identity_op)]
const CHUNK_SIZE: usize = 1 * 1024;

#[allow(clippy::identity_op)]
const MAX_CHUNK_SIZE: usize = 10 * 1024;
