use bitflags::bitflags;
use byteorder::LittleEndian as LE;
use byteorder::WriteBytesExt as _;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io;

use rozen::rcore::buf::fill_buf;

/// High level Logical Stream design
///
/// block := member_id: u32 || block_seq: u32 || flags: u8 || len: u32
///       || payload[len]
///
/// flag: bit0 = is_last (closes its member_id to further writes)
///       bit1-7 MUST be 0 (reserved)
///
///
/// member_id: per-archive logical unit (file, snapshot, cdc chunk, ...)
///     - Identity (type?/hash) lives in footer index keyed by member_id
///     - if id overflows u32::max trigger the archive to be sealed+rolled
///       This permits the last member_id == u32::max
///     - Also this is only for additing new members, so if there's still incomplete members that's
///       fine, just don't admit new members to the archive.
///
/// block_seq: 0 == start of the member unit, per-'member_id' block counter;
///     - Orders members block in a sequence strictly from 0 ... u32::max
///     - Permits interleaving member writes to the archive
///     - Monotonic per member with no gap, if a gap appears its a missing
///         block, useful for identifying corruption/missing data
///
/// Sequencing:
///     - START block == (id = X, seq = 0, flag != is_last)
///     - MIDDLE block == (id = X, seq = 1..(u32::max-1), flag != is_last)
///     - END block == (id = X, seq = 0..u32::max, flag = is_last)
///     - Single-block == (id = X, seq = 0, flag = is_last)
///     - Empty-block == (id = X, seq = 0, flag = is_last, len = 0)
///
/// Notes:
///     - Plaintext, the compression / encryption handles the AEAD/checksum/mac/etc
///     - For non-final blocks (flag != is_last) it must be 16KiB block minium. This
///         permits this format to reach 50TB cap defined by s3. The default writer
///         can preferrably align it to the 4MiB compression chunks/other boundaries.
///     - For final blocks (flag == is_last) the block can be smaller to permit smaller member
///     - For a soft-cap (say 256MiB)
///         * Once the soft-cap is hit, stop accepting new member registeration
///         * Finalize once all *currently-open* members are committed.
///         * Default writer keeps one member open at a time so usually the overshot is a single
///           member bounded
///         * Also if member_id for last entry is u32::max, stop accepting new member registeration
///     - (id/seq) is not used in happy path but for recovery, also decided to not include hash
///         * Can re-generate the hash after retrieving all object, and rehash the content
///
/// Field Widths:
/// - Defined by hard max object max size of 50TB (AWS raised it in Dec 2025)
///     - id: u32
///         * u32 is picked because it becomes a cap on max per-archive index size (limited by ram)
///
///     - seq / len: u32
///         * To store a max sized member, each block length must be at least
///             ~11.4KiB or bigger, hence 16KiB non-final block floor
///         * for 16KiB non-final block it will hit about 3.05 billion blocks for seq
///         * for natural 4MiB size it will hit about 12 million blocks for seq
///         * for members larger than u32 (4gb) it will take multiple blocks to represent
///             - this also allows a max of a 4gb "buffer" per block, can be adjusted by usecases
///
/// Overhead of header block:
/// - 16 KiB block -> 0.08% overhead (832 KiB per GiB of data)
/// -  1 MiB block -> 0.001% overhead (13 KiB per GiB of data)
/// -  4 MiB block -> 0.0003% overhead (3.25 KiB per GiB of data)
///
/// Interleaving -vs- read locality:
/// - Format permits interleaving (id, seq) and the footer fragment list will track it
/// - It is not encouraged, for default workload it will slurp the data in on a contingious
///     block by block basis to reduce fragment-list size for each member
/// - For workload that needs fragmenting, it is a opt-in
///     * The opt in might be via a per-block api where you pass in the (id, seq) pair when you
///         add in a new block of data, and you finalize it manually
///     * The default slurp a reader api will do it contiguously.

// Must be at least 16 KiB for !is_last blocks
const MIN_BLOCK_SIZE: usize = 16 * 1024;

// flag: bit0 = is_last (closes its member_id to further writes)
//       bit1-7 Must be 0 (reserved)
bitflags! {
    #[derive(Copy, Clone)]
    struct BlockFlags: u8 {
        const IS_LAST = 1;
    }
}

// TODO: replace with real hash
type Hash = [u8; 32];

pub struct LogicalBuilder<W: io::Write> {
    // To permit hitting u32::Max and signaling via None
    next_id: Option<u32>,
    index: HashMap<u32, MemberEntry>,
    seen_hash: HashSet<Hash>,
    inner: W,
    pos_soft_cap: u64,
    pos: u64,
}

// TODO: Once a compression/encryption layer is developed figure out how
// to handle the fragment table, but for now have it be logical positioning
#[derive(Default, Debug)]
pub struct MemberEntry {
    // TODO: a type field?
    pub hash: Hash,
    pub is_last: bool,
    // Fragment is a Vec to support interweaving member_ids but that is discouraged.
    // (logical offset (incl. header), block-run-length)
    pub fragment: Vec<(u64, u64)>,
}

// NOTE: clone/copy not permitted to enforce api invartants
pub struct MemberHandle {
    id: u32,
    next_seq: u32,
}

impl<W: io::Write> LogicalBuilder<W> {
    pub fn new(writer: W, soft_cap: u64) -> Self {
        Self {
            next_id: Some(0),
            index: HashMap::new(),
            seen_hash: HashSet::new(),
            inner: writer,
            pos_soft_cap: soft_cap,
            pos: 0,
        }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    fn add_fragment(&mut self, member_id: u32, offset: u64, len: u32, is_last: bool) {
        // TODO: handle consolodating fragments, but for now just insert it all as it is
        // TODO: No attempt is made to deduplicate/deal with runs of blocks at the moment
        let entry = self.index.entry(member_id).or_default();
        entry.is_last = is_last;
        entry.fragment.push((offset, len.into()))
    }

    fn write_block_header(
        &mut self,
        member_id: u32,
        block_seq: u32,
        flags: BlockFlags,
        len: u32,
    ) -> io::Result<usize> {
        // Write out the header block (but not the data) and return the length of the header block
        // block := member_id: u32 || block_seq: u32 || flags: u8 || len: u32
        self.inner.write_u32::<LE>(member_id)?;
        self.inner.write_u32::<LE>(block_seq)?;
        self.inner.write_u8(flags.bits())?;
        self.inner.write_u32::<LE>(len)?;

        // Length of header: 4 + 4 + 1 + 4 = 13 bytes.
        Ok(13)
    }

    fn write_block_data(
        &mut self,
        member_id: u32,
        block_seq: u32,
        flags: BlockFlags,
        buf: &[u8],
    ) -> io::Result<()> {
        // Check if the buf is at least 16KiB to uphold the u32 seq + u32 length invarant
        // However if flag is set to IS_LAST permit less than 16KiB write
        // Additionally check that the buf is not larger than can be held in u32 length
        if !flags.contains(BlockFlags::IS_LAST) && (buf.len() < MIN_BLOCK_SIZE) {
            Err(io::Error::other(format!(
                "Must be at least {MIN_BLOCK_SIZE} the buf is: {}",
                buf.len()
            )))
        } else if !buf_len_u32_check(buf.len()) {
            Err(io::Error::other(format!(
                "Too large to be stored in one block, split it. buf is: {}",
                buf.len()
            )))
        } else {
            let old_pos = self.pos;

            // Write header since we are ready for next block
            self.pos +=
                self.write_block_header(member_id, block_seq, flags, buf.len() as u32)? as u64;

            self.inner.write_all(buf)?;
            self.pos += buf.len() as u64;

            // Update the fragment table
            self.add_fragment(
                member_id,
                old_pos,
                buf.len() as u32,
                flags.contains(BlockFlags::IS_LAST),
            );

            Ok(())
        }
    }

    // TODO: replace Io errors with our own
    pub fn create_member(&mut self, hash: Hash) -> io::Result<MemberHandle> {
        // Abort if:
        //  - next_id == None (member_id exhaustion)
        //  - pos >= pos_soft_cap (soft cap on archive max size)
        //  - hash in index already
        if self.pos >= self.pos_soft_cap {
            Err(io::Error::other("Logical Soft Cap hit"))
        } else if self.seen_hash.contains(&hash) {
            Err(io::Error::other("Duplicate hash given"))
        } else {
            match self.next_id {
                None => Err(io::Error::other("Logical member_id exhaustion")),
                Some(next_id) => {
                    // Check if it is u32::MAX and if so, set it to None to signal exhaustion.
                    self.next_id = next_id.checked_add(1);
                    // We add it to the seen_hash since its attached to the handle now and
                    // initalize an initial fragment table entry
                    self.seen_hash.insert(hash);
                    self.index.insert(
                        next_id,
                        MemberEntry {
                            hash,
                            is_last: false,
                            fragment: vec![],
                        },
                    );

                    Ok(MemberHandle {
                        id: next_id,
                        next_seq: 0,
                    })
                }
            }
        }
    }

    pub fn write_block(&mut self, handle: &mut MemberHandle, buf: &[u8]) -> io::Result<()> {
        // Check if the next seq will be u32::MAX and if so, reject this write to guard
        // against coding yourself into a corner, force consumer to then use finish_member
        // to use the last seq.
        match handle.next_seq.checked_add(1) {
            None => Err(io::Error::other(
                "Member seq is at u32::MAX must use finish_member",
            )),
            Some(next_seq) => {
                let curr_seq = handle.next_seq;
                handle.next_seq = next_seq;

                self.write_block_data(handle.id, curr_seq, !BlockFlags::IS_LAST, buf)
            }
        }
    }

    pub fn finish_member(&mut self, handle: MemberHandle, buf: &[u8]) -> io::Result<()> {
        self.write_block_data(handle.id, handle.next_seq, BlockFlags::IS_LAST, buf)
    }

    pub fn write_reader(
        &mut self,
        mut handle: MemberHandle,
        mut reader: impl io::Read,
        chunk: usize,
    ) -> io::Result<()> {
        // Check that chunk is greater than MIN_BLOCK_SIZE (16 KiB permits 50 TB single member archive)
        if chunk < MIN_BLOCK_SIZE {
            // TODO: do we want to permit api users to pick a suboptimal block size here?
            Err(io::Error::other(format!(
                "Must be at least {MIN_BLOCK_SIZE} the chunk is: {chunk}"
            )))
        } else {
            // NOTE: I feel like this implement isn't very good, tweak it till its better, like
            // can we take advantage of the eof flag from fill_buf?
            let mut curr = vec![0; chunk];
            let mut next = vec![0; chunk];

            let (_, mut curr_len) = fill_buf(&mut reader, &mut curr)?;
            loop {
                let (_, next_len) = fill_buf(&mut reader, &mut next)?;

                if next_len == 0 {
                    return self.finish_member(handle, &curr[..curr_len]);
                }
                self.write_block(&mut handle, &curr[..curr_len])?;
                std::mem::swap(&mut curr, &mut next);
                curr_len = next_len;
            }
        }
    }

    // TODO: how to check for recoverable error, with this design right now any unfinalized
    // member -> hard error
    pub fn finish(self) -> io::Result<(W, HashMap<u32, MemberEntry>)> {
        // TODO: need to check how to handle flush/recheck the flush logic here again on if
        // we handle it here for let it be forwarded?
        let mut bad_member = vec![];
        for (key, member) in self.index.iter() {
            if !member.is_last {
                bad_member.push(key);
            }
        }

        if bad_member.is_empty() {
            // TODO: Spec gap: Don't know how to handle the fragment offset/index yet, for now use
            // logical offset/length. This code will need updating once we know
            Ok((self.inner, self.index))
        } else {
            Err(io::Error::other(format!(
                "Tried to finish this logical builder with still open members: {bad_member:?}"
            )))
        }
    }
}

fn buf_len_u32_check(len: usize) -> bool {
    if usize::BITS <= 32 {
        // on 16/32 anything fits in u32
        true
    } else {
        len <= u32::MAX as usize
    }
}
