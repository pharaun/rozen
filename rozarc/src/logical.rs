use bitflags::bitflags;
use byteorder::LittleEndian as LE;
use byteorder::WriteBytesExt as _;
use std::collections::HashMap;
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
///     - Identity (type/hash/name) lives in footer index keyed by member_id
///     - If id == u32::max -> stop permitting new member, trigger archive to be sealed+rolled
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
///     - MIDDLE block == (id = X, seq = 1..u32::max, flag != is_last)
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
///         * Also if member_id == u32::max, stop accepting new member registeration
///     - Ask for a member_id hash/identification at finalization to permit hash compution during
///         streaming.
///         * Deduplication will need the hash upfront so its only a win for non-deduplication
///           workflow such as a (WORM archive).
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
/// Interleaving -vs- read locality:
/// - Format permits interleaving (id, seq) and the footer fragment list will track it
/// - It is not encouraged, for default workload it will slurp the data in on a contingious
///     block by block basis to reduce fragment-list size for each member
/// - For workload that needs fragmenting, it is a opt-in
///     * The opt in might be via a per-block api where you pass in the (id, seq) pair when you
///         add in a new block of data, and you finalize it manually
///     * The default slurp a reader api will do it contiguously.
use std::io;

// Must be at least 16 KiB for !is_last blocks
const MIN_BLOCK_SIZE: usize = 16 * 1024;

// flag: bit0 = is_last (closes its member_id to further writes)
//       bit1-7 Must be 0 (reserved)
bitflags! {
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
    inner: W,
    pos_soft_cap: u64,
    pos: u64,
}

// TODO: Better define the fragment index and how it interacts
// with the compression and encryption layers but for now just do
// a fragment table of logical offset + length
// TODO: probs want additional data here as well
#[derive(Default, Debug)]
pub struct MemberEntry {
    // TODO: Open question of how to handle duplicate hash (shouldn't admit it)
    pub hash: Option<Hash>,
    // TODO: No attempt is made to deduplicate/deal with runs of blocks at the moment
    // (logical offset + block-length)
    pub fragment: Vec<(u64, u32)>,
}

// NOTE: clone/copy not permitted to enforce api invartants
pub struct MemberHandle {
    id: u32,
    next_seq: Option<u32>,
}

// TODO: Convience methods:
// - write_reader(&mut MemberHandle, R: Read) -> IoResult<?>
//
// Note:
// * Do we want to permit a one shot member api that creates, write, hash, finalize a member?
impl<W: io::Write> LogicalBuilder<W> {
    pub fn new(writer: W, soft_cap: u64) -> Self {
        Self {
            next_id: Some(0),
            index: HashMap::new(),
            inner: writer,
            pos_soft_cap: soft_cap,
            pos: 0,
        }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    // TODO: replace Io errors with our own
    // TODO: If we want to uphold that no duplicate hash can exist,
    // may need to requiree up-front hash in create_member
    pub fn create_member(&mut self) -> io::Result<MemberHandle> {
        // Abort if:
        //  - next_id == None (member_id exhaustion)
        //  - pos >= pos_soft_cap (soft cap on archive max size)
        if self.pos >= self.pos_soft_cap {
            Err(io::Error::other("Logical Soft Cap hit"))
        } else {
            match self.next_id {
                None => Err(io::Error::other("Logical member_id exhaustion")),
                Some(next_id) => {
                    // Check if it is u32::MAX and if so, set it to None to signal exhaustion.
                    self.next_id = next_id.checked_add(1);
                    Ok(MemberHandle {
                        id: next_id,
                        next_seq: Some(0),
                    })
                }
            }
        }
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
    ) -> io::Result<usize> {
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

            // TODO: figure out how to handle this correctly, the issue is, we can write up
            // to u32 "max" which on u32 and u16 pointer platform is fine, but then that
            // means we can't return the true length of data written cuz header is 13 bytes
            // on top of that.... How do we handle this case?
            Ok((self.pos - old_pos) as usize)
        }
    }

    fn update_index(&mut self, member_id: u32, offset: u64, len: u32, hash: Option<Hash>) {
        // Fetch and update the entry
        // TODO: handle consolodating fragments, but for now just insert it all as it is
        let entry = self.index.entry(member_id).or_default();
        entry.hash = hash;
        entry.fragment.push((offset, len))
    }

    pub fn write_block(&mut self, handle: &mut MemberHandle, buf: &[u8]) -> io::Result<usize> {
        match handle.next_seq {
            None => Err(io::Error::other("Member seq counter exhaustion")),
            Some(next_seq) => {
                // Check if it is u32::MAX and if so, set it to None to signal exhaustion.
                handle.next_seq = next_seq.checked_add(1);

                let old_pos = self.pos;
                let len = self.write_block_data(handle.id, next_seq, !BlockFlags::IS_LAST, buf)?;
                // TODO: handle usize/u32 nonsense
                self.update_index(handle.id, old_pos, len as u32, None);
                Ok(len)
            }
        }
    }

    // TODO: Unsure if want to permit a 0 length final write if seq != 0, let's go with error here
    // but if seq = 0, permit a zero block write, actually do we even want to permit a zero block
    // write at all? might have that be handled at metadata layer above
    // TODO: How to handle duplicate hash?
    pub fn finish_member(
        &mut self,
        handle: MemberHandle,
        buf: &[u8],
        hash: Hash,
    ) -> io::Result<usize> {
        match handle.next_seq {
            // If its exhausted its too late to handle it here
            None => Err(io::Error::other("Member seq counter exhaustion")),
            Some(next_seq) => {
                let old_pos = self.pos;
                let len = self.write_block_data(handle.id, next_seq, BlockFlags::IS_LAST, buf)?;
                // TODO: handle usize/u32 nonsense
                self.update_index(handle.id, old_pos, len as u32, Some(hash));
                Ok(len)
            }
        }
    }

    // TODO: do we want a flag on the MemberEntry to flag it as finalized when it is or is
    // the presentence of Hash sufficient or not?
    // TODO: how to check for recoverable error, with this design right now any unfinalized
    // member -> hard error
    pub fn finish(self) -> io::Result<(W, HashMap<u32, MemberEntry>)> {
        // TODO: need to check how to handle flush/recheck the flush logic here again on if
        // we handle it here for let it be forwarded?
        let mut bad_member = vec![];
        for (key, member) in self.index.iter() {
            if member.hash.is_none() {
                bad_member.push(key);
            }
        }

        if bad_member.is_empty() {
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
