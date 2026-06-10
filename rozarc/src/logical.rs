//! High level Logical Stream design
//!
//! block := member_id: u32 || block_seq: u32 || flags: u8 || len: u32
//!       || payload[len]
//!
//! flag: bit0 = is_last (closes its member_id to further writes)
//!       bit1-7 MUST be 0 (reserved)
//!
//!
//! member_id: per-archive logical unit (file, snapshot, cdc chunk, ...)
//!     - Identity (type?/hash) lives in footer index keyed by member_id
//!     - if id overflows u32::max trigger the archive to be sealed+rolled
//!       This permits the last member_id == u32::max
//!     - Also this is only for additing new members, so if there's still incomplete members that's
//!       fine, just don't admit new members to the archive.
//!
//! block_seq: 0 == start of the member unit, per-'member_id' block counter;
//!     - Orders members block in a sequence strictly from 0 ... u32::max
//!     - Permits interleaving member writes to the archive
//!     - Monotonic per member with no gap, if a gap appears its a missing
//!         block, useful for identifying corruption/missing data
//!
//! Sequencing:
//!     - START block == (id = X, seq = 0, flag != is_last)
//!     - MIDDLE block == (id = X, seq = 1..(u32::max-1), flag != is_last)
//!     - END block == (id = X, seq = 0..u32::max, flag = is_last)
//!     - Single-block == (id = X, seq = 0, flag = is_last)
//!     - Empty-block == (id = X, seq = 0, flag = is_last, len = 0)
//!
//! Notes:
//!     - Plaintext, the compression / encryption handles the AEAD/checksum/mac/etc
//!     - For non-final blocks (flag != is_last) it must be 16KiB block minium. This
//!         permits this format to reach 50TB cap defined by s3. The default writer
//!         can preferrably align it to the 4MiB compression chunks/other boundaries.
//!     - For final blocks (flag == is_last) the block can be smaller to permit smaller member
//!     - For a soft-cap (say 256MiB)
//!         * Once the soft-cap is hit, stop accepting new member registeration
//!         * Finalize once all *currently-open* members are committed.
//!         * Default writer keeps one member open at a time so usually the overshot is a single
//!           member bounded
//!         * Also if member_id for last entry is u32::max, stop accepting new member registeration
//!     - (id/seq) is not used in happy path but for recovery, also decided to not include hash
//!         * Can re-generate the hash after retrieving all object, and rehash the content
//!
//! Field Widths:
//! - Defined by hard max object max size of 50TB (AWS raised it in Dec 2025)
//!     - id: u32
//!         * u32 is picked because it becomes a cap on max per-archive index size (limited by ram)
//!
//!     - seq / len: u32
//!         * To store a max sized member, each block length must be at least
//!             ~11.4KiB or bigger, hence 16KiB non-final block floor
//!         * for 16KiB non-final block it will hit about 3.05 billion blocks for seq
//!         * for natural 4MiB size it will hit about 12 million blocks for seq
//!         * for members larger than u32 (4gb) it will take multiple blocks to represent
//!             - this also allows a max of a 4gb "buffer" per block, can be adjusted by usecases
//!
//! Overhead of header block:
//! - 16 KiB block -> 0.08% overhead (832 KiB per GiB of data)
//! -  1 MiB block -> 0.001% overhead (13 KiB per GiB of data)
//! -  4 MiB block -> 0.0003% overhead (3.25 KiB per GiB of data)
//!
//! Interleaving -vs- read locality:
//! - Format permits interleaving (id, seq) and the footer fragment list will track it
//! - It is not encouraged, for default workload it will slurp the data in on a contingious
//!     block by block basis to reduce fragment-list size for each member
//! - For workload that needs fragmenting, it is a opt-in
//!     * The opt in might be via a per-block api where you pass in the (id, seq) pair when you
//!         add in a new block of data, and you finalize it manually
//!     * The default slurp a reader api will do it contiguously.
use bitflags::bitflags;
use byteorder::LittleEndian as LE;
use byteorder::WriteBytesExt as _;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use thiserror::Error;

use rozen::rcore::buf::fill_buf;

// Must be at least 16 KiB for !is_last blocks
const MIN_BLOCK_SIZE: usize = 16 * 1024;

// TODO: replace with real hash
type Hash = [u8; 32];

#[derive(Error, Debug)]
pub enum LogicalError {
    #[error(transparent)]
    IO(#[from] io::Error),
    #[error("Must be at least {MIN_BLOCK_SIZE}. Is: {0}")]
    BelowMinBlockSize(usize),
    #[error("Must be less than u32::MAX. Is: {0}")]
    AboveMaxBlockSize(usize),
    #[error("Soft cap hit. Cap is: {0}, Currently is: {1}")]
    SoftCap(u64, u64),
    #[error("Logical memeber_id exhaustion.")]
    MemberIdCap,
    #[error("Member block_seq is at u32::MAX. Must invoke finish_member")]
    MemberSeqCap,
    #[error("Duplicate hash for member given")]
    DuplicateHash,
    #[error("Member block_seq is {0}, yet finish_member invoked with a empty buffer")]
    MemberSeqNotZeroForEmptyBlock(u32),
}

type LResult<T> = Result<T, LogicalError>;

// flag: bit0 = is_last (closes its member_id to further writes)
//       bit1-7 Must be 0 (reserved)
bitflags! {
    #[derive(Copy, Clone)]
    struct BlockFlags: u8 {
        const IS_LAST = 1;
    }
}

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
#[derive(Default, Debug, PartialEq)]
pub struct MemberEntry {
    // TODO: a type field?
    pub hash: Hash,
    // Fragment is a Vec to support interweaving member_ids but that is discouraged.
    // (logical offset (incl. header), block-run-length)
    pub fragment: Vec<(u64, u64)>,
    is_last: bool,
}

// NOTE: clone/copy not permitted to enforce api invartants
#[derive(Debug)]
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

    fn add_fragment(&mut self, member_id: u32, offset: u64, len: u64, flags: BlockFlags) {
        let entry = self.index.entry(member_id).or_default();
        entry.is_last = flags.contains(BlockFlags::IS_LAST);

        match entry
            .fragment
            .pop_if(|(p_off, p_len)| (*p_off + *p_len) == offset)
        {
            None => entry.fragment.push((offset, len)),
            Some((p_off, p_len)) => entry.fragment.push((p_off, p_len + len)),
        }
    }

    pub fn create_member(&mut self, hash: Hash) -> LResult<MemberHandle> {
        // Abort if:
        //  - next_id == None (member_id exhaustion)
        //  - pos >= pos_soft_cap (soft cap on archive max size)
        //  - hash in index already
        if self.pos >= self.pos_soft_cap {
            Err(LogicalError::SoftCap(self.pos_soft_cap, self.pos))
        } else if self.seen_hash.contains(&hash) {
            Err(LogicalError::DuplicateHash)
        } else {
            match self.next_id {
                None => Err(LogicalError::MemberIdCap),
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

    pub fn write_block(&mut self, handle: &mut MemberHandle, buf: &[u8]) -> LResult<()> {
        // Check if the next seq will be u32::MAX and if so, reject this write to guard
        // against coding yourself into a corner, force consumer to then use finish_member
        // to use the last seq.
        match handle.next_seq.checked_add(1) {
            None => Err(LogicalError::MemberSeqCap),
            Some(next_seq) => {
                let curr_seq = handle.next_seq;
                handle.next_seq = next_seq;

                let old_pos = self.pos;
                self.pos += write_block_header(
                    &mut self.inner,
                    handle.id,
                    curr_seq,
                    !BlockFlags::IS_LAST,
                    buf.len(),
                )?;
                self.pos += write_block_data(&mut self.inner, !BlockFlags::IS_LAST, buf)?;
                self.add_fragment(handle.id, old_pos, self.pos - old_pos, !BlockFlags::IS_LAST);
                Ok(())
            }
        }
    }

    #[expect(clippy::needless_pass_by_value)]
    pub fn finish_member(&mut self, handle: MemberHandle, buf: &[u8]) -> LResult<()> {
        if buf.is_empty() && handle.next_seq != 0 {
            Err(LogicalError::MemberSeqNotZeroForEmptyBlock(handle.next_seq))
        } else {
            let old_pos = self.pos;
            self.pos += write_block_header(
                &mut self.inner,
                handle.id,
                handle.next_seq,
                BlockFlags::IS_LAST,
                buf.len(),
            )?;
            self.pos += write_block_data(&mut self.inner, BlockFlags::IS_LAST, buf)?;
            self.add_fragment(handle.id, old_pos, self.pos - old_pos, BlockFlags::IS_LAST);
            Ok(())
        }
    }

    pub fn write_reader(
        &mut self,
        mut handle: MemberHandle,
        mut reader: impl io::Read,
        chunk: usize,
    ) -> LResult<()> {
        // Check that chunk is greater than MIN_BLOCK_SIZE (16 KiB permits 50 TB single member archive)
        if chunk < MIN_BLOCK_SIZE {
            // TODO: do we want to permit api users to pick a suboptimal block size here?
            Err(LogicalError::BelowMinBlockSize(chunk))
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
    pub fn finish(self) -> LResult<(W, HashMap<u32, MemberEntry>)> {
        // TODO: need to check how to handle flush/recheck the flush logic here again on if
        // we handle it here for let it be forwarded?
        let mut bad_member = vec![];
        for (key, member) in &self.index {
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
            ))
            .into())
        }
    }
}

fn write_block_header(
    mut writer: impl io::Write,
    member_id: u32,
    block_seq: u32,
    flags: BlockFlags,
    len: usize,
) -> LResult<u64> {
    // Write out the header block (but not the data) and return the length of the header block
    // block := member_id: u32 || block_seq: u32 || flags: u8 || len: u32
    writer.write_u32::<LE>(member_id)?;
    writer.write_u32::<LE>(block_seq)?;
    writer.write_u8(flags.bits())?;
    #[expect(clippy::cast_possible_truncation)]
    writer.write_u32::<LE>(len as u32)?;

    // Length of header: 4 + 4 + 1 + 4 = 13 bytes.
    Ok(13)
}

fn write_block_data(mut writer: impl io::Write, flags: BlockFlags, buf: &[u8]) -> LResult<u64> {
    // Check if the buf is at least 16KiB to uphold the u32 seq + u32 length invarant
    // However if flag is set to IS_LAST permit less than 16KiB write
    // Additionally check that the buf is not larger than can be held in u32 length
    if !flags.contains(BlockFlags::IS_LAST) && (buf.len() < MIN_BLOCK_SIZE) {
        Err(LogicalError::BelowMinBlockSize(buf.len()))
    } else if !buf_len_u32_check(buf.len()) {
        Err(LogicalError::AboveMaxBlockSize(buf.len()))
    } else {
        writer.write_all(buf)?;
        Ok(buf.len() as u64)
    }
}

fn buf_len_u32_check(len: usize) -> bool {
    if usize::BITS <= 32 {
        // on 16/32 anything fits in u32
        true
    } else {
        u32::try_from(len).is_ok()
    }
}

#[cfg(test)]
mod test_logical {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn empty_logical() {
        let log = LogicalBuilder::new(vec![], u64::MAX);
        let (out, idx) = log.finish().unwrap();

        assert!(out.is_empty());
        assert!(idx.is_empty());
    }

    #[test]
    fn create_member() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let handle = log.create_member([0; 32]).unwrap();

        assert_eq!(handle.id, 0);
        assert_eq!(handle.next_seq, 0);
    }

    #[test]
    fn create_duplicate_member() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        log.create_member([0; 32]).unwrap();
        let handle = log.create_member([0; 32]);

        assert!(matches!(handle, Err(LogicalError::DuplicateHash)));
    }

    #[test]
    fn create_member_id_exhaustion() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        log.next_id = None;
        let handle = log.create_member([0; 32]);

        assert!(matches!(handle, Err(LogicalError::MemberIdCap)));
    }

    #[test]
    fn create_member_soft_cap() {
        let mut log = LogicalBuilder::new(vec![], u16::MAX.into());
        log.pos = u32::MAX.into();
        let handle = log.create_member([0; 32]);

        assert!(
            matches!(handle, Err(LogicalError::SoftCap(a, b)) if a == u16::MAX.into() && b == u32::MAX.into())
        );
    }

    #[test]
    fn finish_empty_member() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        // Guard against scrambled seq/id in header
        log.next_id = Some(32_767);
        let handle = log.create_member([0; 32]).unwrap();

        log.finish_member(handle, &vec![]).unwrap();

        let (out, idx) = log.finish().unwrap();

        // Header (Little Endian)
        let expect = vec![
            255, 127, 0, 0, // Member Id == 32,767
            0, 0, 0, 0, // Seq == 0
            1, // Flag = 0x1 = is_last
            0, 0, 0, 0, // Len == 0 (its empty data)
        ];
        assert_eq!(out, expect);

        // Idx
        let expect = HashMap::from([(
            32_767,
            MemberEntry {
                hash: [0; 32],
                fragment: vec![(0, 13)],
                is_last: true,
            },
        )]);
        assert_eq!(idx, expect);
    }

    #[test]
    fn finish_nonzero_block_seq_empty_member() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let mut handle = log.create_member([0; 32]).unwrap();
        handle.next_seq = 32_767;

        let res = log.finish_member(handle, &vec![]);
        assert!(matches!(res, Err(LogicalError::MemberSeqNotZeroForEmptyBlock(a)) if a == 32_767));
    }

    #[test]
    fn finish_member() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        // Guard against scrambled seq/id in header
        log.next_id = Some(31_767);

        let mut handle = log.create_member([0; 32]).unwrap();
        // Guard against scrambled seq/id in header
        handle.next_seq = 61_535;

        let data = vec![1, 2, 3, 4];
        log.finish_member(handle, &data).unwrap();

        let (out, idx) = log.finish().unwrap();

        // Header + data
        let mut expect = vec![];
        write_block_header(&mut expect, 31_767, 61_535, BlockFlags::IS_LAST, data.len()).unwrap();
        expect.extend(data);
        assert_eq!(out, expect);

        // Idx
        let expect = HashMap::from([(
            31_767,
            MemberEntry {
                hash: [0; 32],
                fragment: vec![(0, 13 + 4)],
                is_last: true,
            },
        )]);
        assert_eq!(idx, expect);
    }

    #[test]
    fn write_block_finish() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let mut handle = log.create_member([0; 32]).unwrap();

        let data1 = vec![1; 32 * 1024];
        log.write_block(&mut handle, &data1).unwrap();

        let data2 = vec![5, 6, 7, 8];
        log.finish_member(handle, &data2).unwrap();

        let (out, idx) = log.finish().unwrap();

        // Header + data
        let mut expect = vec![];
        write_block_header(&mut expect, 0, 0, !BlockFlags::IS_LAST, data1.len()).unwrap();
        expect.extend(data1);
        write_block_header(&mut expect, 0, 1, BlockFlags::IS_LAST, data2.len()).unwrap();
        expect.extend(data2);

        assert_eq!(out, expect);

        // Idx
        let expect = HashMap::from([(
            0,
            MemberEntry {
                hash: [0; 32],
                fragment: vec![(0, 13 + (32 * 1024) + 13 + 4)],
                is_last: true,
            },
        )]);
        assert_eq!(idx, expect);
    }

    #[test]
    fn write_block_interweave_finish() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let mut handle1 = log.create_member([0; 32]).unwrap();
        let handle2 = log.create_member([1; 32]).unwrap();

        let data11 = vec![1; 32 * 1024];
        log.write_block(&mut handle1, &data11).unwrap();

        let data21 = vec![9, 10, 11, 12];
        log.finish_member(handle2, &data21).unwrap();

        let data12 = vec![5, 6, 7, 8];
        log.finish_member(handle1, &data12).unwrap();

        let (out, idx) = log.finish().unwrap();

        // Header + data
        let mut expect = vec![];
        write_block_header(&mut expect, 0, 0, !BlockFlags::IS_LAST, data11.len()).unwrap();
        expect.extend(data11);
        write_block_header(&mut expect, 1, 0, BlockFlags::IS_LAST, data21.len()).unwrap();
        expect.extend(data21);
        write_block_header(&mut expect, 0, 1, BlockFlags::IS_LAST, data12.len()).unwrap();
        expect.extend(data12);

        assert_eq!(out, expect);

        // Idx
        let expect = HashMap::from([
            (
                0,
                MemberEntry {
                    hash: [0; 32],
                    fragment: vec![(0, 32781), (32798, 17)],
                    is_last: true,
                },
            ),
            (
                1,
                MemberEntry {
                    hash: [1; 32],
                    fragment: vec![(32781, 17)],
                    is_last: true,
                },
            ),
        ]);
        assert_eq!(idx, expect);
    }

    #[test]
    fn write_block_last_seq() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let mut handle = log.create_member([0; 32]).unwrap();
        handle.next_seq = u32::MAX;

        let res = log.write_block(&mut handle, &vec![0; 32 * 1024]);
        assert!(matches!(res, Err(LogicalError::MemberSeqCap)));
    }

    #[test]
    fn write_too_small_block() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let mut handle = log.create_member([0; 32]).unwrap();

        let data1 = vec![1, 2, 3, 4];
        let res = log.write_block(&mut handle, &data1);
        assert!(matches!(res, Err(LogicalError::BelowMinBlockSize(a)) if a == 4));
    }

    #[test]
    fn finish_unfinished_member() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let mut handle = log.create_member([0; 32]).unwrap();
        log.write_block(&mut handle, &vec![0; 32 * 1024]).unwrap();

        // TODO: better define and handle various error types but for now
        // just make sure we throw an io error when the user forget to finish
        // their member writes
        let res = log.finish();
        match res {
            Err(LogicalError::IO(e)) => assert!(matches!(e.kind(), io::ErrorKind::Other)),
            _ => unreachable!(),
        }
    }

    #[test]
    fn write_reader_below_min_block_size() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let handle = log.create_member([0; 32]).unwrap();

        let res = log.write_reader(
            handle,
            Cursor::new(vec![1; MIN_BLOCK_SIZE]),
            MIN_BLOCK_SIZE - 1,
        );
        assert!(matches!(res, Err(LogicalError::BelowMinBlockSize(a)) if a == MIN_BLOCK_SIZE - 1));
    }

    #[test]
    fn write_reader_empty_first_write() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let handle = log.create_member([0; 32]).unwrap();
        log.write_reader(handle, Cursor::new(vec![]), MIN_BLOCK_SIZE)
            .unwrap();

        let (out, _) = log.finish().unwrap();

        // Header + data
        let mut expect = vec![];
        write_block_header(&mut expect, 0, 0, BlockFlags::IS_LAST, 0).unwrap();
        assert_eq!(out, expect);
    }

    #[test]
    fn write_reader_small_write() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let handle = log.create_member([0; 32]).unwrap();

        let data = vec![1; MIN_BLOCK_SIZE / 2];
        log.write_reader(handle, Cursor::new(data.clone()), MIN_BLOCK_SIZE)
            .unwrap();

        let (out, _) = log.finish().unwrap();

        // Header + data
        let mut expect = vec![];
        write_block_header(&mut expect, 0, 0, BlockFlags::IS_LAST, MIN_BLOCK_SIZE / 2).unwrap();
        expect.extend(data);
        assert_eq!(out, expect);
    }

    #[test]
    fn write_reader_three_write_partial_last() {
        let mut log = LogicalBuilder::new(vec![], u64::MAX);
        let handle = log.create_member([0; 32]).unwrap();

        let data1 = vec![1; MIN_BLOCK_SIZE];
        let data2 = vec![2; MIN_BLOCK_SIZE];
        let data3 = vec![3; MIN_BLOCK_SIZE / 2];

        let mut buf = vec![];
        buf.extend(data1.clone());
        buf.extend(data2.clone());
        buf.extend(data3.clone());

        log.write_reader(handle, Cursor::new(buf), MIN_BLOCK_SIZE)
            .unwrap();

        let (out, _) = log.finish().unwrap();

        // Header + data
        let mut expect = vec![];
        write_block_header(&mut expect, 0, 0, !BlockFlags::IS_LAST, MIN_BLOCK_SIZE).unwrap();
        expect.extend(data1);
        write_block_header(&mut expect, 0, 1, !BlockFlags::IS_LAST, MIN_BLOCK_SIZE).unwrap();
        expect.extend(data2);
        write_block_header(&mut expect, 0, 2, BlockFlags::IS_LAST, MIN_BLOCK_SIZE / 2).unwrap();
        expect.extend(data3);
        assert_eq!(out, expect);
    }
}
