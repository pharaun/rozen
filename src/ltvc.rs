use std::io::{Error, Read, Write};

use crate::hash::Checksum;
use crate::hash::Hash;
use crate::buf::fill_buf;

// 1Kb EDAT frame buffer
const CHUNK_SIZE: usize = 1 * 1024;

pub struct LtvcBuilder<W: Write> {
    inner: W,
}

// This is the high level writer interface
impl<W: Write> LtvcBuilder<W> {
    pub fn new(writer: W) -> Self {
        LtvcBuilder {
            inner: writer,
        }
    }

    pub fn to_inner(self) -> W {
        self.inner
    }

    // TODO: Evaulate the need for a hash
    // Length, Type, Value, xxhash32 of Type+Value
    // u32, u32, [u8; N], u32
    fn write(&mut self, chunk_type: &[u8; 4], data: &[u8]) -> Result<usize, Error> {
        let mut hash = Checksum::new();
        hash.update(chunk_type);
        hash.update(data);

        let mut len = 0;
        len += self.inner.write(&(data.len() as u32).to_le_bytes())?;
        len += self.inner.write(chunk_type)?;
        len += self.inner.write(data)?;
        len += self.inner.write(&hash.finalize().to_le_bytes())?;

        Ok(len)
    }

    pub fn write_ahdr(&mut self, version: u8) -> Result<usize, Error> {
        self.write(b"AHDR", &[version])
    }

    pub fn write_fhdr(&mut self, hash: &Hash) -> Result<usize, Error> {
        self.write(b"FHDR", hash.as_bytes())
    }

    pub fn write_edat<R: Read>(&mut self, reader: &mut R) -> Result<usize, Error> {
        let mut r_len = 0;
        let mut in_buf = [0u8; CHUNK_SIZE];

        loop {
            let (eof, len) = fill_buf(reader, &mut in_buf)?;
            r_len += self.write(b"EDAT", &in_buf[..len])?;

            if eof {
                break;
            }
        }
        Ok(r_len)
    }

    pub fn write_fidx(&mut self) -> Result<usize, Error> {
        self.write(b"FIDX", &[])
    }

    pub fn write_aend(&mut self, f_idx: usize) -> Result<usize, Error> {
        self.write(b"AEND", &(f_idx as u32).to_le_bytes())
    }
}

// Read the buffer to convert to a LTVC and validate
// TODO: consider a iterator/streaming option where it takes a buffer
// that begins on a chunk and then it streams the chunk+data one block at a time
// TODO: make sure to reject too large chunk size for preventing out of memory bugs
pub fn read_ltvc(buf: &[u8]) -> Option<(usize, [u8; 4], &[u8])> {
    let len_buf: [u8; 4] = buf[0..4].try_into().unwrap();
    let typ_buf: [u8; 4] = buf[4..8].try_into().unwrap();

    let len: usize = u32::from_le_bytes(len_buf) as usize;

    // TODO: this is bad, do this better, don't trust length
    let dat_buf: &[u8]   = buf[8..(8+len)].try_into().unwrap();
    let has_buf: [u8; 4] = buf[(8+len)..(8+len+4)].try_into().unwrap();

    let old_hash: u32 = u32::from_le_bytes(has_buf);

    // Validate the hash
    let mut hash = Checksum::new();
    hash.update(&typ_buf);
    hash.update(dat_buf);

    let whole_len = 4 + 4 + len + 4;

    if hash.finalize()  == old_hash {
        Some((whole_len, typ_buf, dat_buf))
    } else {
        None
    }
}

