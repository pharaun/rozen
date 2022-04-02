use std::io::{Error, Read, Write};

use crate::hash::Checksum;
use crate::hash::Hash;
use crate::buf::fill_buf;
use crate::ltvc::CHUNK_SIZE;

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

    // TODO: may be worth moving compression/encryption? to ensure that only
    // compressed+encrypted data arrives here, but also the management of those
    // might be better else where cos there might be multi-threading concerns
    pub fn write_edat<R: Read>(&mut self, reader: &mut R) -> Result<usize, Error> {
        let mut r_len = 0;
        let mut in_buf = [0u8; CHUNK_SIZE];

        loop {
            match fill_buf(reader, &mut in_buf)? {
                (true, 0) => break,
                (_, len)  => r_len += self.write(b"EDAT", &in_buf[..len])?,
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