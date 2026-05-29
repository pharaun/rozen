use std::io::ErrorKind;
use std::io::{Error, Read, Write};

use crate::rcore::buf::fill_buf;
use crate::rcore::hash::Checksum;
use crate::rcore::hash::Hash;

use crate::rarc::ltvc::CHUNK_SIZE;

pub(super) struct LtvcBuilder<W: Write> {
    inner: W,
}

// This is the high level writer interface
impl<W: Write> LtvcBuilder<W> {
    pub(super) fn new(writer: W) -> Self {
        Self { inner: writer }
    }

    pub(super) fn into_inner(self) -> W {
        self.inner
    }

    // TODO: Evaulate the need for a mandatory hash (evaulate crc instead?)
    // TODO: improve this whole block
    fn write(&mut self, chunk_type: [u8; 4], data: &[u8]) -> Result<usize, Error> {
        let data_len = u32::try_from(data.len())
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?
            .to_le_bytes();
        #[expect(clippy::cast_possible_truncation)]
        let header_hash = {
            let mut hash = Checksum::new();
            hash.update(&data_len);
            hash.update(&chunk_type);
            hash.finalize() as u16
        };
        let trailing_hash = {
            let mut hash = Checksum::new();
            hash.update(data);
            hash.finalize()
        };

        let mut len = 0;
        len += self.inner.write(&data_len)?;
        len += self.inner.write(&chunk_type)?;
        len += self.inner.write(&header_hash.to_le_bytes())?;
        len += self.inner.write(data)?;
        len += self.inner.write(&trailing_hash.to_le_bytes())?;

        Ok(len)
    }

    pub(super) fn write_ahdr(&mut self, version: u8) -> Result<usize, Error> {
        self.write(*b"AHDR", &[version])
    }

    pub(super) fn write_fhdr(&mut self, hash: &Hash) -> Result<usize, Error> {
        self.write(
            *b"FHDR",
            &{
                let mut data = vec![];
                data.extend_from_slice(hash.as_bytes());
                data
            }[..],
        )
    }

    pub(super) fn write_shdr(&mut self) -> Result<usize, Error> {
        self.write(*b"SHDR", &[])
    }

    // TODO: may be worth moving compression/encryption? to ensure that only
    // compressed+encrypted data arrives here, but also the management of those
    // might be better else where cos there might be multi-threading concerns
    //
    // TODO: consider having an header + edat id to allow reconstruction if header and edat
    // get scrambled, unclear if we need also an incrementing id for the edat to reconstruct
    // ordering as well
    pub(super) fn write_edat<R: Read>(&mut self, reader: &mut R) -> Result<usize, Error> {
        let mut r_len = 0;
        let mut in_buf = [0u8; CHUNK_SIZE];

        loop {
            match fill_buf(reader, &mut in_buf)? {
                (true, 0) => break,
                (_, len) => r_len += self.write(*b"EDAT", &in_buf[..len])?,
            }
        }
        Ok(r_len)
    }

    pub(super) fn write_aidx(&mut self) -> Result<usize, Error> {
        self.write(*b"AIDX", &[])
    }

    pub(super) fn write_pidx(&mut self) -> Result<usize, Error> {
        self.write(*b"PIDX", &[])
    }

    pub(super) fn write_aend(&mut self, f_idx: usize) -> Result<usize, Error> {
        self.write(
            *b"AEND",
            &(u32::try_from(f_idx).map_err(|e| Error::new(ErrorKind::InvalidData, e)))?
                .to_le_bytes(),
        )
    }
}
