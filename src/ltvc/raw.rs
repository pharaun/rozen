use std::io::Read;
use std::fmt::Debug;

use byteorder::{ReadBytesExt, LittleEndian};
use thiserror::Error;

use crate::hash::Checksum;
use crate::ltvc::MAX_CHUNK_SIZE;

#[derive(Error, Debug)]
pub enum LtvcError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("permitted max chunk size exceeded")]
    MaxLengthError,
    #[error("checksum failed")]
    ChecksumError,
    #[error("header checksum failed")]
    HeaderChecksumError,
}

pub struct LtvcReaderRaw<R: Read> {
    inner: R,
}

// This only returns valid entry, invalid will be an Error string
#[derive(Debug, PartialEq)]
pub struct LtvcEntryRaw {
    // TODO: consider the merit of 4 bytes type? with 4 flag value in future
    // versus 1x 8byte type + 8byte flag field.
    // u32, u8, u8, u16 vs u32, u32, u16.
    // Also this opens the question of the u16 checksum or if a 8bit checksum/crc8 is fine?
    pub typ: [u8; 4],
    pub data: Vec<u8>,
}

impl<R: Read> LtvcReaderRaw<R> {
    pub fn new(reader: R) -> Self {
        LtvcReaderRaw {
            inner: reader,
        }
    }

    fn read_entry(&mut self) -> Result<LtvcEntryRaw, LtvcError> {
        let (len, typ) = {
            let len = self.inner.read_u32::<LittleEndian>()?;
            let typ = {
                let mut typ: [u8; 4] = [0; 4];
                self.inner.read_exact(&mut typ)?;
                typ
            };
            let header_hash = self.inner.read_u16::<LittleEndian>()?;

            let mut hash = Checksum::new();
            hash.update(&len.to_le_bytes());
            hash.update(&typ);

            // Validate the header
            if (hash.finalize() as u16) != header_hash {
                return Err(LtvcError::HeaderChecksumError)
            }

            (len as usize, typ)
        };

        if len > MAX_CHUNK_SIZE {
            return Err(LtvcError::MaxLengthError);
        }

        let data = {
            let mut data = vec![0; len];
            self.inner.read_exact(&mut data[..])?;
            data
        };
        let entry_hash = self.inner.read_u32::<LittleEndian>()?;

        let mut hash = Checksum::new();
        hash.update(&data[..]);

        if hash.finalize() == entry_hash {
            Ok(LtvcEntryRaw {
                typ: typ,
                data: data,
            })
        } else {
            Err(LtvcError::ChecksumError)
        }
    }
}

impl<R: Read> Iterator for LtvcReaderRaw<R> {
    type Item = Result<LtvcEntryRaw, LtvcError>;

    fn next(&mut self) -> Option<Self::Item> {
        // For now if IOError is recieved, assume stream is done and return None
        match self.read_entry() {
            // TODO: should be UnexpectedEof
            Err(LtvcError::IOError(_)) => None,
            Err(x) => Some(Err(x)),
            Ok(x)  => Some(Ok(x)),
        }
    }
}


#[cfg(test)]
mod test_ltvc_raw_iterator {
    use std::io::{Cursor, SeekFrom, Seek};
    use crate::crypto;
    use crate::hash;
    use crate::ltvc::builder::LtvcBuilder;
    use crate::ltvc::CHUNK_SIZE;
    use super::*;

    fn test_hash() -> hash::Hash {
        let id = crypto::gen_key();
        hash::Hash::from(id.0)
    }

    #[test]
    fn one_ahdr() {
        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_ahdr(0x01).unwrap();

        // Reset stream
        let mut data = builder.to_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReaderRaw::new(data);

        assert_eq!(
            LtvcEntryRaw {
                typ: *b"AHDR",
                data: vec![0x01],
            },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_fhdr() {
        // Write to the stream
        let data = Cursor::new(Vec::new());
        let hash = test_hash();
        let mut builder = LtvcBuilder::new(data);
        builder.write_fhdr(&hash).unwrap();

        // Reset stream
        let mut data = builder.to_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReaderRaw::new(data);

        assert_eq!(
            LtvcEntryRaw {
                typ: *b"FHDR",
                data: {
                    let mut data = hash.as_bytes().to_vec();
                    data
                },
            },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_fidx() {
        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_fidx().unwrap();

        // Reset stream
        let mut data = builder.to_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReaderRaw::new(data);

        assert_eq!(
            LtvcEntryRaw {
                typ: *b"FIDX",
                data: vec![],
            },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_aend() {
        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_aend(12345).unwrap();

        // Reset stream
        let mut data = builder.to_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReaderRaw::new(data);

        assert_eq!(
            LtvcEntryRaw {
                typ: *b"AEND",
                data: vec![57, 48, 0, 0],
            },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_edat_empty() {
        let mut edat = Cursor::new(Vec::new());

        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_edat(&mut edat).unwrap();

        // Reset stream
        let mut data = builder.to_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReaderRaw::new(data);

        // TODO: do we want to allow an intentional empty EDAT write?
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_edat_half_buffer() {
        let test_data: Vec<u8> = {
            let cap: usize = (0.5 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!!!!!"; // Must be 16 bytes

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret
        };
        let mut edat = Cursor::new(test_data.clone());

        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_edat(&mut edat).unwrap();

        // Reset stream
        let mut data = builder.to_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReaderRaw::new(data);

        assert_eq!(
            LtvcEntryRaw {
                typ: *b"EDAT",
                data: test_data,
            },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_edat_one_buffer() {
        let test_data: Vec<u8> = {
            let cap: usize = (1.0 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!!!!!"; // Must be 16 bytes

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret
        };
        assert_eq!(test_data.len(), CHUNK_SIZE);
        let mut edat = Cursor::new(test_data.clone());

        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_edat(&mut edat).unwrap();

        // Reset stream
        let mut data = builder.to_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReaderRaw::new(data);

        assert_eq!(
            LtvcEntryRaw {
                typ: *b"EDAT",
                data: test_data,
            },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_edat_two_buffer() {
        let test_data: Vec<u8> = {
            let cap: usize = (2.0 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!!!!!"; // Must be 16 bytes

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret
        };
        assert_eq!(test_data.len(), CHUNK_SIZE * 2);
        let mut edat = Cursor::new(test_data.clone());

        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_edat(&mut edat).unwrap();

        // Reset stream
        let mut data = builder.to_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReaderRaw::new(data);

        // Split data into halves
        let split: Vec<&[u8]> = test_data.chunks(CHUNK_SIZE).collect();

        assert_eq!(
            LtvcEntryRaw {
                typ: *b"EDAT",
                data: split.get(0).unwrap().to_vec(),
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"EDAT",
                data: split.get(1).unwrap().to_vec(),
            },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_pseudofile() {
        let test_data_fhdr = vec![1, 2, 3, 4];
        let test_data_fidx = vec![5, 6, 7, 8];
        let test_data_pidx = vec![9, 10, 11, 12];
        let test_data_shdr = vec![13, 14, 15, 16];

        // Write to the stream
        let data = Cursor::new(Vec::new());
        let hash = test_hash();
        let mut edat1 = Cursor::new(test_data_fhdr.clone());
        let mut edat2 = Cursor::new(test_data_fidx.clone());
        let mut edat3 = Cursor::new(test_data_pidx.clone());
        let mut edat4 = Cursor::new(test_data_shdr.clone());
        let mut builder = LtvcBuilder::new(data);

        builder.write_ahdr(0x01).unwrap();
        builder.write_fhdr(&hash).unwrap();
        builder.write_edat(&mut edat1).unwrap();
        builder.write_fidx().unwrap();
        builder.write_edat(&mut edat2).unwrap();
        builder.write_pidx().unwrap();
        builder.write_edat(&mut edat3).unwrap();
        builder.write_shdr().unwrap();
        builder.write_edat(&mut edat4).unwrap();
        builder.write_aend(910).unwrap();

        // Reset stream
        let mut data = builder.to_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReaderRaw::new(data);

        // This is what a small one fhdr+fidx file should look like
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"AHDR",
                data: vec![0x01],
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"FHDR",
                data: {
                    let mut data = hash.as_bytes().to_vec();
                    data
                },
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"EDAT",
                data: test_data_fhdr,
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"FIDX",
                data: vec![],
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"EDAT",
                data: test_data_fidx,
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"PIDX",
                data: vec![],
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"EDAT",
                data: test_data_pidx,
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"SHDR",
                data: vec![],
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"EDAT",
                data: test_data_shdr,
            },
            reader.next().unwrap().unwrap()
        );
        assert_eq!(
            LtvcEntryRaw {
                typ: *b"AEND",
                data: vec![142, 3, 0, 0],
            },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }
}
