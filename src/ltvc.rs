use std::io::{Error, Read, Write};
use std::iter::Peekable;
use std::str::from_utf8;

use byteorder::{ReadBytesExt, LittleEndian, ByteOrder};
use thiserror::Error;

// Single threaded but we are on one thread here for now
use std::rc::Rc;

use crate::hash::Checksum;
use crate::hash::Hash;
use crate::buf::fill_buf;
use crate::buf::flush_buf;

// 1Kb EDAT frame buffer
// TODO: to force ourself to handle sequence of EDAT for now use small
// chunk size such as 1024
const CHUNK_SIZE: usize = 1 * 1024;
const MAX_CHUNK_SIZE: usize = 10 * 1024;

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


#[derive(Error, Debug)]
pub enum LtvcError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("permitted max chunk size exceeded")]
    MaxLengthError,
    #[error("checksum failed")]
    ChecksumError,
}

pub struct LtvcReaderRaw<R: Read> {
    inner: R,
}

// This only returns valid entry, invalid will be an Error string
#[derive(Debug, PartialEq)]
pub struct LtvcEntryRaw {
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
        let len = self.inner.read_u32::<LittleEndian>()? as usize;
        if len > MAX_CHUNK_SIZE {
            return Err(LtvcError::MaxLengthError);
        }

        let mut hash = Checksum::new();

        let typ = {
            let mut typ: [u8; 4] = [0; 4];
            self.inner.read_exact(&mut typ)?;
            typ
        };
        hash.update(&typ);

        let data = {
            let mut data = vec![0; len];
            self.inner.read_exact(&mut data[..])?;
            data
        };
        hash.update(&data[..]);

        // Time to validate the data before we return an entry
        let entry_hash = self.inner.read_u32::<LittleEndian>()?;

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


pub struct LtvcReader<R: Read> {
    inner: Rc<Peekable<LtvcReaderRaw<R>>>,
}

// TODO: have these entries hold Read trait not the EdatReader
pub enum LtvcEntry<R: Read> {
    Ahdr {
        version: u8,
    },
    Fhdr {
        hash: Hash,
        edat: EdatReader<R>,
    },
    Fidx {
        edat: EdatReader<R>,
    },
    Aend {
        idx: usize,
    }
}

pub struct EdatReader<R: Read> {
    inner: Rc<Peekable<LtvcReaderRaw<R>>>,
    out_buf: Vec<u8>,
}

impl<R: Read> Read for EdatReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.out_buf.is_empty() {
            // Fetch the next block of EDAT
            // TODO: handle checksum and other block parsing errors
            let inner = Rc::get_mut(&mut self.inner).unwrap();
            if let Some(Ok(peek)) = inner.peek() {
                if &peek.typ == b"EDAT" {
                    // We in business, grab it and stow the data in out_buf
                    let edata = inner.next().unwrap().unwrap();

                    self.out_buf = edata.data;
                } else {
                    // No more EDAT or none after, return 0
                    // TODO: case where there is only header and no edat is error
                    // catch this case
                    return Ok(0);
                }
            } else {
                // No more block left to decode
                return Ok(0);
            }
        }

        // At this point we *have* something in out_buf, flush it to the reader
        Ok(flush_buf(&mut self.out_buf, buf))
    }
}

impl<R: Read> LtvcReader<R> {
    pub fn new(reader: R) -> Self {
        LtvcReader {
            inner: Rc::new(LtvcReaderRaw {
                inner: reader,
            }.peekable()),
        }
    }
}

impl<R: Read> Iterator for LtvcReader<R> {
    type Item = Result<LtvcEntry<R>, LtvcError>;

    fn next(&mut self) -> Option<Self::Item> {
        let it = Rc::get_mut(&mut self.inner);
        if it.is_none() {
            panic!("Overlap mut of ltvc iter");
        }
        match it.unwrap().next() {
            None            => None,
            Some(Err(x))    => Some(Err(x)),
            Some(Ok(entry)) => {
                match &entry.typ {
                    b"AHDR" => {
                        // data should be 1 byte long, the version
                        if entry.data.len() != 1 {
                            panic!("AHDR isn't only version");
                        }
                        Some(Ok(LtvcEntry::Ahdr {
                            version: entry.data[0],
                        }))
                    },
                    b"FHDR" => {
                        // Should be 32 bytes long for the hash
                        if entry.data.len() != 32 {
                            panic!("FHDR malformed HASH length");
                        }
                        let hash: [u8; 32] = entry.data.try_into().unwrap();

                        // Setup a EDAT reader
                        Some(Ok(LtvcEntry::Fhdr {
                            hash: Hash::from(hash),
                            edat: EdatReader {
                                inner: self.inner.clone(),
                                out_buf: vec![],
                            }
                        }))

                    },
                    b"FIDX" => {
                        // Setup a EDAT reader
                        Some(Ok(LtvcEntry::Fidx {
                            edat: EdatReader {
                                inner: self.inner.clone(),
                                out_buf: vec![],
                            }
                        }))
                    },
                    b"AEND" => {
                        if entry.data.len() != 4 {
                            panic!("AEND isn't only version");
                        }
                        Some(Ok(LtvcEntry::Aend {
                            idx: LittleEndian::read_u32(&entry.data) as usize,
                        }))
                    },
                    // TODO: depends on when, if its after an unconsumed reader, we need to skip
                    // Otherwise its out of place and is an error
                    b"EDAT" => panic!("Standalone EDAT shouldn't happen!"),
                    x       => panic!("Didn't support: {:?}", from_utf8(x)),
                }
            },
        }
    }
}


// Deprecate this
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



#[cfg(test)]
mod test_ltvc_raw_iterator {
    use std::io::{Cursor, SeekFrom, Seek};
    use crate::crypto;
    use crate::hash;
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
                data: hash.as_bytes().to_vec(),
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

        // Write to the stream
        let data = Cursor::new(Vec::new());
        let hash = test_hash();
        let mut edat1 = Cursor::new(test_data_fhdr.clone());
        let mut edat2 = Cursor::new(test_data_fidx.clone());
        let mut builder = LtvcBuilder::new(data);

        builder.write_ahdr(0x01).unwrap();
        builder.write_fhdr(&hash).unwrap();
        builder.write_edat(&mut edat1).unwrap();
        builder.write_fidx().unwrap();
        builder.write_edat(&mut edat2).unwrap();
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
                data: hash.as_bytes().to_vec(),
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
                typ: *b"AEND",
                data: vec![142, 3, 0, 0],
            },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }
}
