use std::io::Read;
use std::iter::Peekable;
use std::str::from_utf8;

#[cfg(test)]
use std::fmt;

#[cfg(test)]
use std::fmt::Debug;

use byteorder::{ByteOrder, LittleEndian};

// Single threaded but we are on one thread here for now
use std::cell::RefCell;
use std::rc::Rc;

use crate::buf::flush_buf;
use crate::hash::Hash;
use crate::ltvc::raw::LtvcError;
use crate::ltvc::raw::LtvcReaderRaw;

pub struct LtvcReader<R: Read> {
    inner: Rc<RefCell<Peekable<LtvcReaderRaw<R>>>>,
}

// TODO: may still be better to return the EdatReader so you can invoke .skip()
// to force the stream to skip to the next non-edat chunk
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum LtvcEntry<R: Read> {
    Ahdr { version: u8 },
    Fhdr { hash: Hash },
    Shdr,
    Fidx,
    Pidx,
    Edat { data: EdatReader<R> },
    Aend { idx: usize },
}

pub struct EdatReader<R: Read> {
    inner: Rc<RefCell<Peekable<LtvcReaderRaw<R>>>>,
    out_buf: Vec<u8>,
}

#[cfg(test)]
impl<R: Read> PartialEq for EdatReader<R> {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

#[cfg(test)]
impl<R: Read> Debug for EdatReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Point")
            .field("inner", &"LtvcReaderRaw Iter".to_string())
            .field("out_buf", &"Output Buffer".to_string())
            .finish()
    }
}

impl<R: Read> Read for EdatReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.out_buf.is_empty() {
            // Fetch the next block of EDAT
            // TODO: handle checksum and other block parsing errors
            let mut inner = self.inner.borrow_mut();
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
            inner: Rc::new(RefCell::new(LtvcReaderRaw::new(reader).peekable())),
        }
    }
}

impl<R: Read> Iterator for LtvcReader<R> {
    type Item = Result<LtvcEntry<R>, LtvcError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut inner = self.inner.borrow_mut();
        match inner.next() {
            None => None,
            Some(Err(x)) => Some(Err(x)),
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
                    }
                    b"FHDR" => {
                        let len = entry.data.len();

                        // Should be 32 bytes for hash
                        if len != 32 {
                            panic!("FHDR malformed HASH length");
                        }
                        let hash: [u8; 32] = entry.data[..len].try_into().unwrap();

                        // Setup a EDAT reader
                        Some(Ok(LtvcEntry::Fhdr {
                            hash: Hash::from(hash),
                        }))
                    }
                    b"SHDR" => Some(Ok(LtvcEntry::Shdr)),
                    b"FIDX" => Some(Ok(LtvcEntry::Fidx)),
                    b"PIDX" => Some(Ok(LtvcEntry::Pidx)),
                    b"EDAT" => {
                        // TODO: If we skip first EDAT we will get second one with a reader
                        // over and over... So might be worth adding additional logic to see
                        // if it has seen at least one edat before if so, automatically skip
                        // if not already skipped by the EdatReader
                        //
                        // Setup a EDAT reader
                        Some(Ok(LtvcEntry::Edat {
                            data: EdatReader {
                                inner: self.inner.clone(),
                                // Preseed it with *THIS* edat's data
                                out_buf: entry.data,
                            },
                        }))
                    }
                    b"AEND" => {
                        if entry.data.len() != 4 {
                            panic!("AEND isn't only version");
                        }
                        Some(Ok(LtvcEntry::Aend {
                            idx: LittleEndian::read_u32(&entry.data) as usize,
                        }))
                    }
                    x => panic!("Didn't support: {:?}", from_utf8(x)),
                }
            }
        }
    }
}

#[cfg(test)]
mod test_ltvc_iterator {
    use super::*;
    use crate::crypto;
    use crate::hash;
    use crate::ltvc::builder::LtvcBuilder;
    use crate::ltvc::CHUNK_SIZE;
    use std::io::{copy, Cursor, Seek, SeekFrom};

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
        let mut data = builder.into_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReader::new(data);

        assert_eq!(
            LtvcEntry::Ahdr { version: 0x01 },
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
        let mut data = builder.into_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReader::new(data);

        assert_eq!(
            LtvcEntry::Fhdr { hash: hash },
            reader.next().unwrap().unwrap()
        );
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_shdr() {
        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_shdr().unwrap();

        // Reset stream
        let mut data = builder.into_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReader::new(data);

        assert_eq!(LtvcEntry::Shdr, reader.next().unwrap().unwrap());
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_fidx() {
        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_fidx().unwrap();

        // Reset stream
        let mut data = builder.into_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReader::new(data);

        assert_eq!(LtvcEntry::Fidx, reader.next().unwrap().unwrap());
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_pidx() {
        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_pidx().unwrap();

        // Reset stream
        let mut data = builder.into_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReader::new(data);

        assert_eq!(LtvcEntry::Pidx, reader.next().unwrap().unwrap());
        assert!(reader.next().is_none());
    }

    #[test]
    fn one_aend() {
        // Write to the stream
        let data = Cursor::new(Vec::new());
        let mut builder = LtvcBuilder::new(data);
        builder.write_aend(12345).unwrap();

        // Reset stream
        let mut data = builder.into_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReader::new(data);

        assert_eq!(
            LtvcEntry::Aend { idx: 12345 },
            reader.next().unwrap().unwrap()
        );
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
        let mut data = builder.into_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReader::new(data);

        // Should be only one reader
        let mut new_data = vec![];
        let edatreader = reader.next().unwrap().unwrap();
        match edatreader {
            LtvcEntry::Edat { data: mut x } => {
                let _ = copy(&mut x, &mut new_data);
            }
            _ => panic!("Invalid data in test"),
        }
        assert_eq!(new_data, test_data);
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
        let mut data = builder.into_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReader::new(data);

        // Should be only one reader
        let mut new_data = vec![];
        let edatreader = reader.next().unwrap().unwrap();
        match edatreader {
            LtvcEntry::Edat { data: mut x } => {
                let _ = copy(&mut x, &mut new_data);
            }
            _ => panic!("Invalid data in test"),
        }
        assert_eq!(new_data, test_data);
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
        let mut data = builder.into_inner();
        data.seek(SeekFrom::Start(0)).unwrap();

        // Read back and assert stuff
        let mut reader = LtvcReader::new(data);

        // Should be only one reader
        let mut new_data = vec![];
        let edatreader = reader.next().unwrap().unwrap();
        match edatreader {
            LtvcEntry::Edat { data: mut x } => {
                let _ = copy(&mut x, &mut new_data);
            }
            _ => panic!("Invalid data in test"),
        }
        assert_eq!(new_data, test_data);
        assert!(reader.next().is_none());
    }
}
