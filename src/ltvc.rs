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
pub struct LtvcEntryRaw {
    // TODO: do we still need the length?
    pub length: usize,
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
                length: len,
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
}

impl<R: Read> Read for EdatReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // TODO: implement this
        // 1. Peek to see if its not EDAT, if its not, abort (EoF)
        // 2. next() to get the next block of vector, grab that and use it to
        //  provide us a buffer to read from for this function, when empty, repeat 1
        Ok(0)
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
                            }
                        }))

                    },
                    b"FIDX" => {
                        // Setup a EDAT reader
                        Some(Ok(LtvcEntry::Fidx {
                            edat: EdatReader {
                                inner: self.inner.clone(),
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
                    b"EDAT" => panic!("Standalone EDAT shouldn't happen!"),
                    x       => panic!("Didn't support: {:?}", from_utf8(x)),
                }
            },
        }
    }
}



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

