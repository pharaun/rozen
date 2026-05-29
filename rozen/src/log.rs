#![expect(unused_qualifications)]
use std::io::Cursor;
use std::io::Error;

use crate::rcore::hash;
use crate::rcore::hash::from_hex;

//use integer_encoding::VarIntReader;
//use integer_encoding::VarIntWriter;

use binrw::io::{Read, Seek, SeekFrom, Write};
use binrw::meta::{EndianKind, ReadEndian, WriteEndian};
use binrw::{BinRead, BinResult, BinWrite, Endian, binrw};

// TODO: AWS and disk stuff
// Look into how to make sure how to commit whole grain bits or none, ie
// make sure that AWS part are at least large enough to hold a entire Grain or none.
// This will make recovery easier + aws part fetching easier to have it fall on grain boundaries
// But will have open question of can we have varying part length or must they all be the same
// length only? if They must be the same length only then we can't

#[binrw]
#[brw(little, magic = b"ROZ-STRA")]
#[derive(Debug, PartialEq)]
pub(crate) struct StrataHeader {
    pub version: u8,
    pub basin_id: u8,
    pub strata_id: u16,
    // TODO: add bits for encryption & compression settings
}

#[derive(Debug, PartialEq)]
pub(crate) struct ChecksumWrapper<T> {
    inner: T,
}

impl<T> BinRead for ChecksumWrapper<T>
where
    T: for<'a> BinRead<Args<'a> = ()>,
{
    type Args<'a> = T::Args<'a>;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let start = reader.stream_position()?;
        let parsed_data = <T>::read_options(reader, endian, args)?;
        let end = reader.stream_position()?;

        let computed_checksum = {
            let _ = reader.seek(SeekFrom::Start(start));
            let mut raw_data: Vec<u8> = vec![0; (end - start) as usize];
            reader.read_exact(&mut raw_data[..])?;

            let mut checksum = hash::Checksum::new();
            checksum.update(&raw_data);
            checksum.finalize()
        };
        let parsed_checksum = <u32>::read_options(reader, endian, args)?;

        // Validate the checksum
        if computed_checksum == parsed_checksum {
            Ok(Self { inner: parsed_data })
        } else {
            Err(binrw::Error::Custom {
                pos: end,
                err: Box::new(format!(
                    "Bad Checksum: {computed_checksum:#x?} != {parsed_checksum:#x?}"
                )),
            })
        }
    }
}

impl<T: ReadEndian> ReadEndian for ChecksumWrapper<T> {
    const ENDIAN: EndianKind = <T as ReadEndian>::ENDIAN;
}

impl<T> BinWrite for ChecksumWrapper<T>
where
    T: for<'a> BinWrite<Args<'a> = ()>,
{
    type Args<'a> = T::Args<'a>;

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        let data: Vec<u8> = {
            let mut cursor = Cursor::new(Vec::new());
            self.inner.write_options(&mut cursor, endian, args)?;
            cursor.into_inner()
        };
        let checksum: u32 = {
            let mut checksum = hash::Checksum::new();
            checksum.update(&data);
            checksum.finalize()
        };

        data.write_options(writer, endian, args)?;
        checksum.write_options(writer, endian, args)?;

        Ok(())
    }
}

impl<T: WriteEndian> WriteEndian for ChecksumWrapper<T> {
    const ENDIAN: EndianKind = <T as WriteEndian>::ENDIAN;
}

#[binrw]
#[brw(little)]
#[derive(Debug, PartialEq)]
pub(crate) struct Grain {
    pub grain_id: u32,
    pub key: hash::Hash,
    pub part: u32,

    #[br(temp)]
    #[bw(calc = data.len() as u32)]
    data_len: u32,

    // TODO: consider doing the data bits separately
    // and/or its own thing for effiency reasons so that
    // we don't end up copying several megabytes buffers of data,
    // but for now this will do
    #[br(count = data_len)]
    pub data: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub(crate) struct StrataFooter {
    pub hash: hash::Hash,
    // TODO: some sort of authentication signature to close the file.
}

#[expect(dead_code)]
pub(crate) struct StrataIndexEntity {
    pub key: hash::Hash,
    pub part: u32,
    pub grain_id: u32,
    pub offset: u32,
    pub length: u32,
}

// Handles the bookkeeping for writing a Strata out
pub(crate) struct StrataWriter<W: Write> {
    inner: W,
    inner_pos: usize,
    index: Vec<StrataIndexEntity>,
    // TODO: add a live hasher for the footer
}

#[expect(dead_code)]
impl<W: Write> StrataWriter<W> {
    pub(crate) fn new(writer: W) -> Self {
        Self {
            inner: writer,
            inner_pos: 0,
            index: Vec::new(),
        }
    }

    pub(crate) fn into_inner(self) -> W {
        self.inner
    }

    fn write_binrw_record<T>(&mut self, record: T) -> Result<usize, Error>
    where
        T: for<'a> BinWrite<Args<'a> = ()> + WriteEndian,
    {
        let mut cursor = Cursor::new(Vec::new());
        record.write(&mut cursor).unwrap();
        let size = self.inner.write(&cursor.into_inner())?;
        self.inner_pos += size;
        Ok(size)
    }

    pub(crate) fn write_header(&mut self, basin_id: u8, strata_id: u16) -> Result<usize, Error> {
        let header = ChecksumWrapper {
            inner: StrataHeader {
                version: 1,
                basin_id,
                strata_id,
            },
        };

        self.write_binrw_record(header)
    }

    pub(crate) fn write_footer(&mut self) -> Result<usize, Error> {
        let footer = StrataFooter {
            hash: from_hex("38236e791c18434a1fad1dd6f96c4ce0d58bb69ca04d80d8e1325d7cb20476be")
                .expect("hexal"),
        };

        self.write_binrw_record(footer)
    }

    pub(crate) fn write_grain(
        &mut self,
        key: hash::Hash,
        part: u32,
        data: Vec<u8>,
    ) -> Result<usize, Error> {
        let grain = ChecksumWrapper {
            inner: Grain {
                grain_id: 1,
                key: key.clone(),
                part,
                data,
            },
        };
        let offset = self.inner_pos;
        let length = self.write_binrw_record(grain)?;

        self.index.push(StrataIndexEntity {
            key,
            part,
            grain_id: 1,
            offset: offset as u32,
            length: length as u32,
        });
        Ok(length)
    }
}

#[cfg(test)]
mod serialize {
    use super::ChecksumWrapper;
    use super::Grain;
    use super::StrataHeader;

    use std::io::Cursor;
    use std::io::Seek;
    use std::io::SeekFrom;

    use binrw::BinRead;
    use binrw::BinWrite;

    use crate::rcore::key::MemKey;

    #[test]
    fn test_strata_header() {
        let data = ChecksumWrapper {
            inner: StrataHeader {
                version: 1,
                basin_id: 1,
                strata_id: 1,
            },
        };

        let mut strata = Cursor::new(Vec::new());
        data.write(&mut strata)?;
        strata.seek(SeekFrom::Start(0))?;
        let header = ChecksumWrapper::<StrataHeader>::read(&mut strata)?;

        assert_eq!(data, header);
    }

    #[test]
    fn test_grain() {
        let key = MemKey::new();
        let data = ChecksumWrapper {
            inner: Grain {
                grain_id: 1,
                key: key.gen_id(),
                part: 1,
                data: vec![0, 1, 2, 3, 4],
            },
        };

        let mut strata = Cursor::new(Vec::new());
        data.write(&mut strata)?;
        strata.seek(SeekFrom::Start(0))?;
        let grain = ChecksumWrapper::<Grain>::read(&mut strata)?;

        assert_eq!(data, grain);
    }
}
