use serde::Deserialize;
use serde::Serialize;
use std::io::Cursor;

use crate::rcore::hash;
use crate::rcore::hash::from_hex;
use crate::rcore::key;

use integer_encoding::VarIntReader;
use integer_encoding::VarIntWriter;

use binrw::{
    BinRead, BinWrite,
    BinResult,
    Endian,
    binrw, binwrite,
};
use binrw::io::{Read, Seek, Write};
use binrw::meta::{
    EndianKind, WriteEndian,
};

// TODO: AWS and disk stuff
// Look into how to make sure how to commit whole grain bits or none, ie
// make sure that AWS part are at least large enough to hold a entire Grain or none.
// This will make recovery easier + aws part fetching easier to have it fall on grain boundaries
// But will have open question of can we have varying part length or must they all be the same
// length only? if They must be the same length only then we can't

#[binrw]
#[brw(little, magic = b"ROZ-STRA")]
#[derive(Debug)]
pub struct StrataHeader {
    pub version: u8,
    pub basin_id: u8,
    pub strata_id: u16,
    // TODO: add bits for encryption & compression settings
}

#[derive(Debug)]
pub struct ChecksumWrapper {
    inner: Grain,
}

//    #[br(temp, assert(checksum == s.finalize(), "bad checksum: {:#x?} != {:#x?}", checksum, s.finalize()))]
//impl BinRead for ChecksumWrapper {
//    type Args<'a> = ();
//
//    fn read_options<R: Read + Seek>(
//        reader: &mut R,
//        endian: Endian,
//        args: Self::Args<'_>,
//    ) -> BinResult<Self> {
//        let key = from_hex("38236e791c18434a1fad1dd6f96c4ce0d58bb69ca04d80d8e1325d7cb20476be").unwrap();
//        Ok(Self {
//            inner: Grain {
//                grain_id: 1,
//                key: key,
//                part: 1,
//            }
//        })
//    }
//}

impl BinWrite for ChecksumWrapper {
    type Args<'a> = ();

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

impl WriteEndian for ChecksumWrapper {
    const ENDIAN: EndianKind = EndianKind::Endian(Endian::Little);
}



#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct Grain {
    pub grain_id: u32,
    pub key: hash::Hash,
    pub part: u32,
    //pub data: Vec<u8>,
}




#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct StrataFooter {
    pub hash: hash::Hash,
    // TODO: some sort of authentication signature to close the file.
}

pub struct StrataIndexEntity {
    pub key: [u8;40],
    pub part: u32,
    pub grain_id: u32,
    pub offset: u32,
    pub length: u32,
}

// Handles the bookkeeping for writing a Strata out
pub struct Strata {

}


#[cfg(test)]
mod serialize {
    use super::StrataHeader;
    use super::ChecksumWrapper;
    use super::Grain;

    use std::io::Cursor;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    use binrw::BinWrite;
    use binrw::BinRead;

    use crate::rcore::key::MemKey;
    use crate::rcore::hash::Checksum;
    use crate::rcore::hash::from_hex;

    #[test]
    fn strata_header() {
        let mut strata = Cursor::new(Vec::new());
        StrataHeader {
            version: 1,
            basin_id: 1,
            strata_id: 1,
        }.write(&mut strata).unwrap();
        println!("{}", hex::encode(strata.clone().into_inner()));

        strata.seek(SeekFrom::Start(0));
        let header = StrataHeader::read(&mut strata);
        println!("{:?}", header);

        assert!(false);
    }

    #[test]
    fn grain() {
        let key = from_hex("38236e791c18434a1fad1dd6f96c4ce0d58bb69ca04d80d8e1325d7cb20476be").unwrap();

        // Manually "write out" data bits to get a checksum
        let mut manual = Cursor::new(Vec::new());
        let one = (1 as u32).to_le_bytes();
        manual.write(&one);
        manual.write(key.as_bytes());
        manual.write(&one);

        let mut checksum = Checksum::new();
        checksum.update(&manual.clone().into_inner());
        manual.write(&checksum.finalize().to_le_bytes());
        println!("manual: {:#x?} - {:#x?}", checksum.finalize(), u32::from_be_bytes(checksum.finalize().to_le_bytes()));
        println!("{}", hex::encode(manual.into_inner()));

        let mut strata = Cursor::new(Vec::new());
        ChecksumWrapper {
            inner: Grain {
                grain_id: 1,
                key: key,
                part: 1,
                //data: vec![0, 1, 2, 3, 4],
            },
        }.write(&mut strata).unwrap();
        println!("{}", hex::encode(strata.clone().into_inner()));

    //    strata.seek(SeekFrom::Start(0));
    //    let grain = ChecksumWrapper::read(&mut strata);
    //    println!("{:?}", grain);

        assert!(false);
    }
}
