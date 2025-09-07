use serde::Deserialize;
use serde::Serialize;
use std::io::{Read, Write};

use crate::rcore::hash;
use crate::rcore::key;

use integer_encoding::VarIntReader;
use integer_encoding::VarIntWriter;
use binrw::binrw;
use binrw::binwrite;

// TODO: AWS and disk stuff
// Look into how to make sure how to commit whole grain bits or none, ie
// make sure that AWS part are at least large enough to hold a entire Grain or none.
// This will make recovery easier + aws part fetching easier to have it fall on grain boundaries
// But will have open question of can we have varying part length or must they all be the same
// length only? if They must be the same length only then we can't

#[binrw]
#[brw(little)]
#[brw(magic = b"ROZ-STRA")]
#[derive(Debug)]
pub struct StrataHeader {
    pub version: u8,
    pub basin_id: u8,
    pub strata_id: u16,
    // TODO: add bits for encryption & compression settings
}

#[binrw]
#[brw(little)]
#[bw(stream = w, map_stream = TestSum::<_>::new)]
#[br(stream = r, map_stream = TestSum::<_>::new)]
#[derive(Debug)]
pub struct Grain {
    pub grain_id: u32,
    pub key: hash::Hash,
    pub part: u32,
    //pub data: Vec<u8>,

    #[bw(calc(w.check()))]
    #[br(temp, assert(checksum == r.check(), "bad checksum: {:#x?} != {:#x?}", checksum, r.check()))]
    checksum: u32,
}

struct TestSum<S> {
    inner: S,
    checksum: hash::Checksum,
    position: u64,
}

impl<S: binrw::io::Seek> TestSum<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            checksum: hash::Checksum::new(),
            position: 0,
        }
    }

    pub fn check(&self) -> u32 {
        self.checksum.finalize()
    }
}

impl<S: binrw::io::Seek> binrw::io::Seek for TestSum<S> {
    fn seek(&mut self, pos: binrw::io::SeekFrom) -> binrw::io::Result<u64> {
        let new_position = self.inner.seek(pos)?;
        Ok(new_position)
    }
}

impl<S: binrw::io::Write> binrw::io::Write for TestSum<S> {
    fn write(&mut self, buf: &[u8]) -> binrw::io::Result<usize> {
        self.checksum.update(buf);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> binrw::io::Result<()> {
        self.inner.flush()
    }
}

impl<S: binrw::io::Read + binrw::io::Seek> binrw::io::Read for TestSum<S> {
    fn read(&mut self, buf: &mut [u8]) -> binrw::io::Result<usize> {
        let position = self.inner.stream_position()?;
        let size = self.inner.read(buf)?;

        // Make sure that read bytes aren't checksummed more than once.
        for (i, byte) in buf[..size].iter().enumerate() {
            if position + i as u64 >= self.position {
                self.checksum.update(&[*byte]);
            }
        }
        self.position = position + size as u64;
        Ok(size)
    }
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
    use super::Grain;

    use std::io::Cursor;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    use binrw::BinWrite;
    use binrw::BinRead;

    use crate::rcore::key::MemKey;
    use crate::rcore::hash::Checksum;

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
        let key = (MemKey::new()).gen_id();

        // Manually "write out" data bits to get a checksum
        let mut manual = Cursor::new(Vec::new());
        let one = (1 as u32).to_le_bytes();
        manual.write(&one);
        manual.write(key.as_bytes());
        manual.write(&one);

        let mut checksum = Checksum::new();
        checksum.update(&manual.clone().into_inner());
        manual.write(&checksum.finalize().to_le_bytes());
        println!("manual: {:#x?}", checksum.finalize());
        println!("{}", hex::encode(manual.into_inner()));

        let mut strata = Cursor::new(Vec::new());
        Grain {
            grain_id: 1,
            key: key,
            part: 1,
            //data: vec![0, 1, 2, 3, 4],
        }.write(&mut strata).unwrap();
        println!("{}", hex::encode(strata.clone().into_inner()));

        strata.seek(SeekFrom::Start(0));
        let grain = Grain::read(&mut strata);
        println!("{:?}", grain);

        assert!(false);
    }
}
