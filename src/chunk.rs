use std::io::{Read, Cursor};

use crate::buf::fill_buf;

const CHUNK_SIZE: usize = 2 * 1024;

pub struct Chunk<R: Read> {
    inner: R,
    chunk: u16,
}

impl<R: Read> Chunk<R> {
    pub fn new(reader: R) -> Self {
        Chunk {
            inner: reader,
            chunk: 0,
        }
    }
}

impl<R: Read> Iterator for Chunk<R> {
    type Item = (Box<dyn Read>, u16);

    fn next(&mut self) -> Option<Self::Item> {
        self.chunk += 1;
        let mut in_buf = [0u8; CHUNK_SIZE];

        match fill_buf(&mut self.inner, &mut in_buf).unwrap() {
            (true, 0) => None,
            (_, len)  => {
                let mut data = Vec::new();
                data.extend_from_slice(&in_buf[..len]);

                Some((Box::new(Cursor::new(data)), (self.chunk - 1)))
            },
        }
    }
}
