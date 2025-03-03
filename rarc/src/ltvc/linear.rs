use std::io::Read;
use log::debug;

use rcore::hash;

use crate::ltvc::reader::EdatReader;
use crate::ltvc::reader::{LtvcEntry, LtvcReader};

// Header of the Edat blocks (ie all Edat must be preceeded by)
#[derive(Debug, Clone)]
pub enum Header {
    Fhdr { hash: hash::Hash },
    Aidx,
    Shdr,
    Pidx,
}

// State machine enum
#[derive(Debug, Clone)]
enum Spo {
    Start,
    Ahdr,
    Header(Header),
    Edat,
    Aend,
}

pub struct EdatStream<R: Read> {
    pub header: Header,
    pub data: EdatReader<R>,
}

pub struct LtvcLinear<R: Read> {
    inner: LtvcReader<R>,
    state: Spo,
}

impl<R: Read> LtvcLinear<R> {
    pub fn new(reader: R) -> Self {
        LtvcLinear {
            inner: LtvcReader::new(reader),
            state: Spo::Start,
        }
    }
}

impl<R: Read> Iterator for LtvcLinear<R> {
    type Item = EdatStream<R>;

    // TODO: add error reporting to the state machine
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match (self.state.clone(), self.inner.next()) {
                // Assert that the first entry is an Ahdr with 0x01 as version
                (Spo::Start, Some(Ok(LtvcEntry::Ahdr { version }))) if version == 0x01 => {
                    debug!("AHDR 0x01");
                    self.state = Spo::Ahdr;
                }

                // Assert that the Header state follows Ahdr or Edat, where
                // header state is: Fhdr/Aidx/Shdr/Pidx
                (Spo::Ahdr, Some(Ok(LtvcEntry::Fhdr { hash })))
                | (Spo::Edat, Some(Ok(LtvcEntry::Fhdr { hash }))) => {
                    debug!("FHDR <{:?}>", hash);
                    self.state = Spo::Header(Header::Fhdr { hash });
                }

                (Spo::Ahdr, Some(Ok(LtvcEntry::Aidx))) | (Spo::Edat, Some(Ok(LtvcEntry::Aidx))) => {
                    debug!("AIDX");
                    self.state = Spo::Header(Header::Aidx);
                }

                (Spo::Ahdr, Some(Ok(LtvcEntry::Shdr))) | (Spo::Edat, Some(Ok(LtvcEntry::Shdr))) => {
                    debug!("SHDR");
                    self.state = Spo::Header(Header::Shdr);
                }

                (Spo::Ahdr, Some(Ok(LtvcEntry::Pidx))) | (Spo::Edat, Some(Ok(LtvcEntry::Pidx))) => {
                    debug!("PIDX");
                    self.state = Spo::Header(Header::Pidx);
                }

                // Assert that Edat follows Header(1 of them)
                (Spo::Header(header), Some(Ok(LtvcEntry::Edat { data }))) => {
                    debug!("<Header> EDAT");
                    self.state = Spo::Edat;

                    // Return a result
                    return Some(EdatStream { header, data });
                }

                // Assert that Aend follows Edat
                (Spo::Edat, Some(Ok(LtvcEntry::Aend { idx: _ }))) => {
                    debug!("AEND");
                    self.state = Spo::Aend;
                }

                // Asserts that the iterator is terminated
                (Spo::Aend, None) => {
                    return None;
                }

                // Unhandled states
                // TODO: improve debuggability
                (s, None) => panic!("In state: {:?} unexpected end of iterator", s),
                (s, Some(Err(_))) => panic!("In state: {:?} error on iterator", s),
                (s, Some(Ok(_))) => panic!("In state: {:?} unknown LtvcEntry", s),
            }
        }
    }
}
