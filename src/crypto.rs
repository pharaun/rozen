use std::cmp;
use std::io::Read;

use sodiumoxide::crypto::secretstream;
use sodiumoxide::crypto::secretstream::{Stream, Tag, Push, Header, Key, ABYTES, Pull};


pub fn init() {
    sodiumoxide::init().unwrap();
}

pub fn gen_key() -> Key {
    secretstream::gen_key()
}


//********************************************************************************
// TODO: this dumps the key+nonce to the stream, is not secure at all
//********************************************************************************
// 8Kb encryption frame buffer
const CHUNK_SIZE: usize = 8 * 1024;

pub struct Crypter<R, E> {
    reader: R,
    engine: E,
    in_buf: Box<[u8]>,
    out_buf: Vec<u8>,
}

pub fn encrypt<R: Read>(reader: R) -> Crypter<R, EncEngine> {
    let fkey = gen_key();
    let (stream, header) = Stream::init_push(&fkey).unwrap();
    let engine = EncEngine(stream);

    // Chunk Frame size + encryption additional bytes (~17 bytes)
    let in_buf = [0u8; CHUNK_SIZE];
    let mut out_buf = Vec::with_capacity(CHUNK_SIZE + ABYTES);

    // Flush fkey + header to out_buf
    out_buf.extend_from_slice(&fkey.0);
    out_buf.extend_from_slice(&header.0);

    Crypter {
        reader,
        engine,
        in_buf: Box::new(in_buf),
        out_buf,
    }
}

pub fn decrypt<R: Read>(mut reader: R) -> std::io::Result<Crypter<R, DecEngine>> {
    // Read out the key + header
    let mut dkey: [u8; 32] = [0; 32];
    reader.read_exact(&mut dkey)?;
    let fkey = Key::from_slice(&dkey).unwrap();

    let mut dheader: [u8; 24] = [0; 24];
    reader.read_exact(&mut dheader)?;
    let fheader = Header::from_slice(&dheader).unwrap();

    // Decrypter setup
    let stream = Stream::init_pull(&fheader, &fkey).unwrap();
    let engine = DecEngine(stream);

    // Chunk Frame size (input will be frame+abytes)
    let in_buf = [0u8; CHUNK_SIZE + ABYTES];
    let out_buf = Vec::with_capacity(CHUNK_SIZE);

    Ok(Crypter {
        reader,
        engine,
        in_buf: Box::new(in_buf),
        out_buf,
    })
}


impl<R: Read, E: Engine> Read for Crypter<R, E> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        crypt_read(
            &mut self.reader,
            &mut self.out_buf,
            &mut self.engine,
            &mut self.in_buf,
            buf,
        )
    }
}



// Trait for wrapping up the encryption/decryption portion of the code
pub trait Engine {
    fn crypt(&mut self, data: &[u8], tag: Tag, out: &mut Vec<u8>) -> Result<(), ()>;
    fn is_finalized(&self) -> bool;
}

pub struct EncEngine(Stream<Push>);
pub struct DecEngine(Stream<Pull>);

impl Engine for EncEngine {
    fn crypt(&mut self, data: &[u8], tag: Tag, out: &mut Vec<u8>) -> Result<(), ()> {
        self.0.push_to_vec(data, None, tag, out).unwrap();
        println!("Enc: in-Len: {}, out-len: {}, tag: {:#?}", data.len(), out.len(), tag);

        // TODO: improve error
        Ok(())
    }

    fn is_finalized(&self) -> bool {
        self.0.is_finalized()
    }
}

impl Engine for DecEngine {
    fn crypt(&mut self, data: &[u8], tag: Tag, out: &mut Vec<u8>) -> Result<(), ()> {
        let dtag = self.0.pull_to_vec(data, None, out).unwrap();
        println!("Dec: in-Len: {}, out-len: {}, tag: {:#?}", data.len(), out.len(), tag);

        // TODO: improve error
        if dtag == tag {
            Ok(())
        } else {
            Err(())
        }
    }

    fn is_finalized(&self) -> bool {
        self.0.is_finalized()
    }
}




// TODO: do i need to figure out a frame format for each message
// for the decryption end?
fn crypt_read<R: Read, E: Engine>(
    data: &mut R,
    out_buf: &mut Vec<u8>,
    engine: &mut E,
    in_buf: &mut [u8],
    buf: &mut [u8]
) -> std::io::Result<usize> {
    let mut buf_write: usize = 0;

    // 1. If buf_write == buf.len() return
    while buf_write < buf.len() {
        if !out_buf.is_empty() {
            // 2. If data in out_buf, flush into buf first
            buf_write += flush_buf(out_buf, &mut buf[buf_write..]);

        } else {
            // 3. Read till there is 8Kb of data in in_buf
            match fill_buf(data, in_buf) {
                // 4a. Nothing left in in_buf, is EoF, and is not finalize, finalize
                Ok((true, 0)) if !engine.is_finalized() => {
                    engine.crypt(
                        &[],
                        Tag::Final,
                        out_buf,
                    ).unwrap();
                },

                // 4b. Nothing left in [in_buf, out_buf] and is EoF, exit
                Ok((true, 0)) if out_buf.is_empty() => return Ok(buf_write),

                // 4c. Copy in_buf -> out_buf
                // 4d. Final read, finalize
                Ok((eof, in_len)) => {
                    let tag = if eof { Tag::Final } else { Tag::Message };

                    engine.crypt(
                        &in_buf[..in_len],
                        tag,
                        out_buf,
                    ).unwrap();
                },

                Err(e) => return Err(e),
            }
        }
    }

    Ok(buf_write)
}


#[cfg(test)]
mod test_encrypt_decrypt_roundtrip {
    use std::io::{copy, Cursor, Write};
    use super::*;

    #[test]
    fn small_data_roundtrip() {
        let data = b"Hello World!";

        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        in_data.write(data).unwrap();
        in_data.set_position(0);

        let enc = encrypt(in_data);
        let mut dec = decrypt(enc).unwrap();

        let mut out_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        copy(&mut dec, &mut out_data).unwrap();
        out_data.set_position(0);

        // Assertions
        assert_eq!(&out_data.get_ref()[..], data);
    }

    #[test]
    fn exactly_chunk_roundtrip() {
        let data: Vec<u8> = {
            let cap: usize = (1.5 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!";

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret[..CHUNK_SIZE].to_vec()
        };
        assert_eq!(data.len(), CHUNK_SIZE);

        let in_data: Cursor<Vec<u8>> = Cursor::new(data.clone());

        let enc = encrypt(in_data);
        let mut dec = decrypt(enc).unwrap();

        let mut out_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        copy(&mut dec, &mut out_data).unwrap();
        out_data.set_position(0);

        // Assertions
        assert_eq!(&out_data.get_ref()[..], data);
    }

    #[test]
    fn big_data_roundtrip() {
        let data: Vec<u8> = {
            let cap: usize = (1.5 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!";

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret
        };
        let in_data: Cursor<Vec<u8>> = Cursor::new(data.clone());

        let enc = encrypt(in_data);
        let mut dec = decrypt(enc).unwrap();

        let mut out_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        copy(&mut dec, &mut out_data).unwrap();
        out_data.set_position(0);

        // Assertions
        assert_eq!(&out_data.get_ref()[..], data);
    }
}



#[cfg(test)]
mod test_crypt_read {
    use std::io::{Cursor, Write};
    use super::*;

    // Struct just for copying data
    struct CopyEngine();
    impl Engine for CopyEngine {
        fn crypt(&mut self, data: &[u8], _tag: Tag, out: &mut Vec<u8>) -> Result<(), ()> {
            out.extend_from_slice(&data);
            Ok(())
        }
        fn is_finalized(&self) -> bool {
            true
        }
    }

    #[test]
    fn small_data_roundtrip() {
        let data = b"Hello World!";

        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        in_data.write(data).unwrap();
        in_data.set_position(0);

        let mut enc = encrypt(in_data);

        // Read out to buffer vec
        let mut dkey: [u8; 32] = [0; 32];
        let mut dheader: [u8; 24] = [0; 24];
        let mut dciphertext = Vec::new();

        enc.read_exact(&mut dkey).unwrap();
        enc.read_exact(&mut dheader).unwrap();
        enc.read_to_end(&mut dciphertext).unwrap();

        assert_ne!(data, &dciphertext[..]);

        // Construct the decrypter and pass the ciphertext through
        let fkey = Key::from_slice(&dkey).unwrap();
        let fheader = Header::from_slice(&dheader).unwrap();

        let mut dec = Stream::init_pull(&fheader, &fkey).unwrap();
        let (dec_data, tag) = dec.pull(&dciphertext[..], None).unwrap();

        assert_eq!(tag, Tag::Final);
        assert_eq!(dec_data, data);
    }

    #[test]
    fn big_data_roundtrip() {
        let data: Vec<u8> = {
            let cap: usize = (1.5 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!";

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret
        };
        let in_data: Cursor<Vec<u8>> = Cursor::new(data.clone());

        let mut enc = encrypt(in_data);

        // Read out to buffer vec
        let mut dkey: [u8; 32] = [0; 32];
        enc.read_exact(&mut dkey).unwrap();
        let fkey = Key::from_slice(&dkey).unwrap();

        let mut dheader: [u8; 24] = [0; 24];
        enc.read_exact(&mut dheader).unwrap();
        let fheader = Header::from_slice(&dheader).unwrap();

        // Decrypter setup
        let mut dec = Stream::init_pull(&fheader, &fkey).unwrap();

        // TODO: improve? For now chunk it by chunk+abytes
        let mut dciphertext1: [u8; CHUNK_SIZE + ABYTES] = [0; CHUNK_SIZE + ABYTES];
        let mut dciphertext2 = Vec::new();

        enc.read_exact(&mut dciphertext1).unwrap();
        enc.read_to_end(&mut dciphertext2).unwrap();

        assert_ne!(data, &dciphertext1[..]);
        assert_ne!(data, &dciphertext2[..]);

        // decrypt each 'chunk' and verify
        let (dec_data1, tag1) = dec.pull(&dciphertext1, None).unwrap();
        assert_eq!(tag1, Tag::Message);

        let (dec_data2, tag2) = dec.pull(&dciphertext2[..], None).unwrap();
        assert_eq!(tag2, Tag::Final);

        // Assert data
        let mut dec_data = Vec::new();
        dec_data.extend_from_slice(&dec_data1[..]);
        dec_data.extend_from_slice(&dec_data2[..]);

        // TODO: split data and assert against each
        assert_eq!(dec_data, data);
    }

    #[test]
    fn awkward_write_final_buf() {
        let data: Vec<u8> = {
            let cap: usize = (1.5 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!";

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret[..CHUNK_SIZE].to_vec()
        };
        assert_eq!(data.len(), CHUNK_SIZE);

        let in_data: Cursor<Vec<u8>> = Cursor::new(data.clone());

        let mut enc = encrypt(in_data);

        // Do awkward reads to see if the control loop breaks down
        let mut dkey: [u8; 32] = [0; 32];
        let mut dheader: [u8; 24] = [0; 24];
        let mut dciphertext1_half: [u8; CHUNK_SIZE / 2] = [0; CHUNK_SIZE / 2];
        let mut dciphertext1_abyt: [u8; CHUNK_SIZE / 2 + ABYTES] = [0; CHUNK_SIZE / 2 + ABYTES];

        // Final should be 17 bytes but let's break it into 2 read of 8 and 9 bytes
        let mut dciphertext2_read8: [u8; 8] = [0; 8];
        let mut dciphertext2_read9: [u8; 9] = [0; 9];

        // 32 bytes
        enc.read_exact(&mut dkey).unwrap();
        // 24 bytes
        enc.read_exact(&mut dheader).unwrap();
        // w/ 8192 -> 4096 bytes
        enc.read_exact(&mut dciphertext1_half).unwrap();
        // w/ 8192 -> 4096 + 17 bytes
        enc.read_exact(&mut dciphertext1_abyt).unwrap();
        // 8 bytes (of 17 for final frame
        enc.read_exact(&mut dciphertext2_read8).unwrap();
        // 9 bytes of 17 for final frame
        enc.read_exact(&mut dciphertext2_read9).unwrap();
    }

    #[test]
    fn empty_data_empty_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        let mut out_buf: Vec<u8> = Vec::new();
        let mut buf: [u8; 4] = [0; 4];

        let mut engine = CopyEngine();
        let mut in_buf = [0u8; CHUNK_SIZE];
        assert_eq!(crypt_read(&mut in_data, &mut out_buf, &mut engine, &mut in_buf, &mut buf).unwrap(), 0);
        assert_eq!(&out_buf[..], &[]);
        assert_eq!(&buf, &[0, 0, 0, 0]);
    }

    #[test]
    fn empty_data_small_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        let mut out_buf: Vec<u8> = vec![1, 2];
        let mut buf: [u8; 4] = [0; 4];

        let mut engine = CopyEngine();
        let mut in_buf = [0u8; CHUNK_SIZE];
        assert_eq!(crypt_read(&mut in_data, &mut out_buf, &mut engine, &mut in_buf, &mut buf).unwrap(), 2);
        assert_eq!(&out_buf[..], &[]);
        assert_eq!(&buf, &[1, 2, 0, 0]);
    }

    #[test]
    fn empty_data_big_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        let mut out_buf: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let mut buf: [u8; 4] = [0; 4];

        let mut engine = CopyEngine();
        let mut in_buf = [0u8; CHUNK_SIZE];
        assert_eq!(crypt_read(&mut in_data, &mut out_buf, &mut engine, &mut in_buf, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[5, 6]);
        assert_eq!(&buf, &[1, 2, 3, 4]);
    }

    #[test]
    fn small_data_empty_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2]);
        let mut out_buf: Vec<u8> = Vec::new();
        let mut buf: [u8; 4] = [0; 4];

        let mut engine = CopyEngine();
        let mut in_buf = [0u8; CHUNK_SIZE];
        assert_eq!(crypt_read(&mut in_data, &mut out_buf, &mut engine, &mut in_buf, &mut buf).unwrap(), 2);
        assert_eq!(&out_buf[..], &[]);
        assert_eq!(&buf, &[1, 2, 0, 0]);
    }

    #[test]
    fn small_data_small_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2]);
        let mut out_buf: Vec<u8> = vec![3, 4];
        let mut buf: [u8; 4] = [0; 4];

        let mut engine = CopyEngine();
        let mut in_buf = [0u8; CHUNK_SIZE];
        assert_eq!(crypt_read(&mut in_data, &mut out_buf, &mut engine, &mut in_buf, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[]);
        assert_eq!(&buf, &[3, 4, 1, 2]);
    }

    #[test]
    fn small_data_big_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2]);
        let mut out_buf: Vec<u8> = vec![3, 4, 5, 6, 7, 8];
        let mut buf: [u8; 4] = [0; 4];

        let mut engine = CopyEngine();
        let mut in_buf = [0u8; CHUNK_SIZE];
        assert_eq!(crypt_read(&mut in_data, &mut out_buf, &mut engine, &mut in_buf, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[7, 8]);
        assert_eq!(&buf, &[3, 4, 5, 6]);
    }

    #[test]
    fn big_data_empty_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2, 3, 4, 5, 6]);
        let mut out_buf: Vec<u8> = Vec::new();
        let mut buf: [u8; 4] = [0; 4];

        let mut engine = CopyEngine();
        let mut in_buf = [0u8; CHUNK_SIZE];
        assert_eq!(crypt_read(&mut in_data, &mut out_buf, &mut engine, &mut in_buf, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[5, 6]);
        assert_eq!(&buf, &[1, 2, 3, 4]);
    }

    #[test]
    fn big_data_small_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2, 3, 4, 5, 6]);
        let mut out_buf: Vec<u8> = vec![7, 8];
        let mut buf: [u8; 4] = [0; 4];

        let mut engine = CopyEngine();
        let mut in_buf = [0u8; CHUNK_SIZE];
        assert_eq!(crypt_read(&mut in_data, &mut out_buf, &mut engine, &mut in_buf, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[3, 4, 5, 6]);
        assert_eq!(&buf, &[7, 8, 1, 2]);
    }

    #[test]
    fn big_data_big_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2, 3, 4, 5, 6]);
        let mut out_buf: Vec<u8> = vec![7, 8, 9, 10, 11, 12];
        let mut buf: [u8; 4] = [0; 4];

        let mut engine = CopyEngine();
        let mut in_buf = [0u8; CHUNK_SIZE];
        assert_eq!(crypt_read(&mut in_data, &mut out_buf, &mut engine, &mut in_buf, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[11, 12]);
        assert_eq!(&buf, &[7, 8, 9, 10]);
    }
}


fn fill_buf<R: Read>(data: &mut R, buf: &mut [u8]) -> std::io::Result<(bool, usize)> {
    let mut buf_read = 0;

    while buf_read < buf.len() {
        match data.read(&mut buf[buf_read..]) {
            Ok(0)  => return Ok((true, buf_read)),
            Ok(x)  => buf_read += x,
            Err(e) => return Err(e),
        };
    }
    Ok((false, buf_read))
}

#[cfg(test)]
mod test_fill_buf {
    use std::io::Cursor;
    use super::*;

    #[test]
    fn big_buf_small_vec() {
        let mut in_buf: Cursor<Vec<u8>> = Cursor::new(vec![1, 2]);
        let mut buf: [u8; 4] = [0; 4];

        assert_eq!(fill_buf(&mut in_buf, &mut buf).unwrap(), (true, 2));
        assert_eq!(&buf, &[1, 2, 0, 0]);
    }

    #[test]
    fn small_buf_big_vec() {
        let mut in_buf: Cursor<Vec<u8>> = Cursor::new(vec![1, 2, 3, 4]);
        let mut buf: [u8; 2] = [0; 2];

        assert_eq!(fill_buf(&mut in_buf, &mut buf).unwrap(), (false, 2));
        assert_eq!(&buf, &[1, 2]);
    }

    #[test]
    fn same_buf_same_vec() {
        let mut in_buf: Cursor<Vec<u8>> = Cursor::new(vec![1, 2, 3, 4]);
        let mut buf: [u8; 4] = [0; 4];

        assert_eq!(fill_buf(&mut in_buf, &mut buf).unwrap(), (false, 4));
        assert_eq!(&buf, &[1, 2, 3, 4]);
    }
}


fn flush_buf(in_buf: &mut Vec<u8>, buf: &mut [u8]) -> usize {
    // 1. Grab slice [0...min(buf.len(), in_buf.len()))
    let split_at = cmp::min(in_buf.len(), buf.len());
    // 2. Copy into buf
    buf[..split_at].clone_from_slice(&in_buf[..split_at]);
    // 3. Drop range from &mut in_buf
    in_buf.drain(..split_at);

    split_at
}

#[cfg(test)]
mod test_flush_buf {
    use super::*;

    #[test]
    fn big_buf_small_vec() {
        let mut in_buf: Vec<u8> = vec![1, 2];
        let mut buf: [u8; 4] = [0; 4];

        assert_eq!(flush_buf(&mut in_buf, &mut buf), 2);
        assert_eq!(&buf, &[1, 2, 0, 0]);
        assert_eq!(&in_buf[..], &[]);
    }

    #[test]
    fn small_buf_big_vec() {
        let mut in_buf: Vec<u8> = vec![1, 2, 3, 4];
        let mut buf: [u8; 2] = [0; 2];

        assert_eq!(flush_buf(&mut in_buf, &mut buf), 2);
        assert_eq!(&buf, &[1, 2]);
        assert_eq!(&in_buf[..], &[3, 4]);
    }

    #[test]
    fn same_buf_same_vec() {
        let mut in_buf: Vec<u8> = vec![1, 2, 3, 4];
        let mut buf: [u8; 4] = [0; 4];

        assert_eq!(flush_buf(&mut in_buf, &mut buf), 4);
        assert_eq!(&buf, &[1, 2, 3, 4]);
        assert_eq!(&in_buf[..], &[]);
    }

    #[test]
    fn one_buf_two_vec() {
        let mut in_buf1: Vec<u8> = vec![1, 2];
        let mut in_buf2: Vec<u8> = vec![3, 4];
        let mut buf: [u8; 4] = [0; 4];

        assert_eq!(flush_buf(&mut in_buf1, &mut buf), 2);
        assert_eq!(flush_buf(&mut in_buf2, &mut buf[2..]), 2);
        assert_eq!(&buf, &[1, 2, 3, 4]);
    }
}
