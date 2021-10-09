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

pub struct Encrypter<R> {
    reader: R,
    stream: Stream<Push>,
    out_buf: Vec<u8>,
}

pub struct Decrypter<R> {
    reader: R,
    stream: Stream<Pull>,
    out_buf: Vec<u8>,
}

impl<R: Read> Encrypter<R> {
    pub fn new(reader: R) -> Self {
        let fkey = gen_key();
        let (stream, header) = Stream::init_push(&fkey).unwrap();

        // Chunk Frame size + encryption additional bytes (~17 bytes)
        let mut out_buf = Vec::with_capacity(CHUNK_SIZE + ABYTES);

        // Flush fkey + header to out_buf
        out_buf.extend_from_slice(&fkey.0);
        out_buf.extend_from_slice(&header.0);

        Encrypter {
            reader,
            stream,
            out_buf,
        }
    }
}

impl<R: Read> Decrypter<R> {
    pub fn new(mut reader: R) -> std::io::Result<Self> {
        // Read out the key + header
        let mut dkey: [u8; 32] = [0; 32];
        reader.read_exact(&mut dkey)?;
        let fkey = Key::from_slice(&dkey).unwrap();

        let mut dheader: [u8; 24] = [0; 24];
        reader.read_exact(&mut dheader)?;
        let fheader = Header::from_slice(&dheader).unwrap();

        // Decrypter setup
        let stream = Stream::init_pull(&fheader, &fkey).unwrap();

        // Chunk Frame size (input will be frame+abytes)
        let out_buf = Vec::with_capacity(CHUNK_SIZE);

        Ok(Decrypter {
            reader,
            stream,
            out_buf,
        })
    }
}

impl<R: Read> Read for Encrypter<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        encrypt_read(
            &mut self.reader,
            &mut self.out_buf,
            &mut self.stream,
            buf,
        )
    }
}

impl<R: Read> Read for Decrypter<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        decrypt_read(
            &mut self.reader,
            &mut self.out_buf,
            &mut self.stream,
            buf,
        )
    }
}

// TODO: do i need to figure out a frame format for each message
// for the decryption end?
fn encrypt_read<R: Read>(
    data: &mut R,
    out_buf: &mut Vec<u8>,
    stream: &mut Stream<Push>,
    buf: &mut [u8]
) -> std::io::Result<usize> {
    let mut buf_write: usize = 0;

    // 1. If buf_write == buf.len() return
    while buf_write < buf.len() {
        if !out_buf.is_empty() {
            // 2. If data in out_buf, flush into buf first
            buf_write += flush_buf(out_buf, &mut buf[buf_write..]);

        } else {
            let mut in_buf: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];

            // 3. Read till there is 8Kb of data in in_buf
            match fill_buf(data, &mut in_buf) {
                // 4a. Nothing left in out_buf and is EoF, exit
                Ok((true, 0)) => return Ok(buf_write),
                Ok((true, in_len)) => {
                    // 4b. Final read, finalize
                    #[cfg(feature = "copy-test")]
                    {
                        // Testing only code
                        out_buf.extend_from_slice(
                            &in_buf[..in_len]
                        );
                    }
                    #[cfg(not(feature = "copy-test"))]
                    {
                        stream.push_to_vec(
                            &in_buf[..in_len],
                            None,
                            Tag::Final,
                            out_buf,
                        ).unwrap();
                    }
                },
                Ok((false, in_len)) => {
                    // 4c. Copy in_buf -> out_buf
                    #[cfg(feature = "copy-test")]
                    {
                        // Testing only code
                        out_buf.extend_from_slice(
                            &in_buf[..in_len]
                        );
                    }
                    #[cfg(not(feature = "copy-test"))]
                    {
                        stream.push_to_vec(
                            &in_buf[..in_len],
                            None,
                            Tag::Message,
                            out_buf,
                        ).unwrap();
                    }
                },
                Err(e) => return Err(e),
            }
        }
    }

    Ok(buf_write)
}


fn decrypt_read<R: Read>(
    data: &mut R,
    out_buf: &mut Vec<u8>,
    stream: &mut Stream<Pull>,
    buf: &mut [u8]
) -> std::io::Result<usize> {
    let mut buf_write: usize = 0;

    // 1. If buf_write == buf.len() return
    while buf_write < buf.len() {
        if !out_buf.is_empty() {
            // 2. If data in out_buf, flush into buf first
            buf_write += flush_buf(out_buf, &mut buf[buf_write..]);

        } else {
            let mut in_buf: [u8; CHUNK_SIZE + ABYTES] = [0; CHUNK_SIZE + ABYTES];

            // 3. Read till there is 8Kb of data in in_buf
            match fill_buf(data, &mut in_buf) {
                // 4a. Nothing left in out_buf and is EoF, exit
                Ok((true, 0)) => return Ok(buf_write),
                Ok((true, in_len)) => {
                    // 4b. Final read, finalize
                    let tag = stream.pull_to_vec(
                        &in_buf[..in_len],
                        None,
                        out_buf,
                    ).unwrap();
                    // TODO: assert tag is Tag::Final
                },
                Ok((false, in_len)) => {
                    // 4c. Copy in_buf -> out_buf
                    let tag = stream.pull_to_vec(
                        &in_buf[..in_len],
                        None,
                        out_buf,
                    ).unwrap();
                    // TODO: assert tag is Tag::Message
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
    #[cfg_attr(feature = "copy-test", ignore)]
    fn small_data_roundtrip() {
        let data = b"Hello World!";

        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        in_data.write(data).unwrap();
        in_data.set_position(0);

        let enc = Encrypter::new(in_data);
        let mut dec = Decrypter::new(enc).unwrap();

        let mut out_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        copy(&mut dec, &mut out_data).unwrap();
        out_data.set_position(0);

        // Assertions
        assert_eq!(&out_data.get_ref()[..], data);
    }

    #[test]
    #[cfg_attr(feature = "copy-test", ignore)]
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

        let enc = Encrypter::new(in_data);
        let mut dec = Decrypter::new(enc).unwrap();

        let mut out_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        copy(&mut dec, &mut out_data).unwrap();
        out_data.set_position(0);

        // Assertions
        assert_eq!(&out_data.get_ref()[..], data);
    }
}



#[cfg(test)]
mod test_encrypt_read {
    use std::io::{Cursor, Write};
    use super::*;

    #[test]
    #[cfg_attr(feature = "copy-test", ignore)]
    fn small_data_roundtrip() {
        let data = b"Hello World!";

        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        in_data.write(data).unwrap();
        in_data.set_position(0);

        let mut enc = Encrypter::new(in_data);

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
    #[cfg_attr(feature = "copy-test", ignore)]
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

        let mut enc = Encrypter::new(in_data);

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
    #[cfg_attr(not(feature = "copy-test"), ignore)]
    fn empty_data_empty_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        let mut out_buf: Vec<u8> = Vec::new();
        let mut buf: [u8; 4] = [0; 4];

        let (mut stream, _) = Stream::init_push(&gen_key()).unwrap();
        assert_eq!(encrypt_read(&mut in_data, &mut out_buf, &mut stream, &mut buf).unwrap(), 0);
        assert_eq!(&out_buf[..], &[]);
        assert_eq!(&buf, &[0, 0, 0, 0]);
    }

    #[test]
    #[cfg_attr(not(feature = "copy-test"), ignore)]
    fn empty_data_small_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        let mut out_buf: Vec<u8> = vec![1, 2];
        let mut buf: [u8; 4] = [0; 4];

        let (mut stream, _) = Stream::init_push(&gen_key()).unwrap();
        assert_eq!(encrypt_read(&mut in_data, &mut out_buf, &mut stream, &mut buf).unwrap(), 2);
        assert_eq!(&out_buf[..], &[]);
        assert_eq!(&buf, &[1, 2, 0, 0]);
    }

    #[test]
    #[cfg_attr(not(feature = "copy-test"), ignore)]
    fn empty_data_big_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        let mut out_buf: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let mut buf: [u8; 4] = [0; 4];

        let (mut stream, _) = Stream::init_push(&gen_key()).unwrap();
        assert_eq!(encrypt_read(&mut in_data, &mut out_buf, &mut stream, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[5, 6]);
        assert_eq!(&buf, &[1, 2, 3, 4]);
    }

    #[test]
    #[cfg_attr(not(feature = "copy-test"), ignore)]
    fn small_data_empty_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2]);
        let mut out_buf: Vec<u8> = Vec::new();
        let mut buf: [u8; 4] = [0; 4];

        let (mut stream, _) = Stream::init_push(&gen_key()).unwrap();
        assert_eq!(encrypt_read(&mut in_data, &mut out_buf, &mut stream, &mut buf).unwrap(), 2);
        assert_eq!(&out_buf[..], &[]);
        assert_eq!(&buf, &[1, 2, 0, 0]);
    }

    #[test]
    #[cfg_attr(not(feature = "copy-test"), ignore)]
    fn small_data_small_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2]);
        let mut out_buf: Vec<u8> = vec![3, 4];
        let mut buf: [u8; 4] = [0; 4];

        let (mut stream, _) = Stream::init_push(&gen_key()).unwrap();
        assert_eq!(encrypt_read(&mut in_data, &mut out_buf, &mut stream, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[]);
        assert_eq!(&buf, &[3, 4, 1, 2]);
    }

    #[test]
    #[cfg_attr(not(feature = "copy-test"), ignore)]
    fn small_data_big_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2]);
        let mut out_buf: Vec<u8> = vec![3, 4, 5, 6, 7, 8];
        let mut buf: [u8; 4] = [0; 4];

        let (mut stream, _) = Stream::init_push(&gen_key()).unwrap();
        assert_eq!(encrypt_read(&mut in_data, &mut out_buf, &mut stream, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[7, 8]);
        assert_eq!(&buf, &[3, 4, 5, 6]);
    }

    #[test]
    #[cfg_attr(not(feature = "copy-test"), ignore)]
    fn big_data_empty_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2, 3, 4, 5, 6]);
        let mut out_buf: Vec<u8> = Vec::new();
        let mut buf: [u8; 4] = [0; 4];

        let (mut stream, _) = Stream::init_push(&gen_key()).unwrap();
        assert_eq!(encrypt_read(&mut in_data, &mut out_buf, &mut stream, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[5, 6]);
        assert_eq!(&buf, &[1, 2, 3, 4]);
    }

    #[test]
    #[cfg_attr(not(feature = "copy-test"), ignore)]
    fn big_data_small_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2, 3, 4, 5, 6]);
        let mut out_buf: Vec<u8> = vec![7, 8];
        let mut buf: [u8; 4] = [0; 4];

        let (mut stream, _) = Stream::init_push(&gen_key()).unwrap();
        assert_eq!(encrypt_read(&mut in_data, &mut out_buf, &mut stream, &mut buf).unwrap(), 4);
        assert_eq!(&out_buf[..], &[3, 4, 5, 6]);
        assert_eq!(&buf, &[7, 8, 1, 2]);
    }

    #[test]
    #[cfg_attr(not(feature = "copy-test"), ignore)]
    fn big_data_big_out_buf() {
        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![1, 2, 3, 4, 5, 6]);
        let mut out_buf: Vec<u8> = vec![7, 8, 9, 10, 11, 12];
        let mut buf: [u8; 4] = [0; 4];

        let (mut stream, _) = Stream::init_push(&gen_key()).unwrap();
        assert_eq!(encrypt_read(&mut in_data, &mut out_buf, &mut stream, &mut buf).unwrap(), 4);
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
