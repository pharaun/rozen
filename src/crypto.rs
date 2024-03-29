use std::io::Read;

use thiserror::Error;

use sodiumoxide::crypto::secretstream::{Header, Pull, Push, Stream, Tag, ABYTES};

use crate::buf::fill_buf;
use crate::buf::flush_buf;
use crate::key;

// 8Kb encryption frame buffer
const CHUNK_SIZE: usize = 8 * 1024;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("sodiumoxide init failed")]
    Init,
    #[error("sodiumoxide init_push failed")]
    InitPush,
    #[error("sodiumoxide init_pull failed")]
    InitPull,
    #[error("sodiumoxide header parse failed")]
    HeaderParse,
    #[error("sodiumoxide encryption failed")]
    EncryptionFailed,
    #[error("sodiumoxide decryption failed")]
    DecryptionFailed,
}

type CResult<T> = Result<T, CryptoError>;

pub fn init() -> CResult<()> {
    sodiumoxide::init().map_err(|_| CryptoError::Init)
}

pub struct Crypter<R, E> {
    reader: R,
    engine: E,
    in_buf: Box<[u8]>,
    out_buf: Vec<u8>,
}

// Encryption
//     - Investigate padding (PADME?) for anonomyizing file size to reduce identification
//     - Chunk/file size is information leak
//          One way to consider information leak is pack file is purely an optimization for
//          glacier store in which the index can be stored in S3 + packfile, and the specified
//          byte range be fetched out of glacier. This leads me to interpret any information leak
//          is also the same as a stand-alone blob in glacier store so... treat both the same.
//          packfile == packed blobs
//
//          Now mind you there *is* information leak via the length cos of compression/plaintext
//          but blob storage would have this as well so resolving blob storage + etc will be good
//          to have also this is more for chunked data ala borg/restic/etc
//
//     - Use the phash (file HMAC) for additional data with the encryption to ensure that
//     the encrypted data matches the phash
pub fn encrypt<R: Read>(key: &key::MemKey, reader: R) -> CResult<Crypter<R, EncEngine>> {
    let (stream, header) = Stream::init_push(&key.enc_key()).map_err(|_| CryptoError::InitPush)?;
    let engine = EncEngine(stream);

    // Chunk Frame size + encryption additional bytes (~17 bytes)
    let in_buf = [0u8; CHUNK_SIZE];
    let mut out_buf = Vec::with_capacity(CHUNK_SIZE + ABYTES);

    // Flush header to out_buf
    out_buf.extend_from_slice(&header.0);

    Ok(Crypter {
        reader,
        engine,
        in_buf: Box::new(in_buf),
        out_buf,
    })
}

pub fn decrypt<R: Read>(key: &key::MemKey, mut reader: R) -> CResult<Crypter<R, DecEngine>> {
    // Read out the header
    let mut dheader: [u8; 24] = [0; 24];
    reader.read_exact(&mut dheader)?;
    let fheader = Header::from_slice(&dheader).ok_or(CryptoError::HeaderParse)?;

    // Decrypter setup
    let stream = Stream::init_pull(&fheader, &key.enc_key()).map_err(|_| CryptoError::InitPull)?;
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
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

// Trait for wrapping up the encryption/decryption portion of the code
pub trait Engine {
    fn crypt(&mut self, data: &[u8], tag: Tag, out: &mut Vec<u8>) -> CResult<()>;
    fn is_finalized(&self) -> bool;
}

pub struct EncEngine(Stream<Push>);
pub struct DecEngine(Stream<Pull>);

impl Engine for EncEngine {
    fn crypt(&mut self, data: &[u8], tag: Tag, out: &mut Vec<u8>) -> CResult<()> {
        self.0
            .push_to_vec(data, None, tag, out)
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn is_finalized(&self) -> bool {
        self.0.is_finalized()
    }
}

impl Engine for DecEngine {
    fn crypt(&mut self, data: &[u8], tag: Tag, out: &mut Vec<u8>) -> CResult<()> {
        self.0
            .pull_to_vec(data, None, out)
            .map_err(|_| CryptoError::DecryptionFailed)
            .and_then(|dtag| {
                if dtag == tag {
                    Ok(())
                } else {
                    Err(CryptoError::DecryptionFailed)
                }
            })
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
    buf: &mut [u8],
) -> CResult<usize> {
    let mut buf_write: usize = 0;

    // 1. If buf_write == buf.len() return
    while buf_write < buf.len() {
        if !out_buf.is_empty() {
            // 2. If data in out_buf, flush into buf first
            buf_write += flush_buf(out_buf, &mut buf[buf_write..]);
        } else {
            // 3. Read till there is 8Kb of data in in_buf
            match fill_buf(data, in_buf)? {
                // 4a. Nothing left in in_buf, is EoF, and is not finalize, finalize
                (true, 0) if !engine.is_finalized() => {
                    engine.crypt(&[], Tag::Final, out_buf)?;
                }

                // 4b. Nothing left in [in_buf, out_buf] and is EoF, exit
                (true, 0) if out_buf.is_empty() => return Ok(buf_write),

                // 4c. Copy in_buf -> out_buf
                // 4d. Final read, finalize
                (eof, in_len) => {
                    let tag = if eof { Tag::Final } else { Tag::Message };

                    engine.crypt(&in_buf[..in_len], tag, out_buf)?;
                }
            }
        }
    }
    Ok(buf_write)
}

#[cfg(test)]
mod test_encrypt_decrypt_roundtrip {
    use super::*;
    use std::io::{copy, Cursor, Write};

    #[test]
    fn small_data_roundtrip() {
        let key = key::MemKey::new();
        let data = b"Hello World!";

        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        in_data.write(data).unwrap();
        in_data.set_position(0);

        let enc = encrypt(&key, in_data).unwrap();
        let mut dec = decrypt(&key, enc).unwrap();

        let mut out_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        copy(&mut dec, &mut out_data).unwrap();
        out_data.set_position(0);

        // Assertions
        assert_eq!(&out_data.get_ref()[..], data);
    }

    #[test]
    fn exactly_chunk_roundtrip() {
        let key = key::MemKey::new();
        let data: Vec<u8> = {
            let cap: usize = (1.5 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!!!!!"; // Must be 16 bytes

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret[..CHUNK_SIZE].to_vec()
        };
        assert_eq!(data.len(), CHUNK_SIZE);

        let in_data: Cursor<Vec<u8>> = Cursor::new(data.clone());

        let enc = encrypt(&key, in_data).unwrap();
        let mut dec = decrypt(&key, enc).unwrap();

        let mut out_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        copy(&mut dec, &mut out_data).unwrap();
        out_data.set_position(0);

        // Assertions
        assert_eq!(&out_data.get_ref()[..], data);
    }

    #[test]
    fn big_data_roundtrip() {
        let key = key::MemKey::new();
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

        let enc = encrypt(&key, in_data).unwrap();
        let mut dec = decrypt(&key, enc).unwrap();

        let mut out_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        copy(&mut dec, &mut out_data).unwrap();
        out_data.set_position(0);

        // Assertions
        assert_eq!(&out_data.get_ref()[..], data);
    }
}

#[cfg(test)]
mod test_crypt_read {
    use super::*;
    use std::io::{Cursor, Write};

    // Struct just for copying data
    struct CopyEngine();
    impl Engine for CopyEngine {
        fn crypt(&mut self, data: &[u8], _tag: Tag, out: &mut Vec<u8>) -> CResult<()> {
            out.extend_from_slice(&data);
            Ok(())
        }
        fn is_finalized(&self) -> bool {
            true
        }
    }

    #[test]
    fn small_data_roundtrip() {
        let key = key::MemKey::new();
        let data = b"Hello World!";

        let mut in_data: Cursor<Vec<u8>> = Cursor::new(vec![]);
        in_data.write(data).unwrap();
        in_data.set_position(0);

        let mut enc = encrypt(&key, in_data).unwrap();

        // Read out to buffer vec
        let mut dheader: [u8; 24] = [0; 24];
        let mut dciphertext = Vec::new();

        enc.read_exact(&mut dheader).unwrap();
        enc.read_to_end(&mut dciphertext).unwrap();

        assert_ne!(data, &dciphertext[..]);

        // Construct the decrypter and pass the ciphertext through
        let fheader = Header::from_slice(&dheader).unwrap();

        let mut dec = Stream::init_pull(&fheader, &key.enc_key()).unwrap();
        let (dec_data, tag) = dec.pull(&dciphertext[..], None).unwrap();

        assert_eq!(tag, Tag::Final);
        assert_eq!(dec_data, data);
    }

    #[test]
    fn big_data_roundtrip() {
        let key = key::MemKey::new();
        let data: Vec<u8> = {
            let cap: usize = (1.5 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!!!!!"; // Must be 16 bytes

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret
        };
        let in_data: Cursor<Vec<u8>> = Cursor::new(data.clone());

        let mut enc = encrypt(&key, in_data).unwrap();

        // Read out to buffer vec
        let mut dheader: [u8; 24] = [0; 24];
        enc.read_exact(&mut dheader).unwrap();
        let fheader = Header::from_slice(&dheader).unwrap();

        // Decrypter setup
        let mut dec = Stream::init_pull(&fheader, &key.enc_key()).unwrap();

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
        let key = key::MemKey::new();
        let data: Vec<u8> = {
            let cap: usize = (1.5 * CHUNK_SIZE as f32) as usize;

            let mut ret: Vec<u8> = Vec::with_capacity(cap);
            let data = b"Hello World!!!!!"; // Must be 16 bytes

            for _ in 0..(cap / data.len()) {
                ret.extend_from_slice(&data[..]);
            }

            ret[..CHUNK_SIZE].to_vec()
        };
        assert_eq!(data.len(), CHUNK_SIZE);

        let in_data: Cursor<Vec<u8>> = Cursor::new(data.clone());

        let mut enc = encrypt(&key, in_data).unwrap();

        // Do awkward reads to see if the control loop breaks down
        let mut dheader: [u8; 24] = [0; 24];
        let mut dciphertext1_half: [u8; CHUNK_SIZE / 2] = [0; CHUNK_SIZE / 2];
        let mut dciphertext1_abyt: [u8; CHUNK_SIZE / 2 + ABYTES] = [0; CHUNK_SIZE / 2 + ABYTES];

        // Final should be 17 bytes but let's break it into 2 read of 8 and 9 bytes
        let mut dciphertext2_read8: [u8; 8] = [0; 8];
        let mut dciphertext2_read9: [u8; 9] = [0; 9];

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
        assert_eq!(
            crypt_read(
                &mut in_data,
                &mut out_buf,
                &mut engine,
                &mut in_buf,
                &mut buf
            )
            .unwrap(),
            0
        );
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
        assert_eq!(
            crypt_read(
                &mut in_data,
                &mut out_buf,
                &mut engine,
                &mut in_buf,
                &mut buf
            )
            .unwrap(),
            2
        );
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
        assert_eq!(
            crypt_read(
                &mut in_data,
                &mut out_buf,
                &mut engine,
                &mut in_buf,
                &mut buf
            )
            .unwrap(),
            4
        );
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
        assert_eq!(
            crypt_read(
                &mut in_data,
                &mut out_buf,
                &mut engine,
                &mut in_buf,
                &mut buf
            )
            .unwrap(),
            2
        );
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
        assert_eq!(
            crypt_read(
                &mut in_data,
                &mut out_buf,
                &mut engine,
                &mut in_buf,
                &mut buf
            )
            .unwrap(),
            4
        );
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
        assert_eq!(
            crypt_read(
                &mut in_data,
                &mut out_buf,
                &mut engine,
                &mut in_buf,
                &mut buf
            )
            .unwrap(),
            4
        );
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
        assert_eq!(
            crypt_read(
                &mut in_data,
                &mut out_buf,
                &mut engine,
                &mut in_buf,
                &mut buf
            )
            .unwrap(),
            4
        );
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
        assert_eq!(
            crypt_read(
                &mut in_data,
                &mut out_buf,
                &mut engine,
                &mut in_buf,
                &mut buf
            )
            .unwrap(),
            4
        );
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
        assert_eq!(
            crypt_read(
                &mut in_data,
                &mut out_buf,
                &mut engine,
                &mut in_buf,
                &mut buf
            )
            .unwrap(),
            4
        );
        assert_eq!(&out_buf[..], &[11, 12]);
        assert_eq!(&buf, &[7, 8, 9, 10]);
    }
}
