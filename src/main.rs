use rusqlite as rs;

use ignore::WalkBuilder;

use std::cmp;
use std::io::{Seek, SeekFrom, copy, Cursor, Read, Write};
use blake3::Hasher;
use blake3::Hash;
use rusqlite::Connection;
use zstd::stream::read::Encoder;
use zstd::stream::read::Decoder;
use serde::Deserialize;

mod backend_mem;
use crate::backend_mem::Backend;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretstream::{gen_key, Stream, Tag, Push, Header, Key};


// Configuration
// At a later time honor: https://aws.amazon.com/blogs/security/a-new-and-standardized-way-to-manage-credentials-in-the-aws-sdks/
// envy = "0.4.2" - for grabbing the env vars via serde
#[derive(Deserialize, Debug)]
struct Config {
    symlink: bool,
    same_fs: bool,

    sources: Vec<Source>,
}

#[derive(Deserialize, Debug)]
struct Source {
    include: Vec<String>,
    exclude: Vec<String>,

    #[serde(rename = "type")]
    source_type: SourceType,
}

#[derive(Deserialize, Debug)]
enum SourceType {
    Worm,
}

fn main() {
    sodiumoxide::init().unwrap();

    // Per run key
    let key = gen_key();

    let config: Config = toml::from_str(r#"
        symlink = true
        same_fs = true

        [[sources]]
            include = ["docs"]
            exclude = ["*.pyc"]
            type = "Worm"

    "#).unwrap();

    println!("CONFIG:");
    println!("{:?}", config);

    let target = config.sources.get(0).unwrap().include.get(0).unwrap();

    // In memory backend for data storage
    let mut backend = backend_mem::MemoryVFS::new();

    {
        // Temp file for rusqlite
        let (mut s_file, s_path) = tempfile::NamedTempFile::new().unwrap().into_parts();
        let conn = Connection::open(&s_path).unwrap();
        // TODO: can't remove file path (sqlite seems to depend on it)
        //s_path.close().unwrap();

        // Setup the db
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE files (
                path VARCHAR NOT NULL,
                permission INTEGER NOT NULL,
                content_hash VARCHAR NOT NULL
             );
             COMMIT;"
        ).unwrap();

        {
            let mut file_stmt = conn.prepare(
                "INSERT INTO files
                 (path, permission, content_hash)
                 VALUES
                 (?, ?, ?)"
            ).unwrap();

            // Sort filename for determistic order
            for entry in WalkBuilder::new(target)
                .follow_links(config.symlink)
                .standard_filters(false)
                .same_file_system(config.same_fs)
                .sort_by_file_name(|a, b| a.cmp(b))
                .build() {

                match entry {
                    Ok(e) => {
                        match e.file_type() {
                            None => println!("NONE: {}", e.path().display()),
                            Some(ft) => {
                                if ft.is_file() {
                                    println!("COMP: {}", e.path().display());

                                    let mut file_data = std::fs::File::open(e.path()).unwrap();

                                    // Hasher
                                    let content_hash = hash(
                                        &key.0,
                                        &mut file_data
                                    ).unwrap().to_hex().to_string();

                                    // Streaming compressor
                                    file_data.seek(SeekFrom::Start(0)).unwrap();

                                    let mut comp = Encoder::new(
                                        &mut file_data,
                                        21
                                    ).unwrap();

                                    // Dump compressed data into memory for encryption
                                    let mut vec_comp = Vec::new();
                                    copy(&mut comp, &mut vec_comp).unwrap();
                                    // Can't move this into encryption cuz comp.finish
                                    comp.finish();

                                    // Stream the data into the backend
                                    let mut write_to = backend.write(content_hash.as_str()).unwrap();

                                    // Encrypt the stream
                                    insecure_encrypt(
                                        &vec_comp[..],
                                        &mut write_to
                                    ).unwrap();

                                    // Load file info into index
                                    file_stmt.execute(rs::params![
                                        format!("{}", e.path().display()),
                                        0000,
                                        content_hash.as_str(),
                                    ]).unwrap();

                                } else {
                                    println!("SKIP: {}", e.path().display());
                                }
                            },
                        }
                    },
                    Err(e) => println!("ERRR: {:?}", e),
                }
            }
        }

        // Spool the sqlite file into the backend as index
        conn.close().unwrap();

        // TODO: not sure we need the seek here since we never touched this handle
        s_file.seek(SeekFrom::Start(0)).unwrap();

        {
            let mut comp = Encoder::new(
                &mut s_file,
                21
            ).unwrap();

            let mut vec_comp = Vec::new();
            copy(&mut comp, &mut vec_comp).unwrap();
            comp.finish();

            // Encrypt the stream
            let fkey = secretbox::gen_key();
            let fnonce = secretbox::gen_nonce();

            let ciphertext = secretbox::seal(
                &vec_comp[..],
                &fnonce,
                &fkey
            );

            // Write to the backend
            let mut write_to = backend.write("INDEX.sqlite.zst").unwrap();

            // Write the key and nonce to the stream
            write_to.write_all(&fkey.0).unwrap();
            write_to.write_all(&fnonce.0).unwrap();

            let mut cursor = Cursor::new(ciphertext);
            copy(&mut cursor, &mut write_to).unwrap();
        }
    }

    println!("\nARCHIVE Dump");
    for k in backend.list_keys().unwrap() {
        let mut read_from = backend.read(&k).unwrap();

        let plaintext = insecure_decrypt(
            &mut read_from
        ).unwrap();

        let len = plaintext.len();

        // Validate the hash now.
        let mut cursor = Cursor::new(plaintext);
        let mut dec = Decoder::new(&mut cursor).unwrap();
        let content_hash = hash(&key.0, &mut dec).unwrap();

        match Hash::from_hex(k.clone()) {
            Ok(data_hash) => {
                let is_same = data_hash == content_hash;

                println!("SAME: {:5} SIZE: {:5}, NAME: {}", is_same, len, k);
            },
            Err(_) => {
                println!("SAME: {:5} SIZE: {:5}, NAME: {}", "----", len, k);
            },
        }
    }

    // Grab db out of backend and put it to a temp handle
    let mut index_content = backend.read("INDEX.sqlite.zst").unwrap();

    let plaintext = insecure_decrypt(
        &mut index_content
    ).unwrap();

    // Setup decompression stream
    let mut cursor = Cursor::new(plaintext);
    let mut dec = Decoder::new(&mut cursor).unwrap();

    let (mut d_file, d_path) = tempfile::NamedTempFile::new().unwrap().into_parts();
    copy(&mut dec, &mut d_file).unwrap();
    let conn = Connection::open(&d_path).unwrap();

    // Dump the sqlite db data so we can view what it is
    println!("\nINDEX Dump");
    {
        let mut dump_stmt = conn.prepare(
            "SELECT path, permission, content_hash FROM files"
        ).unwrap();
        let mut rows = dump_stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let path: String = row.get(0).unwrap();
            let perm: u32 = row.get(1).unwrap();
            let hash: String = row.get(2).unwrap();

            println!("HASH: {:?}, PERM: {:?}, PATH: {:?}", hash, perm, path);
        }
    }
    conn.close().unwrap();
}


fn hash<R: Read>(key: &[u8; 32], data: &mut R) -> Result<Hash, std::io::Error> {
    let mut hash = Hasher::new_keyed(&key);
    copy(data, &mut hash)?;
    Ok(hash.finalize())
}

//********************************************************************************
// TODO: this dumps the key+nonce to the stream, is not secure at all
//********************************************************************************
// 8Kb encryption frame buffer
const CHUNK_SIZE: usize = 8 * 1024;

struct Encrypter<R> {
    reader: R,
    stream: Stream<Push>,
    out_buf: Vec<u8>,
}

impl<R: Read> Encrypter<R> {
    fn new(reader: R) -> Self {
        let fkey = gen_key();
        let (stream, header) = Stream::init_push(&fkey).unwrap();

        let mut out_buf = Vec::with_capacity(CHUNK_SIZE);

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

#[cfg(test)]
mod test_encrypt_read {
    use super::*;

    #[test]
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
    fn big_data_roundtrip() {
        // TODO: implement
        // Make the input data bigger than the frame size so its forced to split
        // into 2 message, then decrypt both message and check the result.
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




fn insecure_encrypt<W: Write>(data: &[u8], output: &mut W) -> std::io::Result<()> {
    // Generate the key + nonce
    let fkey = secretbox::gen_key();
    let fnonce = secretbox::gen_nonce();

    let ciphertext = secretbox::seal(data, &fnonce, &fkey);

    // Write the key and nonce to the stream
    output.write_all(&fkey.0)?;
    output.write_all(&fnonce.0)?;
    output.write_all(&ciphertext)?;

    Ok(())
}

fn insecure_decrypt<R: Read>(data: &mut R) -> std::io::Result<Vec<u8>> {
    // Decrypt the stream
    // read the key then nonce then stream
    let mut dkey: [u8; 32] = [0; 32];
    let mut dnonce: [u8; 24] = [0; 24];
    let mut dciphertext = Vec::new();

    data.read_exact(&mut dkey)?;
    data.read_exact(&mut dnonce)?;
    data.read_to_end(&mut dciphertext)?;

    let fkey = secretbox::Key::from_slice(&dkey).unwrap();
    let fnonce = secretbox::Nonce::from_slice(&dnonce).unwrap();

    let plaintext = secretbox::open(
        &dciphertext[..],
        &fnonce,
        &fkey
    ).unwrap();

    Ok(plaintext)
}
