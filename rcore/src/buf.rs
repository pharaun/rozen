use std::cmp;
use std::io::Read;

pub fn fill_buf<R: Read>(data: &mut R, buf: &mut [u8]) -> std::io::Result<(bool, usize)> {
    let mut buf_read = 0;

    while buf_read < buf.len() {
        match data.read(&mut buf[buf_read..]) {
            Ok(0) => return Ok((true, buf_read)),
            Ok(x) => buf_read += x,
            Err(e) => return Err(e),
        };
    }
    Ok((false, buf_read))
}

pub fn flush_buf(in_buf: &mut Vec<u8>, buf: &mut [u8]) -> usize {
    // 1. Grab slice [0...min(buf.len(), in_buf.len()))
    let split_at = cmp::min(in_buf.len(), buf.len());
    // 2. Copy into buf
    buf[..split_at].clone_from_slice(&in_buf[..split_at]);
    // 3. Drop range from &mut in_buf
    in_buf.drain(..split_at);

    split_at
}

#[cfg(test)]
mod test_fill_buf {
    use super::*;
    use std::io::Cursor;

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

#[cfg(test)]
mod test_flush_buf {
    use super::*;

    #[test]
    fn zero_buf() {
        let mut in_buf: Vec<u8> = vec![1, 2];
        let mut buf: [u8; 0] = [0; 0];

        assert_eq!(flush_buf(&mut in_buf, &mut buf), 0);
        assert_eq!(&buf, &[]);
        assert_eq!(&in_buf[..], &[1, 2]);
    }

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
