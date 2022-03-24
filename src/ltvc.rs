use crate::hash::Checksum;

// 1Kb EDAT frame buffer
pub const CHUNK_SIZE: usize = 1 * 1024;

// TODO: Evaulate the need for a hash
// Length, Type, Value, xxhash32 of Type+Value
// u32, u32, [u8; N], u32
pub fn ltvc(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut hash = Checksum::new();
    hash.update(chunk_type);
    hash.update(data);

    let mut buf: Vec<u8> = Vec::new();

    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(chunk_type);
    buf.extend_from_slice(data);
    buf.extend_from_slice(&hash.finalize().to_le_bytes());

    buf
}

// Read the buffer to convert to a LTVC and validate
// TODO: consider a iterator/streaming option where it takes a buffer
// that begins on a chunk and then it streams the chunk+data one block at a time
// TODO: make sure to reject too large chunk size for preventing out of memory bugs
pub fn read_ltvc(buf: &[u8]) -> Option<(usize, [u8; 4], &[u8])> {
    let len_buf: [u8; 4] = buf[0..4].try_into().unwrap();
    let typ_buf: [u8; 4] = buf[4..8].try_into().unwrap();

    let len: usize = u32::from_le_bytes(len_buf) as usize;

    // TODO: this is bad, do this better, don't trust length
    let dat_buf: &[u8]   = buf[8..(8+len)].try_into().unwrap();
    let has_buf: [u8; 4] = buf[(8+len)..(8+len+4)].try_into().unwrap();

    let old_hash: u32 = u32::from_le_bytes(has_buf);

    // Validate the hash
    let mut hash = Checksum::new();
    hash.update(&typ_buf);
    hash.update(dat_buf);

    let whole_len = 4 + 4 + len + 4;

    if hash.finalize()  == old_hash {
        Some((whole_len, typ_buf, dat_buf))
    } else {
        None
    }
}

