use sodiumoxide::crypto::secretstream;
pub use sodiumoxide::crypto::secretstream::Key;

pub fn gen_key() -> Key {
    secretstream::gen_key()
}
