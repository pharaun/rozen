use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretstream;

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::rcore::hash::Hash;

// Possible Scheme:
//  Sym: (New sub-key based off master key + salt... and salt is new for each chunk...)
//   1. Password -> argon2id -> pw-key
//   2. pw-key encrypt/decrypt -> master-key + hmac-key (Either 2 new key or 1 key + subkey)
//   3. Everything makes a sub-key off master-key/hmac-key
//
//  Asym:
//  a. Write to Repo
//   1. new session-key
//   2. session-key encrypt/decrypt chunks
//   3. Public Key encrypt session-key and add it to repo
//  b. Read from Repo
//   1. Password -> argon2id -> pw-key
//   2. find relevant session-key
//   3. decrypt private-key with pw-key
//   4. decrypt session-key with private-key
//   5. use session key for any chunk to decrypt, and repeat
//
// The currently accepted scheme is the Sym one, simplest possible scheme
//
// Each encryption stream outputs 24 bytes nonce which is
// combo with the given key to generate a subkey:
// subkey  <- HChaCha20(key, N[0..16])
// nonce   <- N[16..24]
// counter <- 1
//
// Ciphertext = [N | encrypted data | tag]
//
// Steps:
// 1. password -> argon2id -> pw-key
// 2. encrypt the master-key with the pw-key
// 3. feed all encrypted stream the master-key
//
// Need to generate:
// 1. salt for argon2id
// 2. cpu/memory requirement for argon2id
// 3. master key generation
// 4. hmac key generation
pub struct MemKey {
    enc: secretstream::Key,
    hmac: secretstream::Key,
}

impl MemKey {
    // TODO: Generate per session keys for now
    pub fn new() -> Self {
        MemKey {
            enc: secretstream::gen_key(),
            hmac: secretstream::gen_key(),
        }
    }

    pub fn enc_key(&self) -> secretstream::Key {
        self.enc.clone()
    }

    pub fn hmac_key(&self) -> secretstream::Key {
        self.hmac.clone()
    }

    // Use a crypto grade random key for the packfile-id
    // TODO: do this better - should be a typed pseudo hash instead of a fake hash
    pub fn gen_id(&self) -> Hash {
        Hash::from(secretstream::gen_key().0)
    }

    // Steps:
    // 1. password -> argon2id -> pw-key
    // 2. encrypt the master-key with the pw-key
    // 3. feed all encrypted stream the master-key
    //
    // Need to generate:
    // 1. salt for argon2id
    // 2. cpu/memory requirement for argon2id
    // 3. master key generation
    // 4. hmac key generation
    pub fn to_disk_key(&self, password: &str) -> DiskKey {
        let salt = argon2id13::gen_salt();
        let key = get_password_key(password, &salt);

        // We now have a key, encrypt the MemKeys
        let nonce = secretbox::gen_nonce();
        let data = {
            let mut data: Vec<u8> = Vec::new();
            data.extend_from_slice(&self.enc.0);
            data.extend_from_slice(&self.hmac.0);

            secretbox::seal(&data, &nonce, &key)
        };

        DiskKey { salt, nonce, data }
    }
}

impl Default for MemKey {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: should salt/nonce be merged in with the data itself?
#[derive(Deserialize, Serialize, Clone)]
pub struct DiskKey {
    #[serde(serialize_with = "base64_salt")]
    #[serde(deserialize_with = "base64_salt_de")]
    salt: argon2id13::Salt,

    #[serde(serialize_with = "base64_nonce")]
    #[serde(deserialize_with = "base64_nonce_de")]
    nonce: secretbox::Nonce,

    #[serde(serialize_with = "base64_slice")]
    #[serde(deserialize_with = "base64_slice_de")]
    data: Vec<u8>,
}

impl DiskKey {
    // TODO: this can fail, support that
    pub fn to_mem_key(&self, password: &str) -> MemKey {
        let key = get_password_key(password, &self.salt);
        let data = secretbox::open(&self.data, &self.nonce, &key).unwrap();

        MemKey {
            enc: secretstream::Key::from_slice(&data[0..32]).unwrap(),
            hmac: secretstream::Key::from_slice(&data[32..64]).unwrap(),
        }
    }
}

impl fmt::Debug for DiskKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiskKey")
            .field("salt", &"****")
            .field("nonce", &"****")
            .field("data", &"****")
            .finish()
    }
}

fn base64_slice<S: Serializer>(x: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&URL_SAFE.encode(x))
}

fn base64_slice_de<'de, D: Deserializer<'de>>(data: D) -> Result<Vec<u8>, D::Error> {
    let s: String = Deserialize::deserialize(data)?;
    URL_SAFE.decode(s).map_err(serde::de::Error::custom)
}

fn base64_nonce<S: Serializer>(x: &secretbox::Nonce, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&URL_SAFE.encode(x))
}

fn base64_nonce_de<'de, D: Deserializer<'de>>(data: D) -> Result<secretbox::Nonce, D::Error> {
    let s: String = Deserialize::deserialize(data)?;
    let v: Vec<u8> = URL_SAFE.decode(s).map_err(serde::de::Error::custom)?;
    secretbox::Nonce::from_slice(&v[..]).ok_or_else(|| serde::de::Error::custom("Nonce"))
}

fn base64_salt<S: Serializer>(x: &argon2id13::Salt, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&URL_SAFE.encode(x))
}

fn base64_salt_de<'de, D: Deserializer<'de>>(data: D) -> Result<argon2id13::Salt, D::Error> {
    let s: String = Deserialize::deserialize(data)?;
    let v: Vec<u8> = URL_SAFE.decode(s).map_err(serde::de::Error::custom)?;
    argon2id13::Salt::from_slice(&v[..]).ok_or_else(|| serde::de::Error::custom("Salt"))
}

fn get_password_key(password: &str, salt: &argon2id13::Salt) -> secretbox::Key {
    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    {
        let secretbox::Key(ref mut kb) = key;
        // TODO: user-settable ops/mem limits
        argon2id13::derive_key(
            kb,
            password.as_bytes(),
            salt,
            argon2id13::OPSLIMIT_INTERACTIVE,
            argon2id13::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
    }
    key
}
