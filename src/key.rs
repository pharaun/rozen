use sodiumoxide::crypto::secretstream::Key;
use sodiumoxide::crypto::secretstream::gen_key;
use crate::hash::Hash;

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
pub struct DiskKey {
}

pub struct MemKey {
    enc: Key,
    hmac: Key,
}

impl MemKey {
    // TODO: Generate per session keys for now
    pub fn new() -> Self {
        MemKey {
            enc: gen_key(),
            hmac: gen_key(),
        }
    }

    pub fn enc_key(&self) -> Key {
        self.enc.clone()
    }

    pub fn hmac_key(&self) -> Key {
        self.hmac.clone()
    }

    // Use a crypto grade random key for the packfile-id
    // TODO: do this better - should be a typed pseudo hash instead of a fake hash
    pub fn gen_id(&self) -> Hash {
        Hash::from(gen_key().0)
    }

    pub fn to_disk_key(mut self, password: &str) -> DiskKey {
        DiskKey {}
    }
}

impl DiskKey {
    pub fn to_mem_key(mut self, password: &str) -> MemKey {
        MemKey::new()
    }
}
