use base64ct::{Base64, Encoding};
use hex::{decode, encode, FromHexError};
use sha2::{Digest, Sha512};

use crate::crypto::utils::{hash_with_salt, hash_with_salt_iter, simple_hash};

use super::{FromBase64, FromHex, ToBase64, ToHex};

pub struct Sha512Hash {
    value: Vec<u8>,
}

impl Sha512Hash {
    pub fn simple(source: &str) -> Self {
        let hasher = Sha512::new();
        let value = simple_hash(hasher, source);
        Self { value }
    }

    pub fn with_salt(source: &str, salt: &str) -> Self {
        let hasher = Sha512::new();
        let value = hash_with_salt(hasher, source, salt);
        Self { value }
    }

    pub fn with_salt_iter(source: &str, salt: &str, times: usize) -> Self {
        let hasher = Sha512::new();
        let value = hash_with_salt_iter(hasher, source, salt, times);
        Self { value }
    }
}

impl ToBase64 for Sha512Hash {
    fn to_base64(&self) -> String {
        Base64::encode_string(&self.value)
    }
}

impl ToHex for Sha512Hash {
    fn to_hex(&self) -> String {
        encode(&self.value)
    }
}

impl ToString for Sha512Hash {
    fn to_string(&self) -> String {
        self.to_hex()
    }
}

impl FromBase64 for Sha512Hash {
    fn from_base64(source: &str) -> Result<Self, base64ct::Error> {
        Base64::decode_vec(source).map(|value| Self { value })
    }
}

impl FromHex for Sha512Hash {
    fn from_hex(source: &str) -> Result<Self, FromHexError> {
        decode(source).map(|value| Self { value })
    }
}
