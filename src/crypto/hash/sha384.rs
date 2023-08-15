use base64ct::{Base64, Encoding};
use hex::{decode, encode};
use sha2::{Digest, Sha384};

use crate::crypto::utils::{hash_with_salt, hash_with_salt_iter, simple_hash};

use super::{FromBase64, FromHex, ToBase64, ToHex};

pub struct Sha384Hash {
    value: Vec<u8>,
}

impl Sha384Hash {
    pub fn simple(source: &str) -> Self {
        let hasher = Sha384::new();
        let value = simple_hash(hasher, source);
        Self { value }
    }

    pub fn with_salt(source: &str, salt: &str) -> Self {
        let hasher = Sha384::new();
        let value = hash_with_salt(hasher, source, salt);
        Self { value }
    }

    pub fn with_salt_iter(source: &str, salt: &str, times: usize) -> Self {
        let hasher = Sha384::new();
        let value = hash_with_salt_iter(hasher, source, salt, times);
        Self { value }
    }
}

impl ToBase64 for Sha384Hash {
    fn to_base64(&self) -> String {
        Base64::encode_string(&self.value)
    }
}

impl ToHex for Sha384Hash {
    fn to_hex(&self) -> String {
        encode(&self.value)
    }
}

impl ToString for Sha384Hash {
    fn to_string(&self) -> String {
        self.to_hex()
    }
}

impl FromBase64 for Sha384Hash {
    fn from_base64(source: &str) -> Result<Self, base64ct::Error>
    where
        Self: Sized,
    {
        Base64::decode_vec(source).map(|value| Self { value })
    }
}

impl FromHex for Sha384Hash {
    fn from_hex(source: &str) -> Result<Self, hex::FromHexError>
    where
        Self: Sized,
    {
        decode(source).map(|value| Self { value })
    }
}
