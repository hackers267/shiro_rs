use base64ct::{Base64, Encoding};
use hex::encode;
use sha1::{Digest, Sha1};

use crate::crypto::utils::{hash_with_salt, hash_with_salt_iter, simple_hash};

use super::{FromBase64, FromHex, ToBase64, ToHex};

pub struct Sha1Hash {
    value: Vec<u8>,
}

impl Sha1Hash {
    pub fn simple(source: &str) -> Self {
        let hasher = Sha1::new();
        let value = simple_hash(hasher, source);
        Self { value }
    }
    pub fn with_salt(source: &str, salt: &str) -> Self {
        let hasher = Sha1::new();
        let value = hash_with_salt(hasher, source, salt);
        Self { value }
    }

    pub fn with_salt_iter(source: &str, salt: &str, count: usize) -> Self {
        let hasher = Sha1::new();
        let value = hash_with_salt_iter(hasher, source, salt, count);
        Self { value }
    }
}

impl ToString for Sha1Hash {
    fn to_string(&self) -> String {
        self.to_hex()
    }
}

impl ToHex for Sha1Hash {
    fn to_hex(&self) -> String {
        encode(&self.value)
    }
}

impl ToBase64 for Sha1Hash {
    fn to_base64(&self) -> String {
        Base64::encode_string(&self.value)
    }
}

impl FromBase64 for Sha1Hash {
    fn from_base64(value: &str) -> Result<Self, base64ct::Error> {
        const BUF_SIZE: usize = 128;
        let mut dst = [0u8; BUF_SIZE];
        let value = Base64::decode(value, &mut dst)?.to_vec();
        Ok(Self { value })
    }
}

impl FromHex for Sha1Hash {
    fn from_hex(source: &str) -> Result<Self, hex::FromHexError>
    where
        Self: Sized,
    {
        let value = hex::decode(source)?;
        Ok(Self { value })
    }
}
