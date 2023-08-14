use base64ct::Base64;
use base64ct::Encoding;
use hex::decode;
use hex::encode;
use md5::{Digest, Md5};

use crate::crypto::utils::{hash_with_salt, hash_with_salt_iter, simple_hash};

use crate::hash::{ToBase64, ToHex};

use super::FromBase64;
use super::FromHex;

pub struct MD5Hash {
    value: Vec<u8>,
}

impl MD5Hash {
    pub fn simple(source: &str) -> Self {
        let hasher = Md5::new();
        let value = simple_hash(hasher, source);
        Self { value }
    }

    pub fn with_salt(source: &str, salt: &str) -> Self {
        let hasher = Md5::new();
        let value = hash_with_salt(hasher, source, salt);
        Self { value }
    }

    pub fn with_salt_iter(source: &str, salt: &str, times: usize) -> Self {
        let hasher = Md5::new();
        let value = hash_with_salt_iter(hasher, source, salt, times);
        Self { value }
    }
}

impl FromBase64 for MD5Hash {
    fn from_base64(source: &str) -> Result<Self, base64ct::Error>
    where
        Self: Sized,
    {
        const BUF_SIZE: usize = 128;
        let mut dst = [0u8; BUF_SIZE];
        let value = Base64::decode(source, &mut dst)?;
        let value = value.to_vec();
        Ok(Self { value })
    }
}

impl FromHex for MD5Hash {
    fn from_hex(source: &str) -> Result<Self, hex::FromHexError>
    where
        Self: Sized,
    {
        let value = decode(source)?;
        Ok(Self { value })
    }
}

impl ToBase64 for MD5Hash {
    fn to_base64(&self) -> String {
        Base64::encode_string(&self.value)
    }
}

impl ToHex for MD5Hash {
    fn to_hex(&self) -> String {
        encode(&self.value)
    }
}

impl ToString for MD5Hash {
    fn to_string(&self) -> String {
        self.to_hex()
    }
}
