use base64ct::Base64;
use base64ct::Encoding;
use hex::encode;
use md5::{Digest, Md5};

use crate::simple_hash::ToHex;
use crate::{
    crypto::utils::{hash_with_salt, hash_with_salt_iter, simple_hash},
    simple_hash::ToBase64,
};

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
