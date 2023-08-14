use base64ct::Base64;
use base64ct::Encoding;
use hex::encode;
use md2::Digest;
use md2::Md2;

use crate::simple_hash::ToBase64;
use crate::simple_hash::ToHex;

use super::utils::hash_with_salt;
use super::utils::hash_with_salt_iter;
use super::utils::simple_hash;

pub struct MD2Hash {
    value: Vec<u8>,
}

impl MD2Hash {
    pub fn simple(source: &str) -> Self {
        let hasher = Md2::new();
        let value = simple_hash(hasher, source);
        Self { value }
    }

    pub fn with_salt(source: &str, salt: &str) -> Self {
        let hasher = Md2::new();
        let value = hash_with_salt(hasher, source, salt);
        Self { value }
    }

    pub fn with_salt_iter(source: &str, salt: &str, times: usize) -> Self {
        let hasher = Md2::new();
        let value = hash_with_salt_iter(hasher, source, salt, times);
        Self { value }
    }
}

impl ToBase64 for MD2Hash {
    fn to_base64(&self) -> String {
        Base64::encode_string(&self.value)
    }
}

impl ToHex for MD2Hash {
    fn to_hex(&self) -> String {
        encode(&self.value)
    }
}

impl ToString for MD2Hash {
    fn to_string(&self) -> String {
        self.to_hex()
    }
}
