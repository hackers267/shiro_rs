use base64ct::Base64;
use base64ct::Encoding;
use hex::encode;
use md2::Digest;
use md2::Md2;

use crate::simple_hash::Algorithm;
use crate::simple_hash::SimpleHash;
use crate::simple_hash::ToBase64;
use crate::simple_hash::ToHex;
pub struct MD2Hash {
    value: Vec<u8>,
}

impl MD2Hash {
    pub fn simple(source: &str) -> Self {
        let mut hasher = Md2::new();
        hasher.update(source);
        let value = hasher.finalize();
        let value = value.to_vec();
        Self { value }
    }

    pub fn with_salt(source: &str, salt: &str) -> Self {
        let mut hasher = Md2::new();
        hasher.update(salt);
        hasher.update(source);
        let value = hasher.finalize();
        let value = value.to_vec();
        Self { value }
    }

    pub fn with_salt_iter(source: &str, salt: &str, times: usize) -> Self {
        let mut hasher = Md2::new();
        hasher.update(salt);
        hasher.update(source);
        let mut hashed = hasher.finalize();
        let range = 1..times;
        for _i in range {
            let mut hasher = Md2::new();
            hasher.update(hashed);
            hashed = hasher.finalize();
        }
        let value = hashed.to_vec();
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
