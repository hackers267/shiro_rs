//! 允许使用多个指定算法名称的哈希实现。
use base64ct::{Base64, Encoding};
use hex::encode;
use md2::Md2;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use super::utils::{hash_with_salt, hash_with_salt_iter, simple_hash};

/// SimpleHash支持的算法
pub enum Algorithm {
    MD2,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

/// 简单哈希算法
/// - MD2
/// - MD5
/// - SHA1
/// - SHA-224
/// - SHA-256
/// - SHA-384
/// - SHA-512
pub struct SimpleHash {
    value: Vec<u8>,
}

impl SimpleHash {
    /// 根据指定算法和源字符串构建一个SImpleHash struct
    ///
    /// # Arguments
    /// - `algorithm`: 算法
    /// - `source`: 源字符串
    ///
    /// # 返回值:
    /// 一个SimpleHash struct
    pub fn simple(algorithm: Algorithm, source: &str) -> Self {
        match algorithm {
            Algorithm::SHA256 => {
                let hasher = Sha256::new();
                Self::hash_simple(hasher, source)
            }
            Algorithm::SHA1 => {
                let hasher = Sha1::new();
                Self::hash_simple(hasher, source)
            }
            Algorithm::SHA224 => {
                let hasher = Sha224::new();
                Self::hash_simple(hasher, source)
            }
            Algorithm::SHA384 => {
                let hasher = Sha384::new();
                Self::hash_simple(hasher, source)
            }
            Algorithm::SHA512 => {
                let hasher = Sha512::new();
                Self::hash_simple(hasher, source)
            }
            Algorithm::MD5 => {
                let hasher = Md5::new();
                Self::hash_simple(hasher, source)
            }
            Algorithm::MD2 => {
                let hasher = Md2::new();
                Self::hash_simple(hasher, source)
            }
        }
    }

    /// 根据指定算法和源字符串及盐构建一个SImpleHash struct
    ///
    /// # Arguments
    /// - `algorithm`: 算法
    /// - `source`: 源字符串
    /// - `salt`: 盐
    ///
    /// # 返回值:
    /// 一个SimpleHash struct
    pub fn with_salt(algorithm: Algorithm, source: &str, salt: &str) -> Self {
        match algorithm {
            Algorithm::SHA256 => {
                let hasher = Sha256::new();
                Self::hash_salt(hasher, source, salt)
            }
            Algorithm::SHA384 => {
                let hasher = Sha384::new();
                Self::hash_salt(hasher, source, salt)
            }
            Algorithm::SHA512 => {
                let hasher = Sha512::new();
                Self::hash_salt(hasher, source, salt)
            }
            Algorithm::SHA224 => {
                let hasher = Sha224::new();
                Self::hash_salt(hasher, source, salt)
            }
            Algorithm::SHA1 => {
                let hasher = Sha1::new();
                Self::hash_salt(hasher, source, salt)
            }
            Algorithm::MD5 => {
                let hasher = Md5::new();
                Self::hash_salt(hasher, source, salt)
            }
            Algorithm::MD2 => {
                let hasher = Md2::new();
                Self::hash_salt(hasher, source, salt)
            }
        }
    }

    /// 根据指定算法和源字符串及盐与迭代次数构建一个SImpleHash struct
    ///
    /// # Arguments
    /// - `algorithm`: 算法
    /// - `source`: 源字符串
    /// - `salt`: 盐
    /// - `times`: 迭代次数
    ///
    /// # 返回值:
    /// 一个SimpleHash struct
    pub fn with_salt_iter(algorithm: Algorithm, source: &str, salt: &str, times: usize) -> Self {
        match algorithm {
            Algorithm::SHA256 => {
                let hasher = Sha256::new();
                Self::hash_salt_iter(hasher, source, salt, times)
            }
            Algorithm::SHA384 => {
                let hasher = Sha384::new();
                Self::hash_salt_iter(hasher, source, salt, times)
            }
            Algorithm::SHA512 => {
                let hasher = Sha512::new();
                Self::hash_salt_iter(hasher, source, salt, times)
            }
            Algorithm::SHA224 => {
                let hasher = Sha224::new();
                Self::hash_salt_iter(hasher, source, salt, times)
            }
            Algorithm::SHA1 => {
                let hasher = Sha1::new();
                Self::hash_salt_iter(hasher, source, salt, times)
            }
            Algorithm::MD2 => {
                let hasher = Md2::new();
                Self::hash_salt_iter(hasher, source, salt, times)
            }
            Algorithm::MD5 => {
                let hasher = Md5::new();
                Self::hash_salt_iter(hasher, source, salt, times)
            }
        }
    }

    fn hash_salt<T>(hasher: T, source: &str, salt: &str) -> Self
    where
        T: Digest + Clone,
    {
        let value = hash_with_salt(hasher, source, salt);
        Self { value }
    }

    fn hash_simple<T>(hasher: T, source: &str) -> Self
    where
        T: Digest + Clone,
    {
        let value = simple_hash(hasher, source);
        Self { value }
    }

    fn hash_salt_iter<T>(hasher: T, source: &str, salt: &str, times: usize) -> Self
    where
        T: Digest + Clone,
    {
        let value = hash_with_salt_iter(hasher, source, salt, times);
        Self { value }
    }
}

pub trait ToBase64 {
    /// 转换为base64字符串
    fn to_base64(&self) -> String;
}

pub trait ToHex {
    /// 转换为16进制字符串
    fn to_hex(&self) -> String;
}

impl ToBase64 for SimpleHash {
    /// 把SimpleHash的内部值转换为base64字符串
    fn to_base64(&self) -> String {
        Base64::encode_string(&self.value)
    }
}

impl ToHex for SimpleHash {
    /// 把SimpleHash的内部值转换为16进制字符串
    fn to_hex(&self) -> String {
        encode(&self.value)
    }
}

impl ToString for SimpleHash {
    fn to_string(&self) -> String {
        self.to_hex()
    }
}
