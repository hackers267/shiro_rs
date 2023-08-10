use base64ct::Base64;
use base64ct::Encoding;
use hex::encode;
use md2::Md2;
use md5::Context;
use sha1::Sha1;
use sha2::Digest;
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha384;

/// TODO: 添加以下算法支持：
/// - [x] MD2
/// - [x] MD5
/// - [x] SHA1
/// - [x] SHA-224
/// - [x] SHA-256
/// - [x] SHA-384
/// - [ ] SHA-512
pub enum Algorithm {
    MD2,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
}

/// 简单哈希算法,支持以下算法：
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
                let mut hasher = Sha256::new();
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::SHA1 => {
                let mut hasher = Sha1::new();
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::SHA224 => {
                let mut hasher = Sha224::new();
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::SHA384 => {
                let mut hasher = Sha384::new();
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::MD5 => {
                let result = md5::compute(source);
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::MD2 => {
                let mut hasher = Md2::new();
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
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
                let mut hasher = Sha256::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::SHA384 => {
                let mut hasher = Sha384::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::SHA224 => {
                let mut hasher = Sha224::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::SHA1 => {
                let mut hasher = Sha1::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::MD5 => {
                let mut context = Context::new();
                context.consume(salt);
                context.consume(source);
                let result = context.compute();
                let value = result.as_slice().to_vec();
                Self { value }
            }
            Algorithm::MD2 => {
                let mut hasher = Md2::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
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
                let mut hasher = Sha256::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let mut hashed = hasher.finalize();
                let range = 1..times;
                for _i in range {
                    let mut hasher = Sha256::new();
                    hasher.reset();
                    hasher.update(hashed);
                    hashed = hasher.finalize();
                }
                let value = hashed.as_slice().to_vec();
                Self { value }
            }
            Algorithm::SHA384 => {
                let mut hasher = Sha384::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let mut hashed = hasher.finalize();
                let range = 1..times;
                for _i in range {
                    let mut hasher = Sha384::new();
                    hasher.reset();
                    hasher.update(hashed);
                    hashed = hasher.finalize();
                }
                let value = hashed.as_slice().to_vec();
                Self { value }
            }
            Algorithm::SHA224 => {
                let mut hasher = Sha224::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let mut hashed = hasher.finalize();
                let range = 1..times;
                for _i in range {
                    let mut hasher = Sha224::new();
                    hasher.reset();
                    hasher.update(hashed);
                    hashed = hasher.finalize();
                }
                let value = hashed.as_slice().to_vec();
                Self { value }
            }
            Algorithm::SHA1 => {
                let mut hasher = Sha1::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let mut hashed = hasher.finalize();
                let range = 1..times;
                for _i in range {
                    let mut hasher = Sha1::new();
                    hasher.reset();
                    hasher.update(hashed);
                    hashed = hasher.finalize();
                }
                let value = hashed.as_slice().to_vec();
                Self { value }
            }
            Algorithm::MD2 => {
                let mut hasher = Md2::new();
                hasher.reset();
                hasher.update(salt);
                hasher.update(source);
                let mut hashed = hasher.finalize();
                let range = 1..times;
                for _i in range {
                    let mut hasher = Md2::new();
                    hasher.reset();
                    hasher.update(hashed);
                    hashed = hasher.finalize();
                }
                let value = hashed.as_slice().to_vec();
                Self { value }
            }
            Algorithm::MD5 => {
                let mut context = Context::new();
                context.consume(salt);
                context.consume(source);
                let mut hashed = context.compute();
                let range = 1..times;
                for _i in range {
                    let mut context = Context::new();
                    context.consume(hashed.as_slice());
                    hashed = context.compute();
                }
                let value = hashed.to_vec();
                Self { value }
            }
        }
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
