use base64ct::Base64;
use base64ct::Encoding;
use hex::encode;
use sha2::Digest;
use sha2::Sha256;

pub enum Algorithm {
    SHA256,
}

pub struct SimpleHash {
    value: Vec<u8>,
}

impl SimpleHash {
    pub fn simple(algorithm: Algorithm, source: &str) -> Self {
        match algorithm {
            Algorithm::SHA256 => {
                let mut hasher = Sha256::new();
                hasher.update(source);
                let result = hasher.finalize();
                let value = result.as_slice().to_vec();
                Self { value }
            }
        }
    }
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
        }
    }

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
        }
    }

    pub fn to_hex(&self) -> String {
        encode(&self.value)
    }

    pub fn to_base64(&self) -> String {
        Base64::encode_string(&self.value)
    }
}

impl ToString for SimpleHash {
    fn to_string(&self) -> String {
        self.to_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::SHA256, source).to_hex();
        assert_eq!(
            result,
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
        );
        let result = SimpleHash::simple(Algorithm::SHA256, source).to_base64();
        assert_eq!(result, "jGl25bVBBBW96Qi9Te4V37Fnqchz/Eu4qB9vKrRIqRg=")
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::SHA256, source, salt).to_hex();
        assert_eq!(
            result,
            "2daceebc4e31654d326ae7889b397ed50ff7e5afff374d1f89525865fd87efe0"
        );
        let result = SimpleHash::with_salt(Algorithm::SHA256, source, salt).to_base64();
        assert_eq!(result, "LazuvE4xZU0yaueImzl+1Q/35a//N00fiVJYZf2H7+A=");
    }

    #[test]
    fn simple_hash_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt_iter(Algorithm::SHA256, source, salt, 10).to_hex();
        assert_eq!(
            result,
            "85c12dfa9332d0d096d78f1d93ea032a84489120d83a6b5d7ac4f968e65fc158"
        );
        let result = SimpleHash::with_salt_iter(Algorithm::SHA256, source, salt, 10).to_base64();
        assert_eq!(result, "hcEt+pMy0NCW148dk+oDKoRIkSDYOmtdesT5aOZfwVg=")
    }

    #[test]
    fn simple_hash_salt_iter_test1() {
        let source = "admin";
        let salt = "admin";
        let result = SimpleHash::with_salt_iter(Algorithm::SHA256, source, salt, 16).to_string();
        assert_eq!(
            result,
            "bf9e46e9b962c6b425f0685626cd64bb45febfac300c4b0322d0586954c20a26"
        );
        let result = SimpleHash::with_salt_iter(Algorithm::SHA256, source, salt, 16).to_base64();
        assert_eq!(result, "v55G6blixrQl8GhWJs1ku0X+v6wwDEsDItBYaVTCCiY=")
    }
}
