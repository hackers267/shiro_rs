#[cfg(test)]
mod sha256_test {
    use shiro::simple_hash::{Algorithm, SimpleHash, ToBase64};
    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::SHA256, source).to_string();
        assert_eq!(
            result,
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
        );
        let result = SimpleHash::simple(Algorithm::SHA256, source).to_base64();
        assert_eq!(result, "jGl25bVBBBW96Qi9Te4V37Fnqchz/Eu4qB9vKrRIqRg=");
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::SHA256, source, salt).to_string();
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
        let result = SimpleHash::with_salt_iter(Algorithm::SHA256, source, salt, 10).to_string();
        assert_eq!(
            result,
            "85c12dfa9332d0d096d78f1d93ea032a84489120d83a6b5d7ac4f968e65fc158"
        );
        let result = SimpleHash::with_salt_iter(Algorithm::SHA256, source, salt, 10).to_base64();
        assert_eq!(result, "hcEt+pMy0NCW148dk+oDKoRIkSDYOmtdesT5aOZfwVg=");
    }
}

#[cfg(test)]
mod sha1_test {
    use shiro::simple_hash::{Algorithm, SimpleHash, ToBase64};

    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::SHA1, source).to_string();
        assert_eq!(result, "d033e22ae348aeb5660fc2140aec35850c4da997");
        let result = SimpleHash::simple(Algorithm::SHA1, source).to_base64();
        assert_eq!(result, "0DPiKuNIrrVmD8IUCuw1hQxNqZc=");
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::SHA1, source, salt).to_string();
        assert_eq!(result, "223ce7b851123353479d85757fbbf4e320d1e251");
        let result = SimpleHash::with_salt(Algorithm::SHA1, source, salt).to_base64();
        assert_eq!(result, "IjznuFESM1NHnYV1f7v04yDR4lE=");
    }

    #[test]
    fn simple_hash_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt_iter(Algorithm::SHA1, source, salt, 10).to_string();
        assert_eq!(result, "b8b8921827b021bdad0f5ded29c5b7404e1156d3");
        let result = SimpleHash::with_salt_iter(Algorithm::SHA1, source, salt, 10).to_base64();
        assert_eq!(result, "uLiSGCewIb2tD13tKcW3QE4RVtM=");
    }
}

/// TODO: 添加to_base64测试
#[cfg(test)]
mod md5_test {
    use shiro::simple_hash::{Algorithm, SimpleHash};

    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::MD5, source).to_string();
        assert_eq!(result, "21232f297a57a5a743894a0e4a801fc3");
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::MD5, source, salt).to_string();
        assert_eq!(result, "b9d11b3be25f5a1a7dc8ca04cd310b28");
    }

    #[test]
    fn simple_hash_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt_iter(Algorithm::MD5, source, salt, 10).to_string();
        assert_eq!(result, "c2e27b84e96213b20c4a59b40286868b")
    }
}

/// TODO: 添加to_base64测试
#[cfg(test)]
mod md2_test {
    use shiro::simple_hash::{Algorithm, SimpleHash};

    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::MD2, source).to_string();
        assert_eq!(result, "3e3e6b0e5c1c68644fc5ce3cf060211d");
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::MD2, source, salt).to_string();
        assert_eq!(result, "bf9327c0436f03d8233304ec588725cf");
    }

    #[test]
    fn simple_hash_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt_iter(Algorithm::MD2, source, salt, 10).to_string();
        assert_eq!(result, "0ca3668884ab55d127f479fc1655e576")
    }
}
#[cfg(test)]
mod sha224_test {
    use shiro::simple_hash::{Algorithm, SimpleHash, ToBase64};

    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::SHA224, source).to_string();
        assert_eq!(
            result,
            "58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
        );
        let result = SimpleHash::simple(Algorithm::SHA224, source).to_base64();
        assert_eq!(result, "WKy3rMzOWP+ouVOxK1p3Ar1C2uRBwa2FBX+nCw==");
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::SHA224, source, salt).to_string();
        assert_eq!(
            result,
            "fe97fa4a3e2a76d1ff2ac0429d269eb8b3a9a297386c4779d4c36dc6"
        );
        let result = SimpleHash::with_salt(Algorithm::SHA224, source, salt).to_base64();
        assert_eq!(result, "/pf6Sj4qdtH/KsBCnSaeuLOpopc4bEd51MNtxg==");
    }

    #[test]
    fn simple_hash_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt_iter(Algorithm::SHA224, source, salt, 10).to_string();
        assert_eq!(
            result,
            "f4bbe2fd0294d10f70d78689599a25b34d972667823a01d2a24a35ac"
        );
        let result = SimpleHash::with_salt_iter(Algorithm::SHA224, source, salt, 10).to_base64();
        assert_eq!(result, "9Lvi/QKU0Q9w14aJWZols02XJmeCOgHSoko1rA==")
    }
}
