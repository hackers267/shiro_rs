#[cfg(test)]
mod sha256_test {
    use shiro::hash::ToBase64;
    use shiro::simple_hash::{Algorithm, SimpleHash};
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
    use shiro::hash::ToBase64;
    use shiro::simple_hash::{Algorithm, SimpleHash};

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

#[cfg(test)]
mod md5_test {
    use shiro::hash::ToBase64;
    use shiro::simple_hash::{Algorithm, SimpleHash};

    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::MD5, source).to_string();
        assert_eq!(result, "21232f297a57a5a743894a0e4a801fc3");
        let result = SimpleHash::simple(Algorithm::MD5, source).to_base64();
        assert_eq!(result, "ISMvKXpXpadDiUoOSoAfww==")
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::MD5, source, salt).to_string();
        assert_eq!(result, "b9d11b3be25f5a1a7dc8ca04cd310b28");
        let result = SimpleHash::with_salt(Algorithm::MD5, source, salt).to_base64();
        assert_eq!(result, "udEbO+JfWhp9yMoEzTELKA==");
    }

    #[test]
    fn simple_hash_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt_iter(Algorithm::MD5, source, salt, 10).to_string();
        assert_eq!(result, "c2e27b84e96213b20c4a59b40286868b");
        let result = SimpleHash::with_salt_iter(Algorithm::MD5, source, salt, 10).to_base64();
        assert_eq!(result, "wuJ7hOliE7IMSlm0AoaGiw==");
    }
}

#[cfg(test)]
mod md2_test {
    use shiro::hash::ToBase64;
    use shiro::simple_hash::{Algorithm, SimpleHash};

    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::MD2, source).to_string();
        assert_eq!(result, "3e3e6b0e5c1c68644fc5ce3cf060211d");
        let result = SimpleHash::simple(Algorithm::MD2, source).to_base64();
        assert_eq!(result, "Pj5rDlwcaGRPxc488GAhHQ==");
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::MD2, source, salt).to_string();
        assert_eq!(result, "bf9327c0436f03d8233304ec588725cf");
        let result = SimpleHash::with_salt(Algorithm::MD2, source, salt).to_base64();
        assert_eq!(result, "v5MnwENvA9gjMwTsWIclzw==");
    }

    #[test]
    fn simple_hash_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt_iter(Algorithm::MD2, source, salt, 10).to_string();
        assert_eq!(result, "0ca3668884ab55d127f479fc1655e576");
        let result = SimpleHash::with_salt_iter(Algorithm::MD2, source, salt, 10).to_base64();
        assert_eq!(result, "DKNmiISrVdEn9Hn8FlXldg==");
    }
}
#[cfg(test)]
mod sha224_test {
    use shiro::hash::ToBase64;
    use shiro::simple_hash::{Algorithm, SimpleHash};

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

#[cfg(test)]
mod sha384_test {
    use shiro::hash::ToBase64;
    use shiro::simple_hash::{Algorithm, SimpleHash};

    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::SHA384, source).to_string();
        assert_eq!(result, "9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782");
        let result = SimpleHash::simple(Algorithm::SHA384, source).to_base64();
        assert_eq!(
            result,
            "nKaUqQKFwDRDLJVQQht7nb1cD0tmc/BfbbzlgFK6IOQkgEGVbujJouyfECkM3AeC"
        );
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::SHA384, source, salt).to_string();
        assert_eq!(result, "8f2864bd3d3a32012e41c7f5543f39677d34f287be064eea24b215212fe4ae2660b10a768edf451ca61f484506d34696");
        let result = SimpleHash::with_salt(Algorithm::SHA384, source, salt).to_base64();
        assert_eq!(
            result,
            "jyhkvT06MgEuQcf1VD85Z3008oe+Bk7qJLIVIS/kriZgsQp2jt9FHKYfSEUG00aW"
        );
    }

    #[test]
    fn simple_hash_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt_iter(Algorithm::SHA384, source, salt, 10).to_string();
        assert_eq!(result, "6b3e41ddaaebb0a85bf0ed0f33e22d42cf2044da72595c243f958eafb11929329b7778c67d71216a258ac9df10946412");
        let result = SimpleHash::with_salt_iter(Algorithm::SHA384, source, salt, 10).to_base64();
        assert_eq!(
            result,
            "az5B3arrsKhb8O0PM+ItQs8gRNpyWVwkP5WOr7EZKTKbd3jGfXEhaiWKyd8QlGQS"
        );
    }
}

#[cfg(test)]
mod sha512_test {
    use shiro::hash::ToBase64;
    use shiro::simple_hash::{Algorithm, SimpleHash};

    #[test]
    fn simple_hash_test() {
        let source = "admin";
        let result = SimpleHash::simple(Algorithm::SHA512, source).to_string();
        assert_eq!(result, "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec");
        let result = SimpleHash::simple(Algorithm::SHA512, source).to_base64();
        assert_eq!(result, "x61Ey612Kl2gpFL56FT9weDnpSo4AV8j8+qx2AuTHdRyY036xxzTTrw10Wq3+4qQyB+XURPWx1ONxp3Y3pB37A==");
    }

    #[test]
    fn simple_hash_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt(Algorithm::SHA512, source, salt).to_string();
        assert_eq!(result, "fae0e84f4db7291b518b3b7d9df1932b0235d64f418c949d93b1a9fbab35b66e243069c0d19823086661efd3213830a5f891e6dac5c53a6d7638b768fb3f289b");
        let result = SimpleHash::with_salt(Algorithm::SHA512, source, salt).to_base64();
        assert_eq!(result, "+uDoT023KRtRizt9nfGTKwI11k9BjJSdk7Gp+6s1tm4kMGnA0ZgjCGZh79MhODCl+JHm2sXFOm12OLdo+z8omw==");
    }

    #[test]
    fn simple_hash_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = SimpleHash::with_salt_iter(Algorithm::SHA512, source, salt, 10).to_string();
        assert_eq!(result, "1208cd7444c810f2c96f58e412e69b492a4c2878480a942543ab92241eb61bd2e8c5eca968a43298e3ccd016d3e96c4c9d7d9b5b16a06608fa431eee30914319");
        let result = SimpleHash::with_salt_iter(Algorithm::SHA512, source, salt, 10).to_base64();
        assert_eq!(result, "EgjNdETIEPLJb1jkEuabSSpMKHhICpQlQ6uSJB62G9LoxeypaKQymOPM0BbT6WxMnX2bWxagZgj6Qx7uMJFDGQ==");
    }
}
