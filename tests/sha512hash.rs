#[cfg(test)]
mod test {
    use shiro::hash::{FromBase64, FromHex, Sha512Hash, ToBase64};

    #[test]
    fn simple_test() {
        let source = "admin";
        let result = Sha512Hash::simple(source);
        assert_eq!(result.to_base64(), "x61Ey612Kl2gpFL56FT9weDnpSo4AV8j8+qx2AuTHdRyY036xxzTTrw10Wq3+4qQyB+XURPWx1ONxp3Y3pB37A==");
        assert_eq!(result.to_string(), "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec");
    }

    #[test]
    fn with_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = Sha512Hash::with_salt(source, salt);
        assert_eq!(result.to_base64(), "+uDoT023KRtRizt9nfGTKwI11k9BjJSdk7Gp+6s1tm4kMGnA0ZgjCGZh79MhODCl+JHm2sXFOm12OLdo+z8omw==");
        assert_eq!(result.to_string(), "fae0e84f4db7291b518b3b7d9df1932b0235d64f418c949d93b1a9fbab35b66e243069c0d19823086661efd3213830a5f891e6dac5c53a6d7638b768fb3f289b");
    }

    #[test]
    fn with_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = Sha512Hash::with_salt_iter(source, salt, 100);
        assert_eq!(result.to_base64(), "EWotkCyNyRkV0suW7Ji5EKn5pZO3VgK2NJTkFYW99EC+x2QKwDf86+II99q/OgG6lzl4gmbnbxjeOxTg0FcE2g==");
        assert_eq!(result.to_string(), "116a2d902c8dc91915d2cb96ec98b910a9f9a593b75602b63494e41585bdf440bec7640ac037fcebe208f7dabf3a01ba9739788266e76f18de3b14e0d05704da");
    }

    #[test]
    fn from_base64_test() {
        let result = Sha512Hash::from_base64("hzAQIJH2WhwLVNu3eM1KWnl7wzM=");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().to_string(),
            "8730102091f65a1c0b54dbb778cd4a5a797bc333"
        );
        let result = Sha512Hash::from_base64("hzAQIJH2WhwLVNu3eM1KWnl7wzM");
        assert!(result.is_err())
    }

    #[test]
    fn from_hex_test() {
        let result = Sha512Hash::from_hex("8730102091f65a1c0b54dbb778cd4a5a797bc333");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_base64(), "hzAQIJH2WhwLVNu3eM1KWnl7wzM=");
        let result = Sha512Hash::from_hex("hzAQIJH2WhwLVNu3eM1KWnl7wzM");
        assert!(result.is_err())
    }
}
