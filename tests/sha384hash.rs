#[cfg(test)]
mod test {
    use shiro::hash::{FromBase64, FromHex, Sha384Hash, ToBase64};

    #[test]
    fn simple_test() {
        let source = "admin";
        let result = Sha384Hash::simple(source);
        assert_eq!(
            result.to_base64(),
            "nKaUqQKFwDRDLJVQQht7nb1cD0tmc/BfbbzlgFK6IOQkgEGVbujJouyfECkM3AeC"
        );
        assert_eq!(result.to_string(), "9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782");
    }

    #[test]
    fn with_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result =Sha384Hash::with_salt(source, salt);
        assert_eq!(
            result.to_base64(),
            "jyhkvT06MgEuQcf1VD85Z3008oe+Bk7qJLIVIS/kriZgsQp2jt9FHKYfSEUG00aW"
        );
        assert_eq!(result.to_string(), "8f2864bd3d3a32012e41c7f5543f39677d34f287be064eea24b215212fe4ae2660b10a768edf451ca61f484506d34696");
    }

    #[test]
    fn with_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = Sha384Hash::with_salt_iter(source, salt, 100);
        assert_eq!(
            result.to_base64(),
            "LdpBpr50oqNuQfKjKTPllVO39brngLsmocUubBxlv652pPAy9XNJgU3c5m2uc6id"
        );
        assert_eq!(result.to_string(), "2dda41a6be74a2a36e41f2a32933e59553b7f5bae780bb26a1c52e6c1c65bfae76a4f032f57349814ddce66dae73a89d");
    }

    #[test]
    fn from_base64_test() {
        let result = Sha384Hash::from_base64("hzAQIJH2WhwLVNu3eM1KWnl7wzM=");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().to_string(),
            "8730102091f65a1c0b54dbb778cd4a5a797bc333"
        );
        let result = Sha384Hash::from_base64("hzAQIJH2WhwLVNu3eM1KWnl7wzM");
        assert!(result.is_err())
    }

    #[test]
    fn from_hex_test() {
        let result = Sha384Hash::from_hex("8730102091f65a1c0b54dbb778cd4a5a797bc333");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_base64(), "hzAQIJH2WhwLVNu3eM1KWnl7wzM=");
        let result = Sha384Hash::from_hex("hzAQIJH2WhwLVNu3eM1KWnl7wzM");
        assert!(result.is_err())
    }
}
