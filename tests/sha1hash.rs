#[cfg(test)]
mod test {
    use shiro::hash::{FromBase64, FromHex, Sha1Hash, ToBase64};

    #[test]
    fn simple_test() {
        let source = "admin";
        let result = Sha1Hash::simple(source);
        assert_eq!(result.to_base64(), "0DPiKuNIrrVmD8IUCuw1hQxNqZc=");
        assert_eq!(
            result.to_string(),
            "d033e22ae348aeb5660fc2140aec35850c4da997"
        );
    }

    #[test]
    fn with_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = Sha1Hash::with_salt(source, salt);
        assert_eq!(result.to_base64(), "IjznuFESM1NHnYV1f7v04yDR4lE=");
        assert_eq!(
            result.to_string(),
            "223ce7b851123353479d85757fbbf4e320d1e251"
        );
    }

    #[test]
    fn with_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = Sha1Hash::with_salt_iter(source, salt, 100);
        assert_eq!(result.to_base64(), "hzAQIJH2WhwLVNu3eM1KWnl7wzM=");
        assert_eq!(
            result.to_string(),
            "8730102091f65a1c0b54dbb778cd4a5a797bc333"
        );
    }

    #[test]
    fn from_base64_test() {
        let result = Sha1Hash::from_base64("hzAQIJH2WhwLVNu3eM1KWnl7wzM=");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().to_string(),
            "8730102091f65a1c0b54dbb778cd4a5a797bc333"
        );
        let result = Sha1Hash::from_base64("hzAQIJH2WhwLVNu3eM1KWnl7wzM");
        assert!(result.is_err())
    }

    #[test]
    fn from_hex_test() {
        let result = Sha1Hash::from_hex("8730102091f65a1c0b54dbb778cd4a5a797bc333");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_base64(), "hzAQIJH2WhwLVNu3eM1KWnl7wzM=");
        let result = Sha1Hash::from_hex("hzAQIJH2WhwLVNu3eM1KWnl7wzM");
        assert!(result.is_err())
    }
}
