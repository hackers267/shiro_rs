#[cfg(test)]
mod test {
    use shiro::hash::{FromBase64, FromHex, Sha256Hash, ToBase64};

    #[test]
    fn simple_test() {
        let source = "admin";
        let result = Sha256Hash::simple(source);
        assert_eq!(
            result.to_base64(),
            "jGl25bVBBBW96Qi9Te4V37Fnqchz/Eu4qB9vKrRIqRg="
        );
        assert_eq!(
            result.to_string(),
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
        );
    }

    #[test]
    fn with_salt_test() {
        let source = "admin";
        let salt = "123456";
        let result = Sha256Hash::with_salt(source, salt);
        assert_eq!(
            result.to_base64(),
            "LazuvE4xZU0yaueImzl+1Q/35a//N00fiVJYZf2H7+A="
        );
        assert_eq!(
            result.to_string(),
            "2daceebc4e31654d326ae7889b397ed50ff7e5afff374d1f89525865fd87efe0"
        );
    }

    #[test]
    fn with_salt_iter_test() {
        let source = "admin";
        let salt = "123456";
        let result = Sha256Hash::with_salt_iter(source, salt, 100);
        assert_eq!(
            result.to_base64(),
            "GCj4QbrCYACweIZOj55BM/NgwS4JvUBIBno+y5/vbyc="
        );
        assert_eq!(
            result.to_string(),
            "1828f841bac26000b078864e8f9e4133f360c12e09bd4048067a3ecb9fef6f27"
        );
    }

    #[test]
    fn from_base64_test() {
        let result = Sha256Hash::from_base64("hzAQIJH2WhwLVNu3eM1KWnl7wzM=");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().to_string(),
            "8730102091f65a1c0b54dbb778cd4a5a797bc333"
        );
        let result = Sha256Hash::from_base64("hzAQIJH2WhwLVNu3eM1KWnl7wzM");
        assert!(result.is_err())
    }

    #[test]
    fn from_hex_test() {
        let result = Sha256Hash::from_hex("8730102091f65a1c0b54dbb778cd4a5a797bc333");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_base64(), "hzAQIJH2WhwLVNu3eM1KWnl7wzM=");
        let result = Sha256Hash::from_hex("hzAQIJH2WhwLVNu3eM1KWnl7wzM");
        assert!(result.is_err())
    }
}
