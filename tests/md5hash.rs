#[cfg(test)]
mod test {
    use shiro::{
        hash::MD5Hash,
        hash::{FromBase64, FromHex, ToBase64},
    };
    #[test]
    fn simple_test() {
        let result = MD5Hash::simple("admin");
        assert_eq!(result.to_base64(), "ISMvKXpXpadDiUoOSoAfww==");
        assert_eq!(result.to_string(), "21232f297a57a5a743894a0e4a801fc3");
    }

    #[test]
    fn with_salt_test() {
        let result = MD5Hash::with_salt("admin", "123456");
        assert_eq!(result.to_base64(), "udEbO+JfWhp9yMoEzTELKA==");
        assert_eq!(result.to_string(), "b9d11b3be25f5a1a7dc8ca04cd310b28");
    }

    #[test]
    fn with_salt_iter_test() {
        let result = MD5Hash::with_salt_iter("admin", "123456", 100);
        assert_eq!(result.to_base64(), "eQsyXnPdEbuw4wnN2M/eHw==");
        assert_eq!(result.to_string(), "790b325e73dd11bbb0e309cdd8cfde1f");
    }

    #[test]
    fn from_base64_test() {
        let result = MD5Hash::from_base64("ISMvKXpXpadDiUoOSoAfww==");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().to_string(),
            "21232f297a57a5a743894a0e4a801fc3"
        );
        let result = MD5Hash::from_base64("udEbO+JfWhp9yMoEzTELKA=");
        assert!(result.is_err())
    }

    #[test]
    fn from_hex_test() {
        let result = MD5Hash::from_hex("21232f297a57a5a743894a0e4a801fc3");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_base64(), "ISMvKXpXpadDiUoOSoAfww==");
        let result = MD5Hash::from_hex("udEbO+JfWhp9yMoEzTELKA=");
        assert!(result.is_err())
    }
}
