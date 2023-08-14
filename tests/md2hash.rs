#[cfg(test)]
mod test {
    use shiro::{hash::MD2Hash, simple_hash::ToBase64};
    #[test]
    fn simple_test() {
        let result = MD2Hash::simple("admin");
        assert_eq!(result.to_base64(), "Pj5rDlwcaGRPxc488GAhHQ==");
        assert_eq!(result.to_string(), "3e3e6b0e5c1c68644fc5ce3cf060211d");
    }

    #[test]
    fn with_salt_test() {
        let result = MD2Hash::with_salt("admin", "123456");
        assert_eq!(result.to_base64(), "v5MnwENvA9gjMwTsWIclzw==");
        assert_eq!(result.to_string(), "bf9327c0436f03d8233304ec588725cf");
    }

    #[test]
    fn with_salt_iter_test() {
        let result = MD2Hash::with_salt_iter("admin", "123456", 100);
        assert_eq!(result.to_base64(), "pQE+9ZSvzv18M6KXg127ow==");
        assert_eq!(result.to_string(), "a5013ef594afcefd7c33a297835dbba3");
    }
}
