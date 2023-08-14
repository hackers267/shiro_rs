pub trait FromBase64 {
    /// 从base64字符串转换
    fn from_base64(source: &str) -> Result<Self, base64ct::Error>
    where
        Self: Sized;
}

pub trait FromHex {
    /// 从16进制字符串转换
    fn from_hex(source: &str) -> Result<Self, hex::FromHexError>
    where
        Self: Sized;
}

pub trait ToBase64 {
    /// 转换为base64字符串
    fn to_base64(&self) -> String;
}

pub trait ToHex {
    /// 转换为16进制字符串
    fn to_hex(&self) -> String;
}
