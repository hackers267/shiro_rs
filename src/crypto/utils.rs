use sha2::Digest;

fn hash<T>(mut hasher: T, source: &str, salt: Option<&str>, times: Option<usize>) -> Vec<u8>
where
    T: Digest + Clone,
{
    let hasher_bak = hasher.clone();
    if let Some(salt) = salt {
        hasher.update(salt);
    }
    hasher.update(source);
    let mut hashed = hasher.finalize();
    let times = times.unwrap_or(1);
    let range = 1..times;
    for _i in range {
        let mut hasher = hasher_bak.clone();
        hasher.update(hashed);
        hashed = hasher.finalize();
    }
    hashed.to_vec()
}

pub(crate) fn simple_hash<T>(hasher: T, source: &str) -> Vec<u8>
where
    T: Digest + Clone,
{
    hash(hasher, source, None, None)
}

pub(crate) fn hash_with_salt<T>(hahser: T, source: &str, salt: &str) -> Vec<u8>
where
    T: Digest + Clone,
{
    hash(hahser, source, Some(salt), None)
}

pub(crate) fn hash_with_salt_iter<T>(hasher: T, source: &str, salt: &str, times: usize) -> Vec<u8>
where
    T: Digest + Clone,
{
    hash(hasher, source, Some(salt), Some(times))
}
