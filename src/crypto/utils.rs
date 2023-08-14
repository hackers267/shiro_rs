use sha2::Digest;

pub(crate) fn hash<T>(
    mut hasher: T,
    source: &str,
    salt: Option<&str>,
    times: Option<usize>,
) -> Vec<u8>
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
