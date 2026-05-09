use anyhow::{anyhow, Result};
use digest::{Digest, DynDigest};
use indicatif::{ProgressBar, ProgressStyle};
use noncrypto_digests::{Fnv, Xxh32, Xxh3_128, Xxh3_64, Xxh64};
use std::{fs, io::Read, mem, path::Path};

#[derive(Debug)]
pub struct HashResult {
    pub filename: String,
    pub hash: String,
}

fn get_progress_bar(progress: bool, len: u64, path: &Path, min_len: Option<u64>) -> ProgressBar {
    // Set a minimum size of 256MB
    let min_len = min_len.map_or(256 * 1024 * 1024_u64, |x| x);
    if progress && len >= min_len {
        let pb = ProgressBar::new(len);
        pb.set_message(path.display().to_string());
        pb.set_style(ProgressStyle::with_template("{spinner:.blue} {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "));
        pb
    } else {
        ProgressBar::hidden()
    }
}

pub trait DynHasher: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;

    /// Only supported for blake3 with the `mmap` and `rayon` features enabled.
    /// All other hashers return an error by default.
    fn update_mmap_rayon(&mut self, _path: &std::path::Path) -> Result<(), anyhow::Error> {
        Err(anyhow::anyhow!(
            "update_mmap_rayon is only supported for blake3 \
             with the 'mmap' and 'rayon' features enabled"
        ))
    }
}

struct DigestHasher(Box<dyn DynDigest + Send>);

impl DynHasher for DigestHasher {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(&mut self) -> Vec<u8> {
        self.0.finalize_reset().into()
    }
}

struct Blake3Hasher(blake3::Hasher);

impl DynHasher for Blake3Hasher {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(&mut self) -> Vec<u8> {
        let digest = self.0.clone().finalize();
        self.0.reset();
        digest.as_bytes().to_vec()
    }

    fn update_mmap_rayon(&mut self, path: &std::path::Path) -> Result<(), anyhow::Error> {
        self.0.update_mmap_rayon(path)?;
        Ok(())
    }
}

struct NonCryptoHasher<H: Digest + Default + Send>(H);

impl<H: Digest + Default + Send> DynHasher for NonCryptoHasher<H> {
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }
    fn finalize(&mut self) -> Vec<u8> {
        mem::take(&mut self.0).finalize().to_vec()
        //mem::replace(&mut self.0, H::default()).finalize().to_vec()
    }
}

/// A dynamic Hasher struct to handle all supported algorithms
pub struct Hasher {
    /// The hasher object, only used internaly
    hasher: Box<dyn DynHasher>,
}

impl Hasher {
    /// Create a hasher for the given algorithm if it's supported
    /// 
    /// Will raise an error on an unsupported algorithm
    /// 
    /// # Examples
    /// 
    /// ```
    /// use hasher::Hasher;
    /// 
    /// let mut hasher = Hasher::new("blake3").unwrap();
    /// ```
    pub fn new(algo: &str) -> Result<Self> {
        let hasher: Box<dyn DynHasher> = match algo {
            "md5" => Box::new(DigestHasher(Box::new(md5::Md5::new()))),
            "sha1" => Box::new(DigestHasher(Box::new(sha1::Sha1::new()))),
            "sha256" => Box::new(DigestHasher(Box::new(sha2::Sha256::new()))),
            "sha512" => Box::new(DigestHasher(Box::new(sha2::Sha512::new()))),
            "sha3_256" => Box::new(DigestHasher(Box::new(sha3::Sha3_256::new()))),
            "sha3_512" => Box::new(DigestHasher(Box::new(sha3::Sha3_512::new()))),
            "blake2" => Box::new(DigestHasher(Box::new(blake2::Blake2b512::new()))),
            "blake3" => Box::new(Blake3Hasher(blake3::Hasher::new())),
            "fnv" => Box::new(NonCryptoHasher(Fnv::default())),
            "xxh32" => Box::new(NonCryptoHasher(Xxh32::default())),
            "xxh64" => Box::new(NonCryptoHasher(Xxh64::default())),
            "xxh3_64" => Box::new(NonCryptoHasher(Xxh3_64::default())),
            "xxh3_128" => Box::new(NonCryptoHasher(Xxh3_128::default())),
            _ => return Err(anyhow!("Unsupported hash algorithm: {}", algo)),
        };

        Ok(Hasher { hasher })
    }

    /// A low-level way to directly update the internal hasher.
    /// Only use if you know what you're doing!
    /// 
    /// # Examples
    /// 
    /// ```
    /// use hasher::Hasher;
    /// 
    /// let mut hasher = Hasher::new("blake3").unwrap();
    /// hasher.update("Hello, World".as_bytes());
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// A low-level way to directly finalize the internal hasher.
    /// Only use if you know what you're doing!
    /// 
    /// # Examples
    /// 
    /// ```
    /// use hasher::Hasher;
    /// use hex;
    /// 
    /// let mut hasher = Hasher::new("blake3").unwrap();
    /// hasher.update("Hello, World".as_bytes());
    /// let hash = hasher.finalize();
    /// println!("{}", hex::encode(hash));
    /// ```
    pub fn finalize(&mut self) -> Vec<u8> {
        self.hasher.finalize()
    }

    /// High-level way to hash text
    /// 
    /// # Examples
    /// 
    /// ```
    /// use hasher::Hasher;
    /// 
    /// let mut hasher = Hasher::new("blake3").unwrap();
    /// let result = hasher.hash_text(String::from("Hello, World")).unwrap();
    /// 
    /// println!("{}", result);
    /// ```
    pub fn hash_text(&mut self, text: String) -> Result<String> {
        self.update(text.as_bytes());
        Ok(hex::encode(self.finalize()))
    }

    /// An internal way to hash a file with Blake3's mmap and rayon features
    /// 
    /// Not publicly exposed, but accessible if `mmap` is set to `true` on 
    /// `hash_file` or `hash_file_progressbar`
    fn hash_file_mmap(&mut self, path: &Path) -> Result<HashResult> {
        self.hasher.update_mmap_rayon(path)?;
        let hash = self.finalize();
        Ok(HashResult {
            filename: path.display().to_string(),
            hash: hex::encode(hash),
        })
    }

    /// Hash a file with an exposed progress bar. Useful for large files
    /// 
    /// Hashes a `path`, optionally showing `progress`. Allows you to use
    /// the Blake3 `mmap` feature as well.
    /// 
    /// If the Hasher's algorithm does not support `mmap` (only blake3 supports `mmap`), 
    /// it will quietly fall back to not using it
    /// 
    /// If `min_len` is specified, a progress bar will not display unless the file
    /// is larger than `min_len` bytes, default 256MB 
    /// 
    /// # Examples
    /// 
    /// ```
    /// use hasher::Hasher;
    /// 
    /// // We'll use SHA256 this time
    /// let mut hasher = Hasher::new("sha256").unwrap();
    /// let result = hasher.hash_file_progressbar(Path::from("path/to/large/file"), true, true, None).unwrap();
    /// 
    /// println!("{}", result.hash);
    /// ```
    pub fn hash_file_progressbar(
        &mut self,
        path: &Path,
        progress: bool,
        mmap: bool,
        min_len: Option<u64>,
    ) -> Result<HashResult> {
        if mmap {
            if let Ok(result) = self.hash_file_mmap(path) {
                return Ok(result);
            }
        }
        let mut file = fs::File::open(path)?;
        let mut buf = [0u8; 8192];

        let pb = get_progress_bar(progress, file.metadata()?.len(), path, min_len);

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            pb.inc(n as u64);
            self.update(&buf[..n]);
        }
        pb.finish_and_clear();
        let hash = self.finalize();
        Ok(HashResult {
            filename: path.display().to_string(),
            hash: hex::encode(hash),
        })
    }

   /// Hash a file with an exposed progress bar. Useful for large files
    /// 
    /// Hashes a `path`. Allows you to use the Blake3 `mmap` feature as well.
    /// 
    /// If the Hasher's algorithm does not support `mmap` (only blake3 supports `mmap`), 
    /// it will quietly fall back to not using it
    /// 
    /// # Examples
    /// 
    /// ```
    /// use hasher::Hasher;
    /// 
    /// // We'll use SHA256 this time
    /// let mut hasher = Hasher::new("sha256").unwrap();
    /// let result = hasher.hash_file(Path::from("path/to/large/file"), true).unwrap();
    /// 
    /// println!("{}", result.hash);
    /// ```
    pub fn hash_file(&mut self, path: &Path, mmap: bool) -> Result<HashResult> {
        if mmap {
            if let Ok(result) = self.hash_file_mmap(path) {
                return Ok(result);
            }
        }
        let mut file = fs::File::open(path)?;
        let mut buf = [0u8; 8192];

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.update(&buf[..n]);
        }
        let hash = self.finalize();
        Ok(HashResult {
            filename: path.display().to_string(),
            hash: hex::encode(hash),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, path::PathBuf};

    static TEST_ALGOS: &[&str] = &[
        "blake3", "md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512", "blake2", "xxh3_128",
        "xxh3_64", "xxh64", "xxh32", "fnv",
    ];
    static VALUES: &[&str] = &[
        "68569ddf344009b938e1db0ec39b151b1626cfe46a87c3910dc18936a233f92b",
        "0cbc6611f5540bd0809a388dc95a615b",
        "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
        "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
        "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31",
        "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0",
        "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7",
        "3d896914f86ae22c48b06140adb4492fa3f8e2686a83cec0c8b1dcd6903168751370078bbd6bbfe02a6ab1df12a19b5991b58e65e243ec279f6a5770b2dd0e31",
        "391c8305c491690bc2da658a2d6348d5",
        "b3f5bb77a55fad5e",
        "da83efc38a8922b4",
        "eac53571",
        "2474e7fb1aec9f05",
    ];

    #[test]
    fn test_hash_file() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests/test.txt");
        for i in 0..TEST_ALGOS.len() {
            let algorithm = TEST_ALGOS[i];
            let mut hasher = Hasher::new(&algorithm).unwrap();
            let result = hasher.hash_file(&file, false).unwrap();
            assert_eq!(result.hash.clone(), String::from(VALUES[i]));
        }
    }

    #[test]
    fn test_hash_file_mmap() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests/test.txt");
        let mut hasher = Hasher::new(TEST_ALGOS[0]).unwrap();
        let result = hasher.hash_file(&file, true).unwrap();
        assert_eq!(result.hash.clone(), String::from(VALUES[0]));
    }

    #[test]
    fn test_hash_file_progressbar() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests/test.txt");
        let mut hasher = Hasher::new(TEST_ALGOS[0]).unwrap();
        let result = hasher
            .hash_file_progressbar(&file, true, false, Some(1))
            .unwrap();
        assert_eq!(result.hash.clone(), String::from(VALUES[0]));
        let result = hasher
            .hash_file_progressbar(&file, false, false, Some(1))
            .unwrap();
        assert_eq!(result.hash.clone(), String::from(VALUES[0]));
    }
}
