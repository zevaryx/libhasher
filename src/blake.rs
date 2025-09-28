use anyhow::Result;
use colored::Colorize;
use digest::Digest;
use indicatif::ProgressStyle;
use std::{
    fs,
    io::{self, BufRead, Read},
    path::Path,
};

use crate::{bytes_to_hash, get_progress_bar, CheckResult, HashResult};

pub fn check(path: &Path, method: &str, mmap: bool, progress: bool) -> Result<CheckResult> {
    let file = fs::File::open(path)?;
    let lines = io::BufReader::new(file).lines();
    let mut total = 0;
    let mut mismatch: u64 = 0;
    let mut read_fail: u64 = 0;
    let mut hash_fail: u64 = 0;
    let mut invalid: u64 = 0;

    for line in lines.map_while(Result::ok) {
        if let [hash, filename, ..] =
            &line.split("  ").map(String::from).collect::<Vec<String>>()[..]
        {
            total += 1;
            print!("{}: ", filename.bright_cyan());
            match hash_file(Path::new(filename), method, mmap, progress) {
                Ok(result) => match result.hash {
                    Some(h) => {
                        if h.eq(hash) {
                            println!("{}", "OK".bright_green());
                        } else if h.len() != hash.len() {
                            println!("{}", "INVALID".bright_red());
                            total -= 1;
                            invalid += 1;
                        } else {
                            println!("{}", "FAILED".bright_red());
                            mismatch += 1;
                        }
                    }
                    None => {
                        println!("{}", "READ_FAIL".bright_red());
                        read_fail += 1;
                    }
                },
                Err(_) => {
                    println!("{}", "HASH_FAIL".bright_red());
                    hash_fail += 1;
                }
            }
        }
    }

    let result = CheckResult {
        total,
        mismatch,
        read_fail,
        hash_fail,
        invalid,
    };

    Ok(result)
}

fn hash_file_blake2(path: &Path, progress: bool) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = blake2::Blake2b512::new();
    let pb = get_progress_bar(progress, file.metadata()?.len());
    pb.set_message(path.display().to_string());
    pb.set_style(ProgressStyle::with_template("{spinner:.blue} {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏ "));
    // .progress_chars("#>-"));

    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        let n = std::io::Read::by_ref(&mut file)
            .take(chunk_size as u64)
            .read_to_end(&mut chunk)?;
        if n == 0 {
            break;
        }
        pb.inc(n as u64);
        hasher.update(&chunk);
        if n < chunk_size {
            break;
        }
    }
    let hash = hasher.finalize();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(&hash)),
        error: None,
    })
}

fn hash_text_blake2(text: String) -> Result<String> {
    let mut hasher = blake2::Blake2b512::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    Ok(bytes_to_hash(&hash))
}

fn hash_file_blake3(path: &Path, mmap: bool, progress: bool) -> Result<HashResult> {
    let mut hasher = blake3::Hasher::new();
    if !mmap {
        let chunk_size = 16 * 1024 * 1024; // 16MB
        let mut file = fs::File::open(path)?;
        let pb = get_progress_bar(progress, file.metadata()?.len());
        pb.set_message(path.display().to_string());
        pb.set_style(ProgressStyle::with_template("{spinner:.blue} {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ "));
        // .progress_chars("#>-"));

        loop {
            let mut chunk = Vec::with_capacity(chunk_size);
            let n = std::io::Read::by_ref(&mut file)
                .take(chunk_size as u64)
                .read_to_end(&mut chunk)?;
            if n == 0 {
                break;
            }
            pb.inc(n as u64);
            hasher.update_rayon(&chunk);
            if n < chunk_size {
                break;
            }
        }
    } else {
        hasher.update_mmap_rayon(path)?;
    }
    let hash = hasher.finalize();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(hash.as_bytes())),
        error: None,
    })
}

fn hash_text_blake3(text: String) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    Ok(bytes_to_hash(hash.as_bytes()))
}

fn hash_file(path: &Path, method: &str, mmap: bool, progress: bool) -> Result<HashResult> {
    match method {
        "blake2" => hash_file_blake2(path, progress),
        "blake3" => hash_file_blake3(path, mmap, progress),
        _ => panic!("Unsupported hash algorithm: {}", method),
    }
}

pub fn hash_text(text: String, method: &str) -> Result<String> {
    match method {
        "blake2" => hash_text_blake2(text),
        "blake3" => hash_text_blake3(text),
        _ => panic!("Unsupported hash algorithm: {}", method),
    }
}

pub fn hash_root(
    root: &Path,
    method: &str,
    symlinks: bool,
    mmap: bool,
    progress: bool,
) -> Result<Vec<HashResult>> {
    let mut hash_results: Vec<HashResult> = Vec::new();
    if root.is_dir() && (symlinks || !root.is_symlink()) {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && (symlinks || !path.is_symlink()) {
                match hash_root(&path, method, symlinks, mmap, progress) {
                    Ok(mut res) => hash_results.append(&mut res),
                    Err(e) => hash_results.push(HashResult {
                        filename: path.as_path().display().to_string(),
                        hash: None,
                        error: Some(e.to_string()),
                    }),
                };
            } else if path.is_file() {
                let result = hash_file(&path, method, mmap, progress)?;
                let hash = match &result.hash {
                    Some(h) => h.to_owned(),
                    None => match &result.error {
                        Some(e) => e.to_owned(),
                        None => String::from("Invalid hash result"),
                    },
                };
                println!("{}  {}", hash.bright_green(), result.filename.bright_cyan());
                hash_results.push(result);
            }
        }
    } else if root.is_file() {
        let result = hash_file(root, method, mmap, progress)?;
        let hash = match &result.hash {
            Some(h) => h.to_owned(),
            None => match &result.error {
                Some(e) => e.to_owned(),
                None => String::from("Invalid hash result"),
            },
        };
        println!("{}  {}", hash.bright_green(), result.filename.bright_cyan());
        hash_results.push(result);
    }

    Ok(hash_results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, path::PathBuf};

    // We are only checking algorithms located in this file
    static TEST_ALGOS: &'static [&str] = &["blake2", "blake3"];
    static VALUES: &'static [&str] = &[
        "3d896914f86ae22c48b06140adb4492fa3f8e2686a83cec0c8b1dcd6903168751370078bbd6bbfe02a6ab1df12a19b5991b58e65e243ec279f6a5770b2dd0e31",
        "68569ddf344009b938e1db0ec39b151b1626cfe46a87c3910dc18936a233f92b",
    ];

    #[test]
    fn test_hash_file() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests/test.txt");
        for i in 0..TEST_ALGOS.len() {
            let hash_result = hash_file(&file, TEST_ALGOS[i], false, false).unwrap();
            assert_eq!(hash_result.hash.unwrap(), String::from(VALUES[i]));
        }
    }

    #[test]
    fn test_check_file() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        for i in 0..TEST_ALGOS.len() {
            let file = PathBuf::from(base_path.clone() + "/tests/test.txt." + TEST_ALGOS[i]);
            let check_result = check(&file, TEST_ALGOS[i], false, false).unwrap();
            assert_eq!(check_result.hash_fail, 0);
            assert_eq!(check_result.invalid, 0);
            assert_eq!(check_result.mismatch, 0);
            assert_eq!(check_result.read_fail, 0);
            assert_eq!(check_result.total, 1);
        }
    }

    #[test]
    fn test_hash_text() {
        let test_txt = String::from("Test");

        for i in 0..TEST_ALGOS.len() {
            let hash = hash_text(test_txt.to_owned(), TEST_ALGOS[i]).unwrap();
            assert_eq!(hash, String::from(VALUES[i]));
        }
    }
}
