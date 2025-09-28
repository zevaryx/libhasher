use anyhow::Result;
use colored::Colorize;
use digest::Digest;
use ignore::Walk;
use indicatif::ProgressStyle;
use noncrypto_digests::{Fnv, Xxh32, Xxh3_128, Xxh3_64, Xxh64};
use std::{
    fs,
    io::{self, BufRead, Read},
    path::Path,
};

use crate::{bytes_to_hash, get_progress_bar, CheckResult, HashResult};

pub fn check(path: &Path, method: &str, progress: bool) -> Result<CheckResult> {
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
            match hash_file(Path::new(filename), method, progress) {
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

fn hash_file_xxh3_128(path: &Path, progress: bool) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Xxh3_128::new();
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

fn hash_text_xxh3_128(text: String) -> Result<String> {
    let mut hasher = Xxh3_128::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    Ok(bytes_to_hash(&hash))
}

fn hash_file_xxh3_64(path: &Path, progress: bool) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Xxh3_64::new();
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

fn hash_text_xxh3_64(text: String) -> Result<String> {
    let mut hasher = Xxh3_64::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    Ok(bytes_to_hash(&hash))
}

fn hash_file_xxh64(path: &Path, progress: bool) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Xxh64::new();
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

fn hash_text_xxh64(text: String) -> Result<String> {
    let mut hasher = Xxh64::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    Ok(bytes_to_hash(&hash))
}

fn hash_file_xxh32(path: &Path, progress: bool) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Xxh32::new();
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

fn hash_text_xxh32(text: String) -> Result<String> {
    let mut hasher = Xxh32::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    Ok(bytes_to_hash(&hash))
}

fn hash_file_fnv(path: &Path, progress: bool) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Fnv::new();
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

fn hash_text_fnv(text: String) -> Result<String> {
    let mut hasher = Fnv::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    Ok(bytes_to_hash(&hash))
}

fn hash_file(path: &Path, method: &str, progress: bool) -> Result<HashResult> {
    match method {
        "xxh3_128" => hash_file_xxh3_128(path, progress),
        "xxh3_64" => hash_file_xxh3_64(path, progress),
        "xxh64" => hash_file_xxh64(path, progress),
        "xxh32" => hash_file_xxh32(path, progress),
        "fnv" => hash_file_fnv(path, progress),
        _ => panic!("Unsupported hash algorithm: {}", method),
    }
}

pub fn hash_text(text: String, method: &str) -> Result<String> {
    match method {
        "xxh3_128" => hash_text_xxh3_128(text),
        "xxh3_64" => hash_text_xxh3_64(text),
        "xxh64" => hash_text_xxh64(text),
        "xxh32" => hash_text_xxh32(text),
        "fnv" => hash_text_fnv(text),
        _ => panic!("Unsupported hash algorithm: {}", method),
    }
}

pub fn hash_and_walk(walker: Walk, method: &str, progress: bool) -> Result<Vec<HashResult>> {
    let mut hash_results: Vec<HashResult> = Vec::new();
    for entry in walker.map_while(Result::ok) {
        if entry.path().is_dir() {
            continue;
        } else if entry.path().is_file() {
            let result = hash_file(entry.path(), method, progress)?;
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

    Ok(hash_results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, path::PathBuf};

    // We are only checking algorithms located in this file
    static TEST_ALGOS: &'static [&str] = &["xxh3_128", "xxh3_64", "xxh64", "xxh32", "fnv"];
    static VALUES: &'static [&str] = &[
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
            let hash_result = hash_file(&file, TEST_ALGOS[i], false).unwrap();
            assert_eq!(hash_result.hash.unwrap(), String::from(VALUES[i]));
        }
    }

    #[test]
    fn test_check_file() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        for i in 0..TEST_ALGOS.len() {
            let file = PathBuf::from(base_path.clone() + "/tests/test.txt." + TEST_ALGOS[i]);
            let check_result = check(&file, TEST_ALGOS[i], false).unwrap();
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
