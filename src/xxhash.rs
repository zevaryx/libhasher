use anyhow::{Result};
use colored::Colorize;
use std::{
    fs,
    io::{self, BufRead, Read},
    path::{Path},
};
use digest::Digest;
use noncrypto_digests::{Fnv, Xxh3_64, Xxh3_128, Xxh32, Xxh64};

use crate::{HashResult, CheckResult, bytes_to_hash};

pub fn check(path: &Path, method: &str) -> Result<CheckResult> {
    let file = fs::File::open(path)?;
    let lines = io::BufReader::new(file).lines();
    let mut total = 0;
    let mut mismatch: u64 = 0;
    let mut read_fail: u64 = 0;
    let mut hash_fail: u64 = 0;
    let mut invalid: u64 = 0;

    for line in lines {
        if let Ok(line) = line {
            if let [hash, filename, ..] =
                &line.split("  ").map(String::from).collect::<Vec<String>>()[..]
            {
                total += 1;
                print!("{}: ", filename.bright_cyan());
                match hash_file(&Path::new(filename), method) {
                    Ok(result) => match result.hash {
                        Some(h) => {
                            if h.eq(hash) {
                                print!("{}\n", "OK".bright_green());
                            } else if h.len() != hash.len() {
                                print!("{}\n", "INVALID".bright_red());
                                total -= 1;
                                invalid += 1;
                            } else {
                                print!("{}\n", "FAILED".bright_red());
                                mismatch += 1;
                            }
                        }
                        None => {
                            print!("{}\n", "READ_FAIL".bright_red());
                            read_fail += 1;
                        }
                    },
                    Err(_) => {
                        print!("{}\n", "HASH_FAIL".bright_red());
                        hash_fail += 1;
                    }
                }
            }
        }
    }

    let result = CheckResult {
        total: total,
        mismatch: mismatch,
        read_fail: read_fail,
        hash_fail: hash_fail,
        invalid: invalid,
    };

    Ok(result)
}

fn hash_file_xxh3_128(path: &Path) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Xxh3_128::new();

    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        let n = std::io::Read::by_ref(&mut file)
            .take(chunk_size as u64)
            .read_to_end(&mut chunk)?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk);
        if n < chunk_size {
            break;
        }
    }
    let hash = hasher.finalize();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(&*hash)),
        error: None,
    })
}

fn hash_file_xxh3_64(path: &Path) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Xxh3_64::new();

    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        let n = std::io::Read::by_ref(&mut file)
            .take(chunk_size as u64)
            .read_to_end(&mut chunk)?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk);
        if n < chunk_size {
            break;
        }
    }
    let hash = hasher.finalize();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(&*hash)),
        error: None,
    })
}

fn hash_file_xxh64(path: &Path) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Xxh64::new();

    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        let n = std::io::Read::by_ref(&mut file)
            .take(chunk_size as u64)
            .read_to_end(&mut chunk)?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk);
        if n < chunk_size {
            break;
        }
    }
    let hash = hasher.finalize();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(&*hash)),
        error: None,
    })
}

fn hash_file_xxh32(path: &Path) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Xxh32::new();

    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        let n = std::io::Read::by_ref(&mut file)
            .take(chunk_size as u64)
            .read_to_end(&mut chunk)?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk);
        if n < chunk_size {
            break;
        }
    }
    let hash = hasher.finalize();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(&*hash)),
        error: None,
    })
}

fn hash_file_fnv(path: &Path) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;
    let mut hasher = Fnv::new();

    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        let n = std::io::Read::by_ref(&mut file)
            .take(chunk_size as u64)
            .read_to_end(&mut chunk)?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk);
        if n < chunk_size {
            break;
        }
    }
    let hash = hasher.finalize();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(&*hash)),
        error: None,
    })
}

fn hash_file(path: &Path, method: &str) -> Result<HashResult> {
    match method {
        "xxh3_128" => hash_file_xxh3_128(path),
        "xxh3_64" => hash_file_xxh3_64(path),
        "xxh64" => hash_file_xxh64(path),
        "xxh32" => hash_file_xxh32(path),
        "fnv" => hash_file_fnv(path),
        _ => panic!("Unsupported hash algorithm: {}", method)
    }
    
}

pub fn hash_root(root: &Path, method: &str, symlinks: bool) -> Result<Vec<HashResult>> {
    let mut hash_results: Vec<HashResult> = Vec::new();
    if root.is_dir() && (symlinks == true || !root.is_symlink()) {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && (symlinks == true || !path.is_symlink()) {
                match hash_root(&path, method, symlinks) {
                    Ok(mut res) => hash_results.append(&mut res),
                    Err(e) => hash_results.push(HashResult {
                        filename: path.as_path().display().to_string(),
                        hash: None,
                        error: Some(e.to_string()),
                    }),
                };
            } else if path.is_file() {
                let result = hash_file(&path, method)?;
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
        let result = hash_file(&root, method)?;
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