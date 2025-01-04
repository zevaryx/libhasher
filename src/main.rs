use anyhow::{anyhow, Result};
use clap::Parser;
use colored::Colorize;
use std::{
    fs::{self, File},
    io::{self, BufRead, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use digest::DynDigest;

static ALGOS: &'static [&str] = &["md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512"];

#[derive(Parser, Debug)]
#[command(author, version, about = "A simple hasher that supports multiple algorithms and directory traversal", long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = String::from("sha256"), help = "Default sha256. Must be one of: md5, sha1, sha256, sha512, sha3_256, sha3_512")]
    algorithm: String,

    #[arg(short, long, help = "Optional. File to save hashsum to")]
    output: Option<PathBuf>,

    #[arg(
        short,
        long,
        help = "Switch to hashsum check mode. File must be a hashsum file"
    )]
    check: bool,

    #[arg(short, long, help = "Follow symlinks")]
    symlinks: bool,

    #[arg(help = "The file or folder to hash")]
    file: PathBuf,
}

#[derive(Debug)]
struct HashResult {
    filename: String,
    hash: Option<String>,
    error: Option<String>,
}

#[derive(Debug)]
struct CheckResult {
    total: u64,
    mismatch: u64,
    read_fail: u64,
    hash_fail: u64,
    invalid: u64,
}

fn bytes_to_hash(hash: &[u8]) -> String {
    let mut result = String::new();

    for byte in hash {
        result.push_str(format!("{:02x?}", byte).as_str());
    }

    result
}

fn check(path: &Path, hasher: &mut dyn DynDigest) -> Result<CheckResult> {
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
                match hash_file(&Path::new(filename), hasher) {
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

fn hash_file(path: &Path, hasher: &mut dyn DynDigest) -> Result<HashResult> {
    let chunk_size = 4096;
    let mut file = fs::File::open(path)?;

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
    let hash = hasher.finalize_reset();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(&*hash)),
        error: None,
    })
}

fn hash_root(root: &Path, hasher: &mut dyn DynDigest, symlinks: bool) -> Result<Vec<HashResult>> {
    let mut hash_results: Vec<HashResult> = Vec::new();
    if root.is_dir() && (symlinks == true || !root.is_symlink()) {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && (symlinks == true || !path.is_symlink()) {
                match hash_root(&path, hasher, symlinks) {
                    Ok(mut res) => hash_results.append(&mut res),
                    Err(e) => hash_results.push(HashResult {
                        filename: path.as_path().display().to_string(),
                        hash: None,
                        error: Some(e.to_string()),
                    }),
                };
            } else if path.is_file() {
                let result = hash_file(&path, hasher)?;
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
        let result = hash_file(&root, hasher)?;
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

fn write_results(path: &Path, results: &Vec<HashResult>) -> Result<()> {
    let file = File::create(path)?;
    let mut file = BufWriter::new(file);

    for res in results {
        let hash = match &res.hash {
            Some(h) => h.to_owned(),
            None => match &res.error {
                Some(e) => e.to_owned(),
                None => String::from("Invalid hash result"),
            },
        };

        writeln!(file, "{}  {}", hash, res.filename)?;
    }

    Ok(())
}

pub fn main() -> Result<()> {
    let args = Args::parse();
    if !ALGOS.contains(&args.algorithm.as_str()) {
        return Err(anyhow!("Unsupported hash algorithm: {}", args.algorithm));
    };

    let mut hasher: Box<dyn DynDigest> = match args.algorithm.as_str() {
        "md5" => Box::new(md5::Md5::default()),
        "sha1" => Box::new(sha1::Sha1::default()),
        "sha256" => Box::new(sha2::Sha256::default()),
        "sha512" => Box::new(sha2::Sha512::default()),
        "sha3_256" => Box::new(sha3::Sha3_256::default()),
        "sha3_512" => Box::new(sha3::Sha3_512::default()),
        _ => panic!("Invalid hash, check failed"),
    };

    if args.check {
        match check(&args.file, &mut *hasher) {
            Ok(result) => {
                if result.total == 0 {
                    println!("{}: no properly formatted lines found", args.file.display());
                }
                if result.mismatch > 0 {
                    println!(
                        "{}: {} computed checksum(s) did NOT match",
                        "WARNING".bright_red(),
                        result.mismatch
                    );
                }
                if result.read_fail > 0 || result.hash_fail > 0 {
                    println!(
                        "{}: Failed to check {} checksum(s)",
                        "WARNING".bright_red(),
                        result.read_fail + result.hash_fail
                    );
                }
                if result.invalid > 0 {
                    println!(
                        "{}: {} invalid checksum(s)",
                        "WARNING".bright_red(),
                        result.invalid
                    );
                }
                if (result.hash_fail + result.invalid + result.read_fail) as f64
                    > (result.total as f64 * 0.8)
                {
                    println!(
                        "{}: > 80% failures. Please check hash algorithm",
                        "WARNING".bright_red()
                    )
                }
                Ok(())
            }
            Err(e) => Err(anyhow!("Failed to validate file: {}", e)),
        }
    } else {
        match hash_root(&args.file, &mut *hasher, args.symlinks) {
            Ok(res) => {
                match args.output {
                    Some(path) => write_results(&path, &res)?,
                    None => (),
                };
                Ok(())
            }
            Err(e) => Err(anyhow!("Failed to hash file(s): {}", e)),
        }
    }
}
