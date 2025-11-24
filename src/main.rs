use anyhow::{anyhow, Result};
use clap::Parser;
use clap_stdin::FileOrStdin;
use colored::Colorize;
use digest::Digest;
use ignore::{overrides::OverrideBuilder, Walk, WalkBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use noncrypto_digests::{Fnv, Xxh32, Xxh3_128, Xxh3_64, Xxh64};
use std::{
    any::type_name,
    fs::{self, File},
    io::{self, BufRead, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser, Debug)]
#[command(author, version, about = "A simple hasher that supports multiple algorithms and directory traversal", long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = String::from("blake3"), help = "Must be one of: blake2, blake3, md5, sha1, sha256, sha512, sha3_256, sha3_512, xxh3_128, xxh3_64, xxh64, xxh32, fnv")]
    algorithm: String,

    #[arg(short, long, help = "Optional. File to save hashsum to")]
    output: Option<PathBuf>,

    #[arg(
        long,
        help = "Disable mmap in blake3. Also disables the progress bar for blake3"
    )]
    no_mmap: bool,

    #[arg(long, help = "Disable progress bar")]
    no_progress: bool,

    #[arg(
        short,
        long,
        help = "Switch to hashsum check mode. File must be a hashsum file"
    )]
    check: bool,

    #[arg(long, help = "Add a path to ignore")]
    exclude: Option<Vec<String>>,

    #[arg(long, help = "Add a path to include")]
    include: Option<Vec<String>>,

    #[arg(long, help = "Max recursion depth")]
    max_depth: Option<usize>,

    #[arg(long, help = "Max file size to show")]
    max_filesize: Option<u64>,

    #[arg(long, help = "Follow links")]
    follow_links: bool,

    #[arg(long, help = "Walk hidden directories")]
    hidden: bool,

    #[arg(long, help = "Ignore .ignore files")]
    no_ignore: bool,

    #[arg(long, help = "Ignore .gitignore files")]
    no_gitignore: bool,

    #[arg(long, help = "Ignore .git/info/exclude")]
    no_git_exclude: bool,

    #[arg(long, help = "Ignore global gitignore files")]
    no_global_gitignore: bool,

    #[arg(long, help = "Ignore parent directory ignore files")]
    no_parents: bool,

    #[arg(help = "The file, folder, or stdin to hash", default_value = "-")]
    file: FileOrStdin,

    #[arg(long, help = "Legacy format (don't print algorithm)")]
    legacy: bool,
}

#[derive(Debug)]
pub struct HashResult {
    filename: String,
    hash: Option<String>,
    error: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct CheckResult {
    total: u64,
    mismatch: u64,
    read_fail: u64,
    hash_fail: u64,
    invalid: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn get_walker(
    path: &PathBuf,
    exclude: Option<Vec<String>>,
    include: Option<Vec<String>>,
    max_depth: Option<usize>,
    max_filesize: Option<u64>,
    follow_links: bool,
    hidden: bool,
    no_ignore: bool,
    no_gitignore: bool,
    no_git_exclude: bool,
    no_global_gitignore: bool,
    no_parents: bool,
) -> Result<Walk> {
    let mut binding = WalkBuilder::new(path);
    let walker = binding
        .hidden(!hidden)
        .max_depth(max_depth)
        .max_filesize(max_filesize)
        .follow_links(follow_links)
        .ignore(!no_ignore)
        .git_ignore(!no_gitignore)
        .git_exclude(!no_git_exclude)
        .git_global(!no_global_gitignore)
        .parents(!no_parents);
    let mut over = OverrideBuilder::new(path);
    if let Some(exclude) = exclude {
        for mut e in exclude {
            if !e.starts_with("!") {
                e.insert(0, '!');
            }
            over.add(&e)?;
        }
    }
    if let Some(include) = include {
        for mut i in include {
            i = String::from(i.strip_prefix("!").unwrap_or(&i));
            over.add(&i)?;
        }
    }
    walker.overrides(over.build()?);
    Ok(walker.build())
}

pub fn get_progress_bar(progress: bool, len: u64) -> ProgressBar {
    // Set a minimum size of 256MB
    let min_len: u64 = 256 * 1024 * 1024;
    if progress && len >= min_len {
        ProgressBar::new(len)
    } else {
        ProgressBar::hidden()
    }
}

pub fn bytes_to_hash(hash: &[u8]) -> String {
    let mut result = String::new();

    for byte in hash {
        result.push_str(format!("{:02x?}", byte).as_str());
    }

    result
}

fn hash_text<T: Digest>(text: String) -> Result<String> {
    let mut hasher = T::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    Ok(bytes_to_hash(&hash))
}

fn hash_file_blake3_mmap(path: &Path) -> Result<HashResult> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_mmap_rayon(path)?;
    let hash = hasher.finalize();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(&hash)),
        error: None,
    })
}

fn hash_file<T: Digest>(path: &Path, progress: bool, mmap: bool) -> Result<HashResult> {
    if type_name::<T>() == "blake3::Hasher" && mmap {
        // Because of the mmap stuff, we need to just route blake3 to a custom function
        hash_file_blake3_mmap(path)
    } else {
        let chunk_size: usize = 8192;
        let mut file = fs::File::open(path)?;
        let mut hasher = T::new();

        let pb = get_progress_bar(progress, file.metadata()?.len());
        pb.set_message(path.display().to_string());
        pb.set_style(ProgressStyle::with_template("{spinner:.blue} {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "));

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
        pb.finish_and_clear();
        let hash = hasher.finalize();
        Ok(HashResult {
            filename: path.display().to_string(),
            hash: Some(bytes_to_hash(&hash)),
            error: None,
        })
    }
}

fn check<T: Digest>(path: &Path, progress: bool, mmap: bool) -> Result<CheckResult> {
    let file = fs::File::open(path)?;
    let lines = io::BufReader::new(file).lines();
    let mut total = 0;
    let mut mismatch: u64 = 0;
    let mut read_fail: u64 = 0;
    let mut hash_fail: u64 = 0;
    let mut invalid: u64 = 0;
    let mut result: Result<HashResult>;

    for line in lines.map_while(Result::ok) {
        if let [hash, filename, ..] =
            &line.split("  ").map(String::from).collect::<Vec<String>>()[..]
        {
            total += 1;
            print!("{}: ", filename.bright_cyan());
            let mut proper_hash = hash.to_owned();

            if let [algo, hash, ..] =
                &hash.split(":").map(String::from).collect::<Vec<String>>()[..]
            {
                proper_hash = hash.to_owned();
                result = match algo.as_str() {
                    "md5" => hash_file::<md5::Md5>(Path::new(filename), progress, mmap),
                    "sha1" => hash_file::<sha1::Sha1>(Path::new(filename), progress, mmap),
                    "sha256" => hash_file::<sha2::Sha256>(Path::new(filename), progress, mmap),
                    "sha512" => hash_file::<sha2::Sha512>(Path::new(filename), progress, mmap),
                    "sha3_256" => hash_file::<sha3::Sha3_256>(Path::new(filename), progress, mmap),
                    "sha3_512" => hash_file::<sha3::Sha3_512>(Path::new(filename), progress, mmap),
                    "blake2" => {
                        hash_file::<blake2::Blake2b512>(Path::new(filename), progress, mmap)
                    }
                    "blake3" => hash_file::<blake3::Hasher>(Path::new(filename), progress, mmap),
                    "fnv" => hash_file::<Fnv>(Path::new(filename), progress, mmap),
                    "xxh32" => hash_file::<Xxh32>(Path::new(filename), progress, mmap),
                    "xxh64" => hash_file::<Xxh64>(Path::new(filename), progress, mmap),
                    "xxh3_64" => hash_file::<Xxh3_64>(Path::new(filename), progress, mmap),
                    "xxh3_128" => hash_file::<Xxh3_128>(Path::new(filename), progress, mmap),
                    _ => panic!("Unsupported hash algorithm: {}", algo),
                };
            }
            else {
                result = hash_file::<T>(Path::new(filename), progress, mmap);
            }
            match result {
                Ok(result) => match result.hash {
                    Some(h) => {
                        if h.eq(&proper_hash) {
                            println!("{}", "OK".bright_green());
                        } else if h.len() != proper_hash.len() {
                            println!("{}", "INVALID".bright_red());
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

fn hash_and_walk<T: Digest>(walker: Walk, progress: bool, mmap: bool, algo: &str, legacy: bool) -> Result<Vec<HashResult>> {
    let mut hash_results: Vec<HashResult> = Vec::new();
    for entry in walker.map_while(Result::ok) {
        if entry.path().is_dir() {
            continue;
        } else if entry.path().is_file() {
            let result = hash_file::<T>(entry.path(), progress, mmap)?;
            let hash = match &result.hash {
                Some(h) => h.to_owned(),
                None => match &result.error {
                    Some(e) => e.to_owned(),
                    None => String::from("Invalid hash result"),
                },
            };
            if legacy {
                println!("{}  {}", hash.bright_green(), result.filename.bright_cyan());
            } else {
                println!("{}:{}  {}", algo.bright_green(), hash.bright_green(), result.filename.bright_cyan());
            }
            hash_results.push(result);
        }
    }

    Ok(hash_results)
}

fn write_results(path: &Path, results: &Vec<HashResult>, algo: &str, legacy: bool) -> Result<()> {
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
        if legacy {
            writeln!(file, "{}  {}", hash, res.filename)?;
        } else {
            writeln!(file, "{}:{}  {}", algo, hash, res.filename)?;
        }
    }

    Ok(())
}

#[cfg(not(tarpaulin_include))]
fn process_non_stdin(args: Args) -> Result<()> {
    let file = PathBuf::from(args.file.filename());
    let walker = get_walker(
        &file,
        args.exclude,
        args.include,
        args.max_depth,
        args.max_filesize,
        args.follow_links,
        args.hidden,
        args.no_ignore,
        args.no_gitignore,
        args.no_git_exclude,
        args.no_global_gitignore,
        args.no_parents,
    )?;

    if args.check {
        let check_result = match args.algorithm.as_str() {
            "md5" => check::<md5::Md5>(&file, !args.no_progress, !args.no_mmap),
            "sha1" => check::<sha1::Sha1>(&file, !args.no_progress, !args.no_mmap),
            "sha256" => check::<sha2::Sha256>(&file, !args.no_progress, !args.no_mmap),
            "sha512" => check::<sha2::Sha512>(&file, !args.no_progress, !args.no_mmap),
            "sha3_256" => check::<sha3::Sha3_256>(&file, !args.no_progress, !args.no_mmap),
            "sha3_512" => check::<sha3::Sha3_512>(&file, !args.no_progress, !args.no_mmap),
            "blake2" => check::<blake2::Blake2b512>(&file, !args.no_progress, !args.no_mmap),
            "blake3" => check::<blake3::Hasher>(&file, !args.no_progress, !args.no_mmap),
            "fnv" => check::<Fnv>(&file, !args.no_progress, !args.no_mmap),
            "xxh32" => check::<Xxh32>(&file, !args.no_progress, !args.no_mmap),
            "xxh64" => check::<Xxh64>(&file, !args.no_progress, !args.no_mmap),
            "xxh3_64" => check::<Xxh3_64>(&file, !args.no_progress, !args.no_mmap),
            "xxh3_128" => check::<Xxh3_128>(&file, !args.no_progress, !args.no_mmap),
            _ => panic!("Unsupported hash algorithm: {}", args.algorithm),
        };
        match check_result {
            Ok(result) => {
                let mut error = false;
                if result.total == 0 {
                    println!(
                        "{}: no properly formatted lines found",
                        args.file.filename()
                    );
                    error = true;
                }
                if result.mismatch > 0 {
                    println!(
                        "{}: {} computed checksum(s) did NOT match",
                        "WARNING".bright_red(),
                        result.mismatch
                    );
                    error = true;
                }
                if result.read_fail > 0 || result.hash_fail > 0 {
                    println!(
                        "{}: Failed to check {} checksum(s)",
                        "WARNING".bright_red(),
                        result.read_fail + result.hash_fail
                    );
                    error = true;
                }
                if result.invalid > 0 {
                    println!(
                        "{}: {} invalid checksum(s)",
                        "WARNING".bright_red(),
                        result.invalid
                    );
                    error = true;
                }
                if (result.hash_fail + result.invalid + result.read_fail) as f64
                    > (result.total as f64 * 0.8)
                {
                    println!(
                        "{}: > 80% failures. Please check hash algorithm",
                        "WARNING".bright_red()
                    );
                    error = true;
                }
                if error {
                    Err(anyhow!("Please check output for errors and/or warnings"))
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(anyhow!("Failed to validate file: {}", e)),
        }
    } else {
        let result = match args.algorithm.as_str() {
            "md5" => hash_and_walk::<md5::Md5>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "sha1" => hash_and_walk::<sha1::Sha1>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "sha256" => hash_and_walk::<sha2::Sha256>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "sha512" => hash_and_walk::<sha2::Sha512>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "sha3_256" => hash_and_walk::<sha3::Sha3_256>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "sha3_512" => hash_and_walk::<sha3::Sha3_512>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "blake2" => {
                hash_and_walk::<blake2::Blake2b512>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy)
            }
            "blake3" => hash_and_walk::<blake3::Hasher>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "fnv" => hash_and_walk::<Fnv>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "xxh32" => hash_and_walk::<Xxh32>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "xxh64" => hash_and_walk::<Xxh64>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "xxh3_64" => hash_and_walk::<Xxh3_64>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            "xxh3_128" => hash_and_walk::<Xxh3_128>(walker, !args.no_progress, !args.no_mmap, &args.algorithm.as_str(), args.legacy),
            _ => panic!("Unsupported hash algorithm: {}", args.algorithm),
        };
        match result {
            Ok(res) => {
                if let Some(path) = args.output {
                    write_results(&path, &res, &args.algorithm.as_str(), args.legacy)?
                }
                Ok(())
            }
            Err(e) => Err(anyhow!("Failed to hash file(s): {}", e)),
        }
    }
}

#[cfg(not(tarpaulin_include))]
fn process_stdin(args: Args) -> Result<()> {
    let hash = match args.algorithm.as_str() {
        "md5" => hash_text::<md5::Md5>(args.file.contents_untrimmed()?)?,
        "sha1" => hash_text::<sha1::Sha1>(args.file.contents_untrimmed()?)?,
        "sha256" => hash_text::<sha2::Sha256>(args.file.contents_untrimmed()?)?,
        "sha512" => hash_text::<sha2::Sha512>(args.file.contents_untrimmed()?)?,
        "sha3_256" => hash_text::<sha3::Sha3_256>(args.file.contents_untrimmed()?)?,
        "sha3_512" => hash_text::<sha3::Sha3_512>(args.file.contents_untrimmed()?)?,
        "blake2" => hash_text::<blake2::Blake2b512>(args.file.contents_untrimmed()?)?,
        "blake3" => hash_text::<blake3::Hasher>(args.file.contents_untrimmed()?)?,
        "fnv" => hash_text::<Fnv>(args.file.contents_untrimmed()?)?,
        "xxh32" => hash_text::<Xxh32>(args.file.contents_untrimmed()?)?,
        "xxh64" => hash_text::<Xxh64>(args.file.contents_untrimmed()?)?,
        "xxh3_64" => hash_text::<Xxh3_64>(args.file.contents_untrimmed()?)?,
        "xxh3_128" => hash_text::<Xxh3_128>(args.file.contents_untrimmed()?)?,
        _ => panic!("Unsupported hash algorithm: {}", args.algorithm),
    };
    println!("{}  {}", hash.bright_green(), "-".bright_cyan());
    Ok(())
}

#[cfg(not(tarpaulin_include))]
pub fn main() -> Result<()> {
    let args = Args::parse();
    let is_stdin = args.file.is_stdin();
    if is_stdin {
        process_stdin(args)
    } else {
        process_non_stdin(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    // We are only checking algorithms located in this file
    static TEST_ALGOS: &[&str] = &[
        "md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512", "blake2", "blake3", "xxh3_128",
        "xxh3_64", "xxh64", "xxh32", "fnv",
    ];
    static VALUES: &[&str] = &[
        "0cbc6611f5540bd0809a388dc95a615b",
        "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
        "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
        "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31",
        "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0",
        "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7",
        "3d896914f86ae22c48b06140adb4492fa3f8e2686a83cec0c8b1dcd6903168751370078bbd6bbfe02a6ab1df12a19b5991b58e65e243ec279f6a5770b2dd0e31",
        "68569ddf344009b938e1db0ec39b151b1626cfe46a87c3910dc18936a233f92b",
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
            let walker = get_walker(
                &file, None, None, None, None, true, true, false, false, false, false, false,
            )
            .unwrap();
            let result = match algorithm {
                "md5" => hash_and_walk::<md5::Md5>(walker, false, true, &algorithm, false),
                "sha1" => hash_and_walk::<sha1::Sha1>(walker, false, true, &algorithm, false),
                "sha256" => hash_and_walk::<sha2::Sha256>(walker, false, true, &algorithm, true),
                "sha512" => hash_and_walk::<sha2::Sha512>(walker, false, true, &algorithm, false),
                "sha3_256" => hash_and_walk::<sha3::Sha3_256>(walker, false, true, &algorithm, false),
                "sha3_512" => hash_and_walk::<sha3::Sha3_512>(walker, false, true, &algorithm, false),
                "blake2" => hash_and_walk::<blake2::Blake2b512>(walker, false, true, &algorithm, false),
                "blake3" => hash_and_walk::<blake3::Hasher>(walker, false, true, &algorithm, false),
                "fnv" => hash_and_walk::<Fnv>(walker, false, true, &algorithm, false),
                "xxh32" => hash_and_walk::<Xxh32>(walker, false, true, &algorithm, false),
                "xxh64" => hash_and_walk::<Xxh64>(walker, false, true, &algorithm, false),
                "xxh3_64" => hash_and_walk::<Xxh3_64>(walker, false, true, &algorithm, false),
                "xxh3_128" => hash_and_walk::<Xxh3_128>(walker, false, true, &algorithm, false),
                _ => panic!("Unsupported hash algorithm: {}", algorithm),
            };
            let result = result.unwrap();
            let hash_result = result.get(0).unwrap();
            assert_eq!(hash_result.hash.clone().unwrap(), String::from(VALUES[i]));
        }
    }

    #[test]
    fn test_check_file() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        for i in 0..TEST_ALGOS.len() {
            let algorithm = TEST_ALGOS[i];
            let file = PathBuf::from(base_path.clone() + "/tests/test.txt." + TEST_ALGOS[i]);
            let result = match algorithm {
                "md5" => check::<md5::Md5>(&file, false, true),
                "sha1" => check::<sha1::Sha1>(&file, false, true),
                "sha256" => check::<sha2::Sha256>(&file, false, true),
                "sha512" => check::<sha2::Sha512>(&file, false, true),
                "sha3_256" => check::<sha3::Sha3_256>(&file, false, true),
                "sha3_512" => check::<sha3::Sha3_512>(&file, false, true),
                "blake2" => check::<blake2::Blake2b512>(&file, false, true),
                "blake3" => check::<blake3::Hasher>(&file, false, true),
                "fnv" => check::<Fnv>(&file, false, true),
                "xxh32" => check::<Xxh32>(&file, false, true),
                "xxh64" => check::<Xxh64>(&file, false, true),
                "xxh3_64" => check::<Xxh3_64>(&file, false, true),
                "xxh3_128" => check::<Xxh3_128>(&file, false, true),
                _ => panic!("Unsupported hash algorithm: {}", algorithm),
            };
            let check_result = result.unwrap();
            assert_eq!(check_result.hash_fail, 0);
            assert_eq!(check_result.invalid, 0);
            assert_eq!(check_result.mismatch, 0);
            assert_eq!(check_result.read_fail, 0);
            assert_eq!(check_result.total, 2);
        }
    }

    #[test]
    fn test_hash_text() {
        let test_txt = String::from("Test");

        for i in 0..TEST_ALGOS.len() {
            let algorithm = TEST_ALGOS[i];
            let result = match algorithm {
                "md5" => hash_text::<md5::Md5>(test_txt.clone()),
                "sha1" => hash_text::<sha1::Sha1>(test_txt.clone()),
                "sha256" => hash_text::<sha2::Sha256>(test_txt.clone()),
                "sha512" => hash_text::<sha2::Sha512>(test_txt.clone()),
                "sha3_256" => hash_text::<sha3::Sha3_256>(test_txt.clone()),
                "sha3_512" => hash_text::<sha3::Sha3_512>(test_txt.clone()),
                "blake2" => hash_text::<blake2::Blake2b512>(test_txt.clone()),
                "blake3" => hash_text::<blake3::Hasher>(test_txt.clone()),
                "fnv" => hash_text::<Fnv>(test_txt.clone()),
                "xxh32" => hash_text::<Xxh32>(test_txt.clone()),
                "xxh64" => hash_text::<Xxh64>(test_txt.clone()),
                "xxh3_64" => hash_text::<Xxh3_64>(test_txt.clone()),
                "xxh3_128" => hash_text::<Xxh3_128>(test_txt.clone()),
                _ => panic!("Unsupported hash algorithm: {}", algorithm),
            };
            let hash = result.unwrap();
            assert_eq!(hash, String::from(VALUES[i]));
        }
    }

    #[test]
    fn test_errors() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let result_fail = check::<sha2::Sha256>(
            PathBuf::from(base_path.clone() + "/tests/test.fail").as_path(),
            false,
            false,
        )
        .unwrap();
        let result_invalid = check::<sha2::Sha256>(
            PathBuf::from(base_path.clone() + "/tests/test.invalid").as_path(),
            false,
            false,
        )
        .unwrap();
        let result_hashfail = check::<sha2::Sha256>(
            PathBuf::from(base_path.clone() + "/tests/test.hashfail").as_path(),
            false,
            false,
        )
        .unwrap();
        let control_fail = CheckResult {
            total: 1,
            mismatch: 1,
            read_fail: 0,
            hash_fail: 0,
            invalid: 0,
        };
        let control_invalid = CheckResult {
            total: 1,
            mismatch: 0,
            read_fail: 0,
            hash_fail: 0,
            invalid: 1,
        };
        let control_hashfail = CheckResult {
            total: 1,
            mismatch: 0,
            read_fail: 0,
            hash_fail: 1,
            invalid: 0,
        };

        assert_eq!(result_fail, control_fail);
        assert_eq!(result_invalid, control_invalid);
        assert_eq!(result_hashfail, control_hashfail);
    }

    #[test]
    fn test_exclude() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests");
        let exclude = vec![String::from("test*")];
        let walker = get_walker(
            &file,
            Some(exclude),
            None,
            None,
            None,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
        )
        .unwrap();

        // Algo isn't important here
        let result = hash_and_walk::<blake3::Hasher>(walker, false, false, "blake3", false).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_include() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests");
        let exclude = vec![String::from("test*")];
        let include = vec![String::from("*.blake3")];
        let walker = get_walker(
            &file,
            Some(exclude),
            Some(include),
            None,
            None,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
        )
        .unwrap();

        // Algo isn't important here
        let result = hash_and_walk::<blake3::Hasher>(walker, false, false, "blake3", false).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_output() {
        use tempfile::NamedTempFile;
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests");
        let walker = get_walker(
            &file, None, None, None, None, true, true, false, false, false, false, false,
        )
        .unwrap();

        // Algo isn't important here
        let result = hash_and_walk::<blake3::Hasher>(walker, false, false, "blake3", false).unwrap();
        let output = NamedTempFile::new().unwrap();

        write_results(output.path(), &result, "blake3", false).unwrap();
        write_results(output.path(), &result, "blake3", true).unwrap();
        output.close().unwrap();
    }
}
