use anyhow::{anyhow, Result};
use clap::Parser;
use clap_stdin::FileOrStdin;
use colored::Colorize;
use ignore::{overrides::OverrideBuilder, Walk, WalkBuilder};
use std::{
    fs::{self, File},
    io::{self, BufRead, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use digest::DynDigest;
use indicatif::{ProgressBar, ProgressStyle};
mod blake;
mod xxhash;

static ALGOS: &[&str] = &[
    "blake2", "blake3", "md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512", "xxh3_128",
    "xxh3_64", "xxh64", "xxh32", "fnv",
];
static XXH3: &[&str] = &["xxh3_128", "xxh3_64", "xxh64", "xxh32", "fnv"];
static BLAKE: &[&str] = &["blake2", "blake3"];

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

fn check(path: &Path, hasher: &mut dyn DynDigest, progress: bool) -> Result<CheckResult> {
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
            match hash_file(Path::new(filename), hasher, progress) {
                Ok(result) => match result.hash {
                    Some(h) => {
                        if h.eq(hash) {
                            println!("{}", "OK".bright_green());
                        } else if h.len() != hash.len() {
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

fn hash_text(text: String, hasher: &mut dyn DynDigest) -> Result<String> {
    hasher.update(text.as_bytes());
    let hash = hasher.finalize_reset();

    Ok(bytes_to_hash(&hash))
}

fn hash_file(path: &Path, hasher: &mut dyn DynDigest, progress: bool) -> Result<HashResult> {
    let chunk_size: usize = 4096;
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
        hasher.update(&chunk);
        if n < chunk_size {
            break;
        }
    }
    pb.finish_and_clear();
    let hash = hasher.finalize_reset();
    Ok(HashResult {
        filename: path.display().to_string(),
        hash: Some(bytes_to_hash(&hash)),
        error: None,
    })
}

fn hash_and_walk(
    walker: Walk,
    hasher: &mut dyn DynDigest,
    progress: bool,
) -> Result<Vec<HashResult>> {
    let mut hash_results: Vec<HashResult> = Vec::new();
    for entry in walker.map_while(Result::ok) {
        if entry.path().is_dir() {
            continue;
        } else if entry.path().is_file() {
            let result = hash_file(entry.path(), hasher, progress)?;
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
    if XXH3.contains(&args.algorithm.as_str()) {
        if args.check {
            match xxhash::check(&file, args.algorithm.as_str(), !args.no_progress) {
                Ok(result) => {
                    if result.total == 0 {
                        println!(
                            "{}: no properly formatted lines found",
                            args.file.filename()
                        );
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
            match xxhash::hash_and_walk(walker, args.algorithm.as_str(), !args.no_progress) {
                Ok(res) => {
                    if let Some(path) = args.output {
                        write_results(&path, &res)?
                    }
                    Ok(())
                }
                Err(e) => Err(anyhow!("Failed to hash file(s): {}", e)),
            }
        }
    } else if BLAKE.contains(&args.algorithm.as_str()) {
        if args.check {
            match blake::check(
                &file,
                args.algorithm.as_str(),
                !args.no_mmap,
                !args.no_progress,
            ) {
                Ok(result) => {
                    if result.total == 0 {
                        println!(
                            "{}: no properly formatted lines found",
                            args.file.filename()
                        );
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
            match blake::hash_and_walk(
                walker,
                args.algorithm.as_str(),
                !args.no_mmap,
                !args.no_progress,
            ) {
                Ok(res) => {
                    if let Some(path) = args.output {
                        write_results(&path, &res)?
                    }
                    Ok(())
                }
                Err(e) => Err(anyhow!("Failed to hash file(s): {}", e)),
            }
        }
    } else {
        let mut hasher: Box<dyn DynDigest> = match args.algorithm.as_str() {
            "md5" => Box::new(md5::Md5::default()),
            "sha1" => Box::new(sha1::Sha1::default()),
            "sha256" => Box::new(sha2::Sha256::default()),
            "sha512" => Box::new(sha2::Sha512::default()),
            "sha3_256" => Box::new(sha3::Sha3_256::default()),
            "sha3_512" => Box::new(sha3::Sha3_512::default()),
            _ => panic!("Unsupported hash algorithm: {}", args.algorithm),
        };

        if args.check {
            match check(&file, &mut *hasher, !args.no_progress) {
                Ok(result) => {
                    if result.total == 0 {
                        println!(
                            "{}: no properly formatted lines found",
                            args.file.filename()
                        );
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
            match hash_and_walk(walker, &mut *hasher, !args.no_progress) {
                Ok(res) => {
                    if let Some(path) = args.output {
                        write_results(&path, &res)?
                    }
                    Ok(())
                }
                Err(e) => Err(anyhow!("Failed to hash file(s): {}", e)),
            }
        }
    }
}

fn process_stdin(args: Args) -> Result<()> {
    let hash: String;
    if XXH3.contains(&args.algorithm.as_str()) {
        hash = xxhash::hash_text(args.file.contents_untrimmed()?, &args.algorithm)?;
    } else if BLAKE.contains(&args.algorithm.as_str()) {
        hash = blake::hash_text(args.file.contents_untrimmed()?, &args.algorithm)?;
    } else {
        let mut hasher: Box<dyn DynDigest> = match args.algorithm.as_str() {
            "md5" => Box::new(md5::Md5::default()),
            "sha1" => Box::new(sha1::Sha1::default()),
            "sha256" => Box::new(sha2::Sha256::default()),
            "sha512" => Box::new(sha2::Sha512::default()),
            "sha3_256" => Box::new(sha3::Sha3_256::default()),
            "sha3_512" => Box::new(sha3::Sha3_512::default()),
            _ => panic!("Unsupported hash algorithm: {}", args.algorithm),
        };
        hash = hash_text(args.file.contents_untrimmed()?, &mut *hasher)?;
    }
    println!("{}  {}", hash.bright_green(), "-".bright_cyan());
    Ok(())
}

pub fn main() -> Result<()> {
    let args = Args::parse();
    let is_stdin = args.file.is_stdin();
    if !ALGOS.contains(&args.algorithm.as_str()) {
        return Err(anyhow!("Unsupported hash algorithm: {}", args.algorithm));
    };
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
    static TEST_ALGOS: &'static [&str] =
        &["md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512"];
    static VALUES: &'static [&str] = &[
        "0cbc6611f5540bd0809a388dc95a615b",
        "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
        "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
        "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31",
        "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0",
        "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7",
    ];

    fn get_hasher(method: &str) -> Box<dyn DynDigest> {
        match method {
            "md5" => Box::new(md5::Md5::default()),
            "sha1" => Box::new(sha1::Sha1::default()),
            "sha256" => Box::new(sha2::Sha256::default()),
            "sha512" => Box::new(sha2::Sha512::default()),
            "sha3_256" => Box::new(sha3::Sha3_256::default()),
            "sha3_512" => Box::new(sha3::Sha3_512::default()),
            _ => panic!("Test failed due to unknown hash algorithm"),
        }
    }

    #[test]
    fn test_hash_file() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests/test.txt");
        for i in 0..TEST_ALGOS.len() {
            let mut hasher = get_hasher(TEST_ALGOS[i]);
            let hash_result = hash_file(&file, &mut *hasher, false).unwrap();
            assert_eq!(hash_result.hash.unwrap(), String::from(VALUES[i]));
        }
    }

    #[test]
    fn test_check_file() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        for i in 0..TEST_ALGOS.len() {
            let file = PathBuf::from(base_path.clone() + "/tests/test.txt." + TEST_ALGOS[i]);
            let mut hasher = get_hasher(TEST_ALGOS[i]);
            let check_result = check(&file, &mut *hasher, false).unwrap();
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
            let mut hasher = get_hasher(TEST_ALGOS[i]);
            let hash = hash_text(test_txt.to_owned(), &mut *hasher).unwrap();
            assert_eq!(hash, String::from(VALUES[i]));
        }
    }

    #[test]
    fn test_errors() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let mut hasher = get_hasher("sha256");
        let result_fail = check(
            PathBuf::from(base_path.clone() + "/tests/test.fail").as_path(),
            &mut *hasher,
            false,
        )
        .unwrap();
        let result_invalid = check(
            PathBuf::from(base_path.clone() + "/tests/test.invalid").as_path(),
            &mut *hasher,
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

        assert_eq!(result_fail, control_fail);
        assert_eq!(result_invalid, control_invalid);
    }
}
