use anyhow::{anyhow, Result};
use clap::Parser;
use clap_stdin::FileOrStdin;
use colored::Colorize;
use hasher::{HashResult, Hasher};
use ignore::{overrides::OverrideBuilder, Walk, WalkBuilder};
#[cfg(not(tarpaulin_include))]
use std::process::ExitCode;
use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead, BufWriter, Write},
    path::{Path, PathBuf},
};

#[derive(Parser, Debug, Clone)]
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

    #[arg(
        short,
        long,
        help = "Don't print OK for each successfully verified file"
    )]
    quiet: bool,

    #[arg(short, long, help = "Only return status code")]
    status: bool,

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

    #[arg(
        long,
        help = "How many hashes to buffer before writing to file",
        default_value = "10000"
    )]
    buffer_size: usize,
}
#[derive(Debug)]
pub struct WalkerOptions {
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
}

pub fn get_walker(path: &PathBuf, opts: WalkerOptions) -> Result<Walk> {
    let mut binding = WalkBuilder::new(path);
    let walker = binding
        .hidden(!opts.hidden)
        .max_depth(opts.max_depth)
        .max_filesize(opts.max_filesize)
        .follow_links(opts.follow_links)
        .ignore(!opts.no_ignore)
        .git_ignore(!opts.no_gitignore)
        .git_exclude(!opts.no_git_exclude)
        .git_global(!opts.no_global_gitignore)
        .parents(!opts.no_parents);
    let mut over = OverrideBuilder::new(path);
    if let Some(exclude) = opts.exclude {
        for mut e in exclude {
            if !e.starts_with("!") {
                e.insert(0, '!');
            }
            over.add(&e)?;
        }
    }
    if let Some(include) = opts.include {
        for mut i in include {
            i = String::from(i.strip_prefix("!").unwrap_or(&i));
            over.add(&i)?;
        }
    }
    walker.overrides(over.build()?);
    Ok(walker.build())
}

#[derive(Debug, PartialEq)]
pub struct CheckResult {
    total: u64,
    mismatch: u64,
    hash_fail: u64,
    invalid: u64,
    unsupported: u64,
}

fn check(
    main_algo: &str,
    path: &Path,
    progress: bool,
    mmap: bool,
    quiet: bool,
    status: bool,
) -> Result<CheckResult> {
    let file = fs::File::open(path)?;
    let lines = io::BufReader::new(file).lines();
    let mut total = 0;
    let mut mismatch: u64 = 0;
    let mut hash_fail: u64 = 0;
    let mut invalid: u64 = 0;
    let mut unsupported: u64 = 0;
    let mut result: Result<HashResult>;

    let progress = progress && (!quiet && !status);

    for line in lines.map_while(Result::ok) {
        if let [hash, filename, ..] =
            &line.split("  ").map(String::from).collect::<Vec<String>>()[..]
        {
            total += 1;
            let mut proper_hash = hash.to_owned();

            if let [algo, hash, ..] =
                &hash.split(":").map(String::from).collect::<Vec<String>>()[..]
            {
                proper_hash = hash.to_owned();
                let hasher = Hasher::new(algo.as_str());
                if let Ok(mut h) = hasher {
                    result = h.hash_file_progressbar(Path::new(filename), progress, mmap, None);
                } else {
                    if !status {
                        println!(
                            "{}: {}:{}",
                            filename.bright_cyan(),
                            "UNSUPPORTED".bright_red(),
                            algo.white()
                        );
                    }
                    unsupported += 1;
                    continue;
                }
            } else {
                let mut hasher = Hasher::new(main_algo)?;
                result = hasher.hash_file_progressbar(Path::new(filename), progress, mmap, None);
            }
            match result {
                Ok(result) => {
                    if result.hash.eq(&proper_hash) {
                        if !quiet && !status {
                            println!("{}: {}", filename.bright_cyan(), "OK".bright_green());
                        }
                    } else if result.hash.len() != proper_hash.len() {
                        if !status {
                            println!("{}: {}", filename.bright_cyan(), "INVALID".bright_red());
                        }
                        invalid += 1;
                    } else {
                        if !status {
                            println!("{}: {}", filename.bright_cyan(), "FAILED".bright_red());
                        }
                        mismatch += 1;
                    }
                }
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
        hash_fail,
        invalid,
        unsupported,
    };

    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn hash_and_walk(
    walker: Walk,
    progress: bool,
    mmap: bool,
    algo: &str,
    legacy: bool,
    status: bool,
    quiet: bool,
    path: Option<PathBuf>,
    queue_size: usize,
) -> Result<Vec<HashResult>> {
    let mut hasher = Hasher::new(algo)?;
    let mut hash_results: Vec<HashResult> = Vec::new();
    for entry in walker.map_while(Result::ok) {
        if entry.path().is_dir() {
            continue;
        } else if entry.path().is_file() {
            let result = hasher.hash_file_progressbar(
                entry.path(),
                progress && (!status && !quiet),
                mmap,
                None,
            )?;
            let hash = &result.hash;
            if legacy {
                println!("{}  {}", hash.bright_green(), result.filename.bright_cyan());
            } else {
                println!(
                    "{}:{}  {}",
                    algo.bright_yellow(),
                    hash.bright_green(),
                    result.filename.bright_blue()
                );
            }
            hash_results.push(result);
            if hash_results.len() > queue_size {
                if let Some(p) = &path {
                    write_results(p, &hash_results, algo, legacy, true)?;
                }
                hash_results.clear();
            }
        }
    }

    if let Some(p) = &path {
        write_results(p, &hash_results, algo, legacy, true)?;
    }

    Ok(hash_results)
}

fn write_results(
    path: &Path,
    results: &Vec<HashResult>,
    algo: &str,
    legacy: bool,
    append: bool,
) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .append(append)
        .create(true)
        .open(path)?;
    let mut file = BufWriter::new(file);

    for res in results {
        let hash = &res.hash;
        if legacy {
            writeln!(file, "{}  {}", hash, res.filename)?;
        } else {
            writeln!(file, "{}:{}  {}", algo, hash, res.filename)?;
        }
    }

    Ok(())
}

#[cfg(not(tarpaulin_include))]
fn process_non_stdin(args: &Args) -> Result<()> {
    let file = PathBuf::from(args.file.filename());
    let walker = get_walker(
        &file,
        WalkerOptions {
            exclude: args.exclude.clone(),
            include: args.include.clone(),
            max_depth: args.max_depth,
            max_filesize: args.max_filesize,
            follow_links: args.follow_links,
            hidden: args.hidden,
            no_ignore: args.no_ignore,
            no_gitignore: args.no_gitignore,
            no_git_exclude: args.no_git_exclude,
            no_global_gitignore: args.no_global_gitignore,
            no_parents: args.no_parents,
        },
    )?;

    if args.check {
        let check_result = check(
            &args.algorithm,
            &file,
            !args.no_progress,
            !args.no_mmap,
            args.quiet,
            args.status,
        );
        match check_result {
            Ok(result) => {
                let mut error = false;
                if result.total == 0 {
                    if !args.status {
                        println!(
                            "{}: no properly formatted lines found",
                            args.file.filename()
                        );
                    }
                    error = true;
                }
                if result.mismatch > 0 {
                    if !args.status {
                        println!(
                            "{}: {} computed checksum(s) did NOT match",
                            "WARNING".bright_red(),
                            result.mismatch
                        );
                    }
                    error = true;
                }
                if result.invalid > 0 {
                    if !args.status {
                        println!(
                            "{}: {} invalid checksum(s)",
                            "WARNING".bright_red(),
                            result.invalid
                        );
                    }
                    error = true;
                }
                if (result.hash_fail + result.invalid) as f64 > (result.total as f64 * 0.8) {
                    if !args.status {
                        println!(
                            "{}: > 80% failures. Please check hash algorithm",
                            "WARNING".bright_red()
                        );
                    }
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
        let _ = hash_and_walk(
            walker,
            !args.no_progress,
            !args.no_mmap,
            args.algorithm.as_str(),
            args.legacy,
            args.quiet,
            args.status,
            args.output.clone(),
            args.buffer_size,
        )?;
        Ok(())
    }
}

#[cfg(not(tarpaulin_include))]
fn process_stdin(args: &Args) -> Result<()> {
    let mut hasher = Hasher::new(&args.algorithm)?;
    let hash = hasher.hash_text(args.file.clone().contents_untrimmed()?)?;
    println!("{}  {}", hash.bright_green(), "-".bright_cyan());
    Ok(())
}

#[cfg(not(tarpaulin_include))]
pub fn main() -> ExitCode {
    let mut args = Args::parse();
    // We need to validate status and/or quiet
    if (args.status || args.quiet) && (!args.check || args.output.is_some()) {
        println!(
            "{}: quiet and status modes require check mode or output, ignoring",
            "WARN".bright_red()
        );
        args.quiet = false;
        args.status = false;
    }
    let is_stdin = args.file.is_stdin();
    let res: Result<()> = if is_stdin {
        process_stdin(&args)
    } else {
        process_non_stdin(&args)
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if !args.status {
                eprintln!("{}", e);
            }
            ExitCode::FAILURE
        }
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
    fn test_hash_file_progressbar() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests/test.txt");
        for i in 0..TEST_ALGOS.len() {
            let algorithm = TEST_ALGOS[i];
            let opts = WalkerOptions {
                no_git_exclude: false,
                exclude: None,
                include: None,
                max_depth: None,
                max_filesize: None,
                follow_links: true,
                hidden: true,
                no_ignore: false,
                no_gitignore: false,
                no_global_gitignore: false,
                no_parents: false,
            };
            let walker = get_walker(&file, opts).unwrap();
            let result = hash_and_walk(
                walker, true, true, &algorithm, false, false, false, None, 100,
            );
            let result = result.unwrap();
            let hash_result = result.get(0).unwrap();
            assert_eq!(hash_result.hash.clone(), String::from(VALUES[i]));
        }
    }

    #[test]
    fn test_check_file() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        for i in 0..TEST_ALGOS.len() {
            let algorithm = TEST_ALGOS[i];
            let file = PathBuf::from(base_path.clone() + "/tests/test.txt." + TEST_ALGOS[i]);
            let result = check(&algorithm.to_string(), &file, false, true, false, false);
            let check_result = result.unwrap();
            assert_eq!(check_result.hash_fail, 0);
            assert_eq!(check_result.invalid, 0);
            assert_eq!(check_result.mismatch, 0);
            assert_eq!(check_result.total, 2);
        }
    }

    #[test]
    fn test_hash_text() {
        let test_txt = String::from("Test");

        for i in 0..TEST_ALGOS.len() {
            let algorithm = TEST_ALGOS[i];
            let mut hasher = Hasher::new(&algorithm.to_string()).unwrap();
            let result = hasher.hash_text(test_txt.clone());
            let hash = result.unwrap();
            assert_eq!(hash, String::from(VALUES[i]));
        }
    }

    #[test]
    fn test_errors() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let result_fail = check(
            &"sha256".to_string(),
            PathBuf::from(base_path.clone() + "/tests/test.fail").as_path(),
            false,
            false,
            false,
            false,
        )
        .unwrap();
        let result_invalid = check(
            &"sha256".to_string(),
            PathBuf::from(base_path.clone() + "/tests/test.invalid").as_path(),
            false,
            false,
            false,
            false,
        )
        .unwrap();
        let result_hashfail = check(
            &"sha256".to_string(),
            PathBuf::from(base_path.clone() + "/tests/test.hashfail").as_path(),
            false,
            false,
            false,
            false,
        )
        .unwrap();

        let result_unsupported = check(
            &"sha256".to_string(),
            PathBuf::from(base_path.clone() + "/tests/test.unsupported").as_path(),
            false,
            false,
            false,
            false,
        )
        .unwrap();
        let control_fail = CheckResult {
            total: 1,
            mismatch: 1,
            hash_fail: 0,
            invalid: 0,
            unsupported: 0,
        };
        let control_invalid = CheckResult {
            total: 1,
            mismatch: 0,
            hash_fail: 0,
            invalid: 1,
            unsupported: 0,
        };
        let control_hashfail = CheckResult {
            total: 1,
            mismatch: 0,
            hash_fail: 1,
            invalid: 0,
            unsupported: 0,
        };
        let control_unsupported = CheckResult {
            total: 1,
            mismatch: 0,
            hash_fail: 0,
            invalid: 0,
            unsupported: 1,
        };

        assert_eq!(result_fail, control_fail);
        assert_eq!(result_invalid, control_invalid);
        assert_eq!(result_hashfail, control_hashfail);
        assert_eq!(result_unsupported, control_unsupported);
    }

    #[test]
    fn test_exclude() {
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests");
        let exclude = vec![String::from("test*")];
        let walker = get_walker(
            &file,
            WalkerOptions {
                exclude: Some(exclude),
                include: None,
                max_depth: None,
                max_filesize: None,
                follow_links: true,
                hidden: true,
                no_git_exclude: false,
                no_gitignore: false,
                no_global_gitignore: false,
                no_ignore: false,
                no_parents: false,
            },
        )
        .unwrap();

        // Algo isn't important here
        let result =
            hash_and_walk(walker, false, false, "blake3", false, false, false, None, 1).unwrap();
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
            WalkerOptions {
                exclude: Some(exclude),
                include: Some(include),
                max_depth: None,
                max_filesize: None,
                follow_links: true,
                hidden: true,
                no_git_exclude: false,
                no_gitignore: false,
                no_global_gitignore: false,
                no_ignore: false,
                no_parents: false,
            },
        )
        .unwrap();

        // Algo isn't important here
        let result = hash_and_walk(
            walker, false, false, "blake3", true, false, false, None, 100,
        )
        .unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_output() {
        use tempfile::NamedTempFile;
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests");
        let opts = WalkerOptions {
            no_git_exclude: false,
            exclude: None,
            include: None,
            max_depth: None,
            max_filesize: None,
            follow_links: true,
            hidden: true,
            no_ignore: false,
            no_gitignore: false,
            no_global_gitignore: false,
            no_parents: false,
        };
        let walker = get_walker(&file, opts).unwrap();

        // Algo isn't important here
        let result = hash_and_walk(
            walker, false, false, "blake3", false, false, false, None, 100,
        )
        .unwrap();
        let output = NamedTempFile::new().unwrap();

        write_results(output.path(), &result, "blake3", false, false).unwrap();
        write_results(output.path(), &result, "blake3", true, false).unwrap();

        let result = check(
            &"blake3".to_string(),
            output.path(),
            false,
            true,
            true,
            false,
        );
        output.close().unwrap();

        assert!(result.is_ok());
    }

    #[test]
    fn test_inline_output() {
        use tempfile::NamedTempFile;
        let base_path = env::var("CARGO_MANIFEST_DIR").unwrap();
        let file = PathBuf::from(base_path + "/tests");
        let opts = WalkerOptions {
            no_git_exclude: false,
            exclude: None,
            include: None,
            max_depth: None,
            max_filesize: None,
            follow_links: true,
            hidden: true,
            no_ignore: false,
            no_gitignore: false,
            no_global_gitignore: false,
            no_parents: false,
        };
        let walker = get_walker(&file, opts).unwrap();

        // Algo isn't important here
        let output = NamedTempFile::new().unwrap();

        let _ = hash_and_walk(
            walker,
            false,
            false,
            "blake3",
            false,
            false,
            false,
            Some(output.path().to_owned()),
            100,
        )
        .unwrap();

        let result = check(
            &"blake3".to_string(),
            output.path(),
            false,
            true,
            true,
            false,
        );
        output.close().unwrap();

        assert!(result.is_ok());
    }
}
