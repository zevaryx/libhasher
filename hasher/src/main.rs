use anyhow::{anyhow, Result};
use clap::Parser;
use clap_stdin::FileOrStdin;
use colored::Colorize;
use ignore::{overrides::OverrideBuilder, Walk, WalkBuilder};
use libhasher::{HashResult, Hasher};
#[cfg(not(tarpaulin_include))]
use std::process::ExitCode;
use std::{
    borrow::Cow,
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
        for i in include {
            over.add(i.strip_prefix('!').unwrap_or(&i))?;
        }
    }
    walker.overrides(over.build()?);
    Ok(walker.build())
}

/// Escape a filename containing control characters (e.g. newlines) so it can't
/// break the hashsum format or reach the terminal. Like GNU coreutils, returns a
/// `\` to start the line with, and escapes `\`, `\n` and `\r`
fn escape_filename(name: &str) -> (&'static str, Cow<'_, str>) {
    if !name.contains(|c: char| c.is_control() && c != '\t') {
        return ("", Cow::Borrowed(name));
    }
    let mut escaped = String::with_capacity(name.len() + 8);
    for c in name.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            c if c.is_control() && c != '\t' => escaped.push_str(&format!("\\x{:02x}", c as u32)),
            c => escaped.push(c),
        }
    }
    ("\\", Cow::Owned(escaped))
}

/// Undo `escape_filename`, returning `None` for an invalid escape
fn unescape_filename(name: &str) -> Option<String> {
    let mut unescaped = String::with_capacity(name.len());
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            unescaped.push(c);
            continue;
        }
        match chars.next()? {
            '\\' => unescaped.push('\\'),
            'n' => unescaped.push('\n'),
            'r' => unescaped.push('\r'),
            'x' => {
                let hex: String = chars.by_ref().take(2).collect();
                unescaped.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            _ => return None,
        }
    }
    Some(unescaped)
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
    // "-" reads the hashsums from stdin
    let reader: Box<dyn BufRead> = if path == Path::new("-") {
        Box::new(io::stdin().lock())
    } else {
        Box::new(io::BufReader::new(fs::File::open(path)?))
    };
    let lines = reader.lines();
    let mut total = 0;
    let mut mismatch: u64 = 0;
    let mut hash_fail: u64 = 0;
    let mut invalid: u64 = 0;
    let mut unsupported: u64 = 0;

    let mut main_hasher = Hasher::new(main_algo)?;

    let progress = progress && (!quiet && !status);

    for line in lines {
        let line = match line {
            Ok(line) => line,
            // Skip lines that aren't valid UTF-8 like any other malformed line,
            // instead of silently ending the check early
            Err(e) if e.kind() == io::ErrorKind::InvalidData => continue,
            Err(e) => return Err(e.into()),
        };
        // A leading backslash means the filename is escaped
        let (escaped, line) = match line.strip_prefix('\\') {
            Some(line) => (true, line),
            None => (false, line.as_str()),
        };
        if let Some((hash, filename)) = line.split_once("  ") {
            let filename = if !escaped {
                Cow::Borrowed(filename)
            } else if let Some(filename) = unescape_filename(filename) {
                Cow::Owned(filename)
            } else {
                continue;
            };
            let path = Path::new(&*filename);
            // Show the filename escaped, the same way it's written
            let (prefix, shown) = escape_filename(&filename);
            let filename = format!("{prefix}{shown}");
            total += 1;
            // Lines without an algorithm prefix use the main algorithm
            let (algo, proper_hash) = hash.split_once(':').unwrap_or((main_algo, hash));
            let result = if algo == main_algo {
                main_hasher.hash_file_progressbar(path, progress, mmap, None)
            } else if let Ok(mut h) = Hasher::new(algo) {
                h.hash_file_progressbar(path, progress, mmap, None)
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
            };
            match result {
                Ok(result) => {
                    if result.hash.eq_ignore_ascii_case(proper_hash) {
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
                    if !status {
                        println!("{}: {}", filename.bright_cyan(), "HASH_FAIL".bright_red());
                    }
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
    path: Option<&Path>,
    queue_size: usize,
) -> Result<Vec<HashResult>> {
    let mut hasher = Hasher::new(algo)?;
    let mut hash_results: Vec<HashResult> = Vec::new();
    // The first write replaces any existing output file, later ones add to it
    let mut append = false;
    // Skip entries that can't be read (e.g. permission denied, dangling
    // symlinks) instead of silently ending the walk at the first one
    for entry in walker.filter_map(Result::ok) {
        if !entry.path().is_file() {
            continue;
        }
        let result = hasher.hash_file_progressbar(
            entry.path(),
            progress && (!status && !quiet),
            mmap,
            None,
        )?;
        if !status && !quiet {
            print_result(&result, algo, legacy);
        }
        hash_results.push(result);
        if hash_results.len() > queue_size {
            if let Some(p) = &path {
                write_results(p, &hash_results, algo, legacy, append)?;
                append = true;
            }
            hash_results.clear();
        }
    }

    if let Some(p) = &path {
        write_results(p, &hash_results, algo, legacy, append)?;
    }

    Ok(hash_results)
}

fn print_result(result: &HashResult, algo: &str, legacy: bool) {
    let (prefix, filename) = escape_filename(&result.filename);
    let hash = &result.hash;
    if legacy {
        println!(
            "{}{}  {}",
            prefix,
            hash.bright_green(),
            filename.bright_cyan()
        );
    } else {
        println!(
            "{}{}:{}  {}",
            prefix,
            algo.bright_yellow(),
            hash.bright_green(),
            filename.bright_blue()
        );
    }
}

fn write_results(
    path: &Path,
    results: &[HashResult],
    algo: &str,
    legacy: bool,
    append: bool,
) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .append(append)
        .truncate(!append)
        .create(true)
        .open(path)?;
    let mut file = BufWriter::new(file);

    for res in results {
        let (prefix, filename) = escape_filename(&res.filename);
        let hash = &res.hash;
        if legacy {
            writeln!(file, "{}{}  {}", prefix, hash, filename)?;
        } else {
            writeln!(file, "{}{}:{}  {}", prefix, algo, hash, filename)?;
        }
    }

    // BufWriter ignores errors when flushing on drop (e.g. a full disk)
    file.flush()?;
    Ok(())
}

#[cfg(not(tarpaulin_include))]
fn process_non_stdin(args: &Args) -> Result<()> {
    let file = PathBuf::from(args.file.filename());
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
                if result.hash_fail > 0 {
                    if !args.status {
                        println!(
                            "{}: {} listed file(s) could not be read",
                            "WARNING".bright_red(),
                            result.hash_fail
                        );
                    }
                    error = true;
                }
                if result.unsupported > 0 {
                    if !args.status {
                        println!(
                            "{}: {} checksum(s) use an unsupported algorithm",
                            "WARNING".bright_red(),
                            result.unsupported
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
        // The walker yields nothing for a path that can't be read, so check it first
        fs::metadata(&file).map_err(|e| anyhow!("{}: {}", file.display(), e))?;
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
        let _ = hash_and_walk(
            walker,
            !args.no_progress,
            !args.no_mmap,
            args.algorithm.as_str(),
            args.legacy,
            args.status,
            args.quiet,
            args.output.as_deref(),
            args.buffer_size,
        )?;
        Ok(())
    }
}

#[cfg(not(tarpaulin_include))]
fn process_stdin(args: &Args) -> Result<()> {
    let mut hasher = Hasher::new(&args.algorithm)?;
    let result = HashResult {
        filename: String::from("-"),
        hash: hasher.hash_stream(&mut args.file.clone().into_reader()?)?,
    };
    if !args.status && !args.quiet {
        print_result(&result, &args.algorithm, args.legacy);
    }
    if let Some(p) = &args.output {
        write_results(p, &[result], &args.algorithm, args.legacy, false)?;
    }
    Ok(())
}

#[cfg(not(tarpaulin_include))]
pub fn main() -> ExitCode {
    let args = Args::parse();
    // We need to validate status and/or quiet
    if (args.status || args.quiet) && !args.check && args.output.is_none() {
        eprintln!(
            "{}: quiet and status modes require check mode or output",
            "ERROR".bright_red()
        );
        return ExitCode::FAILURE;
    }
    let is_stdin = args.file.is_stdin();
    // Check mode reads the hashsums from stdin itself
    let res: Result<()> = if is_stdin && !args.check {
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
    static TEST_CASES: &[(&str, &str)] = &[
        ("blake3", "68569ddf344009b938e1db0ec39b151b1626cfe46a87c3910dc18936a233f92b"),
        ("md5", "0cbc6611f5540bd0809a388dc95a615b"),
        ("sha1", "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa"),
        ("sha256", "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"),
        ("sha512", "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31"),
        ("sha3_256", "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0"),
        ("sha3_512", "301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7"),
        ("blake2", "3d896914f86ae22c48b06140adb4492fa3f8e2686a83cec0c8b1dcd6903168751370078bbd6bbfe02a6ab1df12a19b5991b58e65e243ec279f6a5770b2dd0e31"),
        ("xxh3_128", "391c8305c491690bc2da658a2d6348d5"),
        ("xxh3_64", "b3f5bb77a55fad5e"),
        ("xxh64", "da83efc38a8922b4"),
        ("xxh32", "eac53571"),
        ("fnv","2474e7fb1aec9f05"),
    ];

    fn get_test_file(name: &str) -> PathBuf {
        let base = env::var("CARGO_MANIFEST_DIR").unwrap();
        PathBuf::from(base).join("tests").join(name)
    }

    #[test]
    fn test_hash_file_progressbar() {
        let file = get_test_file("test.txt");
        for (algorithm, expected) in TEST_CASES {
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
            let hash_result = result.first().unwrap();
            assert_eq!(
                hash_result.hash, *expected,
                "Hash mishmatch for algorithm: {algorithm}"
            );
        }
    }

    #[test]
    fn test_check_file() {
        for (algorithm, _) in TEST_CASES {
            let file = get_test_file(&("test.txt.".to_owned() + algorithm));
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

        for (algorithm, expected) in TEST_CASES {
            let mut hasher = Hasher::new(&algorithm.to_string()).unwrap();
            let result = hasher.hash_text(&test_txt);
            let hash = result.unwrap();
            assert_eq!(hash, *expected, "Hash mismatch for algorithm: {algorithm}");
        }
    }

    #[test]
    fn test_fail() {
        let result_fail = check(
            &"sha256".to_string(),
            &get_test_file("test.fail"),
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

        assert_eq!(
            result_fail, control_fail,
            "Failed to catch failures properly"
        );
    }

    #[test]
    fn test_invalid() {
        let result_invalid = check(
            &"sha256".to_string(),
            &get_test_file("test.invalid"),
            false,
            false,
            false,
            false,
        )
        .unwrap();

        let control_invalid = CheckResult {
            total: 1,
            mismatch: 0,
            hash_fail: 0,
            invalid: 1,
            unsupported: 0,
        };

        assert_eq!(
            result_invalid, control_invalid,
            "Failed to catch failures properly"
        );
    }

    #[test]
    fn test_hashfail() {
        let result_hashfail = check(
            &"sha256".to_string(),
            &get_test_file("test.hashfail"),
            false,
            false,
            false,
            false,
        )
        .unwrap();

        let control_hashfail = CheckResult {
            total: 1,
            mismatch: 0,
            hash_fail: 1,
            invalid: 0,
            unsupported: 0,
        };

        assert_eq!(
            result_hashfail, control_hashfail,
            "Failed to catch failed hashes properly"
        );
    }

    #[test]
    fn test_unsupported() {
        let result_unsupported = check(
            &"sha256".to_string(),
            &get_test_file("test.unsupported"),
            false,
            false,
            false,
            false,
        )
        .unwrap();

        let control_unsupported = CheckResult {
            total: 1,
            mismatch: 0,
            hash_fail: 0,
            invalid: 0,
            unsupported: 1,
        };

        assert_eq!(
            result_unsupported, control_unsupported,
            "Failed to catch unsupported properly"
        );
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
        assert_eq!(result.len(), 0, "Failed to exclude expected files");
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
        assert_eq!(result.len(), 1, "Failed to include expected files");
    }

    #[test]
    fn test_output_modern() {
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

        let result = check(
            &"blake3".to_string(),
            output.path(),
            false,
            true,
            true,
            false,
        );

        assert!(result.is_ok(), "Failed to save to file as expected");

        let contents = fs::read_to_string(output.path()).unwrap();
        println!("Contents of output file:\n{}", contents);
        assert!(
            contents.contains("blake3:"),
            "Expected algo prefix in output"
        );
        assert!(
            contents.lines().count() > 0,
            "Output file should not be empty"
        );

        output.close().unwrap();
    }

    #[test]
    fn test_output_legacy() {
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

        write_results(output.path(), &result, "blake3", true, false).unwrap();

        let result = check(
            &"blake3".to_string(),
            output.path(),
            false,
            true,
            true,
            false,
        );

        assert!(result.is_ok(), "Failed to save to file as expected");

        let contents = fs::read_to_string(output.path()).unwrap();
        println!("Contents of output file:\n{}", contents);
        assert!(
            !contents.contains("blake3:"),
            "Expected no algo prefix in output"
        );
        assert!(
            contents.lines().count() > 0,
            "Output file should not be empty"
        );

        output.close().unwrap();
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
            Some(output.path()),
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

        assert!(result.is_ok(), "Inline output failed");

        let contents = fs::read_to_string(output.path()).unwrap();
        assert!(
            contents.contains("blake3:"),
            "Expected algo prefix in output"
        );
        assert!(
            contents.lines().count() > 0,
            "Output file should not be empty"
        );

        output.close().unwrap();
    }

    #[test]
    fn test_inline_output_buffer_flush() {
        use tempfile::NamedTempFile;
        let file = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("tests");
        let walker = get_walker(
            &file,
            WalkerOptions {
                exclude: Some(vec![String::from("*.large")]),
                include: None,
                max_depth: None,
                max_filesize: None,
                follow_links: true,
                hidden: true,
                no_ignore: false,
                no_gitignore: false,
                no_git_exclude: false,
                no_global_gitignore: false,
                no_parents: false,
            },
        )
        .unwrap();

        let output = NamedTempFile::new().unwrap();

        let result = hash_and_walk(
            walker,
            false,
            false,
            "blake3",
            false,
            false,
            false,
            Some(output.path()),
            1,
        )
        .unwrap();

        assert!(!result.is_empty(), "Expected at least one result");

        let contents = fs::read_to_string(output.path()).unwrap();
        assert!(
            contents.contains("blake3:"),
            "Expected algo prefix after mid-loop flush"
        );
        assert!(
            contents.lines().count() > 0,
            "Output file should not be empty after flush"
        );

        output.close().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_walk_skips_non_files() {
        use std::os::unix::fs::symlink;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();

        let real_file = dir.path().join("real.txt");
        fs::write(&real_file, b"hello").unwrap();

        let dangling = dir.path().join("dangling.txt");
        symlink(dir.path().join("nonexistent.txt"), &dangling).unwrap();

        let walker = get_walker(
            &dir.path().to_path_buf(),
            WalkerOptions {
                exclude: None,
                include: None,
                max_depth: None,
                max_filesize: None,
                follow_links: false,
                hidden: true,
                no_ignore: false,
                no_gitignore: false,
                no_git_exclude: false,
                no_global_gitignore: false,
                no_parents: false,
            },
        )
        .unwrap();

        let result = hash_and_walk(
            walker, false, false, "blake3", false, false, false, None, 100,
        )
        .unwrap();

        assert_eq!(result.len(), 1, "Dangling symlink should be skipped");
        assert!(result[0].filename.contains("real.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn test_walk_continues_past_errors() {
        use std::os::unix::fs::symlink;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("file{i}.txt")), b"hello").unwrap();
        }

        // Following a dangling symlink makes the walker yield an error
        let dangling = dir.path().join("dangling.txt");
        symlink(dir.path().join("nonexistent.txt"), &dangling).unwrap();

        let walker = get_walker(
            &dir.path().to_path_buf(),
            WalkerOptions {
                exclude: None,
                include: None,
                max_depth: None,
                max_filesize: None,
                follow_links: true,
                hidden: true,
                no_ignore: false,
                no_gitignore: false,
                no_git_exclude: false,
                no_global_gitignore: false,
                no_parents: false,
            },
        )
        .unwrap();

        let result = hash_and_walk(
            walker, false, false, "blake3", false, false, false, None, 100,
        )
        .unwrap();

        assert_eq!(
            result.len(),
            10,
            "Walk should continue past entries it can't read"
        );
    }

    #[test]
    fn test_check_skips_non_utf8_lines() {
        use tempfile::NamedTempFile;
        let (algorithm, expected) = TEST_CASES[0];
        let file = get_test_file("test.txt");

        let mut sums = NamedTempFile::new().unwrap();
        writeln!(sums, "{}  {}", expected, file.display()).unwrap();
        sums.write_all(b"not utf-8 \xff  file\n").unwrap();
        writeln!(sums, "{}  {}", "0".repeat(expected.len()), file.display()).unwrap();
        sums.flush().unwrap();

        let result = check(algorithm, sums.path(), false, false, true, false).unwrap();

        let control = CheckResult {
            total: 2,
            mismatch: 1,
            hash_fail: 0,
            invalid: 0,
            unsupported: 0,
        };

        assert_eq!(
            result, control,
            "Lines after a non-UTF-8 line should still be checked"
        );
    }

    #[test]
    fn test_write_results_truncates() {
        use tempfile::NamedTempFile;
        let output = NamedTempFile::new().unwrap();
        fs::write(
            output.path(),
            "stale contents longer than the new ones\n".repeat(10),
        )
        .unwrap();

        let results = [HashResult {
            filename: String::from("file.txt"),
            hash: String::from("abcd"),
        }];
        write_results(output.path(), &results, "blake3", false, false).unwrap();

        let contents = fs::read_to_string(output.path()).unwrap();
        assert_eq!(
            contents, "blake3:abcd  file.txt\n",
            "Writing without append should replace old contents"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_escaped_filename_round_trip() {
        use tempfile::{NamedTempFile, TempDir};

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("new\nline\\\x1b.txt"), b"hello").unwrap();
        let walker = get_walker(
            &dir.path().to_path_buf(),
            WalkerOptions {
                exclude: None,
                include: None,
                max_depth: None,
                max_filesize: None,
                follow_links: false,
                hidden: true,
                no_ignore: false,
                no_gitignore: false,
                no_git_exclude: false,
                no_global_gitignore: false,
                no_parents: false,
            },
        )
        .unwrap();

        let output = NamedTempFile::new().unwrap();
        hash_and_walk(
            walker,
            false,
            false,
            "blake3",
            false,
            false,
            false,
            Some(output.path()),
            100,
        )
        .unwrap();

        let contents = fs::read_to_string(output.path()).unwrap();
        assert_eq!(
            contents.lines().count(),
            1,
            "Filename should stay on one line"
        );
        assert!(
            !contents.contains('\x1b'),
            "Control characters should be escaped"
        );

        let result = check("blake3", output.path(), false, false, true, false).unwrap();
        let control = CheckResult {
            total: 1,
            mismatch: 0,
            hash_fail: 0,
            invalid: 0,
            unsupported: 0,
        };
        assert_eq!(result, control, "Escaped filename should check back");
    }
}
