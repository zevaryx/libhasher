# hasher-rs

[![Latest Release](https://git.zevaryx.com/zevaryx/hasher-rs/badges/release.svg?label=Latest%20Release)](https://git.zevaryx.com/zevaryx/hasher-rs/releases/latest) ![Test Status](https://git.zevaryx.com/zevaryx/hasher-rs/badges/workflows/test.yml/badge.svg?branch=dev&label=Test%20Status)

A fully-featured recursive hasher application for file validation. Fully compatible with standard hash outputs (i.e. md5sum, sha256sum, etc)

## Usage

```
A simple hasher that supports multiple algorithms and directory traversal

Usage: hasher.exe [OPTIONS] [FILE]

Arguments:
  [FILE]  The file, folder, or stdin to hash [default: -]

Options:
  -a, --algorithm <ALGORITHM>        Must be one of: blake2, blake3, md5, sha1, sha256, sha512, sha3_256, sha3_512, xxh3_128, xxh3_64, xxh64, xxh32, fnv [default: blake3]
  -o, --output <OUTPUT>              Optional. File to save hashsum to
      --no-mmap                      Disable mmap in blake3. Also disables the progress bar for blake3
      --no-progress                  Disable progress bar
  -c, --check                        Switch to hashsum check mode. File must be a hashsum file
  -q, --quiet                        Don't print OK for each successfully verified file
  -s, --status                       Only return status code
      --exclude <EXCLUDE>            Add a path to ignore
      --include <INCLUDE>            Add a path to include
      --max-depth <MAX_DEPTH>        Max recursion depth
      --max-filesize <MAX_FILESIZE>  Max file size to show
      --follow-links                 Follow links
      --hidden                       Walk hidden directories
      --no-ignore                    Ignore .ignore files
      --no-gitignore                 Ignore .gitignore files
      --no-git-exclude               Ignore .git/info/exclude
      --no-global-gitignore          Ignore global gitignore files
      --no-parents                   Ignore parent directory ignore files
      --legacy                       Legacy format (don't print algorithm)
  -h, --help                         Print help
  -V, --version                      Print version
  ```

### Hashing text input

You can also use hasher inline:

`echo "test" | hasher -a sha256`

## Installing

Run the following:

`curl --proto '=https' --tlsv1.2 -sSf https://git.zevaryx.com/zevaryx/hasher-rs/raw/branch/main/install.sh | sh`