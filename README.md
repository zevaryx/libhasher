# hasher-rs

A fully-featured recursive hasher application for file validation. Fully compatible with standard hash outputs (i.e. md5sum, sha256sum, etc)

## Usage

```
A simple hasher that supports multiple algorithms and directory traversal

Usage: hasher [OPTIONS] <FILE>

Arguments:
  <FILE>  The file or folder to hash

Options:
  -a, --algorithm <ALGORITHM>  Must be one of: blake2, blake3, md5, sha1, sha256, sha512, sha3_256, sha3_512, xxh3_128, xxh3_64, xxh64, xxh32, fnv [default: blake3]
  -o, --output <OUTPUT>        Optional. File to save hashsum to
      --no-mmap                Disable mmap in blake3. Also disables the progress bar for blake3
  -c, --check                  Switch to hashsum check mode. File must be a hashsum file
  -s, --symlinks               Follow symlinks
  -h, --help                   Print help
  -V, --version                Print version
  ```

## Installing

Run the following:

`curl --proto '=https' --tlsv1.2 -sSf https://git.zevaryx.com/zevaryx/hasher-rs/raw/branch/main/install.sh | sh`