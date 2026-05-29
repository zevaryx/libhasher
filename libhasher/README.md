# libhasher

A library for hashing text and files

## Basic usage

### Hashing Text

```rs
use libhasher::Hasher;

fn main() {
    let mut hasher = Hasher::new("sha256").unwrap();
    println!("{}", hasher.hash_text("Hello, World!").unwrap());
}
```

### Hashing a File

#### With a progress bar

The progress bar will show on files >= 256MB in size

```rs
use libhasher::Hasher;
use std::path::PathBuf;

fn main() {
    let mut hasher = Hasher::new("blake3").unwrap();
    let progress = true
    let mmap = false; // This only matters for blake3, no other algorithm supports mmap
    let result = hasher.hash_file_progressbar(&PathBuf::from("very_large.file"), progress, mmap, None).unwrap();
    println!("{}", result.hash);
}
```

#### Without a progress bar

```rs
use libhasher::Hasher;
use std::path::PathBuf;
fn main() {
    let mut hasher = Hasher::new("sha256").unwrap();
    let mmap = true; // If an algorithm doesn't support mmap, this flag will get ignored
    let result = hasher.hash_file(&PathBuf::from("Cargo.toml"), mmap).unwrap();
    println!("{}", result.hash);
}
```