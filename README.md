# hashfile-rs
A file hashing utility for Windows utilizing the CNG API.

# Installation
```
$ cargo build --release
$ move target\release\hashfile.exe \where\ever
```

# Usage
```
$ hashfile --help
$ hashfile *
$ hashfile -a md5 -- *
# quickly generate a checksum of all files in a directory
$ hashfile --relative-paths -- * > checksum.txt 
```
