use anyhow::anyhow;
use clap::{Parser, ValueEnum};
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use itertools::Itertools;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::ptr::slice_from_raw_parts_mut;
use windows::core::PCWSTR;
use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography::{
    BCryptCreateHash, BCryptFinishHash, BCryptGetProperty, BCryptHashData,
    BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_HASH_LENGTH,
    BCRYPT_HASH_REUSABLE_FLAG, BCRYPT_MD2_ALGORITHM, BCRYPT_MD4_ALGORITHM, BCRYPT_MD5_ALGORITHM,
    BCRYPT_OBJECT_LENGTH, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM,
    BCRYPT_SHA512_ALGORITHM,
};

pub const BUFFER_SIZE: usize = 1024 * 1024 * 2;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[repr(usize)]
enum HashAlgorithm {
    MD2 = 0,
    MD4 = 1,
    MD5 = 2,
    SHA1 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
}

const HASH_ALGORITHM_IDENTIFIERS: [PCWSTR; 7] = [
    BCRYPT_MD2_ALGORITHM,
    BCRYPT_MD4_ALGORITHM,
    BCRYPT_MD5_ALGORITHM,
    BCRYPT_SHA1_ALGORITHM,
    BCRYPT_SHA256_ALGORITHM,
    BCRYPT_SHA384_ALGORITHM,
    BCRYPT_SHA512_ALGORITHM,
];

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct HashfileCLI {
    #[arg(short, long, value_enum)]
    algorithm: Option<HashAlgorithm>,

    /// Whether to print paths as relative to the current directory
    #[arg(short, long, action)]
    relative_paths: bool,

    files: Vec<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = HashfileCLI::parse_from(wild::args_os());
    let algorithm = cli.algorithm.unwrap_or(HashAlgorithm::SHA256);
    let cng_algorithm_identifier = HASH_ALGORITHM_IDENTIFIERS[algorithm as usize];

    let algorithm_name = unsafe { cng_algorithm_identifier.to_string() }?;

    // And here starts a giant "unsafe" block of
    // essentially writing C in Rust.

    unsafe {
        let mut algorithm_provider: BCRYPT_ALG_HANDLE = Default::default();
        let mut hash: BCRYPT_HASH_HANDLE = Default::default();

        let mut hash_object_length: u32 = 0;
        let mut hash_output_size: u32 = 0;

        let mut unused: u32 = 0;

        let mut status = BCryptOpenAlgorithmProvider(
            &mut algorithm_provider,
            cng_algorithm_identifier,
            None,
            BCRYPT_HASH_REUSABLE_FLAG,
        );
        if status != STATUS_SUCCESS {
            return Err(anyhow!(
                "Failed to open algorithm provider: {:#010x}",
                status.0
            ));
        }

        status = BCryptGetProperty(
            algorithm_provider,
            BCRYPT_OBJECT_LENGTH,
            Some(&mut *slice_from_raw_parts_mut::<u8>(
                std::mem::transmute(&mut hash_object_length),
                4,
            )),
            &mut unused,
            0,
        );
        if status != STATUS_SUCCESS {
            return Err(anyhow!(
                "Failed call to BCryptGetProperty: {:#010x}",
                status.0
            ));
        }

        status = BCryptGetProperty(
            algorithm_provider,
            BCRYPT_HASH_LENGTH,
            Some(&mut *slice_from_raw_parts_mut::<u8>(
                std::mem::transmute(&mut hash_output_size),
                4,
            )),
            &mut unused,
            0,
        );
        if status != STATUS_SUCCESS {
            return Err(anyhow!(
                "Failed call to BCryptGetProperty: {:#010x}",
                status.0
            ));
        }

        let mut hash_object = vec![0u8; hash_object_length as usize].into_boxed_slice();

        status = BCryptCreateHash(
            algorithm_provider,
            &mut hash,
            Some(&mut *hash_object),
            None,
            0,
        );
        if status != STATUS_SUCCESS {
            return Err(anyhow!(
                "Failed call to BCryptCreateHash: {:#010x}",
                status.0
            ));
        }

        let file_list: Vec<PathBuf> = cli
            .files
            .iter()
            .filter(|p| if p.exists() { !p.is_dir() } else { true })
            .filter_map(|p| {
                dunce::canonicalize(p)
                    .inspect_err(|e| {
                        eprintln!("Failed to read file or directory {}: {}", p.display(), e);
                    })
                    .ok()
            })
            .unique()
            .collect();

        let mut total_len: u64 = 0;

        for file in &file_list {
            let metadata = file.metadata()?;
            total_len += metadata.len();
        }

        eprintln!(
            "Total length of {} file(s): {}",
            file_list.len(),
            HumanBytes(total_len)
        );

        let bar = ProgressBar::new(total_len);
        bar.set_style(
            ProgressStyle::with_template(
                "{msg} [{bar:30}] ({bytes}/{total_bytes}) [{bytes_per_sec}]",
            )?
            .progress_chars("=> "),
        );

        let mut input_buffer = vec![0u8; BUFFER_SIZE].into_boxed_slice();
        for path in &file_list {
            let relative_path = if cli.relative_paths {
                pathdiff::diff_paths(path, std::env::current_dir()?)
            } else {
                None
            };

            let mut file = File::open(path)?;
            let mut digest = vec![0u8; hash_output_size as usize].into_boxed_slice();

            bar.set_message(format!(
                "Hashing file {}...",
                relative_path.as_ref().unwrap_or(path).display()
            ));

            loop {
                let bytes_read = file.read(&mut input_buffer)?;
                if bytes_read == 0 {
                    break;
                };
                let input_bytes = &input_buffer[..bytes_read];

                status = BCryptHashData(hash, input_bytes, 0);
                if status != STATUS_SUCCESS {
                    return Err(anyhow!("Failed call to BCryptHashData: {:#010x}", status.0));
                }

                bar.inc(bytes_read as u64);
            }

            status = BCryptFinishHash(hash, &mut *digest, 0);
            if status != STATUS_SUCCESS {
                return Err(anyhow!(
                    "Failed call to BCryptFinishHash: {:#010x}",
                    status.0
                ));
            }

            bar.println(format!(
                "[{}] {}: {}",
                algorithm_name,
                relative_path.as_ref().unwrap_or(path).display(),
                hex::encode(digest)
            ));
        }

        bar.finish_and_clear();
    }

    // We don't need to de-initialize any states at this point,
    // since the program will exit.

    Ok(())
}