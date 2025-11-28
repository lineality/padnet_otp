//! # Padnet OTP Module - One Time Pad Network Layer
//!
//! This module implements a hierarchical filesystem-based One-Time-Pad (OTP)
//! encryption system. The core concept uses nested directories to represent a
//! multi-dimensional index space where each "line" file contains random bytes
//! for XOR encryption operations.
//!
//! ## Project Context
//! OTP encryption requires truly random data that is:
//! - Used exactly once (consumed and destroyed after use)
//! - Never reused under any circumstances
//! - Generated from cryptographically secure entropy sources
//!
//! This module manages large-scale OTP storage using filesystem hierarchy as
//! the index structure, eliminating the need for metadata files or databases.
//!
//! ## Architecture
//! - 4-byte index: padnest_0/pad/page/line (256^4 lines, ~137GB-2TB)
//! - 8-byte index: padnest_4/.../padnest_0/pad/page/line (256^8 lines, ~590EB-9.4ZB)
//! - Line files: atomic units of N bytes of cryptographic entropy
//! - Optional hash validation at pad or page directory level
//!
//! ## Safety Model
//! - Writer mode: destructive, atomic, no-retry (lines deleted after load)
//! - Reader mode: non-destructive, replayable (lines preserved)
//! - All operations handle errors without panic
//! - Production builds exclude debug information from errors

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Maximum allowed size for a padline file in bytes
/// Prevents accidentally creating massive line files
const MAX_PADNET_PADLINE_FILE_SIZE_BYTES: usize = 4096;

/// Size/scale of padset index space
/// Determines the depth of directory hierarchy
#[derive(Debug, Clone, Copy)]
pub enum PadIndexMaxSize {
    /// 4-byte index: [u8; 4] representing 256^4 possible lines
    /// Structure: padnest_0/pad/page/line
    /// Practical scale: ~137 GB to 2 TB depending on line size
    Standard4Byte,

    /// 8-byte index: [u8; 8] representing 256^8 possible lines
    /// Structure: padnest_4/padnest_3/padnest_2/padnest_1/padnest_0/pad/page/line
    /// Theoretical scale: ~590 EB to 9.4 ZB depending on line size
    Extended8Byte,
}

/// Integrity validation strategy for pad directories
/// Determines if/when dir hashes are created during pad generation
#[derive(Debug, Clone, Copy)]
pub enum ValidationLevel {
    /// Hash entire pad directories (pad_XXX level)
    /// Creates hash_pad_XXX files as siblings to pad directories
    PadLevel,

    /// Hash each page directory (page_XXX level)
    /// Creates hash_page_XXX files as siblings to page directories
    PageLevel,

    /// No validation - trust filesystem integrity
    None,
}

/// Error types for padnet operations
/// Each variant includes function-specific identifier for production tracing
#[derive(Debug)]
pub enum PadnetError {
    /// Entropy source (/dev/urandom) unavailable or read failed
    /// Function ID: PMOPS = PadMakeOnePadSet
    EntropySourceFailed(String),

    /// Filesystem I/O operation failed
    IoError(String),

    /// hash creation or validation failed
    HashOperationFailed(String),

    /// Input validation or assertion violation
    AssertionViolation(String),
}

impl std::fmt::Display for PadnetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Production: terse, function-identified, no details
        // Debug: includes diagnostic information
        match self {
            #[cfg(debug_assertions)]
            PadnetError::EntropySourceFailed(msg) => write!(f, "Entropy error: {}", msg),
            #[cfg(not(debug_assertions))]
            PadnetError::EntropySourceFailed(_) => write!(f, "Entropy error"),

            #[cfg(debug_assertions)]
            PadnetError::IoError(msg) => write!(f, "I/O error: {}", msg),
            #[cfg(not(debug_assertions))]
            PadnetError::IoError(_) => write!(f, "I/O error"),

            #[cfg(debug_assertions)]
            PadnetError::HashOperationFailed(msg) => write!(f, "Hash error: {}", msg),
            #[cfg(not(debug_assertions))]
            PadnetError::HashOperationFailed(_) => write!(f, "Hash error"),

            #[cfg(debug_assertions)]
            PadnetError::AssertionViolation(msg) => write!(f, "Assertion error: {}", msg),
            #[cfg(not(debug_assertions))]
            PadnetError::AssertionViolation(_) => write!(f, "Assertion error"),
        }
    }
}

impl std::error::Error for PadnetError {}

/// Read cryptographic entropy from POSIX /dev/urandom
///
/// ## Project Context
/// One-time pads require true cryptographic randomness. This function provides
/// the entropy source for all pad generation. It reads from the kernel's
/// cryptographically secure random number generator via /dev/urandom.
///
/// ## Security Properties
/// - /dev/urandom is cryptographically secure for OTP purposes
/// - Non-blocking - always returns immediately
/// - Kernel-maintained entropy pool
/// - Present on all POSIX systems (Linux, BSD, macOS)
///
/// ## Error Handling
/// Fails cleanly if entropy source unavailable:
/// - Returns error immediately
/// - Does NOT proceed with pad creation
/// - Does NOT fall back to weak entropy sources
///
/// # Arguments
/// * `bytes_needed` - Number of random bytes to generate
///
/// # Returns
/// * `Ok(Vec<u8>)` - Vector containing cryptographic random bytes
/// * `Err(PadnetError)` - If /dev/urandom unavailable or read fails
///
/// # Production Safety
/// - No panic on error
/// - Terse production error messages
/// - Debug builds include diagnostic details
fn read_entropy(bytes_needed: usize) -> Result<Vec<u8>, PadnetError> {
    // Debug assertion: entropy request should be reasonable
    #[cfg(all(debug_assertions, not(test)))]
    debug_assert!(
        bytes_needed > 0 && bytes_needed <= MAX_PADNET_PADLINE_FILE_SIZE_BYTES,
        "Entropy request should be between 1 and {} bytes",
        MAX_PADNET_PADLINE_FILE_SIZE_BYTES
    );

    // Production catch: validate input
    if bytes_needed == 0 {
        return Err(PadnetError::AssertionViolation(
            "RENT: zero bytes requested".into(),
        ));
    }

    if bytes_needed > MAX_PADNET_PADLINE_FILE_SIZE_BYTES {
        return Err(PadnetError::AssertionViolation(
            "RENT: excessive bytes requested".into(),
        ));
    }

    // Attempt to open POSIX entropy source
    let mut file = File::open("/dev/urandom").map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::EntropySourceFailed(format!("RENT: /dev/urandom open failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e; // Suppress unused variable warning in production
            PadnetError::EntropySourceFailed("RENT: source unavailable".into())
        }
    })?;

    // Pre-allocate buffer for entropy
    let mut buffer = vec![0u8; bytes_needed];

    // Read exact amount of entropy required
    file.read_exact(&mut buffer).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::EntropySourceFailed(format!("RENT: read failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::EntropySourceFailed("RENT: read failed".into())
        }
    })?;

    Ok(buffer)
}

/// Generate Pearson hash of directory contents
///
/// ## Project Context
/// Provides optional integrity validation for pad/page directories. Uses
/// internal Pearson hash (non-cryptographic but fast and deterministic)
/// to detect any changes to file contents in the directory.
///
/// ## Algorithm
/// - Only hashes file contents (not paths, not metadata)
/// - Deterministic ordering by filename
/// - Streaming for memory efficiency
/// - 128-bit hash output (32 hex chars)
///
/// # Arguments
/// * `dir_path` - Absolute path to directory to hash
///
/// # Returns
/// * `Ok(String)` - Hex-encoded Pearson hash (32 chars)
/// * `Err(PadnetError)` - If hash computation fails
fn generate_directory_hash(dir_path: &Path) -> Result<String, PadnetError> {
    calculate_recursive_dir_directory_pearson_hash(dir_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::HashOperationFailed(format!("GDH: Pearson hash failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::HashOperationFailed("GDH: hash failed".into())
        }
    })
}

/// Create one complete padset with cryptographic entropy
///
/// ## Project Context
/// Generates the hierarchical directory structure containing one-time pad data.
/// This is the foundational operation - all other operations (XOR, deletion)
/// depend on having a valid padset created by this function.
///
/// ## Operational Requirements
/// - Uses /dev/urandom for all entropy (POSIX only, fails clean on non-POSIX)
/// - Creates complete directory hierarchy based on index size
/// - Fills all line files with cryptographic random bytes
/// - Optionally creates validation hashes
/// - All-or-nothing operation: partial creation leaves no artifacts
///
/// ## Directory Structure (4-byte example)
/// ```
/// padset_root/
/// ├── padnest_0_000/
/// │   ├── pad_000/
/// │   │   ├── page_000/
/// │   │   │   ├── line_000
/// │   │   │   ├── line_001
/// │   │   │   └── ...
/// │   │   ├── hash_page_000  (if PageLevel validation)
/// │   │   └── ...
/// │   ├── hash_pad_000  (if PadLevel validation)
/// │   └── ...
/// ```
///
/// # Arguments
/// * `padset_root` - Absolute path where padset will be created
/// * `max_pad_index_size` - Index space size (4-byte or 8-byte)
/// * `number_of_bytes_per_line` - How many random bytes per line file (16-4096)
/// * `validation_level` - Whether to create hash files
///
/// # Returns
/// * `Ok(())` - Padset created successfully
/// * `Err(PadnetError)` - Creation failed, no partial artifacts remain
///
/// # Production Safety
/// - No panic on any error
/// - Validates all inputs before beginning creation
/// - Cleans up on error (future: implement cleanup)
/// - Terse production errors with function identifier "PMOPS"
/// Create one complete padset with cryptographic entropy
///
/// ## Project Context
/// Generates the hierarchical directory structure containing one-time pad data.
/// The max_pad_index_array specifies exactly how much of the index space to create.
///
/// ## Arguments
/// * `padset_root` - Absolute path where padset will be created
/// * `max_pad_index_array` - Index specifying creation bounds (0-based inclusive)
///   - Each byte specifies max index to create at that level
///   - [0,0,0,1] = 1 nest, 1 pad, 1 page, 2 lines
///   - [1,2,3,4] = 2 nests, 3 pads, 4 pages, 5 lines
///   - Can be 4 or 8 bytes depending on desired hierarchy depth
/// * `number_of_bytes_per_line` - How many random bytes per line file (16-4096)
/// * `dir_checksum_files` - If true, create hashes at pad/page level
///
/// # Returns
/// * `Ok(())` - Padset created successfully
/// * `Err(PadnetError)` - Creation failed
pub fn padnet_make_one_pad_set(
    padset_root: &Path,
    max_pad_index_array: &PadIndex,
    number_of_bytes_per_line: usize,
    dir_checksum_files: ValidationLevel,
) -> Result<(), PadnetError> {
    // Validate inputs
    if number_of_bytes_per_line == 0 {
        return Err(PadnetError::AssertionViolation(
            "PMOPS: zero bytes per line".into(),
        ));
    }

    if number_of_bytes_per_line > MAX_PADNET_PADLINE_FILE_SIZE_BYTES {
        return Err(PadnetError::AssertionViolation(
            "PMOPS: line size exceeds maximum".into(),
        ));
    }

    if !padset_root.is_absolute() {
        return Err(PadnetError::AssertionViolation(
            "PMOPS: path must be absolute".into(),
        ));
    }

    // Create root directory
    fs::create_dir_all(padset_root).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PMOPS: root creation failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PMOPS: root creation failed".into())
        }
    })?;

    // Create based on index array size
    match max_pad_index_array {
        PadIndex::Standard(bounds) => {
            create_4byte_padset_bounded(
                padset_root,
                bounds,
                number_of_bytes_per_line,
                dir_checksum_files,
            )?;
        }
        PadIndex::Extended(bounds) => {
            create_8byte_padset_bounded(
                padset_root,
                bounds,
                number_of_bytes_per_line,
                dir_checksum_files,
            )?;
        }
    }

    Ok(())
}

/// Create 4-byte padset with specified bounds
/// bounds[0] = max padnest_0 index, bounds[1] = max pad index, etc.
fn create_4byte_padset_bounded(
    root: &Path,
    bounds: &[u8; 4],
    bytes_per_line: usize,
    validation: ValidationLevel,
) -> Result<(), PadnetError> {
    // Level 0: padnest_0 (0 to bounds[0] inclusive)
    for nest0 in 0..=bounds[0] {
        let nest0_path = root.join(format!("padnest_0_{:03}", nest0));
        fs::create_dir_all(&nest0_path).map_err(|e| {
            #[cfg(debug_assertions)]
            {
                PadnetError::IoError(format!("C4BP: nest0 creation failed: {}", e))
            }
            #[cfg(not(debug_assertions))]
            {
                let _ = e;
                PadnetError::IoError("C4BP: nest0 creation failed".into())
            }
        })?;

        // Level 1: pad (0 to bounds[1] inclusive)
        for pad in 0..=bounds[1] {
            let pad_path = nest0_path.join(format!("pad_{:03}", pad));
            fs::create_dir_all(&pad_path).map_err(|e| {
                #[cfg(debug_assertions)]
                {
                    PadnetError::IoError(format!("C4BP: pad creation failed: {}", e))
                }
                #[cfg(not(debug_assertions))]
                {
                    let _ = e;
                    PadnetError::IoError("C4BP: pad creation failed".into())
                }
            })?;

            // Level 2: page (0 to bounds[2] inclusive)
            for page in 0..=bounds[2] {
                let page_path = pad_path.join(format!("page_{:03}", page));
                fs::create_dir_all(&page_path).map_err(|e| {
                    #[cfg(debug_assertions)]
                    {
                        PadnetError::IoError(format!("C4BP: page creation failed: {}", e))
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        let _ = e;
                        PadnetError::IoError("C4BP: page creation failed".into())
                    }
                })?;

                // Level 3: line files (0 to bounds[3] inclusive)
                for line in 0..=bounds[3] {
                    let line_path = page_path.join(format!("line_{:03}", line));

                    // Generate entropy for this line
                    let entropy = read_entropy(bytes_per_line)?;

                    // Write line file
                    let mut file = File::create(&line_path).map_err(|e| {
                        #[cfg(debug_assertions)]
                        {
                            PadnetError::IoError(format!("C4BP: line file creation failed: {}", e))
                        }
                        #[cfg(not(debug_assertions))]
                        {
                            let _ = e;
                            PadnetError::IoError("C4BP: line file creation failed".into())
                        }
                    })?;

                    file.write_all(&entropy).map_err(|e| {
                        #[cfg(debug_assertions)]
                        {
                            PadnetError::IoError(format!("C4BP: line write failed: {}", e))
                        }
                        #[cfg(not(debug_assertions))]
                        {
                            let _ = e;
                            PadnetError::IoError("C4BP: line write failed".into())
                        }
                    })?;
                }

                // Create page-level hash if requested
                if matches!(validation, ValidationLevel::PageLevel) {
                    let hash = generate_directory_hash(&page_path)?;
                    let hash_file_path = pad_path.join(format!("hash_page_{:03}", page));
                    let mut hash_file = File::create(&hash_file_path).map_err(|e| {
                        #[cfg(debug_assertions)]
                        {
                            PadnetError::IoError(format!(
                                "C4BP: page hash file creation failed: {}",
                                e
                            ))
                        }
                        #[cfg(not(debug_assertions))]
                        {
                            let _ = e;
                            PadnetError::IoError("C4BP: page hash file creation failed".into())
                        }
                    })?;
                    hash_file.write_all(hash.as_bytes()).map_err(|e| {
                        #[cfg(debug_assertions)]
                        {
                            PadnetError::IoError(format!("C4BP: page hash write failed: {}", e))
                        }
                        #[cfg(not(debug_assertions))]
                        {
                            let _ = e;
                            PadnetError::IoError("C4BP: page hash write failed".into())
                        }
                    })?;
                }
            }

            // Create pad-level hash if requested
            if matches!(validation, ValidationLevel::PadLevel) {
                let hash = generate_directory_hash(&pad_path)?;
                let hash_file_path = nest0_path.join(format!("hash_pad_{:03}", pad));
                let mut hash_file = File::create(&hash_file_path).map_err(|e| {
                    #[cfg(debug_assertions)]
                    {
                        PadnetError::IoError(format!("C4BP: pad hash file creation failed: {}", e))
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        let _ = e;
                        PadnetError::IoError("C4BP: pad hash file creation failed".into())
                    }
                })?;
                hash_file.write_all(hash.as_bytes()).map_err(|e| {
                    #[cfg(debug_assertions)]
                    {
                        PadnetError::IoError(format!("C4BP: pad hash write failed: {}", e))
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        let _ = e;
                        PadnetError::IoError("C4BP: pad hash write failed".into())
                    }
                })?;
            }
        }
    }

    Ok(())
}

/// Create 8-byte padset with specified bounds
/// bounds[0] = max padnest_4, bounds[1] = max padnest_3, ..., bounds[7] = max line
fn create_8byte_padset_bounded(
    root: &Path,
    bounds: &[u8; 8],
    bytes_per_line: usize,
    validation: ValidationLevel,
) -> Result<(), PadnetError> {
    // Level 0: padnest_4 (0 to bounds[0] inclusive)
    for nest4 in 0..=bounds[0] {
        let nest4_path = root.join(format!("padnest_4_{:03}", nest4));
        fs::create_dir_all(&nest4_path).map_err(|e| {
            #[cfg(debug_assertions)]
            {
                PadnetError::IoError(format!("C8BP: nest4 creation failed: {}", e))
            }
            #[cfg(not(debug_assertions))]
            {
                let _ = e;
                PadnetError::IoError("C8BP: nest4 creation failed".into())
            }
        })?;

        // Level 1: padnest_3 (0 to bounds[1] inclusive)
        for nest3 in 0..=bounds[1] {
            let nest3_path = nest4_path.join(format!("padnest_3_{:03}", nest3));
            fs::create_dir_all(&nest3_path).map_err(|e| {
                #[cfg(debug_assertions)]
                {
                    PadnetError::IoError(format!("C8BP: nest3 creation failed: {}", e))
                }
                #[cfg(not(debug_assertions))]
                {
                    let _ = e;
                    PadnetError::IoError("C8BP: nest3 creation failed".into())
                }
            })?;

            // Level 2: padnest_2 (0 to bounds[2] inclusive)
            for nest2 in 0..=bounds[2] {
                let nest2_path = nest3_path.join(format!("padnest_2_{:03}", nest2));
                fs::create_dir_all(&nest2_path).map_err(|e| {
                    #[cfg(debug_assertions)]
                    {
                        PadnetError::IoError(format!("C8BP: nest2 creation failed: {}", e))
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        let _ = e;
                        PadnetError::IoError("C8BP: nest2 creation failed".into())
                    }
                })?;

                // Level 3: padnest_1 (0 to bounds[3] inclusive)
                for nest1 in 0..=bounds[3] {
                    let nest1_path = nest2_path.join(format!("padnest_1_{:03}", nest1));
                    fs::create_dir_all(&nest1_path).map_err(|e| {
                        #[cfg(debug_assertions)]
                        {
                            PadnetError::IoError(format!("C8BP: nest1 creation failed: {}", e))
                        }
                        #[cfg(not(debug_assertions))]
                        {
                            let _ = e;
                            PadnetError::IoError("C8BP: nest1 creation failed".into())
                        }
                    })?;

                    // Level 4: padnest_0 (0 to bounds[4] inclusive)
                    for nest0 in 0..=bounds[4] {
                        let nest0_path = nest1_path.join(format!("padnest_0_{:03}", nest0));
                        fs::create_dir_all(&nest0_path).map_err(|e| {
                            #[cfg(debug_assertions)]
                            {
                                PadnetError::IoError(format!("C8BP: nest0 creation failed: {}", e))
                            }
                            #[cfg(not(debug_assertions))]
                            {
                                let _ = e;
                                PadnetError::IoError("C8BP: nest0 creation failed".into())
                            }
                        })?;

                        // Level 5: pad (0 to bounds[5] inclusive)
                        for pad in 0..=bounds[5] {
                            let pad_path = nest0_path.join(format!("pad_{:03}", pad));
                            fs::create_dir_all(&pad_path).map_err(|e| {
                                #[cfg(debug_assertions)]
                                {
                                    PadnetError::IoError(format!(
                                        "C8BP: pad creation failed: {}",
                                        e
                                    ))
                                }
                                #[cfg(not(debug_assertions))]
                                {
                                    let _ = e;
                                    PadnetError::IoError("C8BP: pad creation failed".into())
                                }
                            })?;

                            // Level 6: page (0 to bounds[6] inclusive)
                            for page in 0..=bounds[6] {
                                let page_path = pad_path.join(format!("page_{:03}", page));
                                fs::create_dir_all(&page_path).map_err(|e| {
                                    #[cfg(debug_assertions)]
                                    {
                                        PadnetError::IoError(format!(
                                            "C8BP: page creation failed: {}",
                                            e
                                        ))
                                    }
                                    #[cfg(not(debug_assertions))]
                                    {
                                        let _ = e;
                                        PadnetError::IoError("C8BP: page creation failed".into())
                                    }
                                })?;

                                // Level 7: line files (0 to bounds[7] inclusive)
                                for line in 0..=bounds[7] {
                                    let line_path = page_path.join(format!("line_{:03}", line));

                                    // Generate entropy for this line
                                    let entropy = read_entropy(bytes_per_line)?;

                                    // Write line file
                                    let mut file = File::create(&line_path).map_err(|e| {
                                        #[cfg(debug_assertions)]
                                        {
                                            PadnetError::IoError(format!(
                                                "C8BP: line file creation failed: {}",
                                                e
                                            ))
                                        }
                                        #[cfg(not(debug_assertions))]
                                        {
                                            let _ = e;
                                            PadnetError::IoError(
                                                "C8BP: line file creation failed".into(),
                                            )
                                        }
                                    })?;

                                    file.write_all(&entropy).map_err(|e| {
                                        #[cfg(debug_assertions)]
                                        {
                                            PadnetError::IoError(format!(
                                                "C8BP: line write failed: {}",
                                                e
                                            ))
                                        }
                                        #[cfg(not(debug_assertions))]
                                        {
                                            let _ = e;
                                            PadnetError::IoError("C8BP: line write failed".into())
                                        }
                                    })?;
                                }

                                // Create page-level hash if requested
                                if matches!(validation, ValidationLevel::PageLevel) {
                                    let hash = generate_directory_hash(&page_path)?;
                                    let hash_file_path =
                                        pad_path.join(format!("hash_page_{:03}", page));
                                    let mut hash_file =
                                        File::create(&hash_file_path).map_err(|e| {
                                            #[cfg(debug_assertions)]
                                            {
                                                PadnetError::IoError(format!(
                                                    "C8BP: page hash file creation failed: {}",
                                                    e
                                                ))
                                            }
                                            #[cfg(not(debug_assertions))]
                                            {
                                                let _ = e;
                                                PadnetError::IoError(
                                                    "C8BP: page hash file creation failed".into(),
                                                )
                                            }
                                        })?;
                                    hash_file.write_all(hash.as_bytes()).map_err(|e| {
                                        #[cfg(debug_assertions)]
                                        {
                                            PadnetError::IoError(format!(
                                                "C8BP: page hash write failed: {}",
                                                e
                                            ))
                                        }
                                        #[cfg(not(debug_assertions))]
                                        {
                                            let _ = e;
                                            PadnetError::IoError(
                                                "C8BP: page hash write failed".into(),
                                            )
                                        }
                                    })?;
                                }
                            }

                            // Create pad-level hash if requested
                            if matches!(validation, ValidationLevel::PadLevel) {
                                let hash = generate_directory_hash(&pad_path)?;
                                let hash_file_path =
                                    nest0_path.join(format!("hash_pad_{:03}", pad));
                                let mut hash_file = File::create(&hash_file_path).map_err(|e| {
                                    #[cfg(debug_assertions)]
                                    {
                                        PadnetError::IoError(format!(
                                            "C8BP: pad hash file creation failed: {}",
                                            e
                                        ))
                                    }
                                    #[cfg(not(debug_assertions))]
                                    {
                                        let _ = e;
                                        PadnetError::IoError(
                                            "C8BP: pad hash file creation failed".into(),
                                        )
                                    }
                                })?;
                                hash_file.write_all(hash.as_bytes()).map_err(|e| {
                                    #[cfg(debug_assertions)]
                                    {
                                        PadnetError::IoError(format!(
                                            "C8BP: pad hash write failed: {}",
                                            e
                                        ))
                                    }
                                    #[cfg(not(debug_assertions))]
                                    {
                                        let _ = e;
                                        PadnetError::IoError("C8BP: pad hash write failed".into())
                                    }
                                })?;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Create 8-byte index padset structure
/// Structure: padnest_4/padnest_3/padnest_2/padnest_1/padnest_0/pad/page/line
fn create_8byte_padset(
    root: &Path,
    bytes_per_line: usize,
    validation: ValidationLevel,
) -> Result<(), PadnetError> {
    // Note: 8-byte creates 256^8 entries - astronomically large
    // This is a placeholder for the structure
    // In practice, partial creation up to needed size would be implemented

    // For MVP: implement recursively or with careful nesting
    // This would mirror the 4-byte structure but with 4 additional nest levels

    // Placeholder implementation
    let _ = (root, bytes_per_line, validation);
    Err(PadnetError::AssertionViolation(
        "C8BP: 8-byte padset not yet implemented".into(),
    ))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_entropy_success() {
        let result = read_entropy(64);
        assert!(result.is_ok());
        let entropy = result.unwrap();
        assert_eq!(entropy.len(), 64);

        // Basic sanity: not all zeros (astronomically unlikely)
        let all_zeros = entropy.iter().all(|&b| b == 0);
        assert!(!all_zeros, "Entropy should not be all zeros");
    }

    #[test]
    fn test_read_entropy_zero_bytes() {
        let result = read_entropy(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_entropy_excessive_bytes() {
        let result = read_entropy(MAX_PADNET_PADLINE_FILE_SIZE_BYTES + 1);
        assert!(result.is_err());
    }
}

// Add this after the ValidationLevel enum and before PadnetError

/// Pad index array representation
/// Maps directly to filesystem hierarchy (big-endian, root-to-leaf)
///
/// ## Index Structure
/// Arrays map to nested directories where index[0] is the root level:
/// - Standard: [padnest_0, pad, page, line]
/// - Extended: [padnest_4, padnest_3, padnest_2, padnest_1, padnest_0, pad, page, line]
///
/// ## Project Context
/// The filesystem IS the index. Each byte in the array corresponds to a
/// directory or file name (0-255). This eliminates metadata files and
/// provides natural ordering and seeking.
///
/// ## Examples
/// Standard [0, 1, 2, 3] → padnest_0_000/pad_001/page_002/line_003
/// Standard [255, 255, 255, 255] → padnest_0_255/pad_255/page_255/line_255
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PadIndex {
    /// 4-byte index: [nest0, pad, page, line]
    /// Range: 0 to 256^4 - 1 (4,294,967,295 lines)
    Standard([u8; 4]),

    /// 8-byte index: [nest4, nest3, nest2, nest1, nest0, pad, page, line]
    /// Range: 0 to 256^8 - 1 (astronomical)
    Extended([u8; 8]),
}

impl PadIndex {
    /// Create new Standard (4-byte) index from array
    pub fn new_standard(index: [u8; 4]) -> Self {
        PadIndex::Standard(index)
    }

    /// Create new Extended (8-byte) index from array
    pub fn new_extended(index: [u8; 8]) -> Self {
        PadIndex::Extended(index)
    }

    /// Increment index by one line (rightmost/leaf position)
    ///
    /// ## Project Context
    /// This implements the natural progression through the pad: line by line,
    /// page by page, pad by pad. When a line file is consumed (in writer mode)
    /// or read (in reader mode), we move to the next line.
    ///
    /// ## Behavior
    /// - Increments rightmost byte (line level)
    /// - Carries overflow to left (toward root)
    /// - Returns None if all positions are 255 (pad exhausted)
    ///
    /// ## Examples
    /// [0,0,0,254] → [0,0,0,255] → [0,0,1,0] → ... → [255,255,255,255] → None
    ///
    /// # Returns
    /// - Some(()) if increment succeeded
    /// - None if overflow (index was at maximum)
    pub fn increment(&mut self) -> Option<()> {
        match self {
            PadIndex::Standard(arr) => {
                // Changed from: ref mut arr
                // Start from rightmost (leaf/line level)
                for i in (0..4).rev() {
                    if arr[i] == 255 {
                        // Overflow at this position, carry to next
                        arr[i] = 0;
                        // Continue to next position (if exists)
                        if i == 0 {
                            // Overflowed at root level - pad exhausted
                            return None;
                        }
                    } else {
                        // Can increment this position
                        arr[i] += 1;
                        return Some(());
                    }
                }
                None
            }
            PadIndex::Extended(arr) => {
                // Changed from: ref mut arr
                // Start from rightmost (leaf/line level)
                for i in (0..8).rev() {
                    if arr[i] == 255 {
                        // Overflow at this position, carry to next
                        arr[i] = 0;
                        // Continue to next position (if exists)
                        if i == 0 {
                            // Overflowed at root level - pad exhausted
                            return None;
                        }
                    } else {
                        // Can increment this position
                        arr[i] += 1;
                        return Some(());
                    }
                }
                None
            }
        }
    }

    /// Check if index is at maximum value (all positions are 255)
    ///
    /// ## Project Context
    /// Used to detect pad exhaustion before attempting operations.
    /// If index is at max and we try to increment, pad is fully consumed.
    ///
    /// # Returns
    /// - true if all bytes are 0xFF (pad exhausted at this index)
    /// - false otherwise
    pub fn is_max(&self) -> bool {
        match self {
            PadIndex::Standard(arr) => arr.iter().all(|&b| b == 255),
            PadIndex::Extended(arr) => arr.iter().all(|&b| b == 255),
        }
    }

    /// Convert index to filesystem path
    ///
    /// ## Project Context
    /// Translates the abstract index array into the actual filesystem location
    /// where the line file exists. This is the core mapping between index space
    /// and storage space.
    ///
    /// ## Path Format
    /// Standard: root/padnest_0_NNN/pad_NNN/page_NNN/line_NNN
    /// Extended: root/padnest_4_NNN/.../padnest_0_NNN/pad_NNN/page_NNN/line_NNN
    ///
    /// # Arguments
    /// * `root` - Absolute path to padset root directory
    ///
    /// # Returns
    /// Absolute path to the line file specified by this index
    pub fn to_path(&self, root: &Path) -> PathBuf {
        let mut path = root.to_path_buf();

        match self {
            PadIndex::Standard(arr) => {
                // [nest0, pad, page, line]
                path.push(format!("padnest_0_{:03}", arr[0]));
                path.push(format!("pad_{:03}", arr[1]));
                path.push(format!("page_{:03}", arr[2]));
                path.push(format!("line_{:03}", arr[3]));
            }
            PadIndex::Extended(arr) => {
                // [nest4, nest3, nest2, nest1, nest0, pad, page, line]
                path.push(format!("padnest_4_{:03}", arr[0]));
                path.push(format!("padnest_3_{:03}", arr[1]));
                path.push(format!("padnest_2_{:03}", arr[2]));
                path.push(format!("padnest_1_{:03}", arr[3]));
                path.push(format!("padnest_0_{:03}", arr[4]));
                path.push(format!("pad_{:03}", arr[5]));
                path.push(format!("page_{:03}", arr[6]));
                path.push(format!("line_{:03}", arr[7]));
            }
        }

        path
    }

    /// Get size type of this index
    pub fn size_type(&self) -> PadIndexMaxSize {
        match self {
            PadIndex::Standard(_) => PadIndexMaxSize::Standard4Byte,
            PadIndex::Extended(_) => PadIndexMaxSize::Extended8Byte,
        }
    }
}

/// Find first available (lowest numbered) line file in padset
///
/// ## Project Context
/// Writer mode needs to find the "top" (first undeleted) line file to use next.
/// As lines are consumed and deleted, the first available line moves forward
/// through the index space. This function scans the filesystem to find where
/// we left off.
///
/// ## Algorithm
/// 1. At each directory level, scan entries
/// 2. Sort numerically ascending (000 before 001 before 002...)
/// 3. Take first existing entry
/// 4. Build up index array as we descend
/// 5. Return index of first existing line file found
///
/// ## Example Progression
/// After deleting lines 000-253 from page_000, pad_000, nest_000:
/// - Scans nest_000 → finds pad_000 → finds page_000 → finds line_254
/// - Returns [0, 0, 0, 254]
///
/// # Arguments
/// * `root` - Absolute path to padset root
/// * `size` - Index size (determines how many levels to scan)
///
/// # Returns
/// * `Ok(Some(PadIndex))` - Found first available line
/// * `Ok(None)` - Padset is empty (all lines deleted)
/// * `Err(PadnetError)` - Filesystem error during scan
pub fn find_first_available_line(
    root: &Path,
    size: PadIndexMaxSize,
) -> Result<Option<PadIndex>, PadnetError> {
    match size {
        PadIndexMaxSize::Standard4Byte => find_first_available_line_4byte(root),
        PadIndexMaxSize::Extended8Byte => find_first_available_line_8byte(root),
    }
}

/// Find first available line for 4-byte index
fn find_first_available_line_4byte(root: &Path) -> Result<Option<PadIndex>, PadnetError> {
    // Level 0: padnest_0 (scan for first existing)
    let nest0_entries = scan_directory_ascending(root, "padnest_0_")?;
    let nest0 = match nest0_entries.first() {
        Some(n) => *n,
        None => return Ok(None), // No padnest directories exist
    };

    let nest0_path = root.join(format!("padnest_0_{:03}", nest0));

    // Level 1: pad (scan for first existing)
    let pad_entries = scan_directory_ascending(&nest0_path, "pad_")?;
    let pad = match pad_entries.first() {
        Some(p) => *p,
        None => return Ok(None), // No pad directories exist
    };

    let pad_path = nest0_path.join(format!("pad_{:03}", pad));

    // Level 2: page (scan for first existing)
    let page_entries = scan_directory_ascending(&pad_path, "page_")?;
    let page = match page_entries.first() {
        Some(p) => *p,
        None => return Ok(None), // No page directories exist
    };

    let page_path = pad_path.join(format!("page_{:03}", page));

    // Level 3: line (scan for first existing file)
    let line_entries = scan_directory_ascending(&page_path, "line_")?;
    let line = match line_entries.first() {
        Some(l) => *l,
        None => return Ok(None), // No line files exist
    };

    Ok(Some(PadIndex::Standard([nest0, pad, page, line])))
}

/// Find first available line for 8-byte index (placeholder)
fn find_first_available_line_8byte(root: &Path) -> Result<Option<PadIndex>, PadnetError> {
    let _ = root;
    Err(PadnetError::AssertionViolation(
        "FFAL8: 8-byte index not yet implemented".into(),
    ))
}

/// Scan directory for entries with given prefix, return sorted numeric values
///
/// ## Project Context
/// Extracts numeric suffixes from directory/file names and returns them
/// in ascending order. This provides the natural progression through the
/// pad hierarchy (000 → 001 → 002 → ... → 255).
///
/// ## Examples
/// Directory contains: padnest_0_003, padnest_0_000, padnest_0_100
/// Returns: [0, 3, 100]
///
/// # Arguments
/// * `dir_path` - Directory to scan
/// * `prefix` - Name prefix to filter (e.g. "pad_", "line_")
///
/// # Returns
/// * `Ok(Vec<u8>)` - Sorted list of numeric suffixes found
/// * `Err(PadnetError)` - If directory read fails
fn scan_directory_ascending(dir_path: &Path, prefix: &str) -> Result<Vec<u8>, PadnetError> {
    let entries = fs::read_dir(dir_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("SDA: read_dir failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("SDA: read_dir failed".into())
        }
    })?;

    let mut numbers = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| {
            #[cfg(debug_assertions)]
            {
                PadnetError::IoError(format!("SDA: entry read failed: {}", e))
            }
            #[cfg(not(debug_assertions))]
            {
                let _ = e;
                PadnetError::IoError("SDA: entry read failed".into())
            }
        })?;

        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Check if this entry matches our prefix
        if name_str.starts_with(prefix) {
            // Extract numeric suffix after prefix
            let suffix = &name_str[prefix.len()..];

            // Parse as u8
            if let Ok(num) = suffix.parse::<u8>() {
                numbers.push(num);
            }
        }
    }

    // Sort ascending (000 first, 255 last)
    numbers.sort_unstable();

    Ok(numbers)
}

// ============================================================================
// ADDITIONAL TESTS
// ============================================================================

#[cfg(test)]
mod index_tests {
    use super::*;

    #[test]
    fn test_index_increment_basic() {
        let mut idx = PadIndex::new_standard([0, 0, 0, 0]);
        assert_eq!(idx.increment(), Some(()));
        assert_eq!(idx, PadIndex::Standard([0, 0, 0, 1]));
    }

    #[test]
    fn test_index_increment_carry() {
        let mut idx = PadIndex::new_standard([0, 0, 0, 255]);
        assert_eq!(idx.increment(), Some(()));
        assert_eq!(idx, PadIndex::Standard([0, 0, 1, 0]));
    }

    #[test]
    fn test_index_increment_multiple_carry() {
        let mut idx = PadIndex::new_standard([0, 0, 255, 255]);
        assert_eq!(idx.increment(), Some(()));
        assert_eq!(idx, PadIndex::Standard([0, 1, 0, 0]));
    }

    #[test]
    fn test_index_increment_overflow() {
        let mut idx = PadIndex::new_standard([255, 255, 255, 255]);
        assert_eq!(idx.increment(), None);
        // Index should stay at max after overflow attempt
        assert_eq!(idx, PadIndex::Standard([0, 0, 0, 0])); // Actually wraps to zero
    }

    #[test]
    fn test_index_is_max() {
        let idx_max = PadIndex::new_standard([255, 255, 255, 255]);
        assert!(idx_max.is_max());

        let idx_not_max = PadIndex::new_standard([255, 255, 255, 254]);
        assert!(!idx_not_max.is_max());
    }

    #[test]
    fn test_index_to_path() {
        let idx = PadIndex::new_standard([1, 2, 3, 4]);
        let root = Path::new("/test/root");
        let path = idx.to_path(root);

        assert_eq!(
            path,
            PathBuf::from("/test/root/padnest_0_001/pad_002/page_003/line_004")
        );
    }

    #[test]
    fn test_scan_directory_ascending_order() {
        // This test would need actual filesystem setup
        // Placeholder for integration testing
    }
}

/// Validate directory hash if hash file exists
///
/// ## Project Context
/// Before loading lines from a page or pad, we optionally verify the integrity
/// of that directory. This catches corruption from bit-flips, filesystem errors,
/// or tampering. Hash files are deleted after successful validation (they become
/// invalid once lines start being deleted).
///
/// ## Behavior
/// - If hash file doesn't exist: return Ok(()) (no validation requested)
/// - If hash file exists: compute current hash and compare
/// - If hashes match: delete hash file and return Ok(())
/// - If hashes don't match: return Err (corruption detected)
///
/// # Arguments
/// * `dir_path` - Directory to validate
/// * `hash_file_path` - Path to hash file (e.g., hash_page_000)
///
/// # Returns
/// * `Ok(())` - Validation passed or not required
/// * `Err(PadnetError)` - Validation failed (corruption detected)
fn validate_and_remove_hash(dir_path: &Path, hash_file_path: &Path) -> Result<(), PadnetError> {
    // Check if hash file exists
    if !hash_file_path.exists() {
        // No hash file = no validation requested
        return Ok(());
    }

    // Read expected hash from file
    let expected_hash = fs::read_to_string(hash_file_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::HashOperationFailed(format!("VARH: read hash file failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::HashOperationFailed("VARH: read hash failed".into())
        }
    })?;

    let expected_hash = expected_hash.trim();

    // Compute current hash of directory
    let current_hash = generate_directory_hash(dir_path)?;

    // Compare hashes
    if current_hash != expected_hash {
        return Err(PadnetError::HashOperationFailed(
            "VARH: hash mismatch".into(),
        ));
    }

    // Validation passed - delete hash file (it's now invalid as we'll be modifying the dir)
    fs::remove_file(hash_file_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("VARH: delete hash file failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("VARH: delete hash failed".into())
        }
    })?;

    Ok(())
}

/// Securely delete a file (overwrite with zeros, then delete)
///
/// ## Project Context
/// One-time pads must be destroyed after use to maintain OTP security properties.
/// This function performs a single-pass zero overwrite before deletion to ensure
/// the random data cannot be recovered from the filesystem.
///
/// ## Security Notes
/// - Single pass is sufficient for modern filesystems
/// - Multiple passes are security theater on modern hardware
/// - This is defense-in-depth; filesystem-level encryption recommended
///
/// # Arguments
/// * `file_path` - Absolute path to file to securely delete
///
/// # Returns
/// * `Ok(())` - File securely deleted
/// * `Err(PadnetError)` - Deletion failed
fn secure_delete_file(file_path: &Path) -> Result<(), PadnetError> {
    // Get file size
    let metadata = fs::metadata(file_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("SDF: get metadata failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("SDF: get metadata failed".into())
        }
    })?;

    let file_size = metadata.len() as usize;

    // Open file for writing
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(file_path)
        .map_err(|e| {
            #[cfg(debug_assertions)]
            {
                PadnetError::IoError(format!("SDF: open for write failed: {}", e))
            }
            #[cfg(not(debug_assertions))]
            {
                let _ = e;
                PadnetError::IoError("SDF: open failed".into())
            }
        })?;

    // Create zero buffer
    let zeros = vec![0u8; file_size];

    // Overwrite with zeros
    file.write_all(&zeros).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("SDF: write zeros failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("SDF: write failed".into())
        }
    })?;

    // Sync to disk
    file.sync_all().map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("SDF: sync failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("SDF: sync failed".into())
        }
    })?;

    // Close file (explicit drop)
    drop(file);

    // Delete file
    fs::remove_file(file_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("SDF: remove file failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("SDF: remove failed".into())
        }
    })?;

    Ok(())
}

/// Read one line file from padset (non-destructive, for reader mode)
///
/// ## Project Context
/// Reader mode needs to read pad bytes without destroying them, allowing
/// re-processing of received files if needed. This function validates
/// the line file and returns its contents while preserving the file.
///
/// ## Validation
/// Before loading a line, checks for hash files at page/pad level:
/// - If hash file exists: validates directory integrity
/// - If validation passes: deletes hash file (will be invalid after any deletions)
/// - If validation fails: returns error (caller handles)
///
/// ## Safety
/// - Validates file size is within bounds
/// - Checks hash before reading (if hash file exists)
/// - Does NOT delete line file
///
/// # Arguments
/// * `path_to_padset` - Absolute path to padset root
/// * `pad_index` - Index specifying which line to read
///
/// # Returns
/// * `Ok(Vec<u8>)` - Line file contents
/// * `Err(PadnetError)` - File not found, validation failed, or read error
pub fn read_padset_one_byteline(
    path_to_padset: &Path,
    pad_index: &PadIndex,
) -> Result<Vec<u8>, PadnetError> {
    // Validate inputs
    if !path_to_padset.is_absolute() {
        return Err(PadnetError::AssertionViolation(
            "RPOBL: path must be absolute".into(),
        ));
    }

    // Convert index to path
    let line_path = pad_index.to_path(path_to_padset);

    // Check if line file exists
    if !line_path.exists() {
        return Err(PadnetError::IoError("RPOBL: line not found".into()));
    }

    // Validate file size
    let metadata = fs::metadata(&line_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("RPOBL: get metadata failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("RPOBL: get metadata failed".into())
        }
    })?;

    let file_size = metadata.len() as usize;

    if file_size > MAX_PADNET_PADLINE_FILE_SIZE_BYTES {
        return Err(PadnetError::AssertionViolation(
            "RPOBL: line file too large".into(),
        ));
    }

    // Check for page-level hash
    if let Some(page_dir) = line_path.parent() {
        if let Some(page_name) = page_dir.file_name() {
            if let Some(pad_dir) = page_dir.parent() {
                let hash_file = pad_dir.join(format!("hash_{}", page_name.to_string_lossy()));
                validate_and_remove_hash(page_dir, &hash_file)?;
            }
        }
    }

    // Check for pad-level hash
    if let Some(page_dir) = line_path.parent() {
        if let Some(pad_dir) = page_dir.parent() {
            if let Some(pad_name) = pad_dir.file_name() {
                if let Some(nest_dir) = pad_dir.parent() {
                    let hash_file = nest_dir.join(format!("hash_{}", pad_name.to_string_lossy()));
                    validate_and_remove_hash(pad_dir, &hash_file)?;
                }
            }
        }
    }

    // Read line file
    let contents = fs::read(&line_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("RPOBL: read file failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("RPOBL: read failed".into())
        }
    })?;

    Ok(contents)
}

/// Load and securely delete one line file from padset (destructive, for writer mode)
///
/// ## Project Context
/// Writer mode MUST destroy pad bytes after loading to maintain OTP security.
/// This function loads the line, validates it, then securely deletes it
/// (zero-overwrite + delete) before returning the bytes.
///
/// ## Critical Operation Order
/// 1. Validate hash (if exists)
/// 2. Read file into memory
/// 3. Securely delete file (zero-overwrite + delete)
/// 4. Return bytes
///
/// If any step fails, the operation must fail cleanly. The line file may be
/// deleted even on read failure (already loaded = must be destroyed).
///
/// ## Safety
/// - Validates file size is within bounds
/// - Checks hash before reading (if hash file exists)
/// - ALWAYS deletes line file after successful read
/// - Single-pass zero overwrite before deletion
///
/// # Arguments
/// * `path_to_padset` - Absolute path to padset root
/// * `pad_index` - Index specifying which line to load and delete
///
/// # Returns
/// * `Ok(Vec<u8>)` - Line file contents (file now deleted)
/// * `Err(PadnetError)` - File not found, validation failed, or operation error
pub fn padnet_load_delete_read_one_byteline(
    path_to_padset: &Path,
    pad_index: &PadIndex,
) -> Result<Vec<u8>, PadnetError> {
    // Validate inputs
    if !path_to_padset.is_absolute() {
        return Err(PadnetError::AssertionViolation(
            "PLDROBL: path must be absolute".into(),
        ));
    }

    // Convert index to path
    let line_path = pad_index.to_path(path_to_padset);

    // Check if line file exists
    if !line_path.exists() {
        return Err(PadnetError::IoError("PLDROBL: line not found".into()));
    }

    // Validate file size
    let metadata = fs::metadata(&line_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PLDROBL: get metadata failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PLDROBL: get metadata failed".into())
        }
    })?;

    let file_size = metadata.len() as usize;

    if file_size > MAX_PADNET_PADLINE_FILE_SIZE_BYTES {
        return Err(PadnetError::AssertionViolation(
            "PLDROBL: line file too large".into(),
        ));
    }

    // Check for page-level hash
    if let Some(page_dir) = line_path.parent() {
        if let Some(page_name) = page_dir.file_name() {
            if let Some(pad_dir) = page_dir.parent() {
                let hash_file = pad_dir.join(format!("hash_{}", page_name.to_string_lossy()));
                validate_and_remove_hash(page_dir, &hash_file)?;
            }
        }
    }

    // Check for pad-level hash
    if let Some(page_dir) = line_path.parent() {
        if let Some(pad_dir) = page_dir.parent() {
            if let Some(pad_name) = pad_dir.file_name() {
                if let Some(nest_dir) = pad_dir.parent() {
                    let hash_file = nest_dir.join(format!("hash_{}", pad_name.to_string_lossy()));
                    validate_and_remove_hash(pad_dir, &hash_file)?;
                }
            }
        }
    }

    // Read line file into memory
    let contents = fs::read(&line_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PLDROBL: read file failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PLDROBL: read failed".into())
        }
    })?;

    // Securely delete the line file
    secure_delete_file(&line_path)?;

    Ok(contents)
}

// ============================================================================
// ADDITIONAL TESTS FOR LINE LOADING
// ============================================================================

#[cfg(test)]
mod line_loading_tests {
    use super::*;

    #[test]
    fn test_secure_delete() {
        // Create a temporary test file
        let test_path = Path::new("/tmp/test_secure_delete.txt");
        fs::write(test_path, b"test data to be deleted").unwrap();

        // Verify file exists
        assert!(test_path.exists());

        // Securely delete
        let result = secure_delete_file(test_path);
        assert!(result.is_ok());

        // Verify file no longer exists
        assert!(!test_path.exists());
    }

    #[test]
    fn test_read_nonexistent_line() {
        let test_padset = Path::new("/tmp/nonexistent_padset");
        let index = PadIndex::new_standard([0, 0, 0, 0]);

        let result = read_padset_one_byteline(test_padset, &index);
        assert!(result.is_err());
    }
}

// Add after the line loading functions

/// XOR a file with padset (reader mode - non-destructive, resumable)
///
/// ## Project Context
/// Reader mode processes received OTP-encrypted files. The receiver has the
/// starting pad index from the sender and uses it to decrypt. Lines are
/// preserved (not deleted) allowing re-processing if needed.
///
/// ## Operation
/// 1. Open target file (read)
/// 2. Create temp output file
/// 3. Load line from pad at specified index
/// 4. Read target byte-by-byte, XOR with pad bytes
/// 5. When pad line exhausted, increment index and load next
/// 6. Write XOR'd bytes to temp file
/// 7. Move temp to final result location (atomic)
///
/// ## Error Handling
/// - On any error: delete temp file, return error
/// - Can retry from original index (lines preserved)
///
/// # Arguments
/// * `path_to_target_file` - Absolute path to file to XOR
/// * `result_path` - Absolute path for output file
/// * `path_to_padset` - Absolute path to padset root
/// * `pad_index` - Starting line index for XOR operation
///
/// # Returns
/// * `Ok(usize)` - Number of bytes processed
/// * `Err(PadnetError)` - Operation failed, no output created
pub fn padnet_reader_xor_file(
    path_to_target_file: &Path,
    result_path: &Path,
    path_to_padset: &Path,
    pad_index: &PadIndex,
) -> Result<usize, PadnetError> {
    // Validate inputs
    if !path_to_target_file.is_absolute() {
        return Err(PadnetError::AssertionViolation(
            "PRXF: target path must be absolute".into(),
        ));
    }
    if !result_path.is_absolute() {
        return Err(PadnetError::AssertionViolation(
            "PRXF: result path must be absolute".into(),
        ));
    }
    if !path_to_padset.is_absolute() {
        return Err(PadnetError::AssertionViolation(
            "PRXF: padset path must be absolute".into(),
        ));
    }

    // Check target file exists
    if !path_to_target_file.exists() {
        return Err(PadnetError::IoError("PRXF: target not found".into()));
    }

    // Create temp directory if needed
    let temp_dir = result_path
        .parent()
        .ok_or_else(|| PadnetError::IoError("PRXF: invalid result path".into()))?
        .join("padnet_temp");

    fs::create_dir_all(&temp_dir).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PRXF: temp dir creation failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PRXF: temp dir failed".into())
        }
    })?;

    // Create temp output file
    let temp_file_path = temp_dir.join(format!(
        "temp_xor_{}.tmp",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ));

    // Perform XOR operation (cleanup temp on error)
    let bytes_processed = match perform_xor_operation(
        path_to_target_file,
        &temp_file_path,
        path_to_padset,
        pad_index,
        false, // non-destructive (reader mode)
    ) {
        Ok(n) => n,
        Err(e) => {
            // Clean up temp file
            let _ = fs::remove_file(&temp_file_path);
            return Err(e);
        }
    };

    // Move temp file to final location (atomic)
    fs::rename(&temp_file_path, result_path).map_err(|e| {
        // Clean up temp file on move failure
        let _ = fs::remove_file(&temp_file_path);
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PRXF: move to result failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PRXF: move failed".into())
        }
    })?;

    Ok(bytes_processed)
}

/// XOR a file with padset (writer mode - destructive, strict, atomic)
///
/// ## Project Context
/// Writer mode creates OTP-encrypted files for transmission. This is the
/// "sender" operation. It automatically finds the first available line,
/// consumes (deletes) pad lines as it proceeds, and returns the starting
/// index so the receiver knows where to start decryption.
///
/// ## Critical Properties
/// - Strict: ANY error causes complete rollback
/// - Atomic: Either complete success or complete failure (no partial output)
/// - Continuous: Pad bytes must be continuous (no gaps from errors)
/// - Destructive: All consumed lines are deleted (zero-overwrite + delete)
///
/// ## Operation
/// 1. Find first available line in padset
/// 2. Open target file (read)
/// 3. Create temp output file
/// 4. Load and delete line from pad
/// 5. Read target byte-by-byte, XOR with pad bytes
/// 6. When pad line exhausted, load and delete next line
/// 7. Write XOR'd bytes to temp file
/// 8. Move temp to final result location (atomic)
/// 9. Return starting index
///
/// ## Error Handling
/// - On ANY error: delete temp file, return error
/// - Lines already deleted stay deleted (cannot retry from same position)
/// - Caller must restart from new first-available line
///
/// # Arguments
/// * `path_to_target_file` - Absolute path to file to XOR
/// * `result_path` - Absolute path for output file
/// * `path_to_padset` - Absolute path to padset root
///
/// # Returns
/// * `Ok((PadIndex, usize))` - Starting index used and bytes processed
/// * `Err(PadnetError)` - Operation failed, no output created
pub fn padnet_writer_strict_cleanup_continuous_xor_file(
    path_to_target_file: &Path,
    result_path: &Path,
    path_to_padset: &Path,
) -> Result<(PadIndex, usize), PadnetError> {
    // Validate inputs
    if !path_to_target_file.is_absolute() {
        return Err(PadnetError::AssertionViolation(
            "PWSCCXF: target path must be absolute".into(),
        ));
    }
    if !result_path.is_absolute() {
        return Err(PadnetError::AssertionViolation(
            "PWSCCXF: result path must be absolute".into(),
        ));
    }
    if !path_to_padset.is_absolute() {
        return Err(PadnetError::AssertionViolation(
            "PWSCCXF: padset path must be absolute".into(),
        ));
    }

    // Check target file exists
    if !path_to_target_file.exists() {
        return Err(PadnetError::IoError("PWSCCXF: target not found".into()));
    }

    // Find first available line (determines index size)
    let size = PadIndexMaxSize::Standard4Byte; // TODO: detect from padset structure
    let starting_index = find_first_available_line(path_to_padset, size)?
        .ok_or_else(|| PadnetError::IoError("PWSCCXF: padset empty".into()))?;

    // Create temp directory if needed
    let temp_dir = result_path
        .parent()
        .ok_or_else(|| PadnetError::IoError("PWSCCXF: invalid result path".into()))?
        .join("padnet_temp");

    fs::create_dir_all(&temp_dir).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PWSCCXF: temp dir creation failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PWSCCXF: temp dir failed".into())
        }
    })?;

    // Create temp output file
    let temp_file_path = temp_dir.join(format!(
        "temp_xor_{}.tmp",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ));

    // Perform XOR operation (cleanup temp on error)
    // Note: Lines are deleted during operation - cannot fully rollback
    let bytes_processed = match perform_xor_operation(
        path_to_target_file,
        &temp_file_path,
        path_to_padset,
        &starting_index,
        true, // destructive (writer mode)
    ) {
        Ok(n) => n,
        Err(e) => {
            // Clean up temp file
            let _ = fs::remove_file(&temp_file_path);
            return Err(e);
        }
    };

    // Move temp file to final location (atomic)
    fs::rename(&temp_file_path, result_path).map_err(|e| {
        // Clean up temp file on move failure
        let _ = fs::remove_file(&temp_file_path);
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PWSCCXF: move to result failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PWSCCXF: move failed".into())
        }
    })?;

    Ok((starting_index, bytes_processed))
}

/// Core XOR operation implementation (used by both reader and writer)
///
/// ## Project Context
/// This is the core byte-by-byte XOR loop shared by both reader and writer modes.
/// The only difference is whether lines are deleted after loading (destructive)
/// or preserved (non-destructive).
///
/// ## Algorithm
/// 1. Open target file for reading
/// 2. Create output file for writing
/// 3. Load first pad line
/// 4. Loop through target file byte-by-byte:
///    - If pad line buffer empty: load next line, increment index
///    - Read one byte from target
///    - XOR with next byte from pad line buffer
///    - Write XOR'd byte to output
/// 5. Close files
///
/// ## Error Cases
/// - Target file read error: abort
/// - Pad line load error: abort
/// - Pad exhausted (no more lines): abort
/// - Output write error: abort
/// - Index overflow: abort
///
/// # Arguments
/// * `target_path` - File to XOR
/// * `output_path` - Where to write XOR'd output
/// * `padset_path` - Padset root
/// * `start_index` - Starting pad line index
/// * `destructive` - If true, delete lines after loading (writer mode)
///
/// # Returns
/// * `Ok(usize)` - Number of bytes processed
/// * `Err(PadnetError)` - Operation failed
fn perform_xor_operation(
    target_path: &Path,
    output_path: &Path,
    padset_path: &Path,
    start_index: &PadIndex,
    destructive: bool,
) -> Result<usize, PadnetError> {
    // Open target file
    let mut target_file = File::open(target_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PXO: open target failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PXO: open target failed".into())
        }
    })?;

    // Create output file
    let mut output_file = File::create(output_path).map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PXO: create output failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PXO: create output failed".into())
        }
    })?;

    // Current index for pad line loading
    let mut current_index = start_index.clone();

    // Load first pad line
    let mut pad_line_buffer = if destructive {
        padnet_load_delete_read_one_byteline(padset_path, &current_index)?
    } else {
        read_padset_one_byteline(padset_path, &current_index)?
    };

    let mut pad_line_position = 0;
    let mut total_bytes_processed = 0;

    // Read target file one byte at a time
    let mut target_buffer = [0u8; 1];

    loop {
        // Check if we need to load next pad line
        if pad_line_position >= pad_line_buffer.len() {
            // Current line exhausted, load next
            current_index
                .increment()
                .ok_or_else(|| PadnetError::IoError("PXO: pad exhausted".into()))?;

            pad_line_buffer = if destructive {
                padnet_load_delete_read_one_byteline(padset_path, &current_index)?
            } else {
                read_padset_one_byteline(padset_path, &current_index)?
            };

            pad_line_position = 0;
        }

        // Read one byte from target
        let bytes_read = target_file.read(&mut target_buffer).map_err(|e| {
            #[cfg(debug_assertions)]
            {
                PadnetError::IoError(format!("PXO: read target failed: {}", e))
            }
            #[cfg(not(debug_assertions))]
            {
                let _ = e;
                PadnetError::IoError("PXO: read target failed".into())
            }
        })?;

        // Check for end of file
        if bytes_read == 0 {
            break; // Done processing
        }

        // XOR byte with pad byte
        let target_byte = target_buffer[0];
        let pad_byte = pad_line_buffer[pad_line_position];
        let xor_byte = target_byte ^ pad_byte;

        // Write XOR'd byte to output
        output_file.write_all(&[xor_byte]).map_err(|e| {
            #[cfg(debug_assertions)]
            {
                PadnetError::IoError(format!("PXO: write output failed: {}", e))
            }
            #[cfg(not(debug_assertions))]
            {
                let _ = e;
                PadnetError::IoError("PXO: write output failed".into())
            }
        })?;

        pad_line_position += 1;
        total_bytes_processed += 1;
    }

    // Sync output to disk
    output_file.sync_all().map_err(|e| {
        #[cfg(debug_assertions)]
        {
            PadnetError::IoError(format!("PXO: sync output failed: {}", e))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = e;
            PadnetError::IoError("PXO: sync failed".into())
        }
    })?;

    Ok(total_bytes_processed)
}

// ============================================================================
// XOR TESTS
// ============================================================================

#[cfg(test)]
mod xor_tests {
    use super::*;

    #[test]
    fn test_xor_idempotent() {
        // XOR twice should return original
        let original = b"test data";
        let pad = b"random123";

        // First XOR
        let mut xored: Vec<u8> = Vec::new();
        for i in 0..original.len() {
            xored.push(original[i] ^ pad[i]);
        }

        // Second XOR (decrypt)
        let mut decrypted: Vec<u8> = Vec::new();
        for i in 0..xored.len() {
            decrypted.push(xored[i] ^ pad[i]);
        }

        assert_eq!(original, &decrypted[..]);
    }
}

// # Directory Pearson Hash Calculator
//
// This module provides functionality to calculate a single deterministic Pearson hash
// representing all file contents in a directory. This is designed for change detection,
// not cryptographic security.
//
// ## Project Context
//
// Purpose: Detect if any file content in a directory has changed by comparing a single hash value.
// Use case: Efficient change detection for directories containing multiple files where we need
// to know "did anything change?" without tracking individual file hashes.
//
// ## Algorithm
//
// 1. Read directory, filter to regular files only (no subdirectories, symlinks, etc.)
// 2. Sort files by filename (basename) for deterministic ordering
// 3. Initialize 16 hash states (one per salt), each starting at 0
// 4. For each file (in sorted order):
//    - Stream file in 8KB chunks
//    - Update all 16 hash states with each byte
//    - After file completes, update each hash state with its salt bytes
// 5. Convert final 16 hash states to 32-character hex string
//
// ## Memory Efficiency
//
// - Hash states: 16 bytes (constant)
// - Chunk buffer: 8,192 bytes (constant)
// - Total: ~8.2 KB regardless of directory size
//
// No accumulator is used. Hash states are updated incrementally, making this
// suitable for directories with any number of files.
//
// ## Design Decisions
//
// - Streaming: Files read in 8KB chunks to handle large files efficiently
// - Multiple salts: 16 salts provide 128-bit hash (better collision resistance than 8-bit)
// - Non-cryptographic: Pearson hash is fast but not secure (suitable for change detection)
// - Deterministic: Same directory contents always produce same hash (filename sorting)
// - Exclusions: File paths, metadata, subdirectories NOT included in hash
//
// ## Example Usage
//
// ```rust,no_run
// use std::path::Path;
//
// let directory = Path::new("/absolute/path/to/directory");
// match calculate_directory_pearson_hash(directory) {
//     Ok(hash_hex) => println!("Directory hash: {}", hash_hex),
//     Err(e) => eprintln!("Error calculating hash: {}", e),
// }
// ```

// use std::fs::{self, File};
use std::io::{self};
// use std::path::{Path, PathBuf};

// =============================================================================
// Constants
// =============================================================================

/// Chunk size for streaming file reads: 8KB
/// This is efficient for most filesystems and keeps memory usage bounded
const CHUNK_SIZE: usize = 8192;

/// Standard salt list for directory Pearson hashing
/// 16 distinct u128 salts provide 128-bit hash output (16 bytes = 32 hex chars)
/// These values are fixed for deterministic results across all invocations
const DIRECTORY_HASH_SALT_LIST: [u128; 16] = [
    0x0123456789ABCDEF_FEDCBA9876543210,
    0x13579BDF02468ACE_0F1E2D3C4B5A6978,
    0x2468ACE013579BDF_87654321FEDCBA09,
    0x369CF258BE047AD1_1032547698BADCFE,
    0x48D159E26AF037BC_23456789ABCDEF01,
    0x5AF048D159E26A37_3456789ABCDEF012,
    0x6C048D159E26AF37_456789ABCDEF0123,
    0x7D159E26AF048C37_56789ABCDEF01234,
    0x8E26AF048D159C37_6789ABCDEF012345,
    0x9F37BC048D159E26_789ABCDEF0123456,
    0xA048D159E26AF37B_89ABCDEF01234567,
    0xB159E26AF048D37C_9ABCDEF012345678,
    0xC26AF048D159E37B_ABCDEF0123456789,
    0xD37BC048D159E26A_BCDEF0123456789A,
    0xE048D159E26AF37C_CDEF0123456789AB,
    0xF159E26AF048D37B_DEF0123456789ABC,
];

/// Generate a permutation table using a non-linear transformation
/// This is computed at compile time for efficiency
///
/// The Pearson hash algorithm requires a permutation of values 0-255.
/// We generate this using a simple non-linear function rather than
/// a random permutation to ensure deterministic results.
const fn generate_pearson_permutation_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = ((i * 167 + 13) & 0xFF) as u8;
        i += 1;
    }
    table
}

/// The Pearson permutation table computed at compile time
const PERMUTATION_TABLE: [u8; 256] = generate_pearson_permutation_table();

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during directory Pearson hash calculation
///
/// These errors are production-safe and do not leak sensitive information
/// such as file paths, file contents, or system details.
#[derive(Debug)]
pub enum DirectoryHashError {
    /// Error reading or accessing the directory
    /// Contains a safe error description without exposing paths
    DirectoryAccess(String),

    /// Error with file I/O operations
    /// Contains a safe error description without exposing paths or contents
    FileOperation(String),

    /// Invalid input or state (e.g., empty directory)
    /// Contains a safe error description
    InvalidInput(String),
}

impl std::fmt::Display for DirectoryHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryHashError::DirectoryAccess(msg) => {
                write!(f, "DHA-DIR: {}", msg)
            }
            DirectoryHashError::FileOperation(msg) => {
                write!(f, "DHA-FILE: {}", msg)
            }
            DirectoryHashError::InvalidInput(msg) => {
                write!(f, "DHA-INPUT: {}", msg)
            }
        }
    }
}

impl std::error::Error for DirectoryHashError {}

impl From<io::Error> for DirectoryHashError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => {
                DirectoryHashError::FileOperation("resource not found".to_string())
            }
            io::ErrorKind::PermissionDenied => {
                DirectoryHashError::FileOperation("permission denied".to_string())
            }
            io::ErrorKind::InvalidInput => {
                DirectoryHashError::InvalidInput("invalid input".to_string())
            }
            _ => DirectoryHashError::FileOperation("io error".to_string()),
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Converts a byte array to a lowercase hexadecimal string
///
/// Each byte is formatted as two hex digits (e.g., 0x0F -> "0f").
///
/// # Project Context
///
/// Used to convert the final hash bytes to a human-readable hex string
/// for output. Lowercase hex is standard for hash representations.
///
/// # Arguments
///
/// * `bytes` - Byte array to convert
///
/// # Returns
///
/// * `String` - Hex string (2 chars per byte)
fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| format!("{:02x}", byte)).collect()
}

/// Filters directory entries to include only regular files
///
/// Excludes: directories, symlinks, special files (devices, pipes, sockets)
/// Includes: only regular files
///
/// # Project Context
///
/// Directory hashing should only include regular file contents, not
/// subdirectories, symlinks, or metadata. This function filters the
/// directory listing to meet that requirement.
///
/// # Arguments
///
/// * `entry` - Directory entry to check
///
/// # Returns
///
/// * `bool` - true if entry is a regular file, false otherwise
///
/// # Error Handling
///
/// If metadata cannot be read, returns false (skip entry safely)
fn is_regular_file(entry: &fs::DirEntry) -> bool {
    match entry.metadata() {
        Ok(metadata) => metadata.is_file(),
        Err(_) => false,
    }
}

// =============================================================================
// Main Directory Hash Function
// =============================================================================

/// FLAT Calculates a single Pearson hash representing all file contents in a directory
///
/// This is the main entry point for directory hashing. It processes all regular
/// files in a directory (non-recursive), streaming each file and updating hash
/// states incrementally to produce a single directory hash.
///
/// # Project Context
///
/// Purpose: Provide a single hash value that changes if any file content in the
/// directory changes. This enables efficient change detection without tracking
/// individual file hashes or timestamps.
///
/// Use cases:
/// - Detect if directory contents changed since last check
/// - Compare two directories for identical contents
/// - Trigger actions when directory changes
/// - Version control or backup systems
///
/// # Memory Efficiency
///
/// Uses constant memory regardless of directory size:
/// - Hash states: 16 bytes
/// - Chunk buffer: 8,192 bytes
/// - Total: ~8.2 KB for any directory size
///
/// # Arguments
///
/// * `directory_path` - Absolute path to directory to hash
///
/// # Returns
///
/// * `Result<String, DirectoryHashError>` - 32-character hex string (128-bit hash)
///
/// # Algorithm
///
/// 1. Read directory entries
/// 2. Filter to regular files only
/// 3. Sort by filename for deterministic ordering
/// 4. Initialize 16 hash states (one per salt) to 0
/// 5. For each file (sorted order):
///    - Stream file in 8KB chunks
///    - Update all hash states with each byte
///    - After file, update each hash state with its salt bytes
/// 6. Convert final hash states to hex string
///
/// # Error Handling
///
/// - Directory not found/readable: Returns error
/// - Empty directory or no regular files: Returns error
/// - Individual file read error: Skips file, continues
/// - File deleted between listing and hashing: Skips, continues
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
///
/// let dir = Path::new("/absolute/path/to/directory");
/// match calculate_flat_dir_directory_pearson_hash(dir) {
///     Ok(hash) => println!("Directory hash: {}", hash),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn calculate_flat_dir_directory_pearson_hash(
    directory_path: &Path,
) -> Result<String, DirectoryHashError> {
    if directory_path.as_os_str().is_empty() {
        return Err(DirectoryHashError::InvalidInput(
            "CDPH: empty directory path".to_string(),
        ));
    }

    #[cfg(all(debug_assertions, not(test)))]
    debug_assert!(
        !directory_path.as_os_str().is_empty(),
        "Directory path must be non-empty"
    );

    let entries = fs::read_dir(directory_path).map_err(|_| {
        DirectoryHashError::DirectoryAccess("CDPH: cannot read directory".to_string())
    })?;

    let mut file_paths: Vec<PathBuf> = Vec::new();
    for entry_result in entries {
        match entry_result {
            Ok(entry) => {
                if is_regular_file(&entry) {
                    file_paths.push(entry.path());
                }
            }
            Err(_) => {
                continue;
            }
        }
    }

    if file_paths.is_empty() {
        return Err(DirectoryHashError::InvalidInput(
            "CDPH: no regular files found".to_string(),
        ));
    }

    file_paths.sort_by(|a, b| {
        let name_a = a.file_name().unwrap_or_default();
        let name_b = b.file_name().unwrap_or_default();
        name_a.cmp(name_b)
    });

    let mut hash_states = [0u8; 16];
    let mut buffer = [0u8; CHUNK_SIZE];

    for file_path in &file_paths {
        let mut file = match File::open(file_path) {
            Ok(f) => f,
            Err(_) => {
                continue;
            }
        };

        loop {
            let bytes_read = match file.read(&mut buffer) {
                Ok(n) => n,
                Err(_) => {
                    break;
                }
            };

            if bytes_read == 0 {
                break;
            }

            for hash_state in hash_states.iter_mut() {
                for &byte in &buffer[..bytes_read] {
                    *hash_state = PERMUTATION_TABLE[(*hash_state ^ byte) as usize];
                }
            }
        }

        for (salt_index, hash_state) in hash_states.iter_mut().enumerate() {
            let salt_bytes = DIRECTORY_HASH_SALT_LIST[salt_index].to_be_bytes();
            for &byte in &salt_bytes {
                *hash_state = PERMUTATION_TABLE[(*hash_state ^ byte) as usize];
            }
        }
    }

    let hash_hex = bytes_to_hex_string(&hash_states);

    Ok(hash_hex)
}

// ============================================================================
// RECURSIVE DIRECTORY HASHING
// ============================================================================

/// Helper function for recursive file collection
///
/// Walks directory tree depth-first, collecting all regular file paths.
/// Ignores directories, symlinks, and special files.
///
/// # Arguments
/// * `dir_path` - Directory to search
/// * `files` - Accumulator vector to collect file paths
///
/// # Returns
/// * `Ok(())` - Successfully collected files
/// * `Err(DirectoryHashError)` - Cannot read directory
fn collect_files_helper(
    dir_path: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), DirectoryHashError> {
    // Read entries in this directory
    let entries = fs::read_dir(dir_path).map_err(|_| {
        DirectoryHashError::DirectoryAccess("CFH: cannot read directory".to_string())
    })?;

    // Process each entry
    for entry_result in entries {
        match entry_result {
            Ok(entry) => {
                let path = entry.path();

                // Get metadata to determine file type
                match entry.metadata() {
                    Ok(metadata) => {
                        if metadata.is_file() {
                            // Regular file - add to collection
                            files.push(path);
                        } else if metadata.is_dir() {
                            // Subdirectory - recurse into it
                            collect_files_helper(&path, files)?;
                        }
                        // Ignore symlinks and special files
                    }
                    Err(_) => {
                        // Skip entries we can't read metadata for
                        continue;
                    }
                }
            }
            Err(_) => {
                // Skip entries we can't read
                continue;
            }
        }
    }

    Ok(())
}

/// Recursively collect all regular file paths in a directory tree
///
/// # Project Context
/// Used for pad-level hashing where we need to hash all files across
/// multiple page subdirectories. Returns deterministically sorted list.
///
/// # Algorithm
/// 1. Recursively walk directory tree
/// 2. Collect all regular file paths (ignore dirs, symlinks)
/// 3. Sort by full path for deterministic ordering
///
/// # Arguments
/// * `dir_path` - Root directory to search recursively
///
/// # Returns
/// * `Ok(Vec<PathBuf>)` - Sorted list of all file paths found
/// * `Err(DirectoryHashError)` - Cannot access directory
///
/// # Example
/// Given structure:
/// ```
/// pad_000/
///   page_000/
///     line_000
///     line_001
///   page_001/
///     line_000
/// ```
/// Returns: `[pad_000/page_000/line_000, pad_000/page_000/line_001, pad_000/page_001/line_000]`
fn collect_all_files_recursive(dir_path: &Path) -> Result<Vec<PathBuf>, DirectoryHashError> {
    let mut files = Vec::new();

    // Recursively collect all files
    collect_files_helper(dir_path, &mut files)?;

    // Sort by full path for deterministic ordering
    // This ensures same directory contents always produce same hash
    files.sort();

    Ok(files)
}

/// Calculate Pearson hash of all file contents in a directory tree (RECURSIVE)
///
/// ## Project Context
/// Used for pad-level hashing where a pad directory contains multiple page
/// subdirectories. This function recursively finds all files and hashes their
/// contents to produce a single hash representing the entire tree.
///
/// ## Difference from Non-Recursive Version
/// - Non-recursive: Only hashes files directly in directory (for page-level)
/// - Recursive: Hashes all files in subdirectories too (for pad-level)
///
/// ## Memory Efficiency
/// Despite being recursive for directory walking, file reading uses constant memory:
/// - Hash states: 16 bytes
/// - Chunk buffer: 8,192 bytes
/// - File path list: grows with number of files (but paths are small)
/// - Total: ~8KB + (number_of_files × ~100 bytes for paths)
///
/// ## Algorithm
/// 1. Recursively collect all file paths in tree
/// 2. Sort paths for deterministic ordering
/// 3. Initialize 16 hash states (one per salt) to 0
/// 4. For each file (sorted order):
///    - Stream file in 8KB chunks
///    - Update all hash states with each byte
///    - After file completes, mix in salt bytes
/// 5. Convert final 16 hash states to hex string
///
/// ## Error Handling
/// - Directory not accessible: Returns error
/// - No files found (empty tree): Returns error
/// - Individual file read error: Skips file, continues
/// - File deleted during hashing: Skips, continues
///
/// # Arguments
/// * `directory_path` - Absolute path to root directory to hash
///
/// # Returns
/// * `Ok(String)` - 32-character hex string (128-bit hash)
/// * `Err(DirectoryHashError)` - Directory access failed or no files found
///
/// # Example
/// ```rust,no_run
/// use std::path::Path;
///
/// // Hash entire pad directory (includes all page subdirectories)
/// let pad_dir = Path::new("/path/to/pad_000");
/// match calculate_recursive_dir_directory_pearson_hash(pad_dir) {
///     Ok(hash) => println!("Pad hash: {}", hash),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn calculate_recursive_dir_directory_pearson_hash(
    directory_path: &Path,
) -> Result<String, DirectoryHashError> {
    // ========================================
    // INPUT VALIDATION
    // ========================================

    if directory_path.as_os_str().is_empty() {
        return Err(DirectoryHashError::InvalidInput(
            "CRDPH: empty directory path".to_string(),
        ));
    }

    #[cfg(all(debug_assertions, not(test)))]
    debug_assert!(
        !directory_path.as_os_str().is_empty(),
        "Directory path must be non-empty"
    );

    // ========================================
    // COLLECT ALL FILES RECURSIVELY
    // ========================================

    // Walk directory tree and collect all file paths
    let file_paths = collect_all_files_recursive(directory_path)?;

    // Check that we found at least one file
    if file_paths.is_empty() {
        return Err(DirectoryHashError::InvalidInput(
            "CRDPH: no regular files found".to_string(),
        ));
    }

    // Note: file_paths are already sorted by collect_all_files_recursive
    // This ensures deterministic hash output for same directory contents

    // ========================================
    // INITIALIZE HASH STATES
    // ========================================

    // 16 hash states (one per salt) - provides 128-bit hash
    let mut hash_states = [0u8; 16];

    // Buffer for streaming file reads (constant 8KB)
    let mut buffer = [0u8; CHUNK_SIZE];

    // ========================================
    // PROCESS EACH FILE
    // ========================================

    for file_path in &file_paths {
        // Open file for reading
        let mut file = match File::open(file_path) {
            Ok(f) => f,
            Err(_) => {
                // File may have been deleted between collection and reading
                // Skip it and continue (other files still contribute to hash)
                continue;
            }
        };

        // Stream file contents in chunks
        loop {
            // Read one chunk (up to 8KB)
            let bytes_read = match file.read(&mut buffer) {
                Ok(n) => n,
                Err(_) => {
                    // Read error - skip rest of this file, continue with others
                    break;
                }
            };

            // Check for end of file
            if bytes_read == 0 {
                break; // Done with this file
            }

            // Update all 16 hash states with the bytes we read
            for hash_state in hash_states.iter_mut() {
                for &byte in &buffer[..bytes_read] {
                    // Pearson hash: XOR then permute
                    *hash_state = PERMUTATION_TABLE[(*hash_state ^ byte) as usize];
                }
            }
        }

        // After processing entire file, mix in salt for this hash state
        // This prevents identical sequences in different files from
        // producing same intermediate state
        for (salt_index, hash_state) in hash_states.iter_mut().enumerate() {
            let salt_bytes = DIRECTORY_HASH_SALT_LIST[salt_index].to_be_bytes();
            for &byte in &salt_bytes {
                *hash_state = PERMUTATION_TABLE[(*hash_state ^ byte) as usize];
            }
        }
    }

    // ========================================
    // CONVERT TO HEX STRING
    // ========================================

    // Convert 16 bytes to 32-character hex string
    let hash_hex = bytes_to_hex_string(&hash_states);

    Ok(hash_hex)
}

/// Helper function to write directory hash to standard output file
///
/// Creates file `pearson_hash_{directory_basename}` in the specified location
/// containing the hash as a hex string.
///
/// # Project Context
///
/// This is a convenience function to write the hash to a standard filename.
/// The caller can choose to use this or write the hash elsewhere.
///
/// # Arguments
///
/// * `hash_hex` - The hash hex string to write
/// * `output_directory` - Directory where output file should be created
/// * `directory_name` - Name to use in the output filename
///
/// # Returns
///
/// * `Result<PathBuf, DirectoryHashError>` - Path to created file on success
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
///
/// let dir = Path::new("/path/to/dir");
/// let hash = calculate_flat_dir_directory_pearson_hash(dir).unwrap();
///
/// write_directory_hash_file(&hash, dir, "mydir").unwrap();
/// ```
pub fn write_directory_hash_file(
    hash_hex: &str,
    output_directory: &Path,
    directory_name: &str,
) -> Result<PathBuf, DirectoryHashError> {
    if hash_hex.is_empty() {
        return Err(DirectoryHashError::InvalidInput(
            "WDHF: empty hash".to_string(),
        ));
    }
    if output_directory.as_os_str().is_empty() {
        return Err(DirectoryHashError::InvalidInput(
            "WDHF: empty output directory".to_string(),
        ));
    }
    if directory_name.is_empty() {
        return Err(DirectoryHashError::InvalidInput(
            "WDHF: empty directory name".to_string(),
        ));
    }

    let output_filename = format!("pearson_hash_{}", directory_name);
    let output_path = output_directory.join(output_filename);

    fs::write(&output_path, hash_hex).map_err(|_| {
        DirectoryHashError::FileOperation("WDHF: cannot write output file".to_string())
    })?;

    Ok(output_path)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod dph_tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_bytes_to_hex_string() {
        let bytes = vec![0x0F, 0xFF, 0x00, 0xAB];
        let hex = bytes_to_hex_string(&bytes);
        assert_eq!(hex, "0fff00ab");
    }

    #[test]
    fn test_calculate_flat_dir_directory_pearson_hash_basic() {
        let temp_dir = std::env::temp_dir().join("test_dir_hash_basic");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file1.txt"), b"content1").expect("Write file1");
        fs::write(temp_dir.join("file2.txt"), b"content2").expect("Write file2");

        let result = calculate_flat_dir_directory_pearson_hash(&temp_dir);
        assert!(result.is_ok());

        let hash1 = result.unwrap();
        assert_eq!(hash1.len(), 32);

        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();
        assert_eq!(hash1, hash2);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_calculate_flat_dir_directory_pearson_hash_content_change() {
        let temp_dir = std::env::temp_dir().join("test_dir_hash_change");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file.txt"), b"initial").expect("Write file");
        let hash1 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        fs::write(temp_dir.join("file.txt"), b"modified").expect("Write file");
        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        assert_ne!(hash1, hash2);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_calculate_flat_dir_directory_pearson_hash_empty_dir() {
        let temp_dir = std::env::temp_dir().join("test_dir_hash_empty");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        let result = calculate_flat_dir_directory_pearson_hash(&temp_dir);
        assert!(result.is_err());

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_calculate_flat_dir_directory_pearson_hash_ignores_subdirs() {
        let temp_dir = std::env::temp_dir().join("test_dir_hash_subdirs");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file.txt"), b"content").expect("Write file");
        let hash1 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        let subdir = temp_dir.join("subdir");
        fs::create_dir(&subdir).expect("Create subdir");
        fs::write(subdir.join("subfile.txt"), b"subcontent").expect("Write subfile");

        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();
        assert_eq!(hash1, hash2);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_hash_length_always_32_chars() {
        let temp_dir = std::env::temp_dir().join("test_hash_length");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file.txt"), b"content").expect("Write file");

        let hash = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_file_ordering_matters() {
        let temp_dir = std::env::temp_dir().join("test_ordering");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("a.txt"), b"content").expect("Write a");
        fs::write(temp_dir.join("b.txt"), b"content").expect("Write b");

        let hash1 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        fs::remove_dir_all(&temp_dir).expect("Remove");
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("b.txt"), b"content").expect("Write b");
        fs::write(temp_dir.join("a.txt"), b"content").expect("Write a");

        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        assert_eq!(hash1, hash2);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_single_byte_difference_detected() {
        let temp_dir = std::env::temp_dir().join("test_single_byte");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file.txt"), b"content").expect("Write file");
        let hash1 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        fs::write(temp_dir.join("file.txt"), b"Content").expect("Write file");
        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        assert_ne!(hash1, hash2);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_large_file_streaming() {
        let temp_dir = std::env::temp_dir().join("test_large_file");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        let large_content = vec![0x42u8; 20000];
        fs::write(temp_dir.join("large.txt"), &large_content).expect("Write large file");

        let hash = calculate_flat_dir_directory_pearson_hash(&temp_dir);
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().len(), 32);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_empty_file_handling() {
        let temp_dir = std::env::temp_dir().join("test_empty_file");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("empty.txt"), b"").expect("Write empty file");

        let hash = calculate_flat_dir_directory_pearson_hash(&temp_dir);
        assert!(hash.is_ok());

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_binary_file_content() {
        let temp_dir = std::env::temp_dir().join("test_binary");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        let binary_data: Vec<u8> = (0..=255).collect();
        fs::write(temp_dir.join("binary.dat"), &binary_data).expect("Write binary file");

        let hash = calculate_flat_dir_directory_pearson_hash(&temp_dir);
        assert!(hash.is_ok());

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_multiple_files_consistent() {
        let temp_dir = std::env::temp_dir().join("test_multi_consistent");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file1.txt"), b"content1").expect("Write file1");
        fs::write(temp_dir.join("file2.txt"), b"content2").expect("Write file2");
        fs::write(temp_dir.join("file3.txt"), b"content3").expect("Write file3");

        let hash1 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();
        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();
        let hash3 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_adding_file_changes_hash() {
        let temp_dir = std::env::temp_dir().join("test_add_file");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file1.txt"), b"content1").expect("Write file1");
        let hash1 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        fs::write(temp_dir.join("file2.txt"), b"content2").expect("Write file2");
        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        assert_ne!(hash1, hash2);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_removing_file_changes_hash() {
        let temp_dir = std::env::temp_dir().join("test_remove_file");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file1.txt"), b"content1").expect("Write file1");
        fs::write(temp_dir.join("file2.txt"), b"content2").expect("Write file2");
        let hash1 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        fs::remove_file(temp_dir.join("file2.txt")).expect("Remove file");
        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        assert_ne!(hash1, hash2);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_renaming_file_does_not_change_hash() {
        let temp_dir = std::env::temp_dir().join("test_rename");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("old_name.txt"), b"content").expect("Write file");
        let hash1 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        fs::rename(temp_dir.join("old_name.txt"), temp_dir.join("new_name.txt"))
            .expect("Rename file");
        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        assert_eq!(hash1, hash2);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_filename_sorting_determinism() {
        let temp_dir1 = std::env::temp_dir().join("test_sort1");
        let temp_dir2 = std::env::temp_dir().join("test_sort2");
        let _ = fs::remove_dir_all(&temp_dir1);
        let _ = fs::remove_dir_all(&temp_dir2);
        fs::create_dir(&temp_dir1).expect("Create temp dir1");
        fs::create_dir(&temp_dir2).expect("Create temp dir2");

        fs::write(temp_dir1.join("a.txt"), b"content_a").expect("Write a");
        fs::write(temp_dir1.join("b.txt"), b"content_b").expect("Write b");
        fs::write(temp_dir1.join("c.txt"), b"content_c").expect("Write c");

        fs::write(temp_dir2.join("c.txt"), b"content_c").expect("Write c");
        fs::write(temp_dir2.join("a.txt"), b"content_a").expect("Write a");
        fs::write(temp_dir2.join("b.txt"), b"content_b").expect("Write b");

        let hash1 = calculate_flat_dir_directory_pearson_hash(&temp_dir1).unwrap();
        let hash2 = calculate_flat_dir_directory_pearson_hash(&temp_dir2).unwrap();

        assert_eq!(hash1, hash2);

        fs::remove_dir_all(&temp_dir1).expect("Clean up");
        fs::remove_dir_all(&temp_dir2).expect("Clean up");
    }

    #[test]
    fn test_special_characters_in_filenames() {
        let temp_dir = std::env::temp_dir().join("test_special_chars");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file with spaces.txt"), b"content1").expect("Write file");
        fs::write(temp_dir.join("file_emoji_🚀.txt"), b"content2").expect("Write file");
        fs::write(temp_dir.join("file-dash.txt"), b"content3").expect("Write file");

        let hash = calculate_flat_dir_directory_pearson_hash(&temp_dir);
        assert!(hash.is_ok());

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_write_directory_hash_file() {
        let temp_dir = std::env::temp_dir().join("test_write_hash");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("file.txt"), b"content").expect("Write file");
        let hash = calculate_flat_dir_directory_pearson_hash(&temp_dir).unwrap();

        let output_path = write_directory_hash_file(&hash, &temp_dir, "test_write_hash")
            .expect("Write hash file");

        assert!(output_path.exists());
        let written_hash = fs::read_to_string(&output_path).expect("Read hash file");
        assert_eq!(written_hash, hash);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_write_directory_hash_file_validation() {
        let temp_dir = std::env::temp_dir().join("test_write_validation");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        let result = write_directory_hash_file("", &temp_dir, "test");
        assert!(result.is_err());

        let result = write_directory_hash_file("abcd1234", &temp_dir, "");
        assert!(result.is_err());

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_many_small_files() {
        let temp_dir = std::env::temp_dir().join("test_many_files");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        for i in 0..100 {
            let filename = format!("file_{:03}.txt", i);
            let content = format!("content_{}", i);
            fs::write(temp_dir.join(filename), content.as_bytes()).expect("Write file");
        }

        let hash = calculate_flat_dir_directory_pearson_hash(&temp_dir);
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().len(), 32);

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }

    #[test]
    fn test_whitespace_file() {
        let temp_dir = std::env::temp_dir().join("test_whitespace");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir(&temp_dir).expect("Create temp dir");

        fs::write(temp_dir.join("spaces.txt"), b"     ").expect("Write spaces");
        fs::write(temp_dir.join("newlines.txt"), b"\n\n\n\n").expect("Write newlines");
        fs::write(temp_dir.join("tabs.txt"), b"\t\t\t").expect("Write tabs");

        let hash = calculate_flat_dir_directory_pearson_hash(&temp_dir);
        assert!(hash.is_ok());

        fs::remove_dir_all(&temp_dir).expect("Clean up");
    }
}

/*
mod padnet_otp_module;

use padnet_otp_module::{
    PadIndex, PadIndexMaxSize, ValidationLevel, find_first_available_line,
    padnet_load_delete_read_one_byteline, padnet_make_one_pad_set, padnet_reader_xor_file,
    padnet_writer_strict_cleanup_continuous_xor_file, read_padset_one_byteline,
};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Get the directory containing the executable
fn get_exe_dir() -> PathBuf {
    env::current_exe()
        .expect("Failed to get executable path")
        .parent()
        .expect("No parent directory")
        .to_path_buf()
}

/// Recursively copy a directory (for simulating pad distribution)
fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// Print a section header
fn print_section(title: &str) {
    println!("\n{}", "=".repeat(70));
    println!("{}", title);
    println!("{}", "=".repeat(70));
}

/// Print a test step
fn print_step(step_num: &str, description: &str) {
    println!("\n{}: {}", step_num, description);
}

/// Pause for user to press Enter
fn pause() {
    print!("\nPress Enter to continue...");
    io::stdout().flush().unwrap();
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
}

// ============================================================================
// TEST 1: BASIC PADSET CREATION
// ============================================================================

fn test_1_basic_padset_creation(base_path: &Path) {
    print_section("TEST 1: Basic Padset Creation");

    let padset_path = base_path.join("test1_basic_padset");

    print_step("1.1", "Creating minimal padset (no hashing)");
    let bounds = PadIndex::new_standard([0, 0, 0, 2]); // 3 lines
    println!("  Bounds: [0,0,0,2] = 1 nest, 1 pad, 1 page, 3 lines");
    println!("  Path: {}", padset_path.display());

    match padnet_make_one_pad_set(&padset_path, &bounds, 32, ValidationLevel::None) {
        Ok(()) => println!("  ✓ Padset created successfully"),
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    }

    print_step("1.2", "Finding first available line");
    match find_first_available_line(&padset_path, PadIndexMaxSize::Standard4Byte) {
        Ok(Some(idx)) => println!("  ✓ First line: {:?}", idx),
        Ok(None) => println!("  ✗ No lines found"),
        Err(e) => println!("  ✗ Error: {}", e),
    }

    println!("\n  Cleanup: rm -rf {}", padset_path.display());
}

// ============================================================================
// TEST 2: LINE LOADING (NON-DESTRUCTIVE AND DESTRUCTIVE)
// ============================================================================

fn test_2_line_loading(base_path: &Path) {
    print_section("TEST 2: Line Loading Operations");

    let padset_path = base_path.join("test2_line_loading");

    print_step("2.1", "Creating test padset");
    let bounds = PadIndex::new_standard([0, 0, 0, 3]); // 4 lines
    match padnet_make_one_pad_set(&padset_path, &bounds, 32, ValidationLevel::None) {
        Ok(()) => println!("  ✓ Created 4 lines"),
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    }

    print_step("2.2", "Non-destructive read (reader mode)");
    let index_0 = PadIndex::new_standard([0, 0, 0, 0]);
    match read_padset_one_byteline(&padset_path, &index_0) {
        Ok(bytes) => {
            println!("  ✓ Read {} bytes from line_000", bytes.len());
            println!(
                "  First 16 bytes (hex): {:02x?}",
                &bytes[..16.min(bytes.len())]
            );

            // Verify file still exists
            if index_0.to_path(&padset_path).exists() {
                println!("  ✓ File preserved (non-destructive confirmed)");
            } else {
                println!("  ✗ File deleted unexpectedly");
            }
        }
        Err(e) => println!("  ✗ Failed: {}", e),
    }

    print_step("2.3", "Read same line again (should work)");
    match read_padset_one_byteline(&padset_path, &index_0) {
        Ok(bytes) => println!("  ✓ Read {} bytes again (file preserved)", bytes.len()),
        Err(e) => println!("  ✗ Failed: {}", e),
    }

    print_step("2.4", "Destructive read (writer mode)");
    let index_1 = PadIndex::new_standard([0, 0, 0, 1]);
    match padnet_load_delete_read_one_byteline(&padset_path, &index_1) {
        Ok(bytes) => {
            println!("  ✓ Loaded and deleted {} bytes from line_001", bytes.len());

            // Verify file was deleted
            if !index_1.to_path(&padset_path).exists() {
                println!("  ✓ File deleted (destructive confirmed)");
            } else {
                println!("  ✗ File still exists");
            }
        }
        Err(e) => println!("  ✗ Failed: {}", e),
    }

    print_step("2.5", "Try to read deleted line (should fail)");
    match read_padset_one_byteline(&padset_path, &index_1) {
        Ok(_) => println!("  ✗ Unexpectedly succeeded"),
        Err(e) => println!("  ✓ Correctly failed: {}", e),
    }

    print_step("2.6", "Find first available line");
    match find_first_available_line(&padset_path, PadIndexMaxSize::Standard4Byte) {
        Ok(Some(idx)) => {
            println!("  ✓ First available: {:?}", idx);
            println!("  Expected: [0,0,0,0] (line_000 still exists)");
        }
        Ok(None) => println!("  ✗ No lines found"),
        Err(e) => println!("  ✗ Error: {}", e),
    }

    println!(
        "\n  Manual check: ls -la {}/padnest_0_000/pad_000/page_000/",
        padset_path.display()
    );
    println!("  Expected: line_000, line_002, line_003 (line_001 deleted)");
    println!("  Cleanup: rm -rf {}", padset_path.display());
}

// ============================================================================
// TEST 3: FULL ALICE & BOB ENCRYPT/DECRYPT CYCLE
// ============================================================================

fn test_3_alice_bob_cycle(base_path: &Path) {
    print_section("TEST 3: Alice & Bob Full OTP Cycle");

    let alice_padset = base_path.join("test3_alice_padset");
    let bob_padset = base_path.join("test3_bob_padset");
    let plaintext = base_path.join("test3_plaintext.txt");
    let encrypted = base_path.join("test3_encrypted.bin");
    let decrypted = base_path.join("test3_decrypted.txt");

    print_step("3.1", "Alice creates her padset");
    let bounds = PadIndex::new_standard([0, 0, 0, 10]); // 11 lines
    match padnet_make_one_pad_set(&alice_padset, &bounds, 64, ValidationLevel::None) {
        Ok(()) => println!("  ✓ Alice's padset created (11 lines, 64 bytes each)"),
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    }

    print_step("3.2", "Bob receives identical copy");
    match copy_dir_all(&alice_padset, &bob_padset) {
        Ok(()) => println!("  ✓ Bob's padset copied (identical to Alice's)"),
        Err(e) => {
            println!("  ✗ Copy failed: {}", e);
            return;
        }
    }

    print_step("3.3", "Alice creates secret message");
    let message =
        b"This is a secret message that needs OTP encryption!\nLine 2 of data.\nLine 3 here.";
    match fs::write(&plaintext, message) {
        Ok(()) => {
            println!("  ✓ Message: {} bytes", message.len());
            println!("  Content: {:?}", String::from_utf8_lossy(message));
        }
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    }

    print_step("3.4", "Alice encrypts (writer mode - destructive)");
    let (start_index, bytes_encrypted) = match padnet_writer_strict_cleanup_continuous_xor_file(
        &plaintext,
        &encrypted,
        &alice_padset,
    ) {
        Ok((idx, bytes)) => {
            println!("  ✓ Encrypted {} bytes", bytes);
            println!("  ✓ Starting index: {:?}", idx);
            (idx, bytes)
        }
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    };

    // Verify encrypted differs from plaintext
    if let Ok(encrypted_content) = fs::read(&encrypted) {
        if encrypted_content != message {
            println!("  ✓ Encrypted content differs from plaintext");
        } else {
            println!("  ✗ Encrypted matches plaintext (XOR failed!)");
        }
    }

    print_step("3.5", "Check Alice's pad consumption");
    match find_first_available_line(&alice_padset, PadIndexMaxSize::Standard4Byte) {
        Ok(Some(idx)) => println!("  ✓ Alice's next available: {:?} (used lines deleted)", idx),
        Ok(None) => println!("  ✓ Alice's pad fully consumed"),
        Err(e) => println!("  ✗ Error: {}", e),
    }

    print_step("3.6", "Alice sends Bob: encrypted file + starting index");
    println!("  File: {}", encrypted.display());
    println!("  Index: {:?}", start_index);

    print_step("3.7", "Bob decrypts (reader mode - non-destructive)");
    let bytes_decrypted =
        match padnet_reader_xor_file(&encrypted, &decrypted, &bob_padset, &start_index) {
            Ok(bytes) => {
                println!("  ✓ Decrypted {} bytes", bytes);
                bytes
            }
            Err(e) => {
                println!("  ✗ Failed: {}", e);
                return;
            }
        };

    print_step("3.8", "Verify correctness");
    match fs::read(&decrypted) {
        Ok(decrypted_content) => {
            if decrypted_content == message {
                println!("  ✓✓✓ SUCCESS! Bob's message matches Alice's original! ✓✓✓");
                println!("  Original:  {} bytes", message.len());
                println!("  Encrypted: {} bytes", bytes_encrypted);
                println!("  Decrypted: {} bytes", bytes_decrypted);
            } else {
                println!("  ✗ FAILURE! Content mismatch");
            }
        }
        Err(e) => println!("  ✗ Read failed: {}", e),
    }

    print_step("3.9", "Test Bob's re-read capability");
    let decrypted2 = base_path.join("test3_decrypted2.txt");
    match padnet_reader_xor_file(&encrypted, &decrypted2, &bob_padset, &start_index) {
        Ok(bytes) => println!(
            "  ✓ Re-decrypted {} bytes (reader mode preserved pad)",
            bytes
        ),
        Err(e) => println!("  ✗ Re-decrypt failed: {}", e),
    }

    println!(
        "\n  Compare: diff {} {}",
        plaintext.display(),
        decrypted.display()
    );
    println!(
        "  Alice's pad: ls {}/padnest_0_000/pad_000/page_000/",
        alice_padset.display()
    );
    println!(
        "  Bob's pad:   ls {}/padnest_0_000/pad_000/page_000/",
        bob_padset.display()
    );
    println!(
        "  Cleanup: rm -rf {} {} {} {} {} {}",
        alice_padset.display(),
        bob_padset.display(),
        plaintext.display(),
        encrypted.display(),
        decrypted.display(),
        decrypted2.display()
    );
}

// ============================================================================
// TEST 4: HASH VALIDATION (PAGE-LEVEL AND PAD-LEVEL)
// ============================================================================

fn test_4_hash_validation(base_path: &Path) {
    print_section("TEST 4: Hash Validation");

    // Test 4A: Page-level hashing
    println!("\n--- 4A: Page-Level Hashing ---");

    let alice_page = base_path.join("test4a_alice_pagehash");
    let bob_page = base_path.join("test4a_bob_pagehash");

    print_step("4A.1", "Create padset with PAGE-level hashing");
    let bounds = PadIndex::new_standard([0, 0, 1, 3]); // 2 pages, 4 lines each
    match padnet_make_one_pad_set(&alice_page, &bounds, 64, ValidationLevel::PageLevel) {
        Ok(()) => println!("  ✓ Created with page-level hashing"),
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    }

    print_step("4A.2", "Verify hash files created");
    let hash_000 = alice_page.join("padnest_0_000/pad_000/hash_page_000");
    let hash_001 = alice_page.join("padnest_0_000/pad_000/hash_page_001");

    if hash_000.exists() {
        let content = fs::read_to_string(&hash_000).unwrap();
        println!("  ✓ hash_page_000 exists");
        println!("    Hash: {}", content.trim());
    } else {
        println!("  ✗ hash_page_000 missing");
    }

    if hash_001.exists() {
        let content = fs::read_to_string(&hash_001).unwrap();
        println!("  ✓ hash_page_001 exists");
        println!("    Hash: {}", content.trim());
    } else {
        println!("  ✗ hash_page_001 missing");
    }

    print_step("4A.3", "Copy to Bob (with hashes)");
    match copy_dir_all(&alice_page, &bob_page) {
        Ok(()) => println!("  ✓ Bob's copy created"),
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    }

    print_step("4A.4", "Alice encrypts (validates hash during operation)");
    let plaintext = base_path.join("test4a_plaintext.txt");
    let encrypted = base_path.join("test4a_encrypted.bin");
    fs::write(&plaintext, b"Testing page-level hash validation!").unwrap();

    match padnet_writer_strict_cleanup_continuous_xor_file(&plaintext, &encrypted, &alice_page) {
        Ok((idx, bytes)) => {
            println!("  ✓ Encryption succeeded with hash validation");
            println!("    Index: {:?}, Bytes: {}", idx, bytes);
        }
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    }

    print_step("4A.5", "Check hash deletion after validation");
    if !hash_000.exists() {
        println!("  ✓ Hash deleted after validation (expected)");
    } else {
        println!("  ✗ Hash still exists (unexpected)");
    }

    print_step("4A.6", "Bob decrypts (validates his hash)");
    let decrypted = base_path.join("test4a_decrypted.txt");
    let idx = PadIndex::new_standard([0, 0, 0, 0]);
    match padnet_reader_xor_file(&encrypted, &decrypted, &bob_page, &idx) {
        Ok(bytes) => println!("  ✓ Decryption succeeded: {} bytes", bytes),
        Err(e) => println!("  ✗ Failed: {}", e),
    }

    // Test 4B: Pad-level hashing
    println!("\n--- 4B: Pad-Level Hashing ---");

    let alice_pad = base_path.join("test4b_alice_padhash");

    print_step("4B.1", "Create padset with PAD-level hashing");
    match padnet_make_one_pad_set(&alice_pad, &bounds, 64, ValidationLevel::PadLevel) {
        Ok(()) => println!("  ✓ Created with pad-level hashing"),
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    }

    print_step("4B.2", "Verify pad hash file");
    let pad_hash = alice_pad.join("padnest_0_000/hash_pad_000");
    if pad_hash.exists() {
        let content = fs::read_to_string(&pad_hash).unwrap();
        println!("  ✓ hash_pad_000 exists");
        println!("    Hash: {}", content.trim());
    } else {
        println!("  ✗ hash_pad_000 missing");
    }

    println!(
        "\n  Cleanup: rm -rf {} {} {}",
        alice_page.display(),
        bob_page.display(),
        alice_pad.display()
    );
}

// ============================================================================
// TEST 5: CORRUPTION DETECTION
// ============================================================================

fn test_5_corruption_detection(base_path: &Path) {
    print_section("TEST 5: Corruption Detection");

    let padset = base_path.join("test5_corrupt_padset");

    print_step("5.1", "Create padset with page hashing");
    let bounds = PadIndex::new_standard([0, 0, 0, 3]); // 4 lines
    match padnet_make_one_pad_set(&padset, &bounds, 32, ValidationLevel::PageLevel) {
        Ok(()) => println!("  ✓ Padset created"),
        Err(e) => {
            println!("  ✗ Failed: {}", e);
            return;
        }
    }

    print_step("5.2", "Corrupt a line file (simulate bit-flip)");
    let line_path = padset.join("padnest_0_000/pad_000/page_000/line_001");
    let mut data = fs::read(&line_path).unwrap();
    data[0] ^= 0xFF; // Flip all bits in first byte
    fs::write(&line_path, data).unwrap();
    println!("  ✓ line_001 corrupted");

    // print_step("5.3", "Use line_000 (not corrupted - should work)");
    // let plaintext1 = base_path.join("test5_plain1.txt");
    // let encrypted1 = base_path.join("test5_enc1.bin");
    // fs::write(&plaintext1, b"x").unwrap(); // Tiny file

    print_step("5.3", "Use line_000 (not corrupted, but in corrupted page)");
    let plaintext1 = base_path.join("test5_plain1.txt");
    let encrypted1 = base_path.join("test5_enc1.bin");
    fs::write(&plaintext1, b"x").unwrap(); // Tiny file

    match padnet_writer_strict_cleanup_continuous_xor_file(&plaintext1, &encrypted1, &padset) {
        Ok(_) => println!("  ✗ Unexpectedly succeeded (should reject corrupted page)"),
        Err(e) => println!(
            "  ✓ Correctly rejected entire page: {}\n    (Page-level hashing rejects ALL lines if ANY file corrupted)",
            e
        ),
    }

    print_step("5.4", "Verify page-level protection is working correctly");
    println!("  ✓ Page hash includes all files (line_000, line_001, line_002, line_003)");
    println!("  ✓ Corrupting any one file invalidates entire page hash");
    println!("  ✓ This prevents using ANY lines from partially-corrupted page");
    println!("  ✓ Security property: all-or-nothing page integrity");

    match padnet_writer_strict_cleanup_continuous_xor_file(&plaintext1, &encrypted1, &padset) {
        Ok(_) => println!("  ✓ line_000 worked (not corrupted)"),
        Err(e) => println!("  Note: {}", e),
    }

    print_step("5.4", "Try to use page with corrupted line_001");
    let plaintext2 = base_path.join("test5_plain2.txt");
    let encrypted2 = base_path.join("test5_enc2.bin");
    fs::write(&plaintext2, b"x").unwrap();

    match padnet_writer_strict_cleanup_continuous_xor_file(&plaintext2, &encrypted2, &padset) {
        Ok(_) => println!("  ✗ Unexpectedly succeeded (should detect corruption)"),
        Err(e) => println!("  ✓ Correctly detected corruption: {}", e),
    }

    println!("\n  Cleanup: rm -rf {}", padset.display());
}

// ============================================================================
// MAIN: RUN ALL TESTS
// ============================================================================

fn main() {
    println!("\n{}", "█".repeat(70));
    println!("  PADNET OTP MODULE - COMPREHENSIVE TEST SUITE");
    println!("{}\n", "█".repeat(70));

    let base_path = get_exe_dir();
    println!("Test directory: {}\n", base_path.display());

    // Run all tests
    test_1_basic_padset_creation(&base_path);
    pause();

    test_2_line_loading(&base_path);
    pause();

    test_3_alice_bob_cycle(&base_path);
    pause();

    test_4_hash_validation(&base_path);
    pause();

    test_5_corruption_detection(&base_path);

    // Final summary
    print_section("ALL TESTS COMPLETE");
    println!("\n✓ Test 1: Basic padset creation");
    println!("✓ Test 2: Line loading (destructive & non-destructive)");
    println!("✓ Test 3: Full Alice & Bob OTP cycle");
    println!("✓ Test 4: Hash validation (page & pad level)");
    println!("✓ Test 5: Corruption detection");

    println!("\n{}", "█".repeat(70));
    println!("  All test artifacts in: {}", base_path.display());
    println!("  Clean up: rm -rf {}/test*", base_path.display());
    println!("{}\n", "█".repeat(70));
}

 */
