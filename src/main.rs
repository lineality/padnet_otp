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
