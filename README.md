#### padnet_otp

# Padnet (OTP-Network 'Layer') 

This is to be a single flatfile crate, padnet_opt_module.rs file.

2025.11.20,27:

pad_index_array = 4 bytes 2^32 == 4_294_967_296
or 8-bytes = (2^64) 

## Size
Size note: 8-bytes is equivalent to adding another u64 timestamp to the data-sent, not extravagant.

(illustration, not literal numbering, naming)

## up to N size u8 array: here are two examples:
###(size: 4*u8)
0. a 'line' is a 0-255 numbered file containing N bytes
1. a 'page' is a 0-255 numbered directory of 'line' files
2. a 'pad' is a 0-255 numbered directory of page directories
3. a 'padnest_0' is a 0-255 numbered directory of pad
- small, practical

### (size: 8*u8)
4. a 'padnest_1' is a 0-255 numbered directory of padnest_0 directories
5. a 'padnest_2' is a 0-255 numbered directory of padnest_1 directories
6. a 'padnest_3' is a 0-255 numbered directory of padnest_2 directories
7. a 'padnest_4' is a 0-255 numbered directory of padnest_3 directories
- still small, practical

For lookup, the array should follow the next lookup)
[0,1,2,3,4]

#### naming:
keep names uniform and simple: name, one underscore, number: split on underscore, get number.

#### Hybrid:
1. adjustable N bytes per line, e.g. 16 to 512+ (depending on user file size)
512+ is mentioned here as an example for some strange situations. In reality, 16-64 will be used at most.

2. PadsetSize
```rust
pub enum PadsetSize {
    Standard4Byte,  // 4-byte index: ~137 GB to 2 TB
    Extended8Byte,  // 8-byte index: ~590 EB to 9.4 ZB  
}
```
3. Note: a pad does not need to fill the index, a person could make a 10mb pad, as long as the index is not smaller than the pad.




Overview of Pad use:
1. LOAD the entire line file into memory
(yes, pedantically this is a 'whole line' and a 'while file' but this is a unit of pad (usually 32-128 bytes) modulated as a file, called a 'line' purely because One Time "Pads" were physical books, 'pages' physical pages' and 'lines' physical paper lines.)
to repeat that again: Yes, load the unit of bytes designed to be loaded as a module of bytes that is here called a "line" and is saved as a 'file' the rule (of thumb) saying 'Don't load whole files' (e.g. loading unknown material of unknown size or material you know that you do not need) very clearly does not apply in this case. 
2. DELETE the 'line' file (after it is loaded, before it is used)
- XOR bytes using the in-memory line buffer
3. Target file: Read target file one byte at a time
When in-memory pad "line" file bytes are exhausted → loop back, load next pad "line" file

Recap: "read one byte at a time" refers only to the target file, not the pad line.


## Functions:

1. padnet_make_one_pad_set(
max_pad_index_array, struct
number_of_bytes_per_line, int
dir_checksum_files_pad_page, bool
)
- max_pad_index_array: how many of each array item to make: 
this specifies how much to put in with bounded limits
up to 255, but can be smaller [0,0,0,1] is one page.
- uses as much non-pseudo entropy as possible
- single source of truth: the index array size is 4 or 8
depending on max_pad_index_array
- MVP: number_of_bytes_per_line is fixed number per "line" file
- dir_checksum_files_pad_page: if true, dir-hash (https://github.com/lineality/padnet_otp) of pad dir and page dir (not each line file, not nest-set)

~Enum:level_of_validation_hashing
- PadLevelHashing
- PageLevelHashing
- None
(see details below)

2. read_padset_one_byteline(
path_to_padset, 
pad_index_array, 
) -> result<bytes>

- This may be (if ever) used for recipient reading, where they may need to re-process a XOR file for whatever reason.
- before loading a new page/pad check for a hash

3. padnet_load_delete_read_one_byteline(
path_to_padset, 
pad_index_array, 
) -> result<bytes>
- This is either always used period, or always used to for first XOR of a file. An OPT XOR'd file must (strictly) use fresh (never before used bytes). Presumably, the second 'read' pass by the recipient is not as strict. E.g. if a sender needs to re-try then they naturally start again beginning with a fresh (not used before line). But the recipient will lose the ability to try-again read if they destroy their pad.

4. padnet_reader_xor_file(
path_to_target_file, 
result_path,
path_to_padset, 
pad_index_array, 
) -> result<new_bytes>
- for read/re-read
- this reads from a specific byte position
- this can safely append results to the result_path (can be interrupted)

5. padnet_writer_strict_cleanup_continous_xor_file(
path_to_target_file, 
result_path,
path_to_padset, 
) -> result<(starting_pad_index_array_as_pad_start_byte_position, new_bytes)>
- for write
- this (calls a function that) uses (and consumes) each next line
- Writer Starting Position: the 'start line' is observed and reported, not selected; the index of the start is returned. Since these line-files are deleted, the 'first' file is the 'last' or 'next' that exists. the ~name of the files found are reported (remaining items correspond to, or are, the index values that become the index-array that is returned:
The index array directly corresponds to (is) filesystem directory/file names.
```text
padnest0_008/pad_255/page_103/line_254
         ↓     ↓      ↓       ↓
       [8,   255,   103,    254]
```


- the output of this should be 'atomic', making a draft file in an adjacent /padnet_temp/ directory (same parent as target file). 
- e.g. call and increment index for padnet_load_delete_read_one_byteline until A. task done, publish draft or B. abort: pad ran out, or C: error abort
- finally remove tmp

Ff you are at [FF,FF,FF,FF] and the next step it roll-over increment (this can only happen for reading-not writing (for writer the pad-set will literally have been entirely deleted)) exit with terse pad-done message.

# Design questions:
- Best (soundest, not fastest) ways to 'stream-read' bytes from pad moving
from line to line:
maybe:

- It is a somewhat arbitrary choice about how many nested functions there should be in the XOR process.
e.g. 



### writer: 
- padnet_writer_strict_cleanup_continous_xor_file():
- if any exception/error/case occurs such as or such as results in a discontinuity of pad bytes, the entire process must halt, all observed lines should be destroyed (they were destroyed after loading), all created files should be destroyed (the temp-dir can be cleaned). The process can start again only from a fresh pad_index_array (try again from next pad-line).
- 'continuous' vs. 'atomic': 'atomic' is often described as all-or-nothing. write-OPT is simply 'all' whether it succeeds or fails, there is no re-try.

1. get target_file_path
2. get path_to_padset
3. get pad_index_array
4. make new_file
5. load_delet one line from (path_to_padset, pad_index_array)
6. increment pad_index_array
7. read one byte at a time from target_file_path @ current_target_file_byte_position (updating current_target_file_byte_position)
- Open target file once
- track/seek position
- read byte, process byte
- append processed byte to new_file
- until target file path is over, or
- until byte_line in memory is empty
- If at end of padset-stop (cannot proceed)
If byte_line from pad is empty first: repeat steps 6-7
(Loops until end of file or end of padset)

The 'writer' function does not have an input start-byte (start index), it uses the 'top' file that has not been deleted yet (and deletes that one next). 
Example process:
1. Read directory entries at each level
2. Sort numerically ascending (so 000_ is first and 255_ is last)
3. Take the first entry
4. Descend to next level
5. Repeat until finding first existing "line" file

As you 'sort-search' each level, node the index you are building up.

root level 008_
-> [008,,,]
next level 255_
-> [008,255,,]
next level 103_
-> [008,255,103,]
"line" file level, 254
-> [008,255,103,254]

if no errors, this index gets returned with the resulting bytes.

### padnet_reader_xor_file():
- if an exception/error/case occurs such as or such as results in a discontinuity of pad bytes, the entire process must halt, all created files should be destroyed. The process can start again only from the original pad_index_array.

1. get target_file_path
2. get path_to_padset
3. get pad_index_array
4. make new_file
5. load one line from (path_to_padset, pad_index_array)
6. increment pad_index_array
7. read one byte at a time from target_file_path @ current_target_file_byte_position (updating current_target_file_byte_position)
- append processed byte to new_file
- until target file path is over, or
- until byte_line in memory is empty
- If at end of padset-stop (cannot proceed)
If byte_line from pad is empty first: repeat steps 6-7
(Loops until end of file or end of padset)

## Line length:
A line file is a file.
We read it and get bytes. However many bytes are in that file = how many bytes are in the line. As long as we don't run out of pad, there should not be a need to predict or micro-manage how long users choose to make lines.

## File-length:
File lengths are not "padded" as 'file chunks' often are; file byte-length stays the same.

# pad/page verification/validation
- users choose page or pad scale hash-checking
- process to move to next line/pad can check if there is a hash-file for that line/pad and validate first.


## pad-level:
```
padnest0/
├── pad_042/
│   ├── page_000/
│   │   ├── line_000
│   │   ├── line_001
│   │   └── ...
│   ├── page_001/
│   └── ...
├── hash_pad_042          <- Hash file for pad_042 (sibling to directory)
```

## page-level:
```
pad_042/
├── page_000/
│   ├── line_000
│   ├── line_001
│   └── ...
├── hash_page_000         <- Hash file for page_000 (sibling to directory)
```




This should allow for
bytes<u8> size N to give the exact starting line for the one-time-pad

hard-wired into the system, as soon as a line-file is read into memory, 
before it is used,
that file is deleted (probably hex-edit erased, or over-saved as empty, before being 'put in trash', or whatever is thorough. 

e.g. Overwrite with zeros (single pass overwrite in place), then delete file as Rust can do without 3rd-party crate dependencies

the system will allow to continue reading bytes ~continuously into next lines and pages (removing those lines as loaded)

This is an (optional) part of a file gpg/pgp encryption/decryption pipeline:
1. before a file is gpg-encrypted, there is the (boolean flag) option to first one-time-pad encrypt the bytes of that file (e.g. creating a padnet-encrypted file and directing that file to gpg-encryption instead)
the start_line_index_array (the N size u8 array) will be (optionally) passed along with the gpg file (details? does not have to be wrapped in same function, can be stored/passed before encryption). 

2. when a file received it is received with the option of a start_line_index_array array, so that the reverse (byte xor?) process

/// Size/scale of padset index space
pub enum PadIndexMaxSize {
    Standard4Byte,  // [u8; 4]: 256^4 lines
    Extended8Byte,  // [u8; 8]: 256^8 lines
}

/// Integrity validation strategy
pub enum ValidationLevel {
    PadLevel,      // Hash entire pad directories
    PageLevel,     // Hash each page directory
    None,          // No validation (trust filesystem)
}

/// Operational mode for XOR processing
pub enum OperationMode {
    Writer,  // Strict: destroy on any error
    Reader,  // Tolerant: can retry
}

/// Index representation (internal)
enum PadSizeDatatype {
    Standard4Byte([u8; 4]),
    Extended8Byte([u8; 8]),
}


# Pad Making
Pad making is a forever pursuit of ideal entropy.
That said, there should be a simple MPV approach to get some kind of real entropy. Focus on Posix (forget "windows" vaporware)

e.g.
use std::fs::File;
use std::io::Read;

fn read_entropy(bytes_needed: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open("/dev/urandom")?;
    let mut buffer = vec![0u8; bytes_needed];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}
- Present on all POSIX systems (Linux, BSD, macOS, etc.)
- Cryptographically secure for OTP purposes
- Non-blocking - always returns immediately
- Kernel-maintained entropy pool
- Accessible via std library only - no external crates needed

# Error Handling Strategy
### If entropy source fails:
- Return error immediately - Do not proceed with pad creation
- Terse production error: "Entropy source unavailable"
- Debug/test error: "Failed to open /dev/urandom: {io_error}"
- Caller's responsibility to handle (abort pad creation, log, retry, etc.)

### Failure scenarios:
- /dev/urandom doesn't exist (non-POSIX system)
- Permission denied
- I/O error during read
-> No fallbacks - If entropy source fails, pad creation must fail cleanly.


## 'Ordering' Design
For 'line' files (and directories in directories), starting with the sorted ascending first and incrementing seems natural,where next is higher-number not lower.

Start at: 000_→_001_→_002_→_..._→_255

For the index-array, 
[0,1,2,3]
is root to leaf
(root to leaf seems to make more sense)

## Big-endian (most significant first) / Root-to-branch:

array[0] = padnest_0 level (root)
array[1] = pad level
array[2] = page level
array[3] = line level (leaf)

# Errors, handles, cases:
As per rules, debug and test give whatever details are found, production errors are as terse as possible.


# hash checking
- "Check hash" before new pad/page, only before starting a new directory (once something is removed, that dir will not have the same hash)
1. detect next
2. see if a hash exists
3. if there is hash, check
4. if failed: if reader, exit. if writer: delete that dir of data and move on 
I.e. if the hash of the dir fails, that means the directory is corrupted and must be removed. Delete the corrupted data, and move on to the next chunk of data (and check if that is corrupted, etc).
(the normal flow)
5. if there is no hash file: nothing to do, move on


https://github.com/lineality/padnet_otp


If the hash for a dir is confirmed, delete that hash (text-file containing hash). 

If validation failed: delete what failed to be validated and only what failed to be validated, a specific directory.

Format of hash file: Plain text hex string, one line

# no pad metadata file needed, keep it simple, no bloat, no churn:
The filesystem state is the filesystem state:
- Line files exist or do not (deletion tracking)
- Hash files exist or do not (validation choice)
- Index array size is provided by caller
- Line size is whatever bytes are in the file
- No metadata is needed, required, used, or useful.


# Safety Checks:
There can be a reasonable max-size to the "line" length or line-file size. A line size should not be more than 5kb, or 4096. The exact too big number is not critical. when loading "line" file, if file size is above MAX_PADNET_PADLINE_FILE_SIZE_BYTES then error-exit.






(production-Rust rules)
# Rust rules:
- Always best practice.
- Always extensive doc strings: what the code is doing with project context
- Always clear comments.
- Always cargo tests (where possible).
- Never remove documentation.
- Always clear, meaningful, unique names (e.g. variables, functions).
- Always absolute file paths.
- Always error handling.
- Never unsafe code.
- Never use unwrap.

- Load what is needed when it is needed: Do not ever load a whole file or line, rarely load a whole anything. increment and load only what is required pragmatically. Do not fill 'state' with every possible piece of un-used information. Do not insecurity output information broadly in the case of errors and exceptions.

- Always defensive best practice
- Always error and exception handling: Every part of code, every process, function, and operation will fail at some point, if only because of cosmic-ray bit-flips (which are common), hardware failure, power-supply failure, adversarial attacks, etc. There must always be fail-safe error handling where production-release-build code handles issues and moves on without panic-crashing ever. Every failure must be handled smoothly: let it fail and move on. This does not mean that no function can return an error. Handling should occur where needed, e.g. before later functions are reached.

Somehow there seems to be no clear vocabulary for 'Do not stop.' When you come to something to handle, handle it:
- Handle and move on: Do not halt the program. 
- Handle and move on: Do not terminate the program.
- Handle and move on: Do not exit the program.
- Handle and move on: Do not crash the program.
- Handle and move on: Do not panic the program.
- Handle and move on: Do not coredump the program.
- Handle and move on: Do not stop the program.
- Handle and move on: Do not finish the program.

Comments and docs for functions and groups of functions must include project level information: To paraphrase Jack Welch, "The most dangerous thing in the world is a flawless operation that should never have been done in the first place." For projects, functions are not pure platonic abstractions; the project has a need that the function is or is not meeting. It happens constantly that a function does the wrong thing well and so this 'bug' is never detected. Project-level documentation and logic-level documentation are two different things that must both exist such that discrepancies must be identifiable; Project-level documentation, logic-level documentation, and the code, must align and align with user-needs, real conditions, and future conditions.

Safety, reliability, maintainability, fail-safe, communication-documentation, are the goals: not ideology, aesthetics, popularity, momentum-tradition, bad habits, convenience, nihilism, lazyness, lack of impulse control, etc. 

## No third party libraries (or very strictly avoid third party libraries where possible).

## Scale: Code should be future proof and scale well. The Y2K bug was not a wonderful feature, it was a horrendous mistake. Scale and size should be handled in a modular no-load way, not arbitrarily capped so that everything breaks.

## Rule of Thumb, ideals not absolute rules: Follow NASA's 'Power of 10 rules' where possible and sensible (as updated for 2025 and Rust (not narrowly 2006 c for embedded systems):
1. no unsafe stuff: 
- no recursion  
- no goto 
- no pointers 
- no preprocessor

2. upper bound on all normal-loops, failsafe for all always-loops

3. Pre-allocate all memory (no dynamic memory allocation)

4. Clear function scope and Data Ownership: Part of having a function be 'focused' means knowing if the function is in scope. Functions should be neither swiss-army-knife functions that do too many things, nor scope-less micro-functions that may be doing something that should not be done. Many functions should have a narrow focus and a short length, but definition of actual-project scope functionality must be explicit. Replacing one long clear in-scope function with 50 scope-agnostic generic sub-functions with no clear way of telling if they are in scope or how they interact (e.g. hidden indirect recursion) is unsafe. Rust's ownership and borrowing rules focus on Data ownership and hidden dependencies, making it even less appropriate to scatter borrowing and ownership over a spray of microfunctions purely for the ideology of turning every operation into a microfunction just for the sake of doing so. (See more in rule 9.)

5. Defensive programming: debug-assert, test-assert, prod safely check & handle, not 'assert!' panic 

Note: Terminology varies across "error" / "fail" / "exception" / "catch" / "case" et al. The standard terminology is 'error handling' but 'case handling' or 'issue handling' may be a more accurate description, especially where 'error' refers to the output when unable to handle a case (which becomes semantically paradoxical). The goal is not terminating / halting / ending / shutting down / stopping, etc., or crashing / failing / panicking / coredumping / undefined-behavior-ing, etc. the program when an expected case occurs. Here production and debugging/testing starkly diverge: during testing you want to see how (and where in the code) the program may 'fail' and where and when cases are encountered. In production the satellite must not fall out of the sky ever, regardless of how pedantically beautiful the error-message in the ball of flames may have been. 

For production-release code:
1. check and handle without panic/halt in production
2. return result (such as Result<T, E>) and smoothly handle errors (not halt-panic stopping the application): no assert!() outside of test-only code
Return Result<T, E>, with case/error/exception handling, so long as that is caught somewhere. Only in cases where there is no way (or no where) to handle the error-output should the function always return OK(), failing completely silently (sometimes internal-to-function error logging is best). Allow-to-fail and handle is not the same as no-handling. This is case-by case.
3. test assert: use #[cfg(test)] assert!() to test production binaries (not in prod or debug modes)
4. debug assert: use debug_assert! with  #[cfg(all(debug_assertions, not(test)))] to run tests in debug builds (not in prod, not in test)
5. note: #[cfg(debug_assertions)] and debug_assert! ARE active in test builds
6. use defensive programming with recovery of all issues at all times
- use cargo tests
- use debug_asserts
- do not leave assertions in production code.
- use no-panic error handling
- use Option
- use enums and structs
- check bounds
- check returns
- note: a test-flagged assert can test a production release build (whereas debug_assert cannot); cargo test --release
```
#[cfg(test)]
assert!(
```

e.g.
# "Assert & Catch-Handle" 3-part System

A three-part rule of thumb may be:

1. For Debug assertions: Only in debug builds, NOT in tests - use: #[cfg(all(debug_assertions, not(test)))]

2. For Test assertions: use in test functions themselves, not in the function body (easy to conflict with debug/prod handling)
E.g.
When we run a cargo test:
- The #[cfg(test)] assert compiles and is active
- the cargo-test calls string_concat_list_function()
- an assert! in the abc_function (not in the test) panics immediately inside the abc_function
- abc_function never reaches the production error handling
- so abc_function never returns an Err(...)
- so the cargo-test 'fails' with a panic, not with a cargo-test error result

3. Production catches: Always present, return production-safe no-heap terse errors (no panic, no open-ended data exfiltration), with unique error prefixes to identify the function, e.g. 'SCLF error: arg empty' for string_concat_list_function()



// template/example for check/assert format
//    =================================================
// // Debug-Assert, Test-Asset, Production-Catch-Handle
//    =================================================
// This is not included in production builds
// debug_assert: IS also active during test-builds
// use #[cfg(not(test))] to run in debug-build only: will panic
#[cfg(not(test))]
debug_assert!(
    INFOBAR_MESSAGE_BUFFER_SIZE > 0,
    "Info bar buffer must have non-zero capacity"
);

// this is included in debug builds AND test builds
#[cfg(all(debug_assertions, not(test)))]
{
xyz
}
                      

// note: this may be located only in cargo test functions
// This is not included in production builds
// assert: only when running cargo test: will panic
#[cfg(test)]
assert!(
    INFOBAR_MESSAGE_BUFFER_SIZE > 0,
    "Info bar buffer must have non-zero capacity"
);
// Catch & Handle without panic in production
// This IS included in production to safe-catch
if !INFOBAR_MESSAGE_BUFFER_SIZE == 0 {
    // state.set_info_bar_message("Config error");
    return Err(LinesError::GeneralAssertionCatchViolation(
        "zero buffer size error".into(),
    ));
}

Depending on the test, you may need a test-assert to be in a cargo-test function and not in the main function. 

Warning: Do not collide or mix up test-asserts and debug asserts, or forget that debug code also runs in test builds by default.; 
use #[cfg(all(debug_assertions, not(test)))] for debug build only (not test build).
use #[cfg(test)] assert!(  for test build only, not debug).
Give descriptive non-colliding names to cargo-tests and test sets.
            
Note: production-use characters and strings can be formatted, written, printed using modules such as Buffy
https://github.com/lineality/buffy_stack_format_write_module
instead of using standard Rust macros such as format! print! write! that use heap-memory. 


Note: Error messages must be unique per function (e.g. name of function (or abbreviation) in the error message). Colliding generic error messages that cannot be traced to a specific function are a significant liability. 


Avoid heap for error messages and for all things:
Is heap used for error messages because that is THE best way, the most secure, the most efficient, proper separate of debug testing vs. secure production code?
Or is heap used because of oversights and apathy: "it's future dev's problem, let's party."
We can use heap in debug/test modes/builds only.
Production software must not insecurely output debug diagnostics.
Debug information must not be included in production builds: "developers accidentally left development code in the software" is a classic error (not a desired design spec) that routinely leads to security and other issues. That is NOT supposed to happen. It is not coherent to insist the open ended heap output 'must' or 'should' be in a production build.

This is central to the question about testing vs. a pedantic ban on conditional compilation; not putting full traceback insecurity into production code is not a different operational process logic tree for process operations. 

Just like with the pedantic "all loops being bounded" rule, there is a fundamental exception: always-on loops must be the opposite.
With conditional compilations: code NEVER to EVER be in production-builds MUST be always "conditionally" excluded. This is not an OS conditional compilation or a hardware conditional compilation. This is an 'unsafe-testing-only or safe-production-code' condition.

Error messages and error outcomes in 'production' 'release' (real-use, not debug/testing) must not ever contain any information that could be a security vulnerability or attack surface. Failing to remove debugging inspection is a major category of security and hygiene problems.

Security: Error messages in production must NOT contain:
- File paths (can reveal system structure)
- File contents
- environment variables
- user, file, state, data
- internal implementation details
- etc.

All debug-prints not for production must be tagged with:
```
#[cfg(debug_assertions)]
```

Production output following an error / exception / case must be managed and defined, not not open to whatever an api or OS-call wants to dump out.

6. Manage ownership and borrowing

7. Manage return values: 
- use null-void return values 
- check non-void-null returns

8. Navigate debugging and testing on the one hand and not-dangerous conditional-compilation on the other hand:
- Here 'conditional compilation' is interpreted as significant changes to the overall 'tree' of operation depending on build settings/conditions, such as using different modules and basal functions. E.g. "GDPR compliance mode compilation"
- Any LLVM type compilation or build-flag will modify compilation details, but not the target tree logic of what the software does (arguably). 
- 2025+ "compilation" and "conditions" cannot be simplistically compared with single-architecture 1970 pdp-11-only C or similar embedded device compilation.

9. Communicate: 
- Use doc strings; use comments. 
- Document use-cases, edge-cases, and policies (These are project specific and cannot be telepathed from generic micro-function code. When a Mars satellite failed because one team used SI-metric units and another team did not, that problem could not have been detected by looking at, and auditing, any individual function in isolation without documentation. Breaking a process into innumerable undocumented micro-functions can make scope and policy impossible to track. To paraphrase Jack Welch: "The most dangerous thing in the world is a flawless operation that should never have been done in the first place.")

10. Use state-less operations when possible:
- a seemingly invisibly small increase in state often completely destroys projects
- expanding state destroys projects with unmaintainable over-reach

Vigilance: We should help support users and developers and the people who depend upon maintainable software. Maintainable code supports the future for us all.


