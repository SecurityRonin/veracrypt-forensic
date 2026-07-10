#![no_main]
//! Fuzz the full unlock path over arbitrary bytes: a short password taken from the
//! head of the input, the remainder treated as a VeraCrypt container. Drives the
//! header read, the PRF x cipher brute, XTS header decryption, and validation.
//! Invariant: never panic. (Inputs under 512 bytes short-circuit to `TooSmall`
//! before any PBKDF2 work, keeping the fuzzer's early corpus fast.)

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use veracrypt::VeraVolume;

fuzz_target!(|data: &[u8]| {
    // Up to 4 bytes of arbitrary password, the rest is the container.
    let split = data.len().min(4);
    let (password, container) = data.split_at(split);
    let _ = VeraVolume::unlock_with_password(Cursor::new(container), password);
});
