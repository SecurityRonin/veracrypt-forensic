#![no_main]
//! Fuzz `VeraHeader::validate` over arbitrary bytes — the candidate-decrypted
//! 448-byte header validator (magic + dual CRC-32). Invariant: never panic.

use libfuzzer_sys::fuzz_target;
use veracrypt::VeraHeader;

fuzz_target!(|data: &[u8]| {
    let _ = VeraHeader::validate(data);
});
