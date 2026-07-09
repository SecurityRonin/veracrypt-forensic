//! Tier-1 oracle: unlock the cryptsetup-project `vc_1-sha512-xts-aes` VeraCrypt
//! volume (SHA-512 PRF, AES-256-XTS) with its published password and confirm the
//! decrypted sectors match `cryptsetup --veracrypt` byte-for-byte (SHA-256).
//!
//! Tier-1: the cryptsetup project authored this real VeraCrypt volume AND
//! publishes the password (`aaaaaaaaaaaa`), verified independently by cryptsetup.
//! From `tests/tcrypt-images.tar.xz`. Env-gated on `VC_ORACLE` (path to the
//! image). Provenance: `/tmp/vc-oracle/GROUND-TRUTH.md`.
//!
//! ```bash
//! VC_ORACLE=/tmp/vc-oracle/vc_1-sha512-xts-aes \
//!   cargo test -p veracrypt-core --test oracle_veracrypt -- --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs::File;

use common::sha256_hex;
use veracrypt::VeraVolume;

const PASSWORD: &[u8] = b"aaaaaaaaaaaa";

#[test]
fn tier1_vc_sha512_xts_aes_matches_cryptsetup() {
    let Ok(path) = std::env::var("VC_ORACLE") else {
        eprintln!("VC_ORACLE unset — skipping Tier-1 VeraCrypt oracle");
        return;
    };
    let file = File::open(&path).expect("open vc image");
    let mut vol = VeraVolume::unlock_with_password(file, PASSWORD).expect("unlock vc volume");

    assert_eq!(vol.info().prf.name(), "sha512");
    assert_eq!(vol.info().cipher.name(), "aes");
    assert_eq!(vol.info().encrypted_area_start, 131_072);

    // (data-area LBA, expected decrypted-sector SHA-256) — cryptsetup ground truth.
    let cases: [(u64, &str); 4] = [
        (
            0,
            "76a9e8419a1e688732c03236e01e564c6b3660c0bcdc4561eb05e1d1de8ff8fa",
        ),
        (
            1,
            "076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560",
        ),
        (
            2,
            "6242cb7cb043b219a77ffa2bd0aedab6735389bbbe8b3b2e88410cf5f74247a5",
        ),
        (
            16,
            "00882984fac5e7298c45bae80bad8debc4456d06d5189bb91f9f3901ecee4b0f",
        ),
    ];

    for (lba, want) in cases {
        let mut buf = [0u8; 512];
        vol.read_at(lba * 512, &mut buf).expect("read_at");
        let got = sha256_hex(&buf);
        println!("sector {lba}: {got}");
        assert_eq!(
            got, want,
            "decrypted sector {lba} does not match cryptsetup"
        );
    }
}

#[test]
fn wrong_password_fails() {
    let Ok(path) = std::env::var("VC_ORACLE") else {
        return;
    };
    let file = File::open(&path).unwrap();
    // Use a small PIM so the all-PRF brute (which must try every PRF for a wrong
    // password) runs at low iteration counts — the "no PRF matches" path, fast.
    assert!(VeraVolume::unlock_with_pim(file, b"wrongpassword", 1).is_err());
}
