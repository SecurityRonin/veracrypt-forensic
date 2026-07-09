//! VeraCrypt key derivation (PBKDF2 over five PRFs) and AES/Twofish XTS
//! decryption. Every primitive is an audited RustCrypto crate.

use aes::cipher::KeyInit;
use aes::Aes256;
use twofish::Twofish;
use xts_mode::Xts128;

use crate::error::{Result, VeraError};

/// A VeraCrypt header PRF (the PBKDF2 hash), with its non-system iteration count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prf {
    /// SHA-512 (500000 iterations).
    Sha512,
    /// SHA-256 (500000 iterations).
    Sha256,
    /// Whirlpool (500000 iterations).
    Whirlpool,
    /// Streebog-512 (500000 iterations).
    Streebog,
    /// RIPEMD-160 (655331 iterations, TrueCrypt-compatible).
    Ripemd160,
}

impl Prf {
    /// All PRFs, in VeraCrypt's try order.
    #[must_use]
    pub fn all() -> [Prf; 5] {
        [
            Prf::Sha512,
            Prf::Sha256,
            Prf::Whirlpool,
            Prf::Streebog,
            Prf::Ripemd160,
        ]
    }

    /// Human name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Prf::Sha512 => "sha512",
            Prf::Sha256 => "sha256",
            Prf::Whirlpool => "whirlpool",
            Prf::Streebog => "streebog",
            Prf::Ripemd160 => "ripemd160",
        }
    }

    /// Non-system, no-PIM iteration count.
    #[must_use]
    pub fn iterations(self) -> u32 {
        match self {
            Prf::Ripemd160 => 655_331,
            _ => 500_000,
        }
    }

    /// Iterations for an explicit PIM (personal iterations multiplier). PIM 0 uses
    /// the default. For SHA-family/Whirlpool/Streebog: `15000 + PIM*1000`;
    /// RIPEMD-160: `PIM*2048` — matching VeraCrypt's non-system formula.
    #[must_use]
    pub fn iterations_pim(self, pim: u32) -> u32 {
        if pim == 0 {
            return self.iterations();
        }
        match self {
            Prf::Ripemd160 => pim.saturating_mul(2048),
            _ => 15_000u32.saturating_add(pim.saturating_mul(1000)),
        }
    }

    /// Derive `out_len` bytes with PBKDF2-HMAC-<self>.
    pub fn derive(self, password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; out_len];
        let it = iterations.max(1);
        match self {
            Prf::Sha512 => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, it, &mut out),
            Prf::Sha256 => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, it, &mut out),
            Prf::Whirlpool => {
                pbkdf2::pbkdf2_hmac::<whirlpool::Whirlpool>(password, salt, it, &mut out);
            }
            Prf::Streebog => {
                pbkdf2::pbkdf2_hmac::<streebog::Streebog512>(password, salt, it, &mut out);
            }
            Prf::Ripemd160 => {
                pbkdf2::pbkdf2_hmac::<ripemd::Ripemd160>(password, salt, it, &mut out);
            }
        }
        out
    }
}

/// A VeraCrypt data cipher (single-cipher; cascades and Serpent are future
/// extensions — the RustCrypto `serpent` crate is 128-bit-key only, so 256-bit
/// VeraCrypt Serpent needs a different implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-256 (XTS).
    Aes,
    /// Twofish-256 (XTS).
    Twofish,
}

impl Cipher {
    /// All single ciphers, in VeraCrypt's try order.
    #[must_use]
    pub fn all() -> [Cipher; 2] {
        [Cipher::Aes, Cipher::Twofish]
    }

    /// Human name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Cipher::Aes => "aes",
            Cipher::Twofish => "twofish",
        }
    }

    /// XTS key length in bytes (two 256-bit subkeys = 64).
    #[must_use]
    pub fn key_len(self) -> usize {
        64
    }
}

/// Decrypt `buffer` in place as XTS with `cipher`, split into `unit_size`-byte
/// data units; data unit `u` uses tweak `base_unit + u` (little-endian).
///
/// # Errors
/// [`VeraError::Crypto`] if `key` is not 64 bytes.
pub fn xts_decrypt(
    cipher: Cipher,
    key: &[u8],
    buffer: &mut [u8],
    unit_size: usize,
    base_unit: u128,
) -> Result<()> {
    if key.len() != 64 {
        return Err(VeraError::Crypto {
            what: "xts key must be 64 bytes",
        });
    }
    let (k1, k2) = key.split_at(32);
    match cipher {
        Cipher::Aes => decrypt_units(
            &Xts128::new(Aes256::new(k1.into()), Aes256::new(k2.into())),
            buffer,
            unit_size,
            base_unit,
        ),
        Cipher::Twofish => decrypt_units(
            &Xts128::new(Twofish::new(k1.into()), Twofish::new(k2.into())),
            buffer,
            unit_size,
            base_unit,
        ),
    }
    Ok(())
}

fn decrypt_units<C>(xts: &Xts128<C>, buffer: &mut [u8], unit_size: usize, base: u128)
where
    C: aes::cipher::BlockCipher + aes::cipher::BlockEncrypt + aes::cipher::BlockDecrypt,
{
    for (u, chunk) in buffer.chunks_mut(unit_size).enumerate() {
        if chunk.len() < 16 {
            continue; // cov:unreachable: reads are unit-aligned (>= 16)
        }
        let tweak = (base + u as u128).to_le_bytes();
        xts.decrypt_sector(chunk, tweak);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_iterations_and_names() {
        assert_eq!(Prf::Sha512.iterations(), 500_000);
        assert_eq!(Prf::Ripemd160.iterations(), 655_331);
        assert_eq!(Prf::Sha512.iterations_pim(0), 500_000);
        assert_eq!(Prf::Sha512.iterations_pim(10), 25_000);
        assert_eq!(Prf::Ripemd160.iterations_pim(10), 20_480);
        assert_eq!(Prf::all().len(), 5);
        assert_eq!(Cipher::all().map(Cipher::name), ["aes", "twofish"]);
    }

    #[test]
    fn pbkdf2_sha512_matches_python() {
        // PBKDF2-HMAC-SHA512("password","salt",1,32) — cross-checked vs Python.
        let k = Prf::Sha512.derive(b"password", b"salt", 1, 32);
        assert_eq!(
            hex(&k),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
        );
    }

    #[test]
    fn xts_roundtrips_for_each_cipher() {
        for cipher in Cipher::all() {
            let key = [0x24u8; 64];
            let mut buf = vec![0u8; 512];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8) ^ 0x3c;
            }
            let plain = buf.clone();
            // encrypt via the same primitive at unit base 256, then decrypt
            let (k1, k2) = key.split_at(32);
            match cipher {
                Cipher::Aes => encrypt_one(
                    &Xts128::new(Aes256::new(k1.into()), Aes256::new(k2.into())),
                    &mut buf,
                    256,
                ),
                Cipher::Twofish => encrypt_one(
                    &Xts128::new(Twofish::new(k1.into()), Twofish::new(k2.into())),
                    &mut buf,
                    256,
                ),
            }
            xts_decrypt(cipher, &key, &mut buf, 512, 256).unwrap();
            assert_eq!(buf, plain, "cipher {}", cipher.name());
        }
    }

    #[test]
    fn xts_rejects_bad_key_len() {
        let mut b = [0u8; 512];
        assert!(matches!(
            xts_decrypt(Cipher::Aes, &[0u8; 48], &mut b, 512, 0),
            Err(VeraError::Crypto { .. })
        ));
    }

    fn encrypt_one<C>(xts: &Xts128<C>, buf: &mut [u8], unit: u128)
    where
        C: aes::cipher::BlockCipher + aes::cipher::BlockEncrypt + aes::cipher::BlockDecrypt,
    {
        xts.encrypt_sector(buf, unit.to_le_bytes());
    }

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write;
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    }
}
