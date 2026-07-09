//! VeraCrypt/TrueCrypt volume-header field layout and validation.
//!
//! The 512-byte volume header is `salt[64]` followed by a 448-byte header that is
//! XTS-encrypted with a key derived from the password. Once decrypted, offsets
//! (relative to the start of the 448-byte decrypted region) are:
//!
//! ```text
//!    0  "VERA" (TrueCrypt: "TRUE")      44  encrypted-area start  u64
//!    4  format version   u16            52  encrypted-area size   u64
//!    8  CRC-32 of dec[192..448]         64  sector size           u32
//!   28  hidden volume size u64         188  CRC-32 of dec[0..188]
//!   36  volume size      u64           192  master keys[256]
//! ```

/// Length of the salt prefix.
pub const SALT_LEN: usize = 64;
/// Length of the encrypted header following the salt.
pub const HEADER_LEN: usize = 448;
/// Total volume-header length (`salt + header`).
pub const VOLUME_HEADER_LEN: usize = SALT_LEN + HEADER_LEN;
/// Offset of the standard-volume header in the container.
pub const NORMAL_HEADER_OFFSET: u64 = 0;
/// The VeraCrypt magic at decrypted offset 0.
pub const MAGIC_VERA: &[u8; 4] = b"VERA";
/// The TrueCrypt magic at decrypted offset 0.
pub const MAGIC_TRUE: &[u8; 4] = b"TRUE";

fn be_u32(d: &[u8], o: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = d.get(o..o + 4) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

fn be_u64(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = d.get(o..o + 8) {
        b.copy_from_slice(s);
    }
    u64::from_be_bytes(b)
}

/// Whether this container is a TrueCrypt (not VeraCrypt) header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// VeraCrypt (`VERA` magic).
    VeraCrypt,
    /// TrueCrypt (`TRUE` magic).
    TrueCrypt,
}

/// The forensically-relevant fields of a decrypted VeraCrypt header.
#[derive(Debug, Clone)]
pub struct VeraHeader {
    /// VeraCrypt or TrueCrypt.
    pub flavor: Flavor,
    /// Header format version.
    pub version: u16,
    /// Byte offset where the encrypted data area begins.
    pub encrypted_area_start: u64,
    /// Size of the encrypted data area in bytes.
    pub encrypted_area_size: u64,
    /// Declared volume size in bytes.
    pub volume_size: u64,
    /// Hidden-volume size (non-zero only in an outer volume's header).
    pub hidden_size: u64,
    /// Sector size (usually 512).
    pub sector_size: u32,
    /// The 256-byte concatenated master-key material.
    pub master_keys: [u8; 256],
}

impl VeraHeader {
    /// Validate a candidate 448-byte decrypted header: the magic must be `VERA`
    /// or `TRUE` *and* both CRC-32 checks must pass. Returns `None` otherwise, so
    /// a wrong PRF/cipher/password is rejected (no false positives).
    #[must_use]
    pub fn validate(dec: &[u8]) -> Option<VeraHeader> {
        if dec.len() < HEADER_LEN {
            return None;
        }
        let flavor = match dec.get(0..4)? {
            m if m == MAGIC_VERA => Flavor::VeraCrypt,
            m if m == MAGIC_TRUE => Flavor::TrueCrypt,
            _ => return None,
        };
        // CRC-32 of the master-key area and of the header fields.
        if be_u32(dec, 8) != crc32fast::hash(dec.get(192..448)?) {
            return None;
        }
        if be_u32(dec, 188) != crc32fast::hash(dec.get(0..188)?) {
            return None;
        }
        let mut master_keys = [0u8; 256];
        master_keys.copy_from_slice(dec.get(192..448)?);
        Some(VeraHeader {
            flavor,
            version: (be_u32(dec, 4) >> 16) as u16,
            encrypted_area_start: be_u64(dec, 44),
            encrypted_area_size: be_u64(dec, 52),
            volume_size: be_u64(dec, 36),
            hidden_size: be_u64(dec, 28),
            sector_size: be_u32(dec, 64),
            master_keys,
        })
    }
}
