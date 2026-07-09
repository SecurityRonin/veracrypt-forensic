//! Public API: brute the VeraCrypt header PRF+cipher from a password, recover the
//! master key, and decrypt the data area.

use std::io::{Read, Seek, SeekFrom};

use crate::crypto::{xts_decrypt, Cipher, Prf};
use crate::error::{Result, VeraError};
use crate::header::{
    Flavor, VeraHeader, HEADER_LEN, NORMAL_HEADER_OFFSET, SALT_LEN, VOLUME_HEADER_LEN,
};

/// VeraCrypt data-area encryption sector size (bytes).
const DATA_SECTOR: usize = 512;

/// Namespace for opening a VeraCrypt volume.
pub struct VeraVolume;

/// The recovered facts about an unlocked volume.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// VeraCrypt or TrueCrypt.
    pub flavor: Flavor,
    /// The PRF that decrypted the header.
    pub prf: Prf,
    /// The data cipher.
    pub cipher: Cipher,
    /// Header format version.
    pub version: u16,
    /// Byte offset where the encrypted data area begins.
    pub encrypted_area_start: u64,
    /// Size of the encrypted data area in bytes.
    pub encrypted_area_size: u64,
}

impl VeraVolume {
    /// Unlock a VeraCrypt/TrueCrypt volume with `password` (no PIM).
    ///
    /// # Errors
    /// [`VeraError::TooSmall`] if the container is under 512 bytes, or
    /// [`VeraError::AuthenticationFailed`] if no PRF/cipher yields a valid header.
    pub fn unlock_with_password<R: Read + Seek>(
        reader: R,
        password: &[u8],
    ) -> Result<DecryptedVolume<R>> {
        Self::unlock_with_pim(reader, password, 0)
    }

    /// Unlock with an explicit PIM (personal iterations multiplier; 0 = default).
    ///
    /// # Errors
    /// As [`Self::unlock_with_password`].
    pub fn unlock_with_pim<R: Read + Seek>(
        mut reader: R,
        password: &[u8],
        pim: u32,
    ) -> Result<DecryptedVolume<R>> {
        let total_size = reader.seek(SeekFrom::End(0))?;
        if total_size < VOLUME_HEADER_LEN as u64 {
            return Err(VeraError::TooSmall {
                got: total_size as usize,
            });
        }

        let mut hdr = [0u8; VOLUME_HEADER_LEN];
        reader.seek(SeekFrom::Start(NORMAL_HEADER_OFFSET))?;
        read_fill(&mut reader, &mut hdr)?;
        let salt = &hdr[0..SALT_LEN];
        let header_ct = &hdr[SALT_LEN..VOLUME_HEADER_LEN];

        for prf in Prf::all() {
            let hk = prf.derive(password, salt, prf.iterations_pim(pim), 64);
            for cipher in Cipher::all() {
                let mut dec = header_ct.to_vec();
                xts_decrypt(cipher, &hk, &mut dec, HEADER_LEN, 0)?;
                let Some(h) = VeraHeader::validate(&dec) else {
                    continue;
                };
                let mut master_key = vec![0u8; cipher.key_len()];
                master_key.copy_from_slice(&h.master_keys[..cipher.key_len()]);
                return Ok(DecryptedVolume {
                    reader,
                    cipher,
                    master_key,
                    data_offset: h.encrypted_area_start,
                    base_unit: u128::from(h.encrypted_area_start / DATA_SECTOR as u64),
                    total_size,
                    position: 0,
                    info: VolumeInfo {
                        flavor: h.flavor,
                        prf,
                        cipher,
                        version: h.version,
                        encrypted_area_start: h.encrypted_area_start,
                        encrypted_area_size: h.encrypted_area_size,
                    },
                });
            }
        }
        Err(VeraError::AuthenticationFailed)
    }
}

/// A plaintext view of an unlocked VeraCrypt data area.
pub struct DecryptedVolume<R> {
    reader: R,
    cipher: Cipher,
    master_key: Vec<u8>,
    data_offset: u64,
    base_unit: u128,
    total_size: u64,
    position: u64,
    info: VolumeInfo,
}

impl<R: Read + Seek> DecryptedVolume<R> {
    /// The recovered volume facts (flavor, PRF, cipher, offsets).
    #[must_use]
    pub fn info(&self) -> &VolumeInfo {
        &self.info
    }

    /// The recovered master key (sensitive).
    #[must_use]
    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }

    /// Size of the decrypted data area in bytes.
    #[must_use]
    pub fn data_size(&self) -> u64 {
        if self.info.encrypted_area_size != 0 {
            self.info.encrypted_area_size
        } else {
            self.total_size.saturating_sub(self.data_offset)
        }
    }

    /// Read decrypted data at data-area-relative `offset` into `buf`, filling it
    /// completely (bytes past the end read back as zero).
    ///
    /// # Errors
    /// Propagates I/O and cipher errors.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let unit = pos / DATA_SECTOR as u64;
            let within = (pos % DATA_SECTOR as u64) as usize;
            let physical = self.data_offset + unit * DATA_SECTOR as u64;

            let mut ct = [0u8; DATA_SECTOR];
            self.reader.seek(SeekFrom::Start(physical))?;
            read_available(&mut self.reader, &mut ct)?;
            xts_decrypt(
                self.cipher,
                &self.master_key,
                &mut ct,
                DATA_SECTOR,
                self.base_unit + u128::from(unit),
            )?;

            let take = (DATA_SECTOR - within).min(buf.len() - done);
            buf[done..done + take].copy_from_slice(&ct[within..within + take]);
            done += take;
        }
        Ok(())
    }
}

impl<R: Read + Seek> Read for DecryptedVolume<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.data_size();
        if self.position >= size {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(size - self.position) as usize;
        self.read_at(self.position, &mut buf[..n])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.position += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for DecryptedVolume<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let size = self.data_size();
        let new = match pos {
            SeekFrom::Start(o) => i128::from(o),
            SeekFrom::End(o) => i128::from(size) + i128::from(o),
            SeekFrom::Current(o) => i128::from(self.position) + i128::from(o),
        };
        if new < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.position = new as u64;
        Ok(self.position)
    }
}

fn read_fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    reader.read_exact(buf)?;
    Ok(())
}

fn read_available<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    for b in &mut buf[filled..] {
        *b = 0;
    }
    Ok(filled)
}
