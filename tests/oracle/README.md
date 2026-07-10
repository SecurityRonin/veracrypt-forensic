# Tier-1 oracle

The correctness backstop for `veracrypt-core` is the cryptsetup-corpus
**`vc_1-sha512-xts-aes`** VeraCrypt volume unlocked with its published password
`aaaaaaaaaaaa`. `veracrypt-core` must reproduce each decrypted 512-byte sector
byte-for-byte (SHA-256 match) — and the ground truth is confirmed by **two**
independent reference implementations that agree with this crate:

1. **VeraCrypt 1.26.20** (the format's own reference), and
2. **cryptsetup 2.7.0** (an independent reimplementation).

- Image provenance + extraction: [`../data/README.md`](../data/README.md).
- Ground-truth digests + the triple-implementation cross-check:
  [`../../docs/validation.md`](../../docs/validation.md).
- Consuming test: [`../../core/tests/oracle_veracrypt.rs`](../../core/tests/oracle_veracrypt.rs),
  env-gated on `VC_ORACLE` (and `VC_HIDDEN_ORACLE` for the hidden volume).

Regenerate / extend ground truth with `cryptsetup`:

```bash
sudo cryptsetup open --veracrypt --key-file=- vc_1-sha512-xts-aes vc1 <<<'aaaaaaaaaaaa'
sudo dd if=/dev/mapper/vc1 bs=512 count=1 2>/dev/null | sha256sum
sudo cryptsetup close vc1
```
