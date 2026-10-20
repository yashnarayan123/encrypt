# Architecture — from-scratch AES in Python

Only the standard library is used inside `aes/`. The `cryptography`
package appears only in `aes/tests/test_aes.py` as an independent oracle.

## Files

- `aes/gf256.py` — maths everything else stands on. AES bytes are
  polynomials over GF(2); adding is XOR, multiplying is polynomial
  multiply reduced mod `x^8 + x^4 + x^3 + x + 1` (`0x11B`).
  `xtime(a)` multiplies by `0x02` (shift + conditional XOR `0x1B`).
  `gf_mul(a, b)` loops over the bits of `b`, doubling `a` with `xtime`
  and XOR-ing it in wherever the bit is set. `gf_inverse(a)` tries all
  256 values for the one with `a * b == 1` (`0 -> 0` by AES convention).
- `aes/sbox.py` — the S-box, **generated**, never hard-coded. For each
  byte: take `gf_inverse`, then the affine mix
  `inv ^ rotl(inv,1) ^ rotl(inv,2) ^ rotl(inv,3) ^ rotl(inv,4) ^ 0x63`.
  The inverse S-box is built by reversing the table
  (`inv_sbox[sbox[x]] = x`).
- `aes/aes_core.py` — the block cipher. The 16-byte block becomes a 4x4
  column-major matrix (`state[row][col] = block[row + 4*col]`).
  `key_expansion` turns a 16-byte key into 11 round keys (10 rounds) or
  a 32-byte key into 15 round keys (14 rounds). `encrypt_block` /
  `decrypt_block` run the rounds. Both accept `debug=True`, which prints
  the state hex after every step — use it in the demo.
- `aes/modes.py` — turns the single-block cipher into a message cipher.
  `pkcs7_pad` / `pkcs7_unpad` (unpad rejects bad lengths/bytes),
  `ecb_encrypt/decrypt` (each block alone), `cbc_encrypt/decrypt`
  (each plaintext XOR previous ciphertext/IV, then encrypted).
- `aes/__main__.py` — CLI:
  `python -m aes --mode cbc --key HEX --iv HEX --encrypt "text"` prints
  hex; replace `--encrypt` with `--decrypt HEX` to get text back. ECB
  omits `--iv`.
- `aes/tests/test_aes.py` — known-answer + cross-check suite (FIPS-197,
  key schedule, NIST SP 800-38A, 1000 seeded random vectors vs the
  `cryptography` library).

## Each AES step in plain language

- **SubBytes** — every byte looks up the S-box. This is the only
  non-linear step; without it AES would be breakable linear algebra.
  Inverse uses the inverse S-box.
- **ShiftRows** — row `r` rotates left by `r` bytes (row 0 unchanged).
  Bytes move between columns, so later rounds mix across the block.
  Inverse rotates right instead.
- **MixColumns** — each column is multiplied by the fixed matrix
  `[2,3,1,1]` in GF(2^8). One input byte spreads into all four output
  bytes of its column (diffusion). Skipped in the last round so encrypt
  and decrypt mirror each other. Inverse uses `[14,11,13,9]`.
- **AddRoundKey** — XOR the 16-byte round key into the state. It is its
  own inverse and is what makes the encryption key-dependent.
- **Key expansion** — the key is split into 4-byte words; each new word
  is `word[i-Nk] XOR transformed(word[i-1])`. The transform is
  RotWord + SubWord + Rcon (Rcon doubles via `xtime` each round).
  AES-256 has one extra rule: every word with `i % 8 == 4` also goes
  through SubWord. Words are grouped 4-by-4 into round keys.
- **Encrypt order** — `AddKey(k0)`, then `(Sub, Shift, Mix, Add)` for
  rounds 1..Nr-1, then `(Sub, Shift, Add)` with no Mix. **Decrypt** runs
  the exact reverse: `Add(kNr)`, undo final `(Shift, Sub)`, then per
  round `Add, InvMix, InvShift, InvSub`, finishing with `Add(k0)`.
- **PKCS#7** — if `N` bytes are missing from the last block, append `N`
  copies of byte `N`; a full dummy block is added when already aligned,
  so unpadding is unambiguous. Anything else raises `ValueError`.
- **ECB vs CBC** — ECB encrypts blocks independently (simple but leaks
  patterns). CBC XORs each plaintext block with the previous ciphertext
  (IV for block 0) first, so equal blocks encrypt differently; the IV
  must be unique per message but is not secret.
