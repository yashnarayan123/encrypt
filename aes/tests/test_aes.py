"""Full AES test suite: GF(2^8) + S-box + block cipher + modes + NIST vectors.

The `cryptography` package is used ONLY here (never inside aes/) to
cross-check our from-scratch code.

Run with:  python3 -m pytest aes/tests/test_aes.py -v
"""
import random

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as crypto_modes

from aes.gf256 import xtime, gf_mul, gf_inverse
from aes.sbox import SBOX, INV_SBOX
from aes.aes_core import key_expansion, encrypt_block, decrypt_block
from aes.modes import pkcs7_pad, pkcs7_unpad, ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt


def test_xtime_basic():
    # No overflow: 0x57 = 0101_0111 -> 1010_1110 = 0xAE.
    assert xtime(0x57) == 0xAE
    # Overflow: 0x80 = 1000_0000 -> (1_0000_0000 reduced mod 0x11B) = 0x1B.
    assert xtime(0x80) == 0x1B
    # Zero stays zero.
    assert xtime(0x00) == 0x00


def test_gf_mul_fips_example():
    # Worked example from FIPS-197 section 4.2: {57} * {13} = {FE}.
    assert gf_mul(0x57, 0x13) == 0xFE
    # Multiplying by 1 is identity; by 0 gives 0; by 2 equals xtime.
    assert gf_mul(0x57, 0x01) == 0x57
    assert gf_mul(0x57, 0x00) == 0x00
    assert gf_mul(0x57, 0x02) == xtime(0x57)


def test_gf_inverse():
    assert gf_inverse(0x00) == 0x00  # convention, not real math
    for a in (0x01, 0x53, 0x57, 0xFF):
        assert gf_mul(a, gf_inverse(a)) == 0x01


def test_sbox_spot_values():
    # Required known answers (FIPS-197 section 5.1.1).
    assert SBOX[0x00] == 0x63
    assert SBOX[0x01] == 0x7C
    assert SBOX[0x53] == 0xED


def test_inv_sbox_inverts_sbox():
    assert len(SBOX) == 256 and len(INV_SBOX) == 256
    assert sorted(SBOX) == list(range(256))  # S-box is a permutation
    for x in range(256):
        assert INV_SBOX[SBOX[x]] == x


# ---------------- Stage 2: AES block cipher ----------------

def test_aes128_block_fips197():
    # FIPS-197 Appendix B: AES-128 known answer.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert encrypt_block(pt, key_expansion(key)).hex() == \
        "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes256_block_fips197():
    # FIPS-197 Appendix C.3: AES-256 known answer.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert encrypt_block(pt, key_expansion(key)).hex() == \
        "8ea2b7ca516745bfeafc49904b496089"


def test_key_expansion_nist():
    # Key expansion spot check: w[4] and the last round key.
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    rks = key_expansion(key)
    assert len(rks) == 11  # AES-128 -> 11 round keys
    assert rks[1][:4].hex() == "a0fafe17"  # first word of round key 1 = w[4]
    assert rks[-1].hex() == "d014f9a8c9ee2589e13f0cc8b6630ca6"


def test_block_roundtrip():
    for key_hex in ("000102030405060708090a0b0c0d0e0f",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"):
        key = bytes.fromhex(key_hex)
        rks = key_expansion(key)
        for pt in (bytes(16), bytes.fromhex("00112233445566778899aabbccddeeff")):
            assert decrypt_block(encrypt_block(pt, rks), rks) == pt


# ---------------- Stage 3: padding + modes ----------------

def test_pkcs7_roundtrip():
    assert pkcs7_unpad(pkcs7_pad(b"")) == b""
    assert pkcs7_unpad(pkcs7_pad(b"hello")) == b"hello"
    assert pkcs7_unpad(pkcs7_pad(bytes(16))) == bytes(16)  # full extra block
    assert pkcs7_unpad(pkcs7_pad(bytes(32))) == bytes(32)


def test_pkcs7_rejects_bad_padding():
    with pytest.raises(ValueError):
        pkcs7_unpad(b"")                      # empty
    with pytest.raises(ValueError):
        pkcs7_unpad(b"123")                   # not a multiple of 16
    with pytest.raises(ValueError):
        pkcs7_unpad(bytes(15) + b"\x00")      # pad length 0 illegal
    with pytest.raises(ValueError):
        pkcs7_unpad(bytes(14) + b"\x02\x03")  # bytes disagree


def test_modes_roundtrip():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    for msg in (b"", b"hi", b"exactly16bytes!!", bytes(16), b"hello aes, longer text..."):
        assert ecb_decrypt(key, ecb_encrypt(key, msg)) == msg
        assert cbc_decrypt(key, iv, cbc_encrypt(key, iv, msg)) == msg


# ---------------- Stage 4: NIST SP 800-38A vectors ----------------
# NOTE for viva: these vectors are RAW (no padding) because the plaintext
# is already an exact multiple of 16 bytes. Our ecb_/cbc_ helpers always
# add PKCS#7, so here we encrypt block-by-block with aes_core directly.

NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710")
NIST_ECB_CT = bytes.fromhex(
    "3ad77bb40d7a3660a89ecaf32466ef97"
    "f5d3d58503b9699de785895a96fdbaaf"
    "43b1cd7f598ece23881b00e3ed030688"
    "7b0c785e27e8ad3f8223207104725dd4")
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_CBC_CT = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7")


def _raw_ecb_encrypt(key, data):
    """ECB with NO padding (for NIST vectors): each 16-byte block alone."""
    rks = key_expansion(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += encrypt_block(data[i:i + 16], rks)
    return bytes(out)


def _raw_ecb_decrypt(key, data):
    """Inverse of _raw_ecb_encrypt (no unpadding)."""
    rks = key_expansion(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += decrypt_block(data[i:i + 16], rks)
    return bytes(out)


def _raw_cbc_encrypt(key, iv, data):
    """CBC with NO padding: C[i] = AES(P[i] XOR C[i-1]), C[-1] = IV."""
    rks = key_expansion(key)
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(data), 16):
        block = bytes(p ^ q for p, q in zip(data[i:i + 16], prev))
        prev = encrypt_block(block, rks)
        out += prev
    return bytes(out)


def _raw_cbc_decrypt(key, iv, data):
    """Inverse of _raw_cbc_encrypt (no unpadding)."""
    rks = key_expansion(key)
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(data), 16):
        ct = data[i:i + 16]
        pt = decrypt_block(ct, rks)
        out += bytes(p ^ q for p, q in zip(pt, prev))
        prev = bytes(ct)
    return bytes(out)


def test_nist_ecb_38a():
    assert _raw_ecb_encrypt(NIST_KEY, NIST_PT) == NIST_ECB_CT
    assert _raw_ecb_decrypt(NIST_KEY, NIST_ECB_CT) == NIST_PT


def test_nist_cbc_38a():
    assert _raw_cbc_encrypt(NIST_KEY, NIST_IV, NIST_PT) == NIST_CBC_CT
    assert _raw_cbc_decrypt(NIST_KEY, NIST_IV, NIST_CBC_CT) == NIST_PT


# ---------------- Stage 4: 1000-vector cross-check vs library ----------------

def _lib_ecb_encrypt(key, data):
    """Reference ECB encryption using the `cryptography` package (no padding)."""
    enc = Cipher(algorithms.AES(key), crypto_modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def _lib_ecb_decrypt(key, data):
    """Reference ECB decryption using the `cryptography` package."""
    dec = Cipher(algorithms.AES(key), crypto_modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def _lib_cbc_encrypt(key, iv, data):
    """Reference CBC encryption using the `cryptography` package (no padding)."""
    enc = Cipher(algorithms.AES(key), crypto_modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _lib_cbc_decrypt(key, iv, data):
    """Reference CBC decryption using the `cryptography` package."""
    dec = Cipher(algorithms.AES(key), crypto_modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def test_crosscheck_1000_random_vectors():
    # 1000 trials: even i -> AES-128, odd i -> AES-256 (so 500 of each).
    # Each trial checks raw ECB + raw CBC against the library, plus:
    #   - decrypt round-trips both ways (ours<->library),
    #   - our padded ecb_/cbc_ helpers against library encryption of
    #     the PKCS#7-padded message.
    # Seeded RNG makes the test deterministic for the demo.
    rng = random.Random(0)
    for i in range(1000):
        key_len = 16 if i % 2 == 0 else 32
        key = bytes(rng.randrange(256) for _ in range(key_len))
        nblocks = rng.randrange(1, 4)  # 1..3 blocks, always block-aligned
        msg = bytes(rng.randrange(256) for _ in range(16 * nblocks))
        iv = bytes(rng.randrange(256) for _ in range(16))

        # --- raw (unpadded) ECB must match the library ---
        assert _raw_ecb_encrypt(key, msg) == _lib_ecb_encrypt(key, msg)
        # decrypt round-trips: ours decrypts library ct, library decrypts ours
        lib_ct = _lib_ecb_encrypt(key, msg)
        assert _raw_ecb_decrypt(key, lib_ct) == msg
        assert _lib_ecb_decrypt(key, _raw_ecb_encrypt(key, msg)) == msg

        # --- raw (unpadded) CBC must match the library ---
        assert _raw_cbc_encrypt(key, iv, msg) == _lib_cbc_encrypt(key, iv, msg)
        lib_ct = _lib_cbc_encrypt(key, iv, msg)
        assert _raw_cbc_decrypt(key, iv, lib_ct) == msg
        assert _lib_cbc_decrypt(key, iv, _raw_cbc_encrypt(key, iv, msg)) == msg

        # --- padded helpers must match library encryption of padded msg ---
        assert ecb_encrypt(key, msg) == _lib_ecb_encrypt(key, pkcs7_pad(msg))
        assert ecb_decrypt(key, ecb_encrypt(key, msg)) == msg
        assert cbc_encrypt(key, iv, msg) == _lib_cbc_encrypt(key, iv, pkcs7_pad(msg))
        assert cbc_decrypt(key, iv, cbc_encrypt(key, iv, msg)) == msg
