"""Block modes: PKCS#7 padding, ECB, CBC. Only standard library.

Ideas (for viva):
  - AES itself only encrypts exactly 16 bytes. Modes handle longer data.
  - PKCS#7 fills the last block up to 16 bytes: if N bytes are missing,
    append N copies of the byte N. A full extra block is added when the
    data already fits, so unpadding is never ambiguous.
  - ECB encrypts each block alone: same plaintext block -> same
    ciphertext block (leaks patterns; e.g. ECB penguin).
  - CBC chains blocks: each plaintext block is XORed with the previous
    ciphertext (or the IV for block 0) before AES encryption. The IV
    must be random/unique but need not be secret.
"""

from .aes_core import key_expansion, encrypt_block, decrypt_block

BLOCK_SIZE = 16


# ---------------------------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------------------------

def pkcs7_pad(data, block_size=BLOCK_SIZE):
    """Pad `data` up to a multiple of `block_size` (PKCS#7)."""
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be in 1..255")
    data = bytes(data)
    missing = block_size - (len(data) % block_size)
    # If data already fits exactly, missing == block_size, so we add a
    # whole padding block. That is required by the standard.
    return data + bytes([missing]) * missing


def pkcs7_unpad(data, block_size=BLOCK_SIZE):
    """Remove PKCS#7 padding, raising ValueError if it is invalid."""
    data = bytes(data)
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("bad padded length")
    pad_len = data[-1]  # last byte says how many padding bytes there are
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("bad padding length byte")
    # All of the last pad_len bytes must equal pad_len.
    for b in data[len(data) - pad_len:]:
        if b != pad_len:
            raise ValueError("bad padding bytes")
    return data[:len(data) - pad_len]


def _xor_bytes(a, b):
    """XOR two 16-byte strings (used to mix IV / chain with plaintext)."""
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# ECB mode (each block independent)
# ---------------------------------------------------------------------------

def ecb_encrypt(key, data):
    """ECB encrypt: pad, then encrypt each 16-byte block on its own."""
    round_keys = key_expansion(bytes(key))
    padded = pkcs7_pad(bytes(data))
    out = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        out += encrypt_block(padded[i:i + BLOCK_SIZE], round_keys)
    return bytes(out)


def ecb_decrypt(key, data):
    """ECB decrypt: decrypt each block, then remove padding."""
    data = bytes(data)
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext must be a non-empty multiple of 16 bytes")
    round_keys = key_expansion(bytes(key))
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        out += decrypt_block(data[i:i + BLOCK_SIZE], round_keys)
    return pkcs7_unpad(bytes(out))


# ---------------------------------------------------------------------------
# CBC mode (chained: XOR with previous ciphertext / IV, then encrypt)
# ---------------------------------------------------------------------------

def cbc_encrypt(key, iv, data):
    """CBC encrypt: C[i] = AES( P[i] XOR C[i-1] ), C[-1] = IV."""
    iv = bytes(iv)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes")
    round_keys = key_expansion(bytes(key))
    padded = pkcs7_pad(bytes(data))
    out = bytearray()
    prev = iv  # "previous ciphertext", starts as the IV
    for i in range(0, len(padded), BLOCK_SIZE):
        block = _xor_bytes(padded[i:i + BLOCK_SIZE], prev)
        ct = encrypt_block(block, round_keys)
        out += ct
        prev = ct  # chain: this ciphertext masks the next block
    return bytes(out)


def cbc_decrypt(key, iv, data):
    """CBC decrypt: P[i] = AES-decrypt(C[i]) XOR C[i-1], C[-1] = IV."""
    iv = bytes(iv)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes")
    data = bytes(data)
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext must be a non-empty multiple of 16 bytes")
    round_keys = key_expansion(bytes(key))
    out = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        ct = data[i:i + BLOCK_SIZE]
        out += _xor_bytes(decrypt_block(ct, round_keys), prev)
        prev = ct
    return pkcs7_unpad(bytes(out))
