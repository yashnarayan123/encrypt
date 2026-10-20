"""AES-GCM authenticated encryption, built from scratch on our AES.

WHY GCM (for viva): ECB/CBC give PRIVACY only -- flipping ciphertext bits
flips plaintext bits, and nobody notices (Task 3 lived off this). GCM adds
a TAG: a 16-byte checksum over the ciphertext AND over extra authenticated
data (AAD). Decryption recomputes the tag and REFUSES to return anything
if one bit is off. Privacy comes from CTR mode, integrity from GHASH.

Only our own aes package is used (key_expansion + encrypt_block -- GCM
never needs AES decryption). hmac.compare_digest is used for the tag
comparison ONLY (it is a comparison helper, not a crypto library).

Layout (NIST SP 800-38D, 96-bit nonces only):
  H      = AES(key, 0^128)            -- the GHASH subkey
  J0     = nonce || 0x00000001        -- pre-counter block (counter = 1)
  J1..   = nonce || 0x00000002 ...    -- data counter blocks (counter >= 2)
  CT     = plaintext XOR AES(key, J1) XOR AES(key, J2) ... (CTR, no padding)
  S      = GHASH(H, aad, ciphertext)  -- checksum over AAD + ciphertext
  tag    = S XOR AES(key, J0)          -- masked checksum
"""

import hmac as _hmac  # only _hmac.compare_digest is used (see below)

from aes.aes_core import key_expansion, encrypt_block

BLOCK = 16
NONCE_LEN = 12
TAG_LEN = 16
MASK128 = (1 << 128) - 1
# Low 8 bits of the GCM reduction polynomial x^128 + x^7 + x^2 + x + 1,
# sitting at the TOP byte because the loop below shifts RIGHT (see below).
REDUCTION_TOP = 0xE1 << 120


class AuthenticationError(ValueError):
    """Raised when the GCM tag does not verify. Plaintext is never returned."""


# ---------------------------------------------------------------------------
# GF(2^128) multiplication (NIST SP 800-38D, Algorithm 1).
# ---------------------------------------------------------------------------

def gf128_mul(x, y):
    """Multiply two 128-bit ints in the GCM field.

    BIT ORDER (the part everyone gets wrong, so read carefully): GCM reads
    each 16-byte block big-endian -- bit 0 of the field element is the MOST
    significant bit of byte 0 (the x^127 coefficient), bit 127 is the LEAST
    significant bit of byte 15 (the x^0 coefficient). The loop therefore
    scans the bits of y from TOP (MSB) to bottom, while V is halved each
    round (shift RIGHT): whenever the bit shifted out (the old x^0 term)
    is 1, the result has "fallen below" x^0, so we XOR the reduction
    constant. In this right-shifting formulation the constant is 0xE1 in
    the TOP byte (0xE100...00), which equals x^7 + x^2 + x + 1 moved to the
    top -- the mirror image of the polynomial x^128 + x^7 + x^2 + x + 1.
    """
    x &= MASK128
    y &= MASK128
    result = 0
    v = x
    for i in range(128):              # scan y from the top bit downwards
        if (y >> (127 - i)) & 1:      # current bit of y set? add V
            result ^= v
        if v & 1:                     # bit falling off the bottom? reduce
            v = (v >> 1) ^ REDUCTION_TOP
        else:
            v >>= 1
    return result


# ---------------------------------------------------------------------------
# GHASH: the checksum over AAD + ciphertext.
# ---------------------------------------------------------------------------

def _pad16(data):
    """Pad with zero bytes up to a multiple of 16 (GCM pads with zeros,
    NOT PKCS#7 -- the true lengths go into the final length block)."""
    data = bytes(data)
    rem = len(data) % BLOCK
    if rem:
        data += b"\x00" * (BLOCK - rem)
    return data


def ghash(h_bytes, aad, ciphertext):
    """GHASH(H, AAD, CT) -> 16-byte checksum.

    Feed: AAD blocks, then ciphertext blocks, then ONE length block holding
    len(AAD) and len(CT) in BITS as two 64-bit big-endian numbers. Chain:
    X = 0; for every block: X = (X XOR block) * H in GF(2^128).
    """
    h = int.from_bytes(bytes(h_bytes), "big")
    aad = bytes(aad)
    ciphertext = bytes(ciphertext)
    stream = (_pad16(aad) + _pad16(ciphertext)
              + (8 * len(aad)).to_bytes(8, "big")
              + (8 * len(ciphertext)).to_bytes(8, "big"))
    acc = 0
    for i in range(0, len(stream), BLOCK):
        word = int.from_bytes(stream[i:i + BLOCK], "big")
        acc = gf128_mul(acc ^ word, h)
    return acc.to_bytes(BLOCK, "big")


# ---------------------------------------------------------------------------
# CTR keystream: AES(key, nonce || counter), counter starting at 1 or 2.
# ---------------------------------------------------------------------------

def _keystream(round_keys, nonce, start_counter, nbytes):
    """Raw AES-CTR keystream: encrypt J_start, J_start+1, ... and concat."""
    out = bytearray()
    counter = start_counter
    while len(out) < nbytes:
        counter_block = bytes(nonce) + counter.to_bytes(4, "big")
        out += encrypt_block(counter_block, round_keys)
        counter += 1
    return bytes(out[:nbytes])


def _xor(a, b):
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def _check_key_nonce(key, nonce):
    """Validate sizes: AES-128/256 keys, exactly 12-byte nonces."""
    key = bytes(key)
    nonce = bytes(nonce)
    if len(key) not in (16, 32):
        raise ValueError("key must be 16 bytes (AES-128) or 32 (AES-256)")
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be exactly 12 bytes (96-bit GCM)")
    return key, nonce


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------

def gcm_encrypt(key, nonce, plaintext, aad=b""):
    """Encrypt + authenticate. Returns (ciphertext, tag16).

    Counter numbering: J0 = nonce || 0x00000001 masks the tag; DATA blocks
    use counter values 2, 3, 4, ... (the all-zero counter is never used).
    """
    key, nonce = _check_key_nonce(key, nonce)
    plaintext = bytes(plaintext)
    aad = bytes(aad)
    if len(plaintext) > (2 ** 32 - 1) * BLOCK:
        raise ValueError("plaintext too long for 32-bit GCM counter")
    round_keys = key_expansion(key)
    subkey_h = encrypt_block(bytes(BLOCK), round_keys)   # H = AES(0^128)
    data_stream = _xor(plaintext,
                       _keystream(round_keys, nonce, 2, len(plaintext)))
    tag_mask = _keystream(round_keys, nonce, 1, BLOCK)   # AES(J0)
    tag = _xor(ghash(subkey_h, aad, data_stream), tag_mask)
    return data_stream, tag


def gcm_decrypt(key, nonce, ciphertext, aad, tag):
    """Verify the tag FIRST, then decrypt. Returns plaintext bytes.

    Raises AuthenticationError on ANY mismatch (wrong key/nonce/ct/aad/
    tag) and NEVER returns plaintext in that case -- the message is
    dropped before parsing, which is exactly what stops Task 3's tricks.
    Tag comparison uses hmac.compare_digest so the check itself does not
    leak how many bytes matched (constant-time compare).
    """
    key, nonce = _check_key_nonce(key, nonce)
    ciphertext = bytes(ciphertext)
    aad = bytes(aad)
    tag = bytes(tag)
    if len(tag) != TAG_LEN:
        raise AuthenticationError("tag must be 16 bytes")
    round_keys = key_expansion(key)
    subkey_h = encrypt_block(bytes(BLOCK), round_keys)
    tag_mask = _keystream(round_keys, nonce, 1, BLOCK)
    expected = _xor(ghash(subkey_h, aad, ciphertext), tag_mask)
    if not _hmac.compare_digest(expected, tag):   # constant-time compare
        raise AuthenticationError("GCM tag mismatch: message rejected")
    return _xor(ciphertext, _keystream(round_keys, nonce, 2, len(ciphertext)))
