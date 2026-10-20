"""AES S-box, GENERATED (not hard-coded) from GF(2^8) math.

FIPS-197 construction, per byte x in 0..255:
  1. Take the multiplicative inverse in GF(2^8) (with 0 -> 0).
  2. Apply the affine transform over GF(2):
         s = inv XOR ROTL(inv,1) XOR ROTL(inv,2) XOR ROTL(inv,3)
                 XOR ROTL(inv,4) XOR 0x63
     where ROTL is an 8-bit left rotation and 0x63 is the constant
     vector (0110_0011). This bit-mixing breaks the pure algebraic
     structure of the inverse, which helps resist attacks.

The inverse S-box is then built by reversing the mapping:
    INV_SBOX[SBOX[x]] = x  for every x.
"""

from .gf256 import gf_inverse


def _rotl8(x, n):
    """Rotate 8-bit integer ``x`` left by ``n`` bit positions."""
    n %= 8                          # rotating by 8 is a no-op
    return ((x << n) | (x >> (8 - n))) & 0xFF if n else (x & 0xFF)


def _affine_transform(inv):
    """Apply the AES affine transform to a byte (step 2 above).

    Bit-level meaning (FIPS-197 §5.1.1): for each bit position i,
        s_i = inv_i ^ inv_{(i+4)%8} ^ inv_{(i+5)%8}
              ^ inv_{(i+6)%8} ^ inv_{(i+7)%8} ^ c_i,
    with c = 0x63. XOR-ing the five rotations below computes all 8
    bit equations at once.
    """
    return (
        inv
        ^ _rotl8(inv, 1)
        ^ _rotl8(inv, 2)
        ^ _rotl8(inv, 3)
        ^ _rotl8(inv, 4)
        ^ 0x63
    ) & 0xFF


def _build_sbox():
    """Run the two-step construction for all 256 input bytes."""
    return [_affine_transform(gf_inverse(x)) for x in range(256)]


def _build_inv_sbox(sbox):
    """Invert the S-box: inv_sbox[sbox[x]] = x."""
    inv = [0] * 256
    for x in range(256):
        inv[sbox[x]] = x
    return inv


# Public tables, generated at import time (no hard-coded constants).
SBOX = _build_sbox()
INV_SBOX = _build_inv_sbox(SBOX)

# Convenient lowercase aliases (tests may use either spelling).
sbox = SBOX
inv_sbox = INV_SBOX
