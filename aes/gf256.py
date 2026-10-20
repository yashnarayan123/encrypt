"""GF(2^8) arithmetic for AES.

Background (for viva):
  - AES treats every byte as a polynomial over GF(2), i.e. bits are
    coefficients with only 0/1 values. Example: 0x57 = 0101_0111 means
    x^6 + x^4 + x^2 + x + 1.
  - Addition in this field is just XOR (because 1 + 1 = 0 mod 2).
  - Multiplication is polynomial multiplication, followed by reduction
    modulo the AES irreducible polynomial
        m(x) = x^8 + x^4 + x^3 + x + 1   (hex 0x11B).
    Reduction is needed because multiplying two degree-7 polynomials can
    give a degree-14 result, which does not fit in one byte.

Only the standard library is used here (in fact, no imports at all).
"""

# The AES reduction polynomial x^8 + x^4 + x^3 + x + 1.
# As an integer that is 0b1_0001_1011 = 0x11B (9 bits; the x^8 bit
# overflows a byte, so inside byte code we use its low 8 bits 0x1B).
REDUCTION_POLY = 0x11B


def xtime(a):
    """Multiply ``a`` by x (i.e. by 0x02) in GF(2^8).

    Steps:
      1. Left-shift by one (that is polynomial "times x").
      2. If the bit shifted out (the old x^7 coefficient, i.e. 0x80) was 1,
         the result has an x^8 term, so XOR with 0x1B (the low 8 bits of
         0x11B) to reduce it back into one byte.
      3. Mask to 8 bits so Python ints stay in range 0..255.
    """
    a &= 0xFF                       # keep input to one byte
    shifted = (a << 1) & 0xFF       # step 1: times x, drop overflow bit
    if a & 0x80:                    # step 2: overflow -> reduce mod 0x11B
        shifted ^= 0x1B             # 0x1B == 0x11B without the x^8 bit
    return shifted


def gf_mul(a, b):
    """Multiply two bytes in GF(2^8) (Russian-peasant method).

    Idea: write b in binary. While scanning its bits from LSB to MSB,
    keep doubling ``a`` (xtime) and add (XOR) it into the answer whenever
    the current bit of ``b`` is 1. Every intermediate value stays reduced
    because xtime() reduces on every doubling.
    """
    a &= 0xFF
    b &= 0xFF
    result = 0
    while b:                        # loop over the set bits of b
        if b & 1:                   # current bit set -> add current a
            result ^= a             # "add" in GF(2^8) is XOR
        a = xtime(a)                # double a for the next bit position
        b >>= 1                     # move to the next bit of b
    return result & 0xFF


def gf_inverse(a):
    """Multiplicative inverse in GF(2^8). Maps 0 -> 0 by convention.

    AES defines inverse(0) = 0 (0 has no true inverse; this is just the
    convention the S-box construction uses).

    Implementation: brute-force search. Try every candidate b and return
    the one with a * b == 1. This is only 256 trials, so it is instant,
    and it is the easiest version to explain in a viva. (A faster way
    would be a^254 via square-and-multiply, since a^255 == 1 for a != 0.)
    """
    a &= 0xFF
    if a == 0:
        return 0
    for b in range(1, 256):          # 0 can never be the inverse
        if gf_mul(a, b) == 1:
            return b
    raise AssertionError("no inverse found; should be impossible")
