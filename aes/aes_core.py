"""AES block cipher core: state, round steps, key expansion, encrypt/decrypt.

State (for viva):
  - The 16-byte block is arranged as a 4x4 matrix of bytes.
  - It is COLUMN-major: column 0 holds bytes 0..3, column 1 holds
    bytes 4..7, and so on. So state[row][col] = block[row + 4*col].
  - Every round step works on this matrix.

Only the standard library is used.
"""

from .gf256 import xtime, gf_mul
from .sbox import SBOX, INV_SBOX


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------

def bytes_to_state(block):
    """Turn 16 bytes into a 4x4 column-major matrix (list of 4 rows)."""
    if len(block) != 16:
        raise ValueError("block must be exactly 16 bytes")
    state = [[0] * 4 for _ in range(4)]  # 4 rows x 4 columns
    for col in range(4):
        for row in range(4):
            state[row][col] = block[row + 4 * col] & 0xFF
    return state


def state_to_bytes(state):
    """Turn a 4x4 column-major matrix back into 16 bytes."""
    out = bytearray(16)
    for col in range(4):
        for row in range(4):
            out[row + 4 * col] = state[row][col] & 0xFF
    return bytes(out)


def _debug_print(round_no, step, state):
    """Print one line showing the state (hex) after a step. For demos."""
    flat = state_to_bytes(state).hex()
    print("round %2d | after %-14s | %s" % (round_no, step, flat))


# ---------------------------------------------------------------------------
# The four round steps (+ inverses). Each edits `state` in place.
# ---------------------------------------------------------------------------

def sub_bytes(state):
    """SubBytes: replace every byte via the S-box (non-linear layer)."""
    for row in range(4):
        for col in range(4):
            state[row][col] = SBOX[state[row][col]]
    return state


def inv_sub_bytes(state):
    """Inverse of SubBytes: replace every byte via the inverse S-box."""
    for row in range(4):
        for col in range(4):
            state[row][col] = INV_SBOX[state[row][col]]
    return state


def shift_rows(state):
    """ShiftRows: row r shifts LEFT by r bytes (row 0 unchanged).

    This moves bytes between columns, giving diffusion across columns.
    """
    for row in range(4):
        # Left rotation by `row`: e.g. row 2: [a,b,c,d] -> [c,d,a,b].
        state[row] = state[row][row:] + state[row][:row]
    return state


def inv_shift_rows(state):
    """Inverse of ShiftRows: row r shifts RIGHT by r bytes."""
    for row in range(4):
        if row == 0:
            continue  # row 0 never moves
        # Right rotation by `row` = left rotation by (4 - row).
        state[row] = state[row][4 - row:] + state[row][:4 - row]
    return state


def mix_columns(state):
    """MixColumns: mix each column with the fixed matrix [2,3,1,1].

    For one column (s0,s1,s2,s3), top-down:
        t0 = 2*s0 ^ 3*s1 ^ 1*s2 ^ 1*s3
        t1 = 1*s0 ^ 2*s1 ^ 3*s2 ^ 1*s3
        t2 = 1*s0 ^ 1*s1 ^ 2*s2 ^ 3*s3
        t3 = 3*s0 ^ 1*s1 ^ 1*s2 ^ 2*s3
    where * is GF(2^8) multiplication. This spreads one input byte of a
    column into all four output bytes of that column.
    """
    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]
        state[0][col] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3
        state[1][col] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3
        state[2][col] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3)
        state[3][col] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2)
    return state


def inv_mix_columns(state):
    """Inverse of MixColumns: same idea with matrix [14,11,13,9].

    This is the exact inverse, so inv_mix_columns(mix_columns(s)) == s.
    """
    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]
        state[0][col] = gf_mul(s0, 14) ^ gf_mul(s1, 11) ^ gf_mul(s2, 13) ^ gf_mul(s3, 9)
        state[1][col] = gf_mul(s0, 9) ^ gf_mul(s1, 14) ^ gf_mul(s2, 11) ^ gf_mul(s3, 13)
        state[2][col] = gf_mul(s0, 13) ^ gf_mul(s1, 9) ^ gf_mul(s2, 14) ^ gf_mul(s3, 11)
        state[3][col] = gf_mul(s0, 11) ^ gf_mul(s1, 13) ^ gf_mul(s2, 9) ^ gf_mul(s3, 14)
    return state


def add_round_key(state, round_key):
    """AddRoundKey: XOR the 16-byte round key into the state (column-major).

    XOR is its own inverse, so this same function is used for decrypt.
    """
    if len(round_key) != 16:
        raise ValueError("round key must be exactly 16 bytes")
    for col in range(4):
        for row in range(4):
            state[row][col] ^= round_key[row + 4 * col]
    return state


# ---------------------------------------------------------------------------
# Key expansion
# ---------------------------------------------------------------------------

def _sub_word(word):
    """Apply the S-box to each of the 4 bytes of a word."""
    return [SBOX[b] for b in word]


def key_expansion(key):
    """Expand a 16-byte (AES-128) or 32-byte (AES-256) key.

    Returns a list of round keys, each 16 bytes:
      - AES-128: 11 round keys (10 rounds), 44 words.
      - AES-256: 15 round keys (14 rounds), 60 words.

    How it works (FIPS-197 §5.2):
      - Split the key into Nk 4-byte words (Nk=4 for 128-bit, 8 for 256).
      - Grow the word list: each new word = old word Nk back XOR a
        transformed copy of the previous word.
      - The transform is: every Nk-th word gets RotWord + SubWord + Rcon;
        AES-256 additionally applies SubWord in the middle (when
        i % Nk == 4). Rcon starts at 0x01 and doubles (xtime) each use.
      - Group every 4 words into one 16-byte round key.
    """
    key = bytes(key)
    if len(key) not in (16, 32):
        raise ValueError("key must be 16 bytes (AES-128) or 32 bytes (AES-256)")

    nk = len(key) // 4        # 4 for AES-128, 8 for AES-256
    nr = nk + 6               # 10 rounds for AES-128, 14 for AES-256
    nb = 4                    # columns in the state (always 4 for AES)
    total_words = nb * (nr + 1)

    # Start: copy the key bytes into the first Nk words.
    words = []
    for i in range(nk):
        words.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    rcon = 0x01  # round constant, doubles after every use via xtime()
    for i in range(nk, total_words):
        temp = words[i - 1][:]  # copy of previous word
        if i % nk == 0:
            # RotWord: rotate left by one byte: [a0,a1,a2,a3] -> [a1,a2,a3,a0].
            temp = temp[1:] + temp[:1]
            # SubWord: S-box each byte.
            temp = _sub_word(temp)
            # XOR round constant into the first byte.
            temp[0] ^= rcon
            rcon = xtime(rcon)  # next Rcon = old Rcon * 2 in GF(2^8)
        elif nk > 6 and i % nk == 4:
            # AES-256 extra step: SubWord with no RotWord and no Rcon.
            temp = _sub_word(temp)
        # New word = word Nk back XOR transformed temp.
        prev = words[i - nk]
        words.append([prev[j] ^ temp[j] for j in range(4)])

    # Group words 4-by-4 into 16-byte round keys (each word = one column).
    round_keys = []
    for r in range(nr + 1):
        rk = bytearray(16)
        for c in range(4):
            word = words[4 * r + c]
            for row in range(4):
                rk[row + 4 * c] = word[row]
        round_keys.append(bytes(rk))
    return round_keys


# ---------------------------------------------------------------------------
# Block encrypt / decrypt (exactly one 16-byte block)
# ---------------------------------------------------------------------------

def encrypt_block(block, round_keys, debug=False):
    """Encrypt one 16-byte block.

    Flow: AddKey(k0), then (Sub, Shift, Mix, Add) x (Nr-1), then the
    final round (Sub, Shift, Add) with NO MixColumns. The final round
    skips MixColumns so encrypt and decrypt stay symmetric.
    """
    nr = len(round_keys) - 1
    if nr not in (10, 14):
        raise ValueError("need 11 round keys (AES-128) or 15 (AES-256)")
    state = bytes_to_state(bytes(block))
    if debug:
        print("input : %s" % bytes(block).hex())

    add_round_key(state, round_keys[0])
    if debug:
        _debug_print(0, "add_round_key", state)

    for rnd in range(1, nr):
        sub_bytes(state)
        if debug:
            _debug_print(rnd, "sub_bytes", state)
        shift_rows(state)
        if debug:
            _debug_print(rnd, "shift_rows", state)
        mix_columns(state)
        if debug:
            _debug_print(rnd, "mix_columns", state)
        add_round_key(state, round_keys[rnd])
        if debug:
            _debug_print(rnd, "add_round_key", state)

    # Final round (no MixColumns).
    sub_bytes(state)
    if debug:
        _debug_print(nr, "sub_bytes", state)
    shift_rows(state)
    if debug:
        _debug_print(nr, "shift_rows", state)
    add_round_key(state, round_keys[nr])
    if debug:
        _debug_print(nr, "add_round_key", state)

    return state_to_bytes(state)


def decrypt_block(block, round_keys, debug=False):
    """Decrypt one 16-byte block (exact reverse of encrypt_block).

    Flow: AddKey(kNr), undo final round (InvShift, InvSub, Add(k0)-side...),
    then per round: InvShift, InvSub, Add, InvMix. AddRoundKey is the same
    function because XOR undoes itself.
    """
    nr = len(round_keys) - 1
    if nr not in (10, 14):
        raise ValueError("need 11 round keys (AES-128) or 15 (AES-256)")
    state = bytes_to_state(bytes(block))
    if debug:
        print("input : %s" % bytes(block).hex())

    # Undo the final AddRoundKey first.
    add_round_key(state, round_keys[nr])
    if debug:
        _debug_print(nr, "add_round_key", state)

    # Undo the final (Sub, Shift).
    inv_shift_rows(state)
    if debug:
        _debug_print(nr, "inv_shift_rows", state)
    inv_sub_bytes(state)
    if debug:
        _debug_print(nr, "inv_sub_bytes", state)

    # Undo middle rounds in reverse: Add, InvMix, InvShift, InvSub.
    for rnd in range(nr - 1, 0, -1):
        add_round_key(state, round_keys[rnd])
        if debug:
            _debug_print(rnd, "add_round_key", state)
        inv_mix_columns(state)
        if debug:
            _debug_print(rnd, "inv_mix_columns", state)
        inv_shift_rows(state)
        if debug:
            _debug_print(rnd, "inv_shift_rows", state)
        inv_sub_bytes(state)
        if debug:
            _debug_print(rnd, "inv_sub_bytes", state)

    # Undo the initial AddRoundKey.
    add_round_key(state, round_keys[0])
    if debug:
        _debug_print(0, "add_round_key", state)

    return state_to_bytes(state)
