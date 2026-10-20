"""Avalanche (diffusion sanity check) on OUR AES block cipher.

Experiment: take a random block, flip ONE input bit, count how many of
the 128 ciphertext bits change. Repeat for all 128 bit positions over many
random blocks -- and the same with one flipped KEY bit (fresh key schedule
per flip). A healthy cipher averages ~64 changed bits (50%), never ~0.

Also included: avalanche GROWTH per round, replaying the round loop with
aes.aes_core's own step functions (sub_bytes, shift_rows, mix_columns,
add_round_key) WITHOUT editing aes/ -- watch one flipped bit infect the
whole block round by round.

HONEST LIMITS (for viva): this checks DIFFUSION only. Passing it does not
prove security -- differential/linear cryptanalysis, related-key and side-
channel attacks are all outside this experiment. It is a necessary
condition (a cipher failing it would be broken on sight), never a proof.
"""

import random

from aes.aes_core import (key_expansion, encrypt_block, bytes_to_state,
                          state_to_bytes, sub_bytes, shift_rows,
                          mix_columns, add_round_key)

SEED = 20261015  # printed with every result, so runs are reproducible


def _flip(data, pos):
    """Copy of bytes with bit `pos` toggled (pos 0 = LSB of byte 0)."""
    data = bytearray(data)
    data[pos // 8] ^= 1 << (pos % 8)
    return bytes(data)


def _changed_bits(a, b):
    """How many of the 128 bits differ between two 16-byte blocks."""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).bit_count()


def _stats(counts):
    """Mean/min/max + share of 128 bits for a list of changed-bit counts."""
    return {"n": len(counts), "mean": sum(counts) / len(counts),
            "min": min(counts), "max": max(counts),
            "share": sum(counts) / len(counts) / 128.0, "hist": counts}


def run_avalanche(nblocks=32, seed=SEED):
    """Full avalanche experiment for AES-128 and AES-256. Returns dict."""
    rng = random.Random(seed)
    out = {"seed": seed}
    for key_len in (16, 32):
        pt_counts, key_counts = [], []
        for _ in range(nblocks):
            block = bytes(rng.randrange(256) for _ in range(16))
            key = bytes(rng.randrange(256) for _ in range(key_len))
            base = encrypt_block(block, key_expansion(key))
            for pos in range(128):  # every plaintext bit position
                other = encrypt_block(_flip(block, pos), key_expansion(key))
                pt_counts.append(_changed_bits(base, other))
            for pos in range(8 * key_len):  # every key bit position
                other = encrypt_block(block, key_expansion(_flip(key, pos)))
                key_counts.append(_changed_bits(base, other))
        out[key_len] = {"pt": _stats(pt_counts), "key": _stats(key_counts)}
    out["rounds"] = {16: round_growth(16), 32: round_growth(32)}
    return out


def round_growth(key_len, bits=(0, 1, 2, 3, 4, 5, 6, 7)):
    """Mean changed bits after each round stage (fixed block+key, flip a
    few low bit positions). Stage 0 = after the initial AddRoundKey."""
    rng = random.Random(SEED + key_len)  # same inputs every run
    block = bytes(rng.randrange(256) for _ in range(16))
    key = bytes(rng.randrange(256) for _ in range(key_len))
    round_keys = key_expansion(key)
    rounds = len(round_keys) - 1
    totals = [0] * (rounds + 1)
    for bit in bits:
        flipped = _flip(block, bit)
        state, other = bytes_to_state(block), bytes_to_state(flipped)
        add_round_key(state, round_keys[0])
        add_round_key(other, round_keys[0])
        totals[0] += _changed_bits(state_to_bytes(state),
                                   state_to_bytes(other))
        for rnd in range(1, rounds):
            for st in (state, other):
                sub_bytes(st)
                shift_rows(st)
                mix_columns(st)
                add_round_key(st, round_keys[rnd])
            totals[rnd] += _changed_bits(state_to_bytes(state),
                                         state_to_bytes(other))
        for st in (state, other):  # final round: no MixColumns
            sub_bytes(st)
            shift_rows(st)
            add_round_key(st, round_keys[rounds])
        totals[rounds] += _changed_bits(state_to_bytes(state),
                                        state_to_bytes(other))
    return [t / len(bits) for t in totals]
