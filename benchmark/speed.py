"""Throughput + key-size sensitivity of OUR code (plus one labelled reference).

What is measured: aes.modes ECB/CBC and link.gcm encrypt AND decrypt for
AES-128 and AES-256 (6 combinations) at several message sizes, plus the
single-block encrypt (pre-expanded keys) and key expansion alone.

Fairness notes (for viva):
  * Our modes/ECB helpers re-expand the key on EVERY call, and that cost
    is INCLUDED -- it is what real callers of this API pay. The BLOCK rows
    (keys expanded once, outside the timer) show the per-block cost alone.
  * Throughput is quoted on PLAINTEXT bytes, so padded (ECB/CBC) and
    unpadded (GCM) modes compare fairly.
  * CBC/GCM use FIXED IV/nonce here: random generation is excluded on
    purpose (os.urandom speed is an OS question, not an AES question).
  * The REF rows use the `cryptography` package (C/OpenSSL) on the SAME
    block counts, labelled "reference (C/OpenSSL), not our code". They
    exist only to show how far pure Python is from native speed.
  * Absolute numbers are NOT drone-representative (a drone uses hardware
    AES); the RATIOS between our own modes/keys are what matter.
"""

import csv
import random
import time

from aes.aes_core import key_expansion, encrypt_block
from aes.modes import (ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt,
                       pkcs7_pad)
from link.gcm import gcm_encrypt, gcm_decrypt
from benchmark.timing import measure, repeats_for

KEYS = {128: bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        256: bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                           "101112131415161718191a1b1c1d1e1f")}
FIXED_IV = bytes(range(16))
FIXED_NONCE = bytes(range(12))
BASE_SIZES = [64, 1024, 16 * 1024, 64 * 1024]
BIG_SIZE = 256 * 1024
MSG_SEED = 99  # message bytes are seeded (timings don't depend on content)


def _enc_funcs(mode, key):
    """Return (encrypt_fn, decrypt_fn) for our ECB/CBC implementations."""
    if mode == "ECB":
        return (lambda m: ecb_encrypt(key, m),
                lambda c: ecb_decrypt(key, c))
    if mode == "CBC":
        return (lambda m: cbc_encrypt(key, FIXED_IV, m),
                lambda c: cbc_decrypt(key, FIXED_IV, c))
    raise ValueError("GCM has its own closures below (tag must travel)")


def _gcm_funcs(key):
    """GCM closures: the tag made by encrypt is carried to decrypt timing.

    GCM's AAD is empty here (the 16-byte command header in link/ adds one
    GHASH block -- negligible next to message blocks, noted honestly).
    """
    box = {}

    def enc(msg):
        ct, tag = gcm_encrypt(key, FIXED_NONCE, msg)
        box["tag"] = tag
        return ct

    def dec(ct):
        return gcm_decrypt(key, FIXED_NONCE, ct, b"", box["tag"])

    return enc, dec


def _reference_funcs():
    """C/OpenSSL AES-128-ECB on the same block counts (reference ONLY).

    Fresh encryptor per call: these objects are one-shot streams, and per-
    message setup is part of an honest per-message cost anyway.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = KEYS[128]

    def enc(msg):
        return Cipher(algorithms.AES(key), modes.ECB()) \
            .encryptor().update(pkcs7_pad(msg))

    def dec(ct):
        return Cipher(algorithms.AES(key), modes.ECB()) \
            .decryptor().update(ct)

    return enc, dec


def run_speed(sizes=None):
    """Time every mode x key-size x op. Returns a list of row dicts.

    Row: mode, bits, op, size_bytes, reps, median_ms, min_ms, stdev_ms,
    kbps (plaintext KB/s from the median). sizes defaults to BASE_SIZES
    plus 256 KB only if a one-op pilot says the full run stays < ~100 s.
    """
    rng = random.Random(MSG_SEED)
    sizes = list(BASE_SIZES) if sizes is None else list(sizes)
    messages = {n: bytes(rng.randrange(256) for _ in range(n)) for n in sizes}
    rows = []
    for mode in ("ECB", "CBC", "GCM"):
        for bits in (128, 256):
            key = KEYS[bits]
            for size in sizes:
                msg = messages[size]
                reps = repeats_for(size)
                if mode == "GCM":
                    enc, dec = _gcm_funcs(key)
                else:
                    enc, dec = _enc_funcs(mode, key)
                ct = enc(msg)  # setup OUTSIDE the timer (decrypt input)
                stats = measure(lambda: enc(msg), reps)
                rows.append(_row(mode, bits, "encrypt", size, reps, stats))
                stats = measure(lambda: dec(ct), reps)
                rows.append(_row(mode, bits, "decrypt", size, reps, stats))
    # Reference line (clearly labelled, AES-128 only, same block counts).
    enc, dec = _reference_funcs()
    for size in sizes:
        msg = messages[size]
        ct = enc(msg)
        reps = repeats_for(size)
        stats = measure(lambda: enc(msg), reps)
        rows.append(_row("REF", 128, "encrypt", size, reps, stats))
        stats = measure(lambda: dec(ct), reps)
        rows.append(_row("REF", 128, "decrypt", size, reps, stats))
    rows += run_micro()
    return rows


def _row(mode, bits, op, size, reps, stats):
    """Pack one CSV row; throughput from plaintext bytes and the median."""
    return {"mode": mode, "bits": bits, "op": op, "size_bytes": size,
            "reps": reps, "median_ms": stats["median_ms"],
            "min_ms": stats["min_ms"], "stdev_ms": stats["stdev_ms"],
            "kbps": (size / 1024) / (stats["median_ms"] / 1000.0)}


def run_micro():
    """Single-block encrypt (keys pre-expanded) and key expansion alone."""
    rows = []
    block = bytes(range(16))
    for bits in (128, 256):
        rks = key_expansion(KEYS[bits])
        stats = measure(lambda: encrypt_block(block, rks), 2000)
        rows.append(_row("BLOCK", bits, "encrypt", 16, 2000, stats))
        stats = measure(lambda: key_expansion(KEYS[bits]), 500)
        rows.append(_row("KEYEXP", bits, "expand", len(KEYS[bits]),
                         500, stats))
    return rows


def pick_sizes(budget_s=100.0):
    """Choose sizes so the WHOLE speed run fits the budget (default ~100 s).

    Pilot: one ECB-128 encrypt+decrypt at 16 KB (the heaviest enc+dec pair
    per byte -- GCM pairs cost less, so this over-estimates safely).
    Scaling is linear in bytes (see the log-log plot), times a 1.5x margin
    for noise: cost = 6 pairs x sum(reps x bytes) x per-byte pilot x 1.5.
    256 KB joins only if the estimated TOTAL stays under budget.
    """
    rng = random.Random(MSG_SEED + 1)
    msg = bytes(rng.randrange(256) for _ in range(16 * 1024))
    start = time.perf_counter()
    cbc_decrypt(KEYS[128], FIXED_IV, cbc_encrypt(KEYS[128], FIXED_IV, msg))
    per_byte = (time.perf_counter() - start) / (16 * 1024)

    def estimate(sizes):
        return 6 * sum(repeats_for(s) * s for s in sizes) * per_byte * 1.5

    print("pilot ECB-128 16KB enc+dec: %.3f s" % (per_byte * 16 * 1024))
    print("estimated speed-run total without 256KB: %.0f s" %
          estimate(BASE_SIZES))
    print("estimated speed-run total with 256KB:    %.0f s" %
          estimate(BASE_SIZES + [BIG_SIZE]))
    if estimate(BASE_SIZES + [BIG_SIZE]) < budget_s:
        return BASE_SIZES + [BIG_SIZE]
    return list(BASE_SIZES)


def slowdown(rows, op="encrypt", size=16 * 1024):
    """AES-256/AES-128 median-time ratio per mode (expect ~1.4 = 14/10)."""
    out = {}
    for mode in ("ECB", "CBC", "GCM"):
        times = {}
        for r in rows:
            if r["mode"] == mode and r["op"] == op and r["size_bytes"] == size:
                times[r["bits"]] = r["median_ms"]
        if 128 in times and 256 in times:
            out[mode] = times[256] / times[128]
    return out


def save_csv(rows, path):
    """Write raw rows to CSV (every number measured, none computed)."""
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["mode", "bits", "op",
                                               "size_bytes", "reps",
                                               "median_ms", "min_ms",
                                               "stdev_ms", "kbps"])
        writer.writeheader()
        writer.writerows(rows)
