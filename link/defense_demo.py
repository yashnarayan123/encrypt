"""Task 4 demo: every Task 3 attack re-run against the GCM link -- all fail.

Wire recap (92 bytes): nonce(12) | header(16, CLEAR AAD) | ct(48) | tag(16).
The attacker below replays the Task-3 playbook byte-for-byte: splicing,
seq rewriting (now on CLEARtext -- even easier to attempt), bit flips,
replay, truncation/extension. Every forgery dies at the TAG check, which
runs BEFORE any parsing, so the lenient parser never even sees garbage.
ECB/CBC matrix columns are recomputed live via the Task-3 runners for a
fair side-by-side (same key, same afternoon).

Attacker helpers (splice_gcm, rewrite_seq, flip_at) take WIRES ONLY: no
key parameter, no aes import (same rule as Task 3; tests/test_link.py...
tests/test_attacks.py-style signature test enforces it in test_link too).

Run:  python3 -m link.defense_demo
Saves: results/task4_defense_log.txt (full transcript),
       results/task4_defense_matrix.txt (the matrix only).
"""

import inspect as _inspect  # structural self-check helper below only

from link.gcm import gcm_encrypt
from link.secure_link import (
    reset_secure_link, secure_send, secure_receive,
    NONCE_LEN, HEADER_LEN, BODY_LEN, TAG_LEN, WIRE_LEN)
from attacks.ecb_image_leak import (
    make_drone_image, run_image_leak, distinct_blocks)
from attacks.ecb_cut_paste import run_cut_paste, KEY128, KEY256
from attacks.cbc_bitflip import run_bitflip
from attacks.victim import (
    reset_drone, gcs_send as ecb_send, drone_receive as ecb_receive)

FIXED_NONCE = bytes(range(12))  # image demo only (repeatable, not secret)

LOG = []     # full transcript -> task4_defense_log.txt
MATRIX = []  # matrix block only -> task4_defense_matrix.txt


def emit(text=""):
    """Print one line AND remember it for the log file."""
    print(text)
    LOG.append(text)


def emit_matrix(text=""):
    """Print one matrix line; remembered for BOTH files."""
    print(text)
    LOG.append(text)
    MATRIX.append(text)


# ---------------------------------------------------------------------------
# ATTACKER PRIMITIVES -- wires in, wire out. No key, no aes import.
# ---------------------------------------------------------------------------

def splice_gcm(wire_a, wire_b, cut):
    """ECB-style splice: first `cut` bytes from A, rest from B."""
    return bytes(wire_a[:cut]) + bytes(wire_b[cut:])


def rewrite_seq(wire, old4, new4):
    """Rewrite the CLEAR header seq digits (Task-3 IV trick, now easier to
    attempt: the digits sit at wire bytes 24..27 in the clear). Known-
    plaintext as before: the header layout is public."""
    if bytes(wire[24:28]) != bytes(old4):
        raise ValueError("expected seq digits not where the layout says")
    delta = bytes(o ^ n for o, n in zip(bytes(old4), bytes(new4)))
    out = bytearray(wire)
    for i, d in enumerate(delta):
        out[24 + i] ^= d
    return bytes(out)


def flip_at(wire, offset, delta):
    """XOR delta into the wire at byte offset (bit-flip primitive)."""
    out = bytearray(wire)
    for i, d in enumerate(bytes(delta)):
        out[offset + i] ^= d
    return bytes(out)


ATTACKER_FUNCS = (splice_gcm, rewrite_seq, flip_at)


def attacker_touches_no_key():
    """Structural proof helper (used by tests): attacker signatures have
    no key parameter. Returns True iff clean."""
    return all("key" not in _inspect.signature(f).parameters
               for f in ATTACKER_FUNCS)


# ---------------------------------------------------------------------------
# Live runs (setup/drone sides legitimately hold the key; attacker never).
# ---------------------------------------------------------------------------

def run_defense(key):
    """Run all six GCM attacks. Returns outcome dict (no printing).

    Each entry: (forged_wire_or_None, accepted, reason). Legit control
    included ("control" must be True or the setup is broken).
    """
    out = {}
    # Legit traffic the attacker records: seq 11 GOTO, seq 12 LAND.
    wire11, _ = secure_send(key, 11, "GOTO", "ALT:30")
    wire12, _ = secure_send(key, 12, "LAND", "")
    reset_secure_link()
    secure_receive(key, wire11)
    secure_receive(key, wire12)  # drone has obeyed up to seq 12
    # Control: a fresh legit message is accepted.
    fresh, _ = secure_send(key, 13, "RTL", "")
    out["control"] = (fresh,) + secure_receive(key, fresh)
    # 1. Splice: header of 12 + body/tag of 11 (fresh seq, foreign body).
    forged = splice_gcm(wire12, wire11, NONCE_LEN + HEADER_LEN)
    out["splice"] = (forged,) + secure_receive(key, forged)
    # 2. Seq rewrite in the clear: stale seq 11 -> "fresh" 99.
    forged = rewrite_seq(wire11, b"0011", b"0099")
    out["seq_rewrite"] = (forged,) + secure_receive(key, forged)
    # 2b. Nonce byte flip on the fresh message.
    forged = flip_at(fresh, 0, b"\x01")
    out["nonce_flip"] = (forged,) + secure_receive(key, forged)
    # 3. LAND body flip (Task-3 LAND trick: flip ct PARAM region bytes).
    # Fixture stays at last_seq=12; forged seq 14 looks fresh, so ONLY the
    # tag stands in the way -- exactly what this attack measures.
    land, _ = secure_send(key, 14, "LAND", "")
    forged = flip_at(land, NONCE_LEN + HEADER_LEN + 20, b"\x01" * 8)
    out["land_flip"] = (forged,) + secure_receive(key, forged)
    # 4. Whole-wire replay of seq 11 (tag valid, seq stale).
    out["replay"] = (wire11,) + secure_receive(key, wire11)
    # 5. Truncation / extension.
    out["truncated"] = (wire11[:-1],) + secure_receive(key, wire11[:-1])
    out["extended"] = ((wire11 + bytes(16)),) + secure_receive(
        key, wire11 + bytes(16))
    return out


def image_gcm_count():
    """Encrypt the Task-3 drone picture with our GCM (fixed nonce).

    Returns (plain_count, gcm_count, total_blocks). No padding in CTR, so
    total = 3072 blocks; GCM should make ~all of them unique, like CBC.
    """
    pixels = make_drone_image().tobytes()
    ct, _ = gcm_encrypt(KEY128, FIXED_NONCE, pixels, b"")
    total = len(pixels) // 16
    return distinct_blocks(pixels), distinct_blocks(ct), total


def nonce_reuse_demo():
    """BONUS (misuse warning, NOT a break of GCM itself).

    Same key + same nonce + two bodies -> CT1 XOR CT2 = PT1 XOR PT2, so
    anyone who knows/guesses one plaintext recovers the other byte-for-
    byte. secure_send()'s nonce guard exists precisely to forbid this; it
    is bypassed here by calling gcm_encrypt directly to show WHY.
    Returns (xor_matches, recovered_matches).
    """
    from telemetry.packets import pack_command
    body1 = pack_command(50, "LAND", "", auth="GCS")[16:]
    body2 = pack_command(51, "GOTO", "ALT:500", auth="GCS")[16:]
    nonce = bytes([0xAA]) * 12  # deliberately reused below
    ct1, _ = gcm_encrypt(KEY128, nonce, body1, b"hdr")
    ct2, _ = gcm_encrypt(KEY128, nonce, body2, b"hdr")
    xor_ct = bytes(a ^ b for a, b in zip(ct1, ct2))
    xor_pt = bytes(a ^ b for a, b in zip(body1, body2))
    recovered = bytes(a ^ b for a, b in zip(xor_ct, body1))
    return xor_ct == xor_pt, recovered == body2


def stale_replay_row():
    """Whole-wire replay of an already-seen seq in each mode (live runs).

    Returns (ecb_attacker_wins, cbc_attacker_wins): True iff the drone
    OBEYS the replay. Expect False/False -- the wire is untampered so
    crypto passes, but the SEQ RULE rejects: replay protection is
    orthogonal to encryption in every mode.
    """
    wins = []
    for mode in ("ecb", "cbc"):
        reset_drone()
        old = ecb_send(mode, KEY128, 11, "GOTO", "ALT:30")[0]
        new = ecb_send(mode, KEY128, 12, "LAND", "")[0]
        ecb_receive(mode, KEY128, old)
        ecb_receive(mode, KEY128, new)  # drone has seen up to seq 12
        wins.append(ecb_receive(mode, KEY128, old)[0] is True)
    return tuple(wins)


def main():
    """Full transcript: GCM attacks, image numbers, bonus, matrix."""
    emit("=" * 72)
    emit("TASK 4 DEMO: Task-3 attacks vs the GCM link (AES-128 shown;")
    emit("Task 3 proved key size changes nothing, tests cover AES-256 too)")
    emit("Wire = nonce(12) | header(16, CLEAR AAD) | ct(48) | tag(16) = 92B")
    emit("=" * 72)
    res = run_defense(KEY128)
    assert res["control"][1] is True  # setup broken if legit mail fails
    emit("Control: fresh legit seq 13 accepted: %s" % res["control"][1])
    emit("")
    for name, title in (
            ("splice", "1. ECB-style splice (header of seq12 + body/tag of"
             " seq11):"),
            ("seq_rewrite", "2a. Cleartext seq rewrite 0011 -> 0099 (the"
             " Task-3 IV trick, now attemptable in the clear):"),
            ("nonce_flip", "2b. One flipped nonce byte on the fresh msg:"),
            ("land_flip", "3. LAND body flip (ct PARAM region, Task-3 LAND"
             " trick):"),
            ("replay", "4. Whole-wire replay of seq 11 (already obeyed):"),
            ("truncated", "5a. Truncated wire (91 bytes):"),
            ("extended", "5b. Extended wire (108 bytes):")):
        _, accepted, reason = res[name][0], res[name][1], res[name][2]
        emit("%s" % title)
        emit("   drone says: accepted=%s reason=%r" % (accepted, reason))
    emit("")
    emit("Why the LAND flip dies here but lived in Task 3: the tag is")
    emit("verified BEFORE parsing, so garbage never reaches the lenient")
    emit("parser. CBC had no tag -- its only hope was the parser, and the")
    emit("parser was (deliberately) forgiving.")
    emit("")
    emit("-" * 72)
    _, _, _, stats = run_image_leak()
    plain_n, gcm_n, total = image_gcm_count()
    emit("Pattern leak, distinct 16-byte blocks (Task-3 numbers remeasured")
    emit("live just now for the side-by-side):")
    emit("  plain=%d ecb128=%d cbc128=%d gcm128=%d (of %d blocks)" %
         (stats["plain"], stats["ecb128"], stats["cbc128"], gcm_n, total))
    emit("  GCM looks like CBC (noise), not ECB (silhouette): no padding in")
    emit("  CTR plus a fresh keystream per nonce randomises every block.")
    emit("")
    emit("-" * 72)
    emit("BONUS -- nonce reuse under one key (misuse warning, not a break):")
    xor_ok, recover_ok = nonce_reuse_demo()
    emit("  CT1 XOR CT2 == PT1 XOR PT2: %s" % xor_ok)
    emit("  attacker knowing PT1 recovers PT2 exactly: %s" % recover_ok)
    emit("  Same-key/same-nonce also leaks the GHASH key H over time, which")
    emit("  is why secure_send() refuses nonce reuse (guard tested in")
    emit("  tests/test_link.py). GCM is only as good as its nonces.")
    emit("")
    emit("=" * 72)
    emit_matrix("DEFENSE MATRIX (attacker outcome, all cells from live runs)")
    emit_matrix("Attack          | ECB         | CBC         | GCM")
    emit_matrix("----------------+-------------+-------------+----------")
    _, outcomes, _, cbc_out = run_cut_paste(KEY128)
    bit = run_bitflip(KEY128)
    gcm = res
    ecb_replay_win, cbc_replay_win = stale_replay_row()
    rows = [
        ("pattern leak", stats["ecb128"] <= 2 * stats["plain"],
         stats["cbc128"] <= 2 * stats["plain"], gcm_n <= 2 * plain_n),
        ("cut-and-paste", all(outcomes[n][1] for n in ("a", "b", "c")),
         bool(cbc_out[1]), bool(gcm["splice"][1])),
        ("IV/nonce flip", None, bool(bit["a"][2]),
         bool(gcm["seq_rewrite"][1]) or bool(gcm["nonce_flip"][1])),
        ("block flip", bool(bit["b_ecb_land"][2]),
         bool(bit["b_land"][2]), bool(gcm["land_flip"][1])),
        ("replay (stale)", ecb_replay_win, cbc_replay_win,
         bool(gcm["replay"][1])),
    ]
    for name, ecb, cbc, gcm_ok in rows:
        def cell(v):
            return "N/A (no IV)" if v is None else ("SUCCESS" if v
                                                    else "FAILED")
        emit_matrix("%-15s | %-11s | %-11s | %-8s"
                    % (name, cell(ecb), cell(cbc), cell(gcm_ok)))
    emit_matrix("=" * 72)
    emit_matrix("Read: ECB falls to everything; CBC hides patterns and kills")
    emit_matrix("splices but stays malleable; GCM fails EVERY attack above --")
    emit_matrix("tampering is caught by the tag, replay by the seq rule.")
    with open("results/task4_defense_log.txt", "w") as f:
        f.write("\n".join(LOG) + "\n")
    with open("results/task4_defense_matrix.txt", "w") as f:
        f.write("\n".join(MATRIX) + "\n")
    print("Saved results/task4_defense_log.txt + task4_defense_matrix.txt")


if __name__ == "__main__":
    main()

