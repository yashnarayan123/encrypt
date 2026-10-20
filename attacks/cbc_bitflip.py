"""Attacks 3+4: CBC bit-flips without the key (IV flip works, CT flip caught).

CBC decryption is Pi = AESdec(Ci) XOR C(i-1), with P0 = AESdec(C0) XOR IV.
XOR is malleable: flipping a bit in C(i-1) flips the SAME bit in Pi, while
Mi-1 (= AESdec of the touched block) turns to unrecognisable garbage. The
attacker needs no key -- only XOR on wire bytes plus known plaintext (the
command layout is public: block 0 is always "DRONE01|SEQ=NNNN", so the
attacker knows those bytes and the seq counter from traffic watching).

Attack A -- IV bit-flip (REPLAY WITH A FORGED SEQ, accepted):
  Capture a CBC GOTO seq=0011 wire. The drone has since obeyed seq=0012,
  so replaying it whole dies as "stale". Flip IV bytes 12..15 with
  (b"0011" XOR b"0099"): decrypted block 0 becomes "...SEQ=0099" while
  blocks 1..4 are untouched (the IV appears ONLY in P0's equation -- that
  is why ONLY block 0 changes). The drone sees a fresh seq 99 and obeys.
Attack B -- ciphertext-block bit-flip (LAND accepted, GOTO rejected):
  Capture LAND seq=30, flip 8 bytes inside CIPHERTEXT block C2 (wire chunk
  3, bytes 8..15) with a fixed nonzero delta. Two things happen at once:
  M2 (= PARAM block) decrypts to garbage, and M3 (= AUTH block) becomes
  P3 XOR delta. The delta touches only M3's '.' filler tail, so the AUTH
  VALUE field (bytes 0-7) still reads exactly "AUTH=GCS".
  LAND ignores PARAM entirely -> ACCEPTED (garbage printed as proof).
  The SAME flip on a GOTO seq=31 -> REJECTED ("bad PARAM block"), because
  GOTO must parse PARAM. Comment: this is the price of CBC chaining -- a
  blind flip always garbles the neighbour block, so it only slips through
  where the protocol ignores that neighbour. The IV is the attacker's only
  surgical tool (single-block damage); the real fix is a MAC (see link/).
BONUS measured below: the same flip on an ECB LAND wire garbles ONLY the
PARAM block (ECB has no chaining), so ECB accepts it too -- ECB flips are
strictly worse (surgical anywhere), CBC flips are caught unless an
unchecked neighbour absorbs the garbage.

ATTACKER CODE (flip_bytes, forge_iv_seq, forge_ct_block) imports NOTHING
from aes and takes NO key parameter -- pure byte surgery on the wire.
Feeding the result to drone_receive() is the drone's own receive path.

Run:  python3 -m attacks.cbc_bitflip
Log:  results/task3_cbc_bitflip.txt (written by the script itself).
"""

from attacks.victim import reset_drone, decrypt, drone_receive, gcs_send

KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
KEY256 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f")

SEQ_AT = 12          # seq digits live at block-0 bytes 12..15 ("...SEQ=NNNN")
FLIP_CHUNK = 3       # C2 is wire chunk 3 (chunk 0 = IV, chunks 1..5 = C0..C4)
FLIP_START = 8       # touch only the filler tail of the AUTH block (M3[8:16])
DELTA_B = bytes([0x01]) * 8  # fixed nonzero delta: dots -> non-dots, value intact

LINES = []


def emit(text=""):
    """Print one line AND remember it for the results file."""
    print(text)
    LINES.append(text)


# ---------------------------------------------------------------------------
# ATTACKER PRIMITIVES -- no key, no aes import, only public layout knowledge.
# ---------------------------------------------------------------------------

def flip_bytes(wire, offset, delta):
    """XOR delta into the wire at byte offset. The one and only tool."""
    wire = bytearray(wire)
    for i, d in enumerate(bytes(delta)):
        wire[offset + i] ^= d
    return bytes(wire)


def forge_iv_seq(wire, old_seq4, new_seq4):
    """Rewrite the seq digits by flipping the IV (known-plaintext attack).

    wire[12:16] is the IV region controlling decrypted M0[12:16], which the
    public layout fixes as the 4 seq digits. old/new are 4 ASCII digits.
    """
    delta = bytes(o ^ n for o, n in zip(old_seq4, new_seq4))
    return flip_bytes(wire, SEQ_AT, delta)


def forge_ct_block(wire, chunk, start, delta):
    """Flip delta into wire chunk (chunk 0 = IV for CBC, 0-based CT for ECB)."""
    return flip_bytes(wire, chunk * 16 + start, delta)


# ---------------------------------------------------------------------------
# Full runs (setup uses the key; attacker steps never do).
# ---------------------------------------------------------------------------

def show_blocks(plaintext):
    """Print decrypted bytes block by block (tolerant ASCII for garbage)."""
    for i in range(0, len(plaintext), 16):
        blk = plaintext[i:i + 16]
        emit("      M%d: %s  %r" % (i // 16, blk.hex(), blk.decode(
            "ascii", errors="replace")))


def run_bitflip(key):
    """Run Attacks A+B (+ECB bonus). Returns outcome dicts (no printing)."""
    out = {}
    # --- Attack A: IV flip, replay GOTO seq 11 as seq 99 (fixture: seen 12).
    feed, _ = gcs_send("cbc", key, 12, "LAND", "")
    captured, _ = gcs_send("cbc", key, 11, "GOTO", "ALT:30")
    forged = forge_iv_seq(captured, b"0011", b"0099")
    reset_drone()
    drone_receive("cbc", key, feed)
    out["a"] = (captured, forged) + drone_receive("cbc", key, forged)
    # --- Attack B on LAND: garble PARAM (M2), keep AUTH value (M3[0:8]).
    feed, _ = gcs_send("cbc", key, 29, "LAND", "")
    captured, _ = gcs_send("cbc", key, 30, "LAND", "")
    forged = forge_ct_block(captured, FLIP_CHUNK, FLIP_START, DELTA_B)
    reset_drone()
    drone_receive("cbc", key, feed)
    out["b_land"] = (captured, forged) + drone_receive("cbc", key, forged)
    # --- Same flip on GOTO: garbled PARAM must kill it.
    feed, _ = gcs_send("cbc", key, 30, "LAND", "")
    captured, _ = gcs_send("cbc", key, 31, "GOTO", "ALT:30")
    forged = forge_ct_block(captured, FLIP_CHUNK, FLIP_START, DELTA_B)
    reset_drone()
    drone_receive("cbc", key, feed)
    out["b_goto"] = (captured, forged) + drone_receive("cbc", key, forged)
    # --- Bonus: same flip on ECB LAND (single-block damage, no chaining).
    feed, _ = gcs_send("ecb", key, 29, "LAND", "")
    captured, _ = gcs_send("ecb", key, 30, "LAND", "")
    forged = forge_ct_block(captured, 2, FLIP_START, DELTA_B)
    reset_drone()
    drone_receive("ecb", key, feed)
    out["b_ecb_land"] = (captured, forged) + drone_receive(
        "ecb", key, forged)
    return out


def main():
    """Run both attacks under both key sizes; save the log file."""
    for key, keyname in ((KEY128, "AES-128"), (KEY256, "AES-256")):
        emit("=" * 70)
        emit("CBC BIT-FLIPS under %s (attacker never touches the key)" % keyname)
        emit("=" * 70)
        res = run_bitflip(key)
        captured, forged, accepted, reason, parsed = res["a"]
        emit("Attack A: IV flip turns stale seq=0011 into fresh seq=0099")
        emit("  captured wire IV : %s" % captured[:16].hex())
        emit("  forged wire IV   : %s" % forged[:16].hex())
        emit("  ciphertext blocks identical: %s (only the IV changed)"
             % (captured[16:] == forged[16:],))
        emit("  drone decrypts forged M0: %r"
             % decrypt("cbc", key, forged)[:16].decode("ascii"))
        emit("  drone says: accepted=%s reason=%r parsed=%s"
             % (accepted, reason, parsed))
        emit("  WHY ONLY BLOCK 0: Pi = AESdec(Ci) XOR C(i-1); the IV occurs")
        emit("  in P0's equation alone, so M1..M4 (incl. AUTH) are untouched.")
        emit("")
        captured, forged, accepted, reason, parsed = res["b_land"]
        emit("Attack B on LAND seq=30: flip 8 bytes of C2 (garbage M2,")
        emit("  controlled M3 tail; AUTH value bytes 0-7 intact)")
        emit("  drone decrypts forged wire to:")
        show_blocks(decrypt("cbc", key, forged))
        emit("  M2 is garbage (ignored: LAND never reads PARAM); M3's AUTH")
        emit("  value field still 'AUTH=GCS' (only filler changed).")
        emit("  drone says: accepted=%s reason=%r parsed=%s"
             % (accepted, reason, parsed))
        emit("")
        captured, forged, accepted, reason, parsed = res["b_goto"]
        emit("SAME flip on GOTO seq=31:")
        emit("  drone says: accepted=%s reason=%r parsed=%s"
             % (accepted, reason, parsed))
        emit("  GOTO must parse PARAM, so the garbled M2 kills it. The LAND /")
        emit("  GOTO difference is the ignored-field rule, measured live.")
        emit("")
        captured, forged, accepted, reason, parsed = res["b_ecb_land"]
        emit("BONUS: same flip on ECB LAND (chunk 2, ECB has no IV):")
        emit("  drone says: accepted=%s reason=%r" % (accepted, reason))
        emit("  ECB damage is single-block (no chaining): only M2 garbles,")
        emit("  AUTH stays byte-identical -- ECB flips are surgical ANYWHERE.")
        emit("")
    with open("results/task3_cbc_bitflip.txt", "w") as f:
        f.write("\n".join(LINES) + "\n")
    print("Full log saved to results/task3_cbc_bitflip.txt")


if __name__ == "__main__":
    main()
