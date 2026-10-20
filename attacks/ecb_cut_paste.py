"""Attack 2: ECB cut-and-paste forgery (works), same splice vs CBC (fails).

Scenario: the attacker records legitimate encrypted GCS commands off the
link. It cannot decrypt them (no key), but ECB encrypts every 16-byte
block independently, and every command field sits exactly inside one
block (see telemetry/packets.py). So the attacker builds commands the GCS
NEVER SENT by splicing recorded ciphertext blocks together.

Recordings (all AUTH=GCS):
  R1 seq=11 GOTO  ALT:30   (obeyed by the drone: benign survey leg)
  R2 seq=12 LAND           (obeyed by the drone: landed, done)
  R3 seq=13 DISARM         (jammed: recorded, drone never saw it)
  R4 seq=14 RTL            (jammed: recorded, drone never saw it)
  R5 seq=15 GOTO  ALT:500  (jammed: recorded, drone never saw it)

The demo drone has obeyed R1+R2, so last_seen = 12. R3..R5 were jammed on
arrival (a classic: jam, record, forge later), which is why the attacker
can still use their "future" sequence numbers.

SEQ RULE (why the forgeries use the newest header): drone_accepts()
rejects any seq <= last_seen, so a replayed old message dies as "stale".
Every forgery below therefore carries the header block of the MOST RECENT
recording (R5, seq=15): it is fresh, while CMD/PARAM come from elsewhere.
A replay of R5 whole would also pass the seq check -- but replay can only
repeat what the GCS said; splicing executes (seq, cmd, param) triples the
GCS never combined.

Forgeries (ECB wire = 5 blocks B0..B4: header, cmd, param, auth, pad):
  (a) (15, DISARM): [R5.hdr, R3.cmd, R3.param, R3.auth, R3.pad]
  (b) (15, GOTO ALT:500): [R5.hdr, R1.cmd, R5.param, R1.auth, R1.pad]
  (c) (15, LAND): [R5.hdr, R2.cmd, R2.param, R2.auth, R2.pad]
BONUS ECB TELL printed below: every recording's pad block (B4) is byte-
identical -- PKCS#7 pads 64 bytes with a full 0x10-block, and ECB encrypts
it deterministically. The attacker can literally SEE the block grid.

The SAME index splice is then replayed against CBC wires (IV||5 blocks,
same IV as the header's recording): only the header block decrypts
cleanly; the first spliced join decrypts to garbage (it is XORed with the
wrong predecessor), so the drone rejects it. Longer keys change nothing:
the demo runs the whole thing under AES-128 AND AES-256.

Attacker code (forge_* below) only ever touches recorded WIRES and block
numbers -- it never imports aes, never sees the key. Feeding the forged
wire to drone_receive() is the drone's own legitimate receive path.

Run:  python3 -m attacks.ecb_cut_paste
Log:  results/task3_ecb_cutpaste.txt (written by the script itself).
"""

from attacks.victim import reset_drone, decrypt, drone_receive, gcs_send

KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
KEY256 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f")

# The legitimate traffic scripts, in order. (seq, cmd, param).
TRAFFIC = [(11, "GOTO", "ALT:30"),
           (12, "LAND", ""),
           (13, "DISARM", ""),
           (14, "RTL", ""),
           (15, "GOTO", "ALT:500")]

# Forgery plans: forged block i = recordings[src][block].
# (R index, block index) with blocks B0=header B1=cmd B2=param B3=auth B4=pad.
FORGERIES = {
    "a": {"want": "(15, DISARM, no param)",
          "plan": [(4, 0), (2, 1), (2, 2), (2, 3), (2, 4)]},
    "b": {"want": "(15, GOTO, ALT:500)",
          "plan": [(4, 0), (0, 1), (4, 2), (0, 3), (0, 4)]},
    "c": {"want": "(15, LAND, no param)",
          "plan": [(4, 0), (1, 1), (1, 2), (1, 3), (1, 4)]},
}

LINES = []


def emit(text=""):
    """Print one line AND remember it for the results file."""
    print(text)
    LINES.append(text)


def cut(blocks):
    """Split bytes into 16-byte blocks (attacker framing helper)."""
    return [blocks[i:i + 16] for i in range(0, len(blocks), 16)]


def record_traffic(mode, key):
    """GCS side: send the legitimate traffic, attacker records every wire.

    Returns (recordings, plaintexts): the wires as seen on the link plus
    the cleartexts (known ONLY to GCS/drone setup, never to the attacker).
    """
    recordings, plaintexts = [], []
    for seq, cmd, param in TRAFFIC:
        wire, pt = gcs_send(mode, key, seq, cmd, param)
        recordings.append(wire)
        plaintexts.append(pt)
    return recordings, plaintexts


def forge_wire(recordings, plan):
    """ATTACKER: splice 16-byte blocks from recorded wires. No key used.

    plan = list of (recording index, block index) for each forged block.
    For CBC wires block 0 of each recording is its IV (kept with the
    header's recording); forged block 0 below means "that cipher block".
    Returns the forged wire bytes.
    """
    out = bytearray()
    for rec_idx, blk_idx in plan:
        out += cut(recordings[rec_idx])[blk_idx]
    return bytes(out)


def describe_plan(plan):
    """Human-readable provenance, e.g. 'B0 <- R5.B0 (header seq=15)'."""
    names = {0: "header", 1: "cmd", 2: "param", 3: "auth", 4: "pad"}
    return ["B%d <- R%d.%s" % (i, TRAFFIC[r][0], names[b])
            for i, (r, b) in enumerate(plan)]


def drone_fixture(mode, key, recordings):
    """Fresh drone that has legitimately obeyed R1+R2 (last_seen = 12)."""
    reset_drone()
    for wire in recordings[:2]:
        accepted, _, _ = drone_receive(mode, key, wire)
        assert accepted  # setup must be valid, else the demo is meaningless


def run_cut_paste(key):
    """Run ECB forgeries + the CBC counter-demo. Returns everything.

    Pure computation (no printing): main(), tests and summary.py reuse
    this, so displayed wires and judged outcomes always match.
    Returns (ecb_recs, outcomes, cbc_recs, cbc_outcome) where
    outcomes[name] = (forged, accepted, reason, parsed) for the ECB
    forgery and cbc_outcome is the SAME splice (forgery a) vs CBC wires.
    """
    ecb_recs, _ = record_traffic("ecb", key)
    outcomes = {}
    for name, spec in FORGERIES.items():
        forged = forge_wire(ecb_recs, spec["plan"])
        drone_fixture("ecb", key, ecb_recs)
        outcomes[name] = (forged,) + drone_receive("ecb", key, forged)
    cbc_recs, _ = record_traffic("cbc", key)
    forged = forge_wire_cbc(cbc_recs, FORGERIES["a"]["plan"])
    drone_fixture("cbc", key, cbc_recs)
    cbc_outcome = (forged,) + drone_receive("cbc", key, forged)
    return ecb_recs, outcomes, cbc_recs, cbc_outcome


def forge_wire_cbc(recordings, plan):
    """ATTACKER: same splice on CBC wires (wire = IV || 5 cipher blocks).

    The forged wire keeps the header recording's IV (chunk 0) and splices
    cipher chunks per plan (chunk = plan block + 1, skipping the IV).
    """
    iv = cut(recordings[plan[0][0]])[0]  # IV of the header's recording
    out = bytearray(iv)
    for rec_idx, blk_idx in plan:
        out += cut(recordings[rec_idx])[blk_idx + 1]
    return bytes(out)


def show_wire(title, wire, has_iv):
    """Print a wire as 16-byte chunks (IV first for CBC)."""
    chunks = cut(wire)
    emit("  %s (%d bytes):" % (title, len(wire)))
    start = 0
    if has_iv:
        emit("      IV      : %s" % chunks[0].hex())
        start = 1
    for i in range(start, len(chunks)):
        emit("      block %d: %s" % (i - start, chunks[i].hex()))


def main():
    """Record, forge, judge under both key sizes; save the log file."""
    for key, keyname in ((KEY128, "AES-128"), (KEY256, "AES-256")):
        emit("=" * 70)
        emit("ECB CUT-AND-PASTE under %s (key %s...)" % (keyname, key.hex()[:16]))
        emit("=" * 70)
        ecb_recs, outcomes, cbc_recs, cbc_outcome = run_cut_paste(key)
        emit("Recorded %d legit ECB wires (attacker sees wires only):"
             % len(ecb_recs))
        for (seq, cmd, param), wire in zip(TRAFFIC, ecb_recs):
            emit("  R seq=%d %-6s param=%-7r ct B0=%s.."
                 % (seq, cmd, param, wire[:16].hex()[:24]))
        pads = {wire[64:80].hex() for wire in ecb_recs}
        emit("Distinct pad blocks B4 across recordings: %d %s"
             % (len(pads), "(identical -- ECB encrypts the same padding"
                " to the same bytes every time)" if len(pads) == 1 else ""))
        emit("")
        for name, spec in FORGERIES.items():
            forged, accepted, reason, parsed = outcomes[name]
            emit("Forgery (%s): GCS never sent %s" % (name, spec["want"]))
            for line in describe_plan(spec["plan"]):
                emit("    " + line)
            show_wire("forged ciphertext", forged, has_iv=False)
            pt = decrypt("ecb", key, forged)
            emit("  drone decrypts to: %r" % pt.decode("ascii"))
            emit("  drone says: accepted=%s reason=%r parsed=%s"
                 % (accepted, reason, parsed))
            emit("")
        emit("-" * 70)
        emit("SAME splice (forgery a) against CBC wires:")
        forged, accepted, reason, parsed = cbc_outcome
        show_wire("forged CBC wire", forged, has_iv=True)
        emit("  drone says: accepted=%s reason=%r parsed=%s"
             % (accepted, reason, parsed))
        emit("  WHY IT FAILS: forged B1 is decrypted XOR the WRONG predecessor")
        emit("  (R5.B0 instead of R3.B0), so the CMD block is garbage while the")
        emit("  header/param/auth blocks survive -- exactly one garbled join,")
        emit("  and it lands on a CHECKED block. Chaining saves CBC here.")
        emit("")
    with open("results/task3_ecb_cutpaste.txt", "w") as f:
        f.write("\n".join(LINES) + "\n")
    print("Full log saved to results/task3_ecb_cutpaste.txt")


if __name__ == "__main__":
    main()
