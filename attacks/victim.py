"""The 'drone': decrypts incoming wires and decides whether to obey.

Wire format (matches telemetry/demo_encrypt.py):
  ECB: wire = ciphertext straight from aes.modes.ecb_encrypt (padded).
  CBC: wire = IV || ciphertext; the first 16 bytes are the IV in the clear.

Everyone shares these helpers: the GCS uses gcs_send() to transmit, the
drone uses decrypt() + drone_accepts() to receive, and the ATTACKER reuses
the same drone code as its oracle (real attackers also test against the
real receiver's behaviour).

All encryption/decryption goes through our own aes.modes package.
Message bytes come from telemetry/packets.py.
"""

import os

from aes.modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt
from telemetry.packets import pack_command, COMMAND_SIZE

# Commands the drone understands. Anything else is rejected.
VALID_COMMANDS = ("ARM", "DISARM", "LAND", "GOTO", "RTL")

# Highest sequence number obeyed so far. Fresh demos reset it with
# reset_drone(). Kept as module state so drone_accepts() keeps the exact
# spec signature drone_accepts(plaintext) -> (accepted, reason, parsed).
_LAST_SEQ = -1


def reset_drone(last_seq=-1):
    """Forget everything (fresh drone) or fast-forward to last_seq."""
    global _LAST_SEQ
    _LAST_SEQ = last_seq


def decrypt(mode, key, wire):
    """Decrypt one wire back to the raw command bytes (64 bytes).

    ECB: wire IS the ciphertext. CBC: wire = IV || ciphertext, so the
    first 16 bytes are split off as the IV. May raise ValueError if the
    PKCS#7 padding is destroyed (that itself is evidence of tampering).
    Key length picks AES-128 (16 bytes) or AES-256 (32 bytes) by itself.
    """
    wire = bytes(wire)
    if mode == "ecb":
        return ecb_decrypt(bytes(key), wire)
    if mode == "cbc":
        if len(wire) < 32 or len(wire) % 16 != 0:
            raise ValueError("CBC wire must be IV + whole blocks")
        return cbc_decrypt(bytes(key), wire[:16], wire[16:])
    raise ValueError("mode must be 'ecb' or 'cbc'")


def drone_accepts(plaintext):
    """Leniently check a decrypted command. Returns (accepted, reason, parsed).

    WHY lenient parsing instead of just calling unpack_command():
    real firmware ignores fields it does not need (e.g. PARAM for LAND),
    and unpack_command() raises ValueError on the first malformed block,
    which would hide exactly what the attacker got away with. So each
    field is checked on its own 16-byte block, in order:
      1. length must be 64 bytes (4 blocks);
      2. must decode as ASCII (garbled CBC blocks fail here);
      3. header block must read DRONE01|SEQ=<number>, seq strictly newer
         than anything obeyed before (replay protection);
      4. CMD block must name a known command;
      5. AUTH block must be exactly AUTH=GCS (stripped of '.' padding);
      6. PARAM is parsed ONLY for GOTO; every other command ignores the
         PARAM block completely, even if it is garbage. THIS is the hole
         the CBC block-flip attack walks through.
    On success the seen-seq memory updates and parsed holds
    {seq, cmd, param, auth}; param is None unless cmd == "GOTO".

    Two deliberate firmware-style choices (needed for Task 3):
    * Bytes are decoded tolerantly (errors="replace"): real firmware
      compares raw bytes, it does not abort on non-ASCII. Garbage in a
      CHECKED block still fails that block's prefix check; garbage in the
      ignored PARAM block is simply never looked at.
    * AUTH compares the 8-byte VALUE field (bytes 0-7) with "AUTH=GCS";
      trailing '.' filler is not part of the value (fixed-offset compare,
      as in C firmware: memcmp(block+0, "AUTH=GCS", 8)). A strict
      whole-block compare would additionally catch filler tampering --
      attacks/cbc_bitflip.py measures exactly that difference.
    """
    global _LAST_SEQ
    data = bytes(plaintext)
    if len(data) != COMMAND_SIZE:
        return False, "bad length %d (want 64)" % len(data), None
    text = data.decode("ascii", errors="replace")
    blocks = [text[i:i + 16] for i in range(0, 64, 16)]
    # 3. Header block: exact prefix + integer seq + freshness.
    if not blocks[0].startswith("DRONE01|SEQ="):
        return False, "bad header block %r" % blocks[0], None
    try:
        seq = int(blocks[0][len("DRONE01|SEQ="):])
    except ValueError:
        return False, "header seq not a number", None
    if seq <= _LAST_SEQ:
        return False, "stale seq %d (last obeyed %d)" % (seq, _LAST_SEQ), None
    # 4. CMD block: known command name (padding dots stripped).
    if not blocks[1].startswith("CMD="):
        return False, "bad CMD block %r" % blocks[1], None
    cmd = blocks[1][len("CMD="):].rstrip(".")
    if cmd not in VALID_COMMANDS:
        return False, "unknown command %r" % cmd, None
    # 5. AUTH block: the value field must read exactly "AUTH=GCS".
    if blocks[3][:8] != "AUTH=GCS":
        return False, "bad AUTH value %r (want AUTH=GCS)" % blocks[3], None
    # 6. PARAM block: read ONLY for GOTO, ignored for all other commands.
    param = None
    if cmd == "GOTO":
        if not blocks[2].startswith("PARAM="):
            return False, "bad PARAM block %r" % blocks[2], None
        param = blocks[2][len("PARAM="):].rstrip(".")
    _LAST_SEQ = seq
    return True, "ok", {"seq": seq, "cmd": cmd, "param": param, "auth": "GCS"}


def drone_receive(mode, key, wire):
    """Full receive path: decrypt, then judge. Never raises.

    Returns (accepted, reason, parsed). A destroyed padding (ValueError
    from decrypt) counts as REJECTED, with the error text as the reason.
    Demos use this so one line covers decrypt + accept.
    """
    try:
        plaintext = decrypt(mode, key, wire)
    except ValueError as exc:
        return False, "decrypt failed: %s" % exc, None
    return drone_accepts(plaintext)


def gcs_send(mode, key, seq, cmd, param):
    """Build a legitimate GCS command (auth always GCS) and encrypt it.

    Returns (wire, plaintext): the bytes that travel over the link plus
    the cleartext the GCS put in (the GCS obviously knows what it sent;
    the attacker on the link only ever sees the wire). CBC draws a fresh
    random IV per message and prepends it: wire = IV || ciphertext.
    """
    plaintext = pack_command(seq, cmd, param, auth="GCS")
    if mode == "ecb":
        return ecb_encrypt(bytes(key), plaintext), plaintext
    if mode == "cbc":
        iv = os.urandom(16)  # fresh IV for THIS message only
        return iv + cbc_encrypt(bytes(key), iv, plaintext), plaintext
    raise ValueError("mode must be 'ecb' or 'cbc'")
