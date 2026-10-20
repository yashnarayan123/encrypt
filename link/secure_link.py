"""The defended drone link: AES-GCM instead of raw ECB/CBC.

Wire format (92 bytes, fixed):
  nonce (12, clear) || header (16, CLEAR, = the AAD) || ct (48) || tag (16)

NOTE ON THE BRIEF (flagged in the final report): the brief writes
"wire = nonce(12) || ciphertext || tag(16)" with "AAD = the cleartext
header". Taken literally (76 bytes, no header on the wire) the receiver
could never LEARN the AAD it must verify -- AAD has to travel somehow.
So here the brief's "ciphertext" slot carries the 16 clear header bytes
first, then the 48 encrypted body bytes. Every byte the drone needs is
either authenticated-only (header: readable for routing, seq visible to
watchers) or encrypted+authenticated (CMD/PARAM/AUTH body).

Order on receive: split wire -> verify TAG first -> parse ONLY after the
tag passes. Parsing a message whose tag failed is forbidden (that is how
Task 3's lenient-parser tricks die: garbage never reaches the parser).

Nonces: fresh random 12 bytes per message (os.urandom). The sender keeps a
set of used (key, nonce) pairs and REFUSES to reuse one. WHY: GCM's CTR
keystream repeats under a reused nonce, so CT1 XOR CT2 = PT1 XOR PT2
(shown in the BONUS demo), and worse, repeated GHASH masks leak the
authentication subkey H, letting attackers forge tags. Random 96-bit
nonces collide ~never; the guard is a seatbelt, demo-grade (production
code would use a persistent counter instead of an ever-growing set).

Only our own code is used: link.gcm for crypto, telemetry/packets.py for
message bytes. Replay rule mirrors attacks/victim.py (seq strictly newer)
but with LOCAL state, so the GCM link and the Task-3 playground never
share a replay window.
"""

import os

from link.gcm import gcm_encrypt, gcm_decrypt, AuthenticationError
from telemetry.packets import pack_command, COMMAND_SIZE

NONCE_LEN = 12
HEADER_LEN = 16                      # AAD = first block ("DRONE01|SEQ=..")
BODY_LEN = COMMAND_SIZE - HEADER_LEN  # encrypted part = 48 bytes
TAG_LEN = 16
WIRE_LEN = NONCE_LEN + HEADER_LEN + BODY_LEN + TAG_LEN  # 92 bytes, always

VALID_COMMANDS = ("ARM", "DISARM", "LAND", "GOTO", "RTL")  # as in victim.py

_LAST_SEQ = -1         # highest obeyed seq on THIS link
_USED_NONCES = set()   # (key, nonce) pairs already sent (demo-grade guard)


def reset_secure_link(last_seq=-1):
    """Fresh receiver (and empty nonce log, for repeatable demos/tests)."""
    global _LAST_SEQ
    _LAST_SEQ = last_seq
    _USED_NONCES.clear()


def _claim_nonce(key, nonce):
    """Refuse an already-used (key, nonce) pair. Raises RuntimeError."""
    pair = (bytes(key), bytes(nonce))
    if pair in _USED_NONCES:
        raise RuntimeError("nonce reuse under one key is forbidden (see "
                           "module docstring: it leaks plaintext XORs and "
                           "the GHASH subkey)")
    _USED_NONCES.add(pair)


def secure_send(key, seq, cmd, param):
    """GCS side: pack (auth always GCS), encrypt body, return (wire, plain).

    plain is the full 64-byte command (for the sender's own logs only;
    the link carries nonce || clear header || encrypted body || tag).
    """
    full = pack_command(seq, cmd, param, auth="GCS")  # raises if too long
    header, body = full[:HEADER_LEN], full[HEADER_LEN:]
    nonce = os.urandom(NONCE_LEN)  # fresh every message
    _claim_nonce(key, nonce)
    ciphertext, tag = gcm_encrypt(bytes(key), nonce, body, header)
    return nonce + header + ciphertext + tag, full


def _parse_verified(header, body):
    """Field checks on a TAG-VERIFIED message. Same rules as victim.py.

    Returns (accepted, reason, parsed). Lenient on purpose (PARAM ignored
    except for GOTO) -- the point of the defense demo is that tampering is
    caught by the TAG first, so parser leniency no longer matters.
    """
    global _LAST_SEQ
    if not header.startswith(b"DRONE01|SEQ="):
        return False, "bad header block", None
    try:
        seq = int(header[len(b"DRONE01|SEQ="):])
    except ValueError:
        return False, "header seq not a number", None
    if seq <= _LAST_SEQ:
        return False, "stale seq %d (last obeyed %d)" % (seq, _LAST_SEQ), None
    cmd_blk, param_blk, auth_blk = body[:16], body[16:32], body[32:48]
    if not cmd_blk.startswith(b"CMD="):
        return False, "bad CMD block", None
    cmd = cmd_blk[len(b"CMD="):].rstrip(b".").decode("ascii", "replace")
    if cmd not in VALID_COMMANDS:
        return False, "unknown command %r" % cmd, None
    if auth_blk[:8] != b"AUTH=GCS":  # value field, as in victim.py
        return False, "bad AUTH value", None
    param = None
    if cmd == "GOTO":
        if not param_blk.startswith(b"PARAM="):
            return False, "bad PARAM block", None
        param = param_blk[len(b"PARAM="):].rstrip(b".").decode("ascii")
    _LAST_SEQ = seq
    return True, "ok", {"seq": seq, "cmd": cmd, "param": param,
                        "auth": "GCS"}


def secure_receive(key, wire):
    """Drone side: (accepted, reason, parsed); tag checked BEFORE parsing.

    Any failure (bad length, tag mismatch from tampered nonce/header/ct/
    tag or wrong key) -> (False, reason, None). Only verified messages
    reach the field checks + replay rule.
    """
    global _LAST_SEQ
    wire = bytes(wire)
    if len(wire) != WIRE_LEN:
        return False, "bad wire length %d (want 92)" % len(wire), None
    nonce = wire[:NONCE_LEN]
    header = wire[NONCE_LEN:NONCE_LEN + HEADER_LEN]
    ciphertext = wire[NONCE_LEN + HEADER_LEN:WIRE_LEN - TAG_LEN]
    tag = wire[WIRE_LEN - TAG_LEN:]
    try:
        body = gcm_decrypt(bytes(key), nonce, ciphertext, header, tag)
    except AuthenticationError as exc:
        return False, "tag check failed: %s" % exc, None
    return _parse_verified(header, body)
