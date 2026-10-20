"""Drone-link packet formats (MAVLink-inspired, NOT real MAVLink).

Two message types:

A) Telemetry packet (drone -> ground): 19 bytes, binary, big-endian.
   Built with the struct module. Layout:
     msg_id      1 byte  (always 1 = telemetry)
     seq         2 bytes (unsigned short, 0..65535)
     lat         4 bytes (signed int, latitude in degrees * 1e7)
     lon         4 bytes (signed int, longitude in degrees * 1e7)
     alt_mm      4 bytes (signed int, altitude in millimetres)
     battery_pct 1 byte  (0..100)
     speed_cm_s  2 bytes (unsigned short, ground speed in cm/s)
     armed       1 byte  (0 = disarmed, 1 = armed)

B) Command packet (ground -> drone): 64 bytes of fixed-width ASCII.
   Exactly 4 blocks of exactly 16 bytes; each field fills ONE block,
   padded on the right with '.' dots:
     block 0: "DRONE01|SEQ=%04d"  (header + sequence number, already 16)
     block 1: "CMD=" + command    (e.g. "CMD=ARM.........")
     block 2: "PARAM=" + param    (e.g. "PARAM=ALT:30.....")
     block 3: "AUTH=" + level     (e.g. "AUTH=GCS........")

WHY one field per block (important for Task 3):
  ECB encrypts every 16-byte block on its own, with no mixing between
  blocks. Because each field sits exactly inside one ciphertext block,
  an attacker who cannot read the key can still CUT a ciphertext block
  out of one message and PASTE it into another (for example, copying an
  "AUTH=GCS........" block over an "AUTH=NONE......." block, or replaying
  an old "CMD=ARM" block). The swapped message still decrypts cleanly
  because each block decrypts independently. If fields straddled block
  boundaries, a swap would garble two fields at once and the trick would
  be much harder to exploit. CBC chains blocks together, so the same
  cut-and-paste corrupts the next block and is detectable.

Standard library only (struct). Encryption lives in aes.modes.
"""

import struct

# Big-endian (>): B = 1-byte unsigned, H = 2-byte unsigned, i = 4-byte signed.
# Sizes: 1 + 2 + 4 + 4 + 4 + 1 + 2 + 1 = 19 bytes total.
TELEMETRY_FORMAT = ">B H i i i B H B"
TELEMETRY_SIZE = struct.calcsize(TELEMETRY_FORMAT)  # 19
TELEMETRY_MSG_ID = 1

COMMAND_BLOCKS = 4
COMMAND_BLOCK_SIZE = 16
COMMAND_SIZE = 64  # 4 blocks x 16 bytes


# ---------------------------------------------------------------------------
# A) Telemetry packet (binary)
# ---------------------------------------------------------------------------

def pack_telemetry(seq, lat, lon, alt_mm, battery_pct, speed_cm_s, armed):
    """Pack telemetry fields into 19 binary bytes (big-endian).

    lat/lon are integers in degrees * 1e7 (e.g. 51.5074 deg -> 515074000).
    armed accepts True/False or 1/0.
    """
    if not 0 <= seq <= 0xFFFF:
        raise ValueError("seq must fit in 2 bytes (0..65535)")
    if not -(2 ** 31) <= lat <= 2 ** 31 - 1:
        raise ValueError("lat out of int32 range")
    if not -(2 ** 31) <= lon <= 2 ** 31 - 1:
        raise ValueError("lon out of int32 range")
    if not -(2 ** 31) <= alt_mm <= 2 ** 31 - 1:
        raise ValueError("alt_mm out of int32 range")
    if not 0 <= battery_pct <= 100:
        raise ValueError("battery_pct must be 0..100")
    if not 0 <= speed_cm_s <= 0xFFFF:
        raise ValueError("speed_cm_s must fit in 2 bytes (0..65535)")
    armed_byte = 1 if armed else 0  # accept True/1 or False/0
    # struct.pack raises struct.error if a value still does not fit.
    return struct.pack(TELEMETRY_FORMAT, TELEMETRY_MSG_ID, seq, lat, lon,
                       alt_mm, battery_pct, speed_cm_s, armed_byte)


def unpack_telemetry(data):
    """Unpack 19 binary bytes into a dict of telemetry fields."""
    data = bytes(data)
    if len(data) != TELEMETRY_SIZE:
        raise ValueError("telemetry packet must be exactly 19 bytes")
    msg_id, seq, lat, lon, alt_mm, battery_pct, speed_cm_s, armed_byte = \
        struct.unpack(TELEMETRY_FORMAT, data)
    if msg_id != TELEMETRY_MSG_ID:
        raise ValueError("bad msg_id (expected 1 for telemetry)")
    if armed_byte not in (0, 1):
        raise ValueError("armed flag must be 0 or 1")
    return {
        "msg_id": msg_id,
        "seq": seq,
        "lat": lat,
        "lon": lon,
        "alt_mm": alt_mm,
        "battery_pct": battery_pct,
        "speed_cm_s": speed_cm_s,
        "armed": bool(armed_byte),
    }


# ---------------------------------------------------------------------------
# B) Command packet (fixed-width ASCII, 4 x 16-byte blocks)
# ---------------------------------------------------------------------------

def _pad_block(text):
    """Pad ASCII text on the right with '.' dots to exactly 16 bytes."""
    if len(text) > COMMAND_BLOCK_SIZE:
        raise ValueError("field %r does not fit in one 16-byte block" % text)
    return text + "." * (COMMAND_BLOCK_SIZE - len(text))


def pack_command(seq, cmd, param, auth):
    """Pack a command into exactly 64 ASCII bytes (4 blocks of 16).

    seq:   0..9999, printed as DRONE01|SEQ=%04d (already 16 chars).
    cmd:   e.g. "ARM", "DISARM", "LAND", "GOTO", "RTL".
    param: e.g. "ALT:30" (may be "" for commands without parameters).
    auth:  e.g. "GCS" or "NONE".
    Raises ValueError if any field would overflow its 16-byte block.
    """
    if not 0 <= seq <= 9999:
        raise ValueError("seq must be 0..9999 so it fits DRONE01|SEQ=NNNN")
    block0 = "DRONE01|SEQ=%04d" % seq  # exactly 16 chars, no padding needed
    block1 = _pad_block("CMD=" + cmd)
    block2 = _pad_block("PARAM=" + param)
    block3 = _pad_block("AUTH=" + auth)
    raw = block0 + block1 + block2 + block3  # 64 chars
    return raw.encode("ascii")  # raises UnicodeEncodeError if not ASCII


def unpack_command(data):
    """Unpack 64 command bytes into a dict {seq, cmd, param, auth}."""
    data = bytes(data)
    if len(data) != COMMAND_SIZE:
        raise ValueError("command packet must be exactly 64 bytes")
    text = data.decode("ascii")  # raises UnicodeDecodeError if not ASCII
    # Split on the 16-byte boundaries: each field occupies one block.
    raw_blocks = [text[i:i + COMMAND_BLOCK_SIZE]
                  for i in range(0, COMMAND_SIZE, COMMAND_BLOCK_SIZE)]
    # Remove the '.' padding on the right of each block.
    fields = [b.rstrip(".") for b in raw_blocks]
    if not fields[0].startswith("DRONE01|SEQ="):
        raise ValueError("bad header block: %r" % raw_blocks[0])
    if not fields[1].startswith("CMD="):
        raise ValueError("bad CMD block: %r" % raw_blocks[1])
    if not fields[2].startswith("PARAM="):
        raise ValueError("bad PARAM block: %r" % raw_blocks[2])
    if not fields[3].startswith("AUTH="):
        raise ValueError("bad AUTH block: %r" % raw_blocks[3])
    return {
        "seq": int(fields[0][len("DRONE01|SEQ="):]),
        "cmd": fields[1][len("CMD="):],
        "param": fields[2][len("PARAM="):],
        "auth": fields[3][len("AUTH="):],
    }
