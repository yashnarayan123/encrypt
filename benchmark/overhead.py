"""Wire overhead: what each mode ADDS to a real 64-byte command.

Measured from REAL wires out of our own code (nothing assumed):
  ECB: ecb_encrypt padding          -> 80 bytes (one PKCS#7 block added)
  CBC: 16-byte IV + ecb padding     -> 96 bytes
  GCM: 12-byte nonce + 16-byte tag  -> 92 bytes (CTR needs no padding;
       the 16 clear header bytes are part of the 64-byte message, and the
       48 body bytes encrypt to exactly 48 bytes)

Plus the cost at 50 packets/second (stated assumption: a busy telemetry
downlink; capability, not a claim about any real drone).
"""

from aes.modes import ecb_encrypt, cbc_encrypt
from link.secure_link import secure_send
from telemetry.packets import pack_command

KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
FIXED_IV = bytes(range(16))
PACKETS_PER_SECOND = 50  # stated assumption, see docstring


def run_overhead():
    """Build one real command and all three wires. Returns a dict."""
    plain = pack_command(7, "GOTO", "ALT:30", auth="GCS")  # 64 bytes
    ecb_wire = ecb_encrypt(KEY128, plain)            # padded only
    cbc_wire = FIXED_IV + cbc_encrypt(KEY128, FIXED_IV, plain)  # IV on wire
    gcm_wire, _ = secure_send(KEY128, 7, "GOTO", "ALT:30")     # nonce+tag
    out = {"plain_bytes": len(plain)}
    for name, wire in (("ECB", ecb_wire), ("CBC", cbc_wire),
                       ("GCM", gcm_wire)):
        extra = len(wire) - len(plain)
        out[name] = {"wire_bytes": len(wire),
                     "overhead_bytes": extra,
                     "overhead_pct": 100.0 * extra / len(plain),
                     "bytes_per_s": len(wire) * PACKETS_PER_SECOND,
                     "kbit_per_s": len(wire) * PACKETS_PER_SECOND * 8 / 1000}
    return out
