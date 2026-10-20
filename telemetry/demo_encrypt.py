"""Task 2 demo: encrypt/decrypt sample drone-link packets.

Covers all four configurations (ECB-128, CBC-128, ECB-256, CBC-256) on a
sample telemetry packet and a sample command packet, plus two extra
demos that make the ECB-vs-CBC difference visible:
  * "Same message twice" (ECB deterministic, CBC differs per IV).
  * "Repeated blocks" (ECB repeats ciphertext blocks, CBC does not).

All encryption uses our own aes.modes functions only. For CBC a fresh
random IV (os.urandom(16)) is drawn per message and SENT PREPENDED to
the ciphertext, i.e. wire = IV || ciphertext; the receiver splits the
first 16 bytes off as the IV before decrypting.

Run:  python3 -m telemetry.demo_encrypt
The script prints everything to the screen AND writes it to
results/task2_demo.txt by itself.

Standard library only here (os, time) plus our own aes/telemetry code.
"""

import os
import time

from aes.modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt
from telemetry.packets import (
    pack_telemetry,
    unpack_telemetry,
    pack_command,
)

# Fixed demo keys so the output is comparable across runs.
KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
KEY256 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f")

# One sample telemetry packet and one sample command packet for everything.
SAMPLE_TELEMETRY = pack_telemetry(
    seq=42, lat=515074000, lon=-1278000, alt_mm=120000,
    battery_pct=87, speed_cm_s=1250, armed=True)
SAMPLE_COMMAND = pack_command(seq=7, cmd="GOTO", param="ALT:30", auth="GCS")

# Collected output lines: printed to screen and saved to results file.
LINES = []


def emit(text=""):
    """Print one line AND remember it for the results file."""
    print(text)
    LINES.append(text)


def show_blocks(blob, indent="      "):
    """Print a byte string as 16-byte blocks, one block (hex) per line."""
    for i in range(0, len(blob), 16):
        emit("%sblock %d: %s" % (indent, i // 16, blob[i:i + 16].hex()))


def demo_one_packet(title, plaintext, key, key_hex, mode):
    """Encrypt/decrypt one packet in one configuration, print everything."""
    emit("  [%s]" % title)
    # Readable form: telemetry bytes decode as a dict, command as ASCII.
    if title.startswith("Telemetry"):
        emit("  Plaintext (dict)  : %s" % (unpack_telemetry(plaintext),))
    else:
        emit("  Plaintext (ascii) : %r" % (plaintext.decode("ascii"),))
    emit("  Plaintext (hex)   : %s (%d bytes)" % (plaintext.hex(), len(plaintext)))
    emit("  Key (hex)         : %s" % (key_hex,))
    t0 = time.perf_counter()  # start the encryption timer
    if mode == "ecb":
        emit("  IV                : (none - ECB needs no IV)")
        ciphertext = ecb_encrypt(key, plaintext)
        wire = ciphertext  # nothing prepended in ECB
    else:
        iv = os.urandom(16)  # fresh random IV for THIS message only
        ciphertext = cbc_encrypt(key, iv, plaintext)
        wire = iv + ciphertext  # IV travels in the clear, prepended
        emit("  IV (hex, fresh)   : %s" % (iv.hex(),))
    enc_ms = (time.perf_counter() - t0) * 1000.0
    emit("  Encrypt time      : %.3f ms" % (enc_ms,))
    emit("  Ciphertext (%d bytes%s):"
         % (len(wire), ", IV || CT" if mode == "cbc" else ""))
    if mode == "cbc":
        emit("      IV      : %s" % (wire[:16].hex(),))
        show_blocks(wire[16:])
    else:
        show_blocks(wire)
    # Decrypt: split the IV back off first in CBC mode.
    if mode == "ecb":
        decrypted = ecb_decrypt(key, wire)
    else:
        decrypted = cbc_decrypt(key, wire[:16], wire[16:])
    if title.startswith("Telemetry"):
        emit("  Decrypted (dict)  : %s" % (unpack_telemetry(decrypted),))
    else:
        emit("  Decrypted (ascii) : %r" % (decrypted.decode("ascii"),))
    emit("  Decrypted (hex)   : %s" % (decrypted.hex(),))
    emit("  %s" % ("ROUNDTRIP OK" if decrypted == plaintext else "ROUNDTRIP FAILED"))
    emit("")


def demo_same_message_twice():
    """Same command encrypted twice: ECB repeats, CBC differs (new IV)."""
    emit("EXTRA DEMO 1: same message twice")
    emit("  Sending the identical command twice back-to-back.")
    cmd = pack_command(seq=9, cmd="ARM", param="", auth="GCS")
    emit("  Plaintext (ascii) : %r" % (cmd.decode("ascii"),))
    emit("")
    emit("  ECB-128, twice (no IV, deterministic):")
    ct1 = ecb_encrypt(KEY128, cmd)
    ct2 = ecb_encrypt(KEY128, cmd)
    emit("    first:")
    show_blocks(ct1, indent="      ")
    emit("    second:")
    show_blocks(ct2, indent="      ")
    emit("    identical ciphertext: %s (ECB always repeats)" % (ct1 == ct2,))
    emit("")
    emit("  CBC-128, twice (fresh random IV each time):")
    iv1 = os.urandom(16)
    iv2 = os.urandom(16)
    wire1 = iv1 + cbc_encrypt(KEY128, iv1, cmd)
    wire2 = iv2 + cbc_encrypt(KEY128, iv2, cmd)
    emit("    first  IV: %s" % (iv1.hex(),))
    show_blocks(wire1[16:], indent="      ")
    emit("    second IV: %s" % (iv2.hex(),))
    show_blocks(wire2[16:], indent="      ")
    emit("    identical on wire: %s (CBC differs because the IV differs)"
         % (wire1 == wire2,))
    emit("")


def demo_repeated_blocks():
    """One message, three identical blocks: ECB leaks it, CBC hides it."""
    emit("EXTRA DEMO 2: repeated blocks in one message")
    emit("  Message = the same 16-byte block 3 times (48 bytes).")
    emit("  NOTE: our modes add PKCS#7 padding, so a 4th padding block")
    emit("  (16 bytes of 0x10) appears; compare the FIRST THREE blocks.")
    msg = b"ABCDEFGHIJKLMNOP" * 3
    emit("  Plaintext (hex)   : %s" % (msg.hex(),))
    emit("")
    emit("  ECB-128 ciphertext:")
    ct_ecb = ecb_encrypt(KEY128, msg)
    show_blocks(ct_ecb, indent="    ")
    blocks = [ct_ecb[i:i + 16] for i in range(0, 48, 16)]
    emit("    first three blocks identical: %s (pattern leaks!)"
         % (blocks[0] == blocks[1] == blocks[2],))
    emit("")
    emit("  CBC-128 ciphertext:")
    iv = os.urandom(16)
    ct_cbc = cbc_encrypt(KEY128, iv, msg)
    emit("    IV: %s" % (iv.hex(),))
    show_blocks(ct_cbc, indent="    ")
    blocks = [ct_cbc[i:i + 16] for i in range(0, 48, 16)]
    same = (blocks[0] == blocks[1]) or (blocks[1] == blocks[2]) \
        or (blocks[0] == blocks[2])
    emit("    any two of first three identical: %s (chaining hides it)"
         % (same,))
    emit("")


def main():
    """Run every demo and save the full output to results/task2_demo.txt."""
    emit("=" * 70)
    emit("TASK 2 DEMO: encrypt/decrypt on the drone link (our own AES)")
    emit("Generated: %s" % (time.asctime(),))
    emit("Keys are fixed so runs are comparable; CBC IVs are fresh random.")
    emit("=" * 70)
    emit("")
    configs = [("ECB-128", "ecb", KEY128, KEY128.hex()),
               ("CBC-128", "cbc", KEY128, KEY128.hex()),
               ("ECB-256", "ecb", KEY256, KEY256.hex()),
               ("CBC-256", "cbc", KEY256, KEY256.hex())]
    for name, mode, key, key_hex in configs:
        emit("-" * 70)
        emit("Config: %s (%s, %d-bit key)"
             % (name, mode.upper(), len(key) * 8))
        emit("-" * 70)
        demo_one_packet("Telemetry packet", SAMPLE_TELEMETRY, key, key_hex, mode)
        demo_one_packet("Command packet", SAMPLE_COMMAND, key, key_hex, mode)
    emit("-" * 70)
    demo_same_message_twice()
    emit("-" * 70)
    demo_repeated_blocks()
    emit("=" * 70)
    emit("END OF TASK 2 DEMO")
    emit("=" * 70)
    # Save the exact same text that was printed.
    os.makedirs("results", exist_ok=True)
    with open("results/task2_demo.txt", "w") as f:
        f.write("\n".join(LINES) + "\n")
    print("Full output saved to results/task2_demo.txt")


if __name__ == "__main__":
    main()
