"""Task 2 tests: packet formats and encrypt/decrypt behaviour.

Covers: pack/unpack roundtrips for both message types, the exact 64-byte
block-aligned command layout, ValueError on oversized fields, encrypt
then decrypt roundtrips for all four configurations (ECB/CBC x 128/256),
and the ECB-repeats / CBC-hides block property.

Run:  python3 -m pytest tests/test_telemetry.py aes/tests/test_aes.py -v
"""
import pytest

from aes.modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt
from telemetry.packets import (
    pack_telemetry,
    unpack_telemetry,
    pack_command,
    unpack_command,
    TELEMETRY_SIZE,
    COMMAND_SIZE,
)

KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
KEY256 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f")
IV_A = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
IV_B = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")


def test_telemetry_roundtrip():
    """pack_telemetry -> unpack_telemetry returns the same fields."""
    raw = pack_telemetry(seq=42, lat=515074000, lon=-1278000, alt_mm=120000,
                         battery_pct=87, speed_cm_s=1250, armed=True)
    assert len(raw) == TELEMETRY_SIZE == 19
    fields = unpack_telemetry(raw)
    assert fields == {"msg_id": 1, "seq": 42, "lat": 515074000,
                      "lon": -1278000, "alt_mm": 120000, "battery_pct": 87,
                      "speed_cm_s": 1250, "armed": True}


def test_telemetry_rejects_bad_bytes():
    """Wrong length or wrong msg_id must raise ValueError."""
    with pytest.raises(ValueError):
        unpack_telemetry(b"\x00" * 18)  # too short
    with pytest.raises(ValueError):
        unpack_telemetry(b"\x02" + b"\x00" * 18)  # msg_id != 1


def test_command_roundtrip():
    """pack_command -> unpack_command returns the same fields."""
    raw = pack_command(seq=7, cmd="GOTO", param="ALT:30", auth="GCS")
    assert len(raw) == COMMAND_SIZE == 64
    assert unpack_command(raw) == {"seq": 7, "cmd": "GOTO",
                                   "param": "ALT:30", "auth": "GCS"}


def test_command_block_layout():
    """The command is 64 bytes with each field on a 16-byte boundary."""
    raw = pack_command(seq=7, cmd="GOTO", param="ALT:30", auth="GCS")
    assert raw == (b"DRONE01|SEQ=0007"      # bytes 0..15
                   b"CMD=GOTO........"      # bytes 16..31
                   b"PARAM=ALT:30...."       # bytes 32..47
                   b"AUTH=GCS........")      # bytes 48..63
    assert raw[0:16] == b"DRONE01|SEQ=0007"
    assert raw[16:32] == b"CMD=GOTO........"
    assert raw[32:48] == b"PARAM=ALT:30...."
    assert raw[48:64] == b"AUTH=GCS........"


def test_command_oversized_fields_rejected():
    """Any field that would overflow its 16-byte block raises ValueError."""
    with pytest.raises(ValueError):
        pack_command(seq=10000, cmd="ARM", param="", auth="GCS")  # seq too big
    with pytest.raises(ValueError):
        pack_command(seq=1, cmd="A" * 13, param="", auth="GCS")  # CMD= + 13 > 16
    with pytest.raises(ValueError):
        pack_command(seq=1, cmd="ARM", param="P" * 11, auth="GCS")  # PARAM= + 11 > 16
    with pytest.raises(ValueError):
        pack_command(seq=1, cmd="ARM", param="", auth="G" * 12)  # AUTH= + 12 > 16
    with pytest.raises(ValueError):
        unpack_command(b"short")  # not 64 bytes


def test_encrypt_roundtrip_all_four_configs():
    """Encrypt then decrypt works for ECB/CBC x AES-128/256, both packets."""
    telemetry = pack_telemetry(seq=1, lat=1000000, lon=2000000, alt_mm=5000,
                               battery_pct=50, speed_cm_s=100, armed=False)
    command = pack_command(seq=3, cmd="LAND", param="", auth="GCS")
    for key in (KEY128, KEY256):
        for msg in (telemetry, command):
            assert ecb_decrypt(key, ecb_encrypt(key, msg)) == msg
            assert cbc_decrypt(key, IV_A, cbc_encrypt(key, IV_A, msg)) == msg


def test_ecb_repeats_blocks_cbc_hides_them():
    """Three identical plaintext blocks: ECB repeats CT, CBC does not."""
    msg = b"ABCDEFGHIJKLMNOP" * 3  # 48 bytes, 3 identical blocks
    ct_ecb = ecb_encrypt(KEY128, msg)
    blocks = [ct_ecb[i:i + 16] for i in range(0, 48, 16)]
    assert blocks[0] == blocks[1] == blocks[2]  # ECB leaks the pattern
    ct_cbc = cbc_encrypt(KEY128, IV_A, msg)
    blocks = [ct_cbc[i:i + 16] for i in range(0, 48, 16)]
    assert not (blocks[0] == blocks[1] == blocks[2])  # CBC hides it


def test_same_message_twice_ecb_same_cbc_different():
    """Same message twice: ECB output identical, CBC (new IV) differs."""
    cmd = pack_command(seq=9, cmd="ARM", param="", auth="GCS")
    assert ecb_encrypt(KEY128, cmd) == ecb_encrypt(KEY128, cmd)
    wire1 = IV_A + cbc_encrypt(KEY128, IV_A, cmd)
    wire2 = IV_B + cbc_encrypt(KEY128, IV_B, cmd)
    assert wire1 != wire2
