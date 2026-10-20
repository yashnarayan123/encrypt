"""Task 3 tests: each attack's success/failure outcome per mode.

Every assertion is measured from a REAL run of the attack code (fixed
inputs where determinism matters; random IVs only where the outcome is
structural). Nothing here hard-codes ciphertext.

Run:  python3 -m pytest tests/test_attacks.py -v
"""
import inspect

from aes.modes import ecb_encrypt
from telemetry.packets import pack_command
from attacks.victim import reset_drone, decrypt, drone_receive, gcs_send
from attacks.ecb_image_leak import run_image_leak, distinct_blocks
from attacks.ecb_cut_paste import (
    run_cut_paste, forge_wire, forge_wire_cbc, KEY128, KEY256)
from attacks.cbc_bitflip import (
    run_bitflip, flip_bytes, forge_iv_seq, forge_ct_block)

ATTACKER_FUNCS = (forge_wire, forge_wire_cbc, flip_bytes,
                  forge_iv_seq, forge_ct_block)


def blocks(data):
    """Split bytes into 16-byte chunks."""
    return [data[i:i + 16] for i in range(0, len(data), 16)]


def test_image_ecb_leaks_cbc_hides():
    """ECB keeps ~plaintext block count (69 vs 68); CBC is all unique."""
    original, _, _, stats = run_image_leak()
    total = len(original.tobytes()) // 16 + 1  # 3072 pixel blocks + 1 pad
    assert stats["ecb128"] <= 2 * stats["plain"]
    assert stats["ecb256"] <= 2 * stats["plain"]
    assert stats["cbc128"] == total  # every CBC block unique
    assert stats["cbc256"] == total
    assert stats["ecb128"] * 10 < stats["cbc128"]  # ECB far fewer: leak


def test_ecb_cut_paste_accepted_both_keys():
    """All three ECB forgeries obeyed under AES-128 AND AES-256."""
    for key in (KEY128, KEY256):
        _, outcomes, _, _ = run_cut_paste(key)
        assert outcomes["a"][1]  # (15, DISARM)
        assert outcomes["a"][3]["cmd"] == "DISARM"
        assert outcomes["b"][1]  # (15, GOTO ALT:500)
        assert outcomes["b"][3]["param"] == "ALT:500"
        assert outcomes["c"][1]  # (15, LAND)
        assert outcomes["c"][3]["seq"] == 15


def test_cbc_same_splice_rejected():
    """The identical splice against CBC wires is rejected (both keys)."""
    for key in (KEY128, KEY256):
        _, _, _, cbc_outcome = run_cut_paste(key)
        _, accepted, _, parsed = cbc_outcome
        assert accepted is False
        assert parsed is None


def test_iv_flip_accepts_both_keys():
    """Forged seq 99 via IV flip is obeyed; only the IV changed."""
    for key in (KEY128, KEY256):
        res = run_bitflip(key)
        captured, forged, accepted, _, parsed = res["a"]
        assert accepted is True
        assert parsed["seq"] == 99
        assert captured[16:] == forged[16:]  # ciphertext untouched
        assert captured[:16] != forged[:16]  # IV is the only difference
        assert decrypt("cbc", key, forged)[:16].endswith(b"SEQ=0099")


def test_ct_flip_land_accepts_goto_rejects():
    """Garbage PARAM ignored for LAND, fatal for GOTO (both keys)."""
    for key in (KEY128, KEY256):
        res = run_bitflip(key)
        _, forged_land, accepted_land, _, _ = res["b_land"]
        _, forged_goto, accepted_goto, reason_goto, _ = res["b_goto"]
        assert accepted_land is True
        assert accepted_goto is False
        assert "PARAM" in reason_goto
        # Only M2 garbles; M0/M1 identical, M3 value field intact.
        pt_land = decrypt("cbc", key, forged_land)
        assert blocks(pt_land)[1] == b"CMD=LAND........"
        assert blocks(pt_land)[3][:8] == b"AUTH=GCS"


def test_attacker_code_touches_no_key():
    """Structural proof: attacker helpers take no key parameter at all."""
    for func in ATTACKER_FUNCS:
        assert "key" not in inspect.signature(func).parameters


def test_victim_rejects_forgeries_and_replays():
    """Drone rules sanity: bad AUTH, stale seq, unknown CMD all rejected."""
    reset_drone()
    wire = gcs_send("ecb", KEY128, 40, "LAND", "")[0]
    assert drone_receive("ecb", KEY128, wire)[0] is True
    assert drone_receive("ecb", KEY128, wire)[0] is False  # replay: stale
    reset_drone()
    bad_auth = ecb_encrypt(KEY128, pack_command(41, "LAND", "", "NONE"))
    assert drone_receive("ecb", KEY128, bad_auth)[0] is False
