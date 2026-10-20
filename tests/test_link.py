"""Task 4 tests: our from-scratch AES-GCM is correct and tamper-proof.

Sources of truth (implementation uses ONLY our aes package; the
`cryptography` library appears here solely as an independent reference):
  * Known answers: Test Cases 1-4 (AES-128) and 13-16 (AES-256) from
    McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)",
    Appendix B (inputs below are the published values; they cover empty
    plaintext, block-aligned and partial-block messages, and AAD).
  * Random cross-checks vs the reference library (many lengths, both keys).
  * Tamper checks: flipping ANY single bit of ct/tag/nonce/aad fails.

Run:  python3 -m pytest tests/test_link.py -v
"""
import random

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from link.gcm import gcm_encrypt, gcm_decrypt, ghash, AuthenticationError
from link.secure_link import (
    reset_secure_link, secure_send, secure_receive, _claim_nonce,
    WIRE_LEN)
from link.defense_demo import (
    run_defense, image_gcm_count, nonce_reuse_demo, ATTACKER_FUNCS)

KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
KEY256 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f")

# Published vectors: (name, key, nonce, plaintext, aad, out=ct||tag).
# Cases 1/13 have empty plaintext; cases 4/16 carry 20 bytes of AAD.
VECTORS = [
    ("128-c1", "00" * 16, "00" * 12, "", "",
     "58E2FCCEFA7E3061367F1D57A4E7455A"),
    ("128-c2", "00" * 16, "00" * 12, "00" * 16, "",
     "0388DACE60B6A392F328C2B971B2FE78AB6E47D42CEC13BDF53A67B21257BDDF"),
    ("128-c3", "FEFFE9928665731C6D6A8F9467308308",
     "CAFEBABEFACEDBADDECAF888",
     "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A72"
     "1C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255",
     "",
     "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E"
     "21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F5985"
     "4D5C2AF327CD64A62CF35ABD2BA6FAB4"),
    ("128-c4", "FEFFE9928665731C6D6A8F9467308308",
     "CAFEBABEFACEDBADDECAF888",
     "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A72"
     "1C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39",
     "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
     "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E"
     "21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091"
     "5BC94FBC3221A5DB94FAE95AE7121A47"),
    ("256-c13", "00" * 32, "00" * 12, "", "",
     "530F8AFBC74536B9A963B4F1C4CB738B"),
    ("256-c14", "00" * 32, "00" * 12, "00" * 16, "",
     "CEA7403D4D606B6E074EC5D3BAF39D18D0D1C8A799996BF0265B98B5D48AB919"),
    ("256-c15", "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308",
     "CAFEBABEFACEDBADDECAF888",
     "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A72"
     "1C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255",
     "",
     "522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA"
     "8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015AD"
     "B094DAC5D93471BDEC1A502270E3CC6C"),
    ("256-c16", "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308",
     "CAFEBABEFACEDBADDECAF888",
     "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A72"
     "1C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39",
     "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
     "522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA"
     "8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F66276FC6ECE"
     "0F4E1768CDDF8853BB2D551B"),
]


def test_ghash_empty_is_zero():
    """GHASH over empty AAD + empty CT is 0 (only the zero length block)."""
    assert ghash(bytes(16), b"", b"") == bytes(16)


@pytest.mark.parametrize("name,key,nonce,pt,aad,out", VECTORS)
def test_published_vectors(name, key, nonce, pt, aad, out):
    """Our GCM reproduces the published McGrew-Viega outputs exactly."""
    key_b, nonce_b = bytes.fromhex(key), bytes.fromhex(nonce)
    pt_b, aad_b = bytes.fromhex(pt), bytes.fromhex(aad)
    ct, tag = gcm_encrypt(key_b, nonce_b, pt_b, aad_b)
    assert (ct + tag).hex().upper() == out
    # And our decrypt accepts the published pair back to the plaintext.
    assert gcm_decrypt(key_b, nonce_b, ct, aad_b, tag) == pt_b


def test_crosscheck_library_many_lengths():
    """Random keys/nonces/AAD/messages match the reference library."""
    rng = random.Random(7)  # fixed seed: deterministic demo
    for trial in range(40):
        klen = 16 if trial % 2 == 0 else 32
        key = bytes(rng.randrange(256) for _ in range(klen))
        nonce = bytes(rng.randrange(256) for _ in range(12))
        plen = [0, 1, 15, 16, 17, 64, 1000][trial % 7]
        alen = [0, 5, 16, 20][trial % 4]
        pt = bytes(rng.randrange(256) for _ in range(plen))
        aad = bytes(rng.randrange(256) for _ in range(alen))
        my_ct, my_tag = gcm_encrypt(key, nonce, pt, aad)
        lib = AESGCM(key).encrypt(nonce, pt, aad if aad else None)
        assert (my_ct, my_tag) == (lib[:-16], lib[-16:])
        # Both directions decrypt: lib reads ours, ours reads lib's.
        assert AESGCM(key).decrypt(nonce, my_ct + my_tag,
                                   aad if aad else None) == pt
        assert gcm_decrypt(key, nonce, lib[:-16], aad, lib[-16:]) == pt


def _flip(data, bit):
    """Copy of data with one bit toggled (tamper primitive)."""
    data = bytearray(data)
    data[bit // 8] ^= 1 << (bit % 8)
    return bytes(data)


def test_tamper_any_single_bit_fails():
    """Flipping ANY one bit of ct/tag/nonce/aad -> AuthenticationError."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    nonce = bytes.fromhex("000102030405060708090a0b")  # 12-byte GCM nonce
    pt = b"LAND this drone now, seq 30!!!"  # 30 bytes: spans 2 CTR blocks
    aad = b"DRONE01|SEQ=0030"               # 16 bytes of header
    ct, tag = gcm_encrypt(key, nonce, pt, aad)
    assert gcm_decrypt(key, nonce, ct, aad, tag) == pt  # sanity: valid ok
    checked = 0
    for label, blob, flip in (("ct", ct, lambda b: (b, aad, nonce, tag)),
                              ("aad", aad, lambda b: (ct, b, nonce, tag)),
                              ("nonce", nonce, lambda b: (ct, aad, b, tag)),
                              ("tag", tag, lambda b: (ct, aad, nonce, b))):
        for bit in range(8 * len(blob)):
            bad = _flip(blob, bit)
            args = flip(bad)
            with pytest.raises(AuthenticationError):
                gcm_decrypt(key, args[2], args[0], args[1], args[3])
            checked += 1
    # Count from the real buffers so the "every bit" claim is checkable.
    assert checked == 8 * (len(ct) + len(aad) + len(nonce) + len(tag))
    # Wrong-length tag is rejected too (not just wrong bytes).
    with pytest.raises(AuthenticationError):
        gcm_decrypt(key, nonce, ct, aad, tag[:12])


# ---------------- Stage 3/4: defended link + attack outcomes ----------------

def test_secure_link_roundtrip_both_keys():
    """Legit GCS mail is obeyed under AES-128 and AES-256 (92-byte wire)."""
    for key in (KEY128, KEY256):
        reset_secure_link()
        wire, plain = secure_send(key, 11, "GOTO", "ALT:30")
        assert len(wire) == WIRE_LEN == 92 and len(plain) == 64
        accepted, _, parsed = secure_receive(key, wire)
        assert accepted is True
        assert parsed == {"seq": 11, "cmd": "GOTO", "param": "ALT:30",
                          "auth": "GCS"}


def test_secure_link_tamper_each_region_rejected():
    """One flipped byte in nonce/header/ct/tag each -> rejected."""
    reset_secure_link()
    wire, _ = secure_send(KEY128, 11, "LAND", "")
    for offset, name in ((0, "nonce"), (12, "header"),
                         (12 + 16, "ciphertext"), (12 + 16 + 48, "tag")):
        bad = bytearray(wire)
        bad[offset] ^= 0x01
        accepted, reason, _ = secure_receive(KEY128, bytes(bad))
        assert accepted is False, name
        assert "tag check failed" in reason, name


def test_secure_link_replay_rejected():
    """Untampered replay of an obeyed seq is rejected as stale."""
    reset_secure_link()
    old, _ = secure_send(KEY128, 11, "GOTO", "ALT:30")
    new, _ = secure_send(KEY128, 12, "LAND", "")
    assert secure_receive(KEY128, old)[0] is True
    assert secure_receive(KEY128, new)[0] is True
    accepted, reason, _ = secure_receive(KEY128, old)
    assert accepted is False
    assert "stale" in reason


def test_secure_link_nonce_guard():
    """The sender refuses to reuse a (key, nonce) pair."""
    reset_secure_link()
    _claim_nonce(KEY128, b"N" * 12)
    with pytest.raises(RuntimeError):
        _claim_nonce(KEY128, b"N" * 12)


def test_defense_every_attack_fails():
    """Full Task-3 playbook vs GCM: control passes, all six attacks fail."""
    for key in (KEY128, KEY256):
        res = run_defense(key)
        assert res["control"][1] is True  # setup sane
        for name in ("splice", "seq_rewrite", "nonce_flip", "land_flip",
                     "replay", "truncated", "extended"):
            assert res[name][1] is False, name
        assert "stale" in res["replay"][2]  # replay dies on seq, not tag
        assert "tag check failed" in res["land_flip"][2]


def test_defense_image_gcm_like_cbc():
    """GCM ciphertext blocks ~all unique (3072/3072), nothing like ECB."""
    plain_n, gcm_n, total = image_gcm_count()
    assert gcm_n == total         # every block unique: no pattern to leak
    assert gcm_n > 10 * plain_n   # ECB keeps ~plain count (69 vs 68)


def test_defense_attacker_touches_no_key():
    """Structural proof: GCM attacker helpers take no key parameter."""
    import inspect
    for func in ATTACKER_FUNCS:
        assert "key" not in inspect.signature(func).parameters


def test_nonce_reuse_leaks_plaintext_xor():
    """BONUS, measured: same nonce twice -> CT1^CT2 = PT1^PT2, PT2 falls."""
    assert nonce_reuse_demo() == (True, True)
