"""Task 6 tests: dashboard Session outcomes + one HTTP smoke test.

Strategy: drive Session directly (no HTTP) through jammed-tail stories
(deliver ARM/GOTO/LAND/DISARM, then jam RTL + LAND so forgeries have a
fresh header). Every ACCEPTED/REJECTED asserted here comes from the real
drone_receive / secure_receive paths. Guided-demo rows are compared
against the Task-3/Task-4 runners (run live, never hard-coded).

Run:  python3 -m pytest tests/test_dashboard.py -v
"""
import inspect
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from dashboard.session import Session
from dashboard import server as server_mod
from attacks.ecb_cut_paste import (forge_wire, forge_wire_cbc, run_cut_paste,
                                   KEY128, KEY256)
from attacks.cbc_bitflip import (forge_iv_seq, forge_ct_block, run_bitflip)
from link.defense_demo import run_defense

KEY_HEXES = (KEY128.hex(), KEY256.hex())


def jammed_tail(session):
    """Delivered ARM/GOTO/LAND/DISARM, then jammed RTL + LAND (fresh head)."""
    for cmd in ("ARM", "GOTO", "LAND", "DISARM"):
        session.gcs_send(cmd)
    session.toggle_jam(True)
    session.gcs_send("RTL")
    session.gcs_send("LAND")
    return session


def test_ecb_splice_disarm_accepted_both_keys():
    """Forged (fresh-seq, DISARM) is obeyed under ECB-128 and ECB-256."""
    for bits in (128, 256):
        s = jammed_tail(Session("ecb", bits))
        entry = s.splice()
        assert entry["accepted"] is True, entry["reason"]
        assert s.matrix["ECB-%d:splice" % bits] == "SUCCESS"


def test_cbc_splice_rejected_ivflip_accepted():
    """Same splice dies under CBC; the IV rewrite of LAND passes."""
    s = jammed_tail(Session("cbc", 128))
    assert s.splice()["accepted"] is False
    assert s.matrix["CBC-128:splice"] == "FAILED"
    entry = s.iv_flip(2)  # delivered LAND: burst estimate is exact
    assert entry["accepted"] is True, entry["reason"]
    assert s.matrix["CBC-128:iv_flip"] == "SUCCESS"


def test_cbc_block_flip_land_accepts_goto_rejects():
    """Isolated fresh fixtures: garbage PARAM ignored for LAND only."""
    s = Session("cbc", 128)
    s.gcs_send("LAND")
    s.toggle_jam(True)
    s.gcs_send("LAND")  # jammed, seq 2 still fresh (drone saw 1)
    assert s.block_flip(1)["accepted"] is True
    s = Session("cbc", 128)
    s.gcs_send("GOTO")
    s.toggle_jam(True)
    s.gcs_send("GOTO")
    entry = s.block_flip(1)
    assert entry["accepted"] is False
    assert "PARAM" in entry["reason"]


def test_gcm_everything_rejected():
    """Replay, splice, nonce flip and block flip ALL fail under GCM."""
    for bits in (128, 256):
        s = jammed_tail(Session("gcm", bits))
        assert s.replay(0)["accepted"] is False  # stale seq
        assert s.splice()["accepted"] is False  # tag
        assert s.iv_flip(2)["accepted"] is False  # tag over nonce
        assert s.block_flip(4)["accepted"] is False  # tag first
        key = "GCM-%d" % bits
        assert s.matrix[key + ":replay"] == "FAILED"
        assert s.matrix[key + ":splice"] == "FAILED"
        assert s.matrix[key + ":iv_flip"] == "FAILED"
        assert s.matrix[key + ":block_flip"] == "FAILED"


def test_key_never_in_snapshot():
    """Neither demo key hex appears in any snapshot, all modes, with traffic."""
    for mode in ("ecb", "cbc", "gcm"):
        s = jammed_tail(Session(mode, 128))
        s.splice()
        blob = json.dumps(s.snapshot())
        for hx in KEY_HEXES:
            assert hx not in blob


def test_attacker_helpers_take_no_key():
    """Structural proof, same rule as Tasks 3-4: no key parameter."""
    for func in (forge_wire, forge_wire_cbc, forge_iv_seq, forge_ct_block):
        assert "key" not in inspect.signature(func).parameters


def test_fresh_session_starts_empty():
    """A new Session (mode switch / reset) clears recordings and drone."""
    s = jammed_tail(Session("ecb", 128))
    assert len(s.recordings) == 6
    fresh = Session("gcm", 256)
    assert fresh.recordings == [] and fresh.matrix == {}
    assert fresh.drone == {"armed": False, "altitude": 0, "crashed": False,
                           "last_cmd": None, "last_seq": None, "note": ""}
    assert fresh.seq_next == 1 and fresh.jam is False


def _guided_cells(mode, bits=128):
    """The client's guided-demo script, run through Session (forged row).

    Order matters and is honest: each forgery needs a seq fresher than
    everything obeyed so far, so block flip (seq 6) runs before splice
    (seq 7) runs before the IV rewrite (seq 17). Replay of seq 1 is stale
    everywhere by construction.
    """
    s = Session(mode, bits)
    for cmd in ("ARM", "GOTO", "LAND", "DISARM"):
        s.gcs_send(cmd)
    s.toggle_jam(True)
    s.gcs_send("RTL")
    s.gcs_send("LAND")
    s.gcs_send("GOTO")
    land = [i for i, r in enumerate(s.recordings) if r["cmd"] == "LAND"]
    s.block_flip(land[-1])  # jammed LAND, seq 6, still fresh
    s.splice()              # newest jammed header, seq 7
    if mode != "ecb":
        s.iv_flip(land[0])  # delivered LAND rewritten to seq 17
    s.replay(0)
    return dict(s.matrix)


def test_guided_row_matches_task3_matrix():
    """Dashboard ECB/CBC rows equal the Task-3 runners' live outcomes."""
    _, outcomes, _, cbc_out = run_cut_paste(KEY128)
    bit = run_bitflip(KEY128)
    ecb = _guided_cells("ecb")
    assert ecb["ECB-128:splice"] == ("SUCCESS" if outcomes["a"][1]
                                     else "FAILED")
    assert "ECB-128:iv_flip" not in ecb  # N/A stays blank, not FAILED
    assert ecb["ECB-128:block_flip"] == ("SUCCESS" if bit["b_ecb_land"][2]
                                         else "FAILED")
    assert ecb["ECB-128:replay"] == "FAILED"
    cbc = _guided_cells("cbc")
    assert cbc["CBC-128:splice"] == ("SUCCESS" if cbc_out[1] else "FAILED")
    assert cbc["CBC-128:iv_flip"] == ("SUCCESS" if bit["a"][2] else "FAILED")
    assert cbc["CBC-128:block_flip"] == ("SUCCESS" if bit["b_land"][2]
                                         else "FAILED")
    assert cbc["CBC-128:replay"] == "FAILED"


def test_guided_row_matches_task4_defense():
    """Dashboard GCM row equals link/defense_demo's live outcomes."""
    ref = run_defense(KEY128)  # control + six attacks, computed live
    assert ref["control"][1] is True
    gcm = _guided_cells("gcm")
    assert gcm["GCM-128:splice"] == ("SUCCESS" if ref["splice"][1]
                                     else "FAILED")
    assert gcm["GCM-128:iv_flip"] == ("SUCCESS" if ref["seq_rewrite"][1]
                                      else "FAILED")
    assert gcm["GCM-128:block_flip"] == ("SUCCESS" if ref["land_flip"][1]
                                         else "FAILED")
    assert gcm["GCM-128:replay"] == ("SUCCESS" if ref["replay"][1]
                                     else "FAILED")


def _post(port, path, body):
    """Minimal JSON POST helper (standard library only)."""
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
                                 data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return r.status, r.read().decode()


def test_http_smoke_ephemeral_port():
    """Real server on a throwaway port: page, API, mode switch, no key."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), server_mod.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/" % port) as r:
            assert r.status == 200
            assert "Drone Link Security Demo" in r.read().decode()
        status, body = _post(port, "/api/mode", {"mode": "cbc", "bits": 128})
        assert status == 200 and '"mode": "cbc"' in body
        status, body = _post(port, "/api/send", {"cmd": "ARM"})
        assert status == 200 and '"accepted": true' in body
        status, body = _post(port, "/api/replay", {"idx": 0})
        assert status == 200  # replay of the only (obeyed) wire: stale
        for hx in KEY_HEXES:
            assert hx not in body
    finally:
        server.shutdown()
        thread.join()
