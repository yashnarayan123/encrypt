"""Task 5 tests: timer sanity, table shapes, formulas, avalanche band.

Kept TINY on purpose (64-byte messages, 2 avalanche blocks) so this file
runs in a few seconds. It checks STRUCTURE and known formulas -- the real
numbers live in results/task5_*, produced by benchmark/report.py.

Run:  python3 -m pytest tests/test_benchmark.py -v
"""
import csv
import os

from benchmark.timing import measure, repeats_for, machine_info
from benchmark.speed import run_speed, slowdown, save_csv
from benchmark.overhead import run_overhead
from benchmark.avalanche import run_avalanche, round_growth, SEED
from benchmark import report as report_mod


def test_timer_is_sane():
    """Samples kept, median >= min >= 0, stdev non-negative, machine known."""
    stats = measure(lambda: None, 5)
    assert len(stats["samples"]) == 5
    assert stats["median_ms"] >= stats["min_ms"] >= 0.0
    assert stats["stdev_ms"] >= 0.0
    assert set(machine_info()) == {"machine", "os", "cpu", "python"}
    assert (repeats_for(64), repeats_for(1024), repeats_for(16 * 1024),
            repeats_for(64 * 1024), repeats_for(256 * 1024)) == (200, 30,
                                                                 5, 3, 2)


def test_speed_table_covers_all_combos():
    """Every mode x key-size x op row exists; throughput matches time."""
    rows = run_speed(sizes=[64])
    combos = {(r["mode"], r["bits"], r["op"]) for r in rows}
    for mode in ("ECB", "CBC", "GCM"):
        for bits in (128, 256):
            assert (mode, bits, "encrypt") in combos
            assert (mode, bits, "decrypt") in combos
    for r in rows:
        if r["mode"] in ("ECB", "CBC", "GCM", "REF"):
            expect = (r["size_bytes"] / 1024) / (r["median_ms"] / 1000.0)
            assert abs(r["kbps"] - expect) / expect < 1e-9
    ratios = slowdown(rows, op="encrypt", size=64)
    assert set(ratios) == {"ECB", "CBC", "GCM"}
    assert all(v > 1.0 for v in ratios.values())  # 256-bit always slower


def test_save_csv_writes_header(tmp_path):
    """CSV has the documented columns plus one row per input row."""
    rows = run_speed(sizes=[64])
    path = str(tmp_path / "speed.csv")
    save_csv(rows, path)
    with open(path) as f:
        reader = list(csv.DictReader(f))
    assert reader and len(reader) == len(rows)
    assert "kbps" in reader[0]


def test_overhead_matches_known_formulas():
    """Real wires: ECB 80, CBC 96, GCM 92 bytes for the 64-byte command."""
    over = run_overhead()
    assert over["plain_bytes"] == 64
    assert over["ECB"]["wire_bytes"] == 80    # +16 PKCS#7 block
    assert over["CBC"]["wire_bytes"] == 96    # +16 IV +16 pad
    assert over["GCM"]["wire_bytes"] == 92    # +12 nonce +16 tag
    assert over["ECB"]["overhead_pct"] == 25.0
    assert over["CBC"]["overhead_pct"] == 50.0
    assert over["GCM"]["overhead_pct"] == 43.75


def test_avalanche_sits_near_half():
    """Mean changed share in 45-55% for pt and key flips, both key sizes."""
    out = run_avalanche(nblocks=2, seed=SEED)
    assert out["seed"] == SEED
    for key_len in (16, 32):
        for what in ("pt", "key"):
            assert 0.45 < out[key_len][what]["share"] < 0.55
    assert len(out["rounds"][16]) == 11  # 10 rounds + initial stage
    assert len(out["rounds"][32]) == 15  # 14 rounds + initial stage
    assert out["rounds"][16][-1] > 50  # diffusion saturates by the end
    assert round_growth(16)[0] <= 2  # one flipped bit barely spreads pre-mix


def test_report_plots_and_summary_created(tmp_path):
    """Every plotter + the summary writer produce real files."""
    rows = run_speed(sizes=[64])
    over = run_overhead()
    aval = run_avalanche(nblocks=2, seed=SEED)
    info = machine_info()
    paths = {
        "throughput": str(tmp_path / "t.png"),
        "vssize": str(tmp_path / "v.png"),
        "slowdown": str(tmp_path / "s.png"),
        "overhead": str(tmp_path / "o.png"),
        "avalanche": str(tmp_path / "a.png"),
        "summary": str(tmp_path / "summary.txt"),
    }
    report_mod.plot_throughput(rows, paths["throughput"], size=64)
    report_mod.plot_time_vs_size(rows, paths["vssize"])
    report_mod.plot_slowdown(rows, paths["slowdown"], size=64)
    report_mod.plot_overhead(over, paths["overhead"])
    report_mod.plot_avalanche(aval, paths["avalanche"])
    report_mod.write_summary(paths["summary"], info, rows, over, aval,
                             [64], 0.0)
    for path in paths.values():
        assert os.path.getsize(path) > 0
    with open(paths["summary"]) as f:
        assert "TASK 5 SUMMARY" in f.read()
