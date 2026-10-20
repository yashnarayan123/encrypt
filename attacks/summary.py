"""Task 3 summary: re-run every attack and print the ATTACK MATRIX.

Each cell is computed from a REAL run made right here (no hard-coded
outcomes): cell = attacker outcome, SUCCESS = the attacker got what it
wanted, FAILED = the mode resisted, N/A = attack does not apply (ECB has
no IV to flip). The table is printed and saved to
results/task3_matrix.txt. The image PNGs are regenerated too.

Run:  python3 -m attacks.summary
"""

from attacks.ecb_image_leak import run_image_leak, save_results
from attacks.ecb_cut_paste import run_cut_paste, KEY128, KEY256
from attacks.cbc_bitflip import run_bitflip

LINES = []


def emit(text=""):
    """Print one line AND remember it for the results file."""
    print(text)
    LINES.append(text)


def leak_ok(distinct_ct, distinct_pt):
    """Pattern leak counts as attacker SUCCESS iff the ciphertext keeps
    about the plaintext's block count (ECB: 69 vs 68 plain). CBC gives
    ~every block unique (3073/3073), so this is False there."""
    return distinct_ct <= 2 * distinct_pt


def main():
    """Compute every cell from live runs, print + save the matrix."""
    # Image attack (plaintext is key-independent; stats cover both keys).
    original, ecb_img, cbc_img, stats = run_image_leak()
    save_results(original, ecb_img, cbc_img)
    plain = stats["plain"]
    # Cut-paste + bit-flips under each key size (real runs, both modes).
    per_key = {}
    for key, bits in ((KEY128, 128), (KEY256, 256)):
        _, outcomes, _, cbc_outcome = run_cut_paste(key)
        res = run_bitflip(key)
        per_key[bits] = {
            "cut_ecb": all(outcomes[n][1] for n in ("a", "b", "c")),
            "cut_cbc": bool(cbc_outcome[1]),
            "iv": bool(res["a"][2]),
            "blk_cbc": bool(res["b_land"][2]),
            "blk_ecb": bool(res["b_ecb_land"][2]),
        }
    emit("=" * 72)
    emit("TASK 3 ATTACK MATRIX (attacker outcome, computed from live runs)")
    emit("Evidence: distinct-block counts below; full attack transcripts in")
    emit("results/task3_ecb_cutpaste.txt and results/task3_cbc_bitflip.txt.")
    emit("=" * 72)
    emit("Mode     | pattern leak | cut-and-paste | IV flip | block flip")
    emit("---------+--------------+---------------+---------+-------------")
    rows = [
        ("ECB-128", leak_ok(stats["ecb128"], plain),
         per_key[128]["cut_ecb"], None, per_key[128]["blk_ecb"]),
        ("ECB-256", leak_ok(stats["ecb256"], plain),
         per_key[256]["cut_ecb"], None, per_key[256]["blk_ecb"]),
        ("CBC-128", leak_ok(stats["cbc128"], plain),
         per_key[128]["cut_cbc"], per_key[128]["iv"], per_key[128]["blk_cbc"]),
        ("CBC-256", leak_ok(stats["cbc256"], plain),
         per_key[256]["cut_cbc"], per_key[256]["iv"], per_key[256]["blk_cbc"]),
    ]
    for mode, leak, cut, iv, blk in rows:
        cells = [mode.ljust(8),
                 ("SUCCESS" if leak else "FAILED").ljust(12),
                 ("SUCCESS" if cut else "FAILED").ljust(13),
                 ("N/A (no IV)" if iv is None
                  else ("SUCCESS" if iv else "FAILED")).ljust(7),
                 ("SUCCESS" if blk else "FAILED")]
        emit(" | ".join(cells))
    emit("=" * 72)
    emit("Distinct 16-byte blocks: plain=%d ecb128=%d ecb256=%d cbc128=%d "
         "cbc256=%d" % (plain, stats["ecb128"], stats["ecb256"],
                        stats["cbc128"], stats["cbc256"]))
    emit("Reading: ECB leaks patterns and accepts splices at BOTH key")
    emit("sizes (longer key fixes nothing); CBC hides patterns and kills")
    emit("splices, but stays malleable (IV flip) and forgiving of garbage")
    emit("in ignored fields (LAND block flip). Fix = authentication.")
    with open("results/task3_matrix.txt", "w") as f:
        f.write("\n".join(LINES) + "\n")
    print("Matrix saved to results/task3_matrix.txt")


if __name__ == "__main__":
    main()
