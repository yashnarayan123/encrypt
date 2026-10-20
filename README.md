# encrypt

AES on a hostile drone telemetry link — a cryptography course project that
builds AES from scratch, attacks a drone command link, then defends it.

Same AES key, three modes, one drone link. The project shows *why mode choice
matters*: ECB leaks structure, CBC hides it but stays malleable, AES-GCM
authenticates. Conclusion: **ECB leaks, CBC hides but is malleable, GCM
authenticates.**

## What is inside

| Folder | What it does |
| --- | --- |
| `aes/` | AES-128/256 implemented from scratch (standard library only): key schedule, rounds, ECB/CBC modes. |
| `telemetry/` | Packs drone commands into fixed 16-byte blocks and round-trips them. |
| `attacks/` | The hostile link: ECB image leak, ECB cut-and-paste, CBC bit-flipping, replay/sequence attacks. |
| `link/` | The fix: from-scratch AES-GCM (`gcm.py`) plus the defended wire (`secure_link.py`) and a re-run of every attack. |
| `benchmark/` | Speed, key-size sensitivity, wire overhead and avalanche diffusion. |
| `dashboard/` | Offline three-panel live demo: GCS, attacker, drone, driven by the real code above. |
| `tests/`, `aes/tests/` | 65 tests, including NIST vectors and a 1000-vector cross-check. |
| `results/` | Real run outputs: logs, matrices, graphs, image-leak comparison. |
| `docs/` | `DEMO_SCRIPT.md`, the 4-minute live talk track. |
| `Project.md` | Task-by-task status, requirements and rules. |
| `ARCHITECTURE.md` | Design notes. |

## Run it

Requires Python 3 (standard library plus `cryptography` and `matplotlib`
for tests/plots only).

```sh
# full test suite (Tasks 1-6)
python3 -m pytest tests aes/tests -q

# the live dashboard (offline, localhost only)
python3 -m dashboard
# then open http://127.0.0.1:8077/
```

The dashboard is intentionally offline: no CDNs, no external fonts, no
network access. Attack verdicts come from the real receiver code, never from
hard-coded values.

## Key idea

- **ECB** encrypts equal plaintext blocks to equal ciphertext blocks, so the
  drone silhouette survives encryption (69 distinct blocks out of 3072 vs all
  3073 unique under CBC) and block splicing works.
- **CBC** hides patterns, but an attacker can still rewrite the IV sequence
  number or flip ciphertext bits; the receiver has no way to detect it.
- **AES-GCM** adds a 16-byte authentication tag over header and ciphertext,
  checked before parsing — every tampering attempt fails the tag.
- Key length (AES-128 vs AES-256) changes nothing about the attack outcomes.
