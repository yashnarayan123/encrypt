# Project: AES on a hostile drone telemetry link (Cryptography course, 35 marks)

## Teacher's requirements (everything must map to these)
1. Working cryptographic model (AES, implemented from scratch)
2. Demonstrate encryption/decryption with sample inputs and outputs
3. Analyze performance (speed, key size sensitivity) and security
4. Compare ECB vs CBC, and AES-128 vs AES-256, to show real-world impact

## Rules for the agent
- Student must be able to explain every line in a viva. Write clear, commented
  code. No clever one-liners, no unexplained magic numbers.
- Standard library only inside aes/. The `cryptography` package is allowed
  only for cross-checking in tests and for the GCM "fix" in link/.
- Work on ONE task at a time. Stop after each task, show real test output,
  and wait for approval.
- If a test fails, explain why before fixing it.
- Save all demo outputs, graphs and logs into results/ with clear filenames.
- Never fake or hard-code results. Everything shown must come from real runs.

## Task status
- [x] TASK 1 (aes/): finished and tested — 15 tests pass
  (FIPS-197, key schedule, NIST SP 800-38A, 1000-vector cross-check).
- [x] TASK 2 (telemetry/): finished and tested — telemetry/packets.py,
  telemetry/demo_encrypt.py, tests/test_telemetry.py; full suite
  (Task 1 + Task 2) passes 23/23; demo output saved in
  results/task2_demo.txt (real run, 8x ROUNDTRIP OK, 0 FAILED).
- [x] TASK 3 (attacks/): finished and tested — attacks/victim.py,
  attacks/ecb_image_leak.py, attacks/ecb_cut_paste.py,
  attacks/cbc_bitflip.py, attacks/summary.py, tests/test_attacks.py;
  full suite (Tasks 1+2+3) passes 30/30; artefacts saved in results/
  (img_original/ecb/cbc/comparison.png, task3_ecb_cutpaste.txt,
  task3_cbc_bitflip.txt, task3_matrix.txt). aes/ and telemetry/
  untouched.
- [x] TASK 4 (link/): finished and tested — from-scratch AES-GCM
  (link/gcm.py), defended wire (link/secure_link.py), re-run of all
  Task-3 attacks (link/defense_demo.py), tests/test_link.py; full suite
  (Tasks 1+2+3+4) passes 49/49; artefacts saved in results/
  (task4_defense_log.txt, task4_defense_matrix.txt). aes/, telemetry/
  and attacks/ untouched.
- [x] TASK 5 (benchmark/): finished and tested — honest timer
  (benchmark/timing.py), speed + key-size ratios (benchmark/speed.py),
  wire overhead (benchmark/overhead.py), avalanche diffusion
  (benchmark/avalanche.py), graphs + summary (benchmark/report.py),
  tests/test_benchmark.py; full suite (Tasks 1-5) passes 55/55;
  artefacts saved in results/ (task5_speed.csv, task5_throughput.png,
  task5_time_vs_size.png, task5_slowdown.png, task5_overhead.png,
  task5_avalanche.png, task5_summary.txt). aes/, telemetry/, attacks/
  and link/ untouched.
- [x] TASK 6 (dashboard/): finished and tested — live three-panel attack
  dashboard (dashboard/session.py, dashboard/server.py + __main__.py on
  127.0.0.1:8077, dashboard/static/index.html light-theme UI with image-
  leak modal), tests/test_dashboard.py, docs/DEMO_SCRIPT.md (4-minute talk
  track); full suite (Tasks 1-6) passes 65/65; run with
  `python3 -m dashboard`. aes/, telemetry/, attacks/, link/ and
  benchmark/ untouched. No screenshot: no headless browser available.
