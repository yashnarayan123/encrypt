# Demo script — 4-minute live talk track (drone link attack dashboard)

Run command (offline, localhost only):
  python3 -m dashboard
then open http://127.0.0.1:8077/ in any browser. No internet needed.

One-line conclusion to close with:
"ECB leaks, CBC hides but is malleable, GCM authenticates."

## 0:00 — Open with the image leak (IMAGE LEAK button)

Say: "Same AES key, same picture. Under ECB the drone silhouette survives
encryption -- I can literally see it. Under CBC it is pure noise. That is
because ECB encrypts equal blocks to equal blocks: 69 distinct blocks out
of 3072, versus all 3073 unique under CBC."

Click: IMAGE LEAK, point at the three panels, CLOSE.

## 0:45 — ECB guided demo (mode ECB-128 selected already)

Say: "I send four innocent commands, then jam the link -- the attacker
records but the drone hears nothing. Watch the red team: splice takes the
fresh header and a recorded DISARM block, and the drone obeys a DISARM the
ground station never sent."

Click: RUN GUIDED DEMO. Narrate each log line as it lands:
splice ACCEPTED, block flip ACCEPTED (garbage PARAM, LAND does not care),
replay REJECTED as stale seq. "The only thing that stops them is an old
sequence number."

## 1:45 — CBC guided demo (switch mode to CBC)

Say: "Same story, chained mode. Splicing now garbles exactly one block --
the command block -- so the drone rejects it. Chaining saves CBC here."

Click: RUN GUIDED DEMO. Point out: splice FAILED with a garbled CMD block,
but IV FLIP is ACCEPTED -- "I rewrote the sequence number in the IV, so a
stale message looks fresh, and every later block is untouched." Block flip
on LAND is ACCEPTED -- "the garbage lands in PARAM, which LAND ignores" --
"and the same flip on GOTO would die on PARAM."

## 2:45 — GCM guided demo (switch mode to GCM)

Say: "Now the defended link: every wire carries a 16-byte authentication
tag that covers the header and the ciphertext, checked before any parsing."

Click: RUN GUIDED DEMO. Every attack reads "tag check failed". "The parser
is exactly as lenient as before -- it never even sees the garbage, because
the tag dies first. Replay of an untampered wire is the only one that gets
past crypto, and the sequence rule catches it as stale."

## 3:30 — Matrix and close

Say: "The matrix filled itself from real receiver verdicts -- nothing here
is staged. Read the GCM column: FAILED, FAILED, FAILED, FAILED. And key
length changed nothing anywhere: every attack behaves identically under
AES-128 and AES-256. So: ECB leaks, CBC hides but is malleable,
GCM authenticates."

## If something breaks (checklist)

- "Cannot reach the server API": the server is not running -- rerun
  `python3 -m dashboard` in the project directory, keep that terminal open.
- Port busy (`Address already in use`): an old server is still running --
  `pkill -f "python3 -m dashboard"`, then start again. Tests use throwaway
  ports and never clash.
- Guided demo frozen mid-run: only one run at a time is allowed; press
  RESET (fresh drone, recordings cleared) and click RUN GUIDED DEMO again.
- SPLICE disabled with a hint: no obeyed DISARM observed yet -- with JAM
  off, send DISARM once (drone must obey it), then jam and continue.
- REPLAY/IV FLIP/BLOCK FLIP disabled: select a recording row first.
- ECB + IV FLIP: intentionally unavailable (ECB has no IV); the matrix cell
  stays blank, which is different from a rejected attack.
- After RESET or mode/key change the session is fresh: recordings, log and
  drone state clear, matrix blanks for that row only (other rows persist).
- Projector too dim: the page is a light theme already; raise browser zoom
  to 125% -- layout stacks without horizontal scroll.
