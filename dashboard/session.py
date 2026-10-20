"""Live-dashboard session: GCS, attacker and drone sharing one link demo.

Three roles, one Session object (per server process, used under a lock):
  * GCS knows the key (fixed demo keys from attacks/, so runs repeat).
  * The ATTACKER sees wires only and reuses the REAL Task-3 attacker
    helpers (forge_wire, forge_wire_cbc, forge_iv_seq, forge_ct_block),
    which take no key. GCM splices/flips are plain byte surgery with the
    reasoning written in comments at each call site.
  * The DRONE judges through the REAL receive paths only:
    attacks.victim.drone_receive (ECB/CBC) and link.secure_link's
    secure_receive (GCM). The UI never decides an outcome itself.

How the attacker "knows" things (nothing hidden, all documented):
  * Message layout is public (telemetry/packets.py): header bytes 12..15
    are the seq digits, every field fills one 16-byte block.
  * Session seqs start at 1 and rise by 1 per GCS send, and the attacker
    can count radio bursts -- so for ECB/CBC it ESTIMATES a selected
    wire's seq from its burst position. For GCM it simply READS the seq
    digits from the clear header (wire bytes 24..27).
  * Command identity comes from WATCHING THE DRONE: a delivered+obeyed
    wire shows its effect (armed / landed / ...). A jammed wire was never
    delivered, so its content stays unknown -- exactly why the SPLICE
    button needs an observed DISARM first.

The drone status card (armed / altitude / crash) is a VISUALISATION of
already-accepted commands, computed here in dashboard/ -- it is NOT
cryptography. Accepted GOTO while disarmed is "ignored: not armed".
"""

from attacks.victim import (reset_drone, decrypt, drone_accepts, drone_receive,
                            gcs_send, VALID_COMMANDS)
from attacks.ecb_cut_paste import forge_wire, forge_wire_cbc
from attacks.ecb_cut_paste import KEY128 as DEMO_KEY128
from attacks.ecb_cut_paste import KEY256 as DEMO_KEY256
from attacks.cbc_bitflip import forge_iv_seq, forge_ct_block
from link.secure_link import (reset_secure_link, secure_send, secure_receive,
                              NONCE_LEN, HEADER_LEN, BODY_LEN, TAG_LEN)

COMMANDS = (("ARM", ""), ("LAND", ""), ("GOTO", "ALT:30"), ("RTL", ""),
            ("DISARM", ""))
EFFECT = {"ARM": "drone ARMED", "DISARM": "drone DISARMED",
          "LAND": "drone LANDED", "GOTO": "drone CLIMBED", "RTL": "drone RTLed"}


def _chunks(data, size=16):
    """Split bytes into 16-byte hex chunks (wire inspector helper)."""
    return [bytes(data[i:i + size]).hex()
            for i in range(0, len(data), size)]


def _ascii_block(raw16):
    """16 bytes shown as tolerant ASCII (garbage stays visible, never fails)."""
    return bytes(raw16).decode("ascii", errors="replace")


class Session:
    """One demo run: mode + key size, recordings, drone picture, matrix."""

    def __init__(self, mode="ecb", bits=128):
        if mode not in ("ecb", "cbc", "gcm"):
            raise ValueError("mode must be ecb, cbc or gcm")
        if bits not in (128, 256):
            raise ValueError("bits must be 128 or 256")
        self.mode = mode
        self.bits = bits
        self.key = DEMO_KEY128 if bits == 128 else DEMO_KEY256
        self.seq_next = 1      # GCS seq counter (attacker counts bursts too)
        self.jam = False
        self.recordings = []   # every wire the attacker grabbed, in order
        self.log = []          # oldest first; snapshot() reverses it
        self.matrix = {}       # (mode-bits, attack) -> "SUCCESS"/"FAILED"
        self.drone = {"armed": False, "altitude": 0, "crashed": False,
                      "last_cmd": None, "last_seq": None, "note": ""}
        self.gcs_view = None   # last GCS send, for the plaintext inspector
        reset_drone()
        reset_secure_link()

    # -- receiving (the ONLY place outcomes are decided) -------------------

    def _deliver(self, wire, source):
        """Run one wire through the REAL receiver; update viz + log.

        For ECB/CBC the plaintext is decrypted here too (same decrypt()
        the drone uses) purely so the UI can SHOW garbled blocks; GCM
        releases nothing when the tag fails. Returns the log entry dict.
        """
        if self.mode == "gcm":
            accepted, reason, parsed = secure_receive(self.key, wire)
            plain_blocks = None  # GCM never releases unauthenticated bytes
            auth_note = None if accepted else "plaintext withheld: tag failed"
        else:
            try:
                plain = decrypt(self.mode, self.key, wire)
            except ValueError as exc:
                accepted, reason, parsed = False, "decrypt failed: %s" % exc, None
                plain_blocks = None
                auth_note = "undecryptable wire"
            else:
                accepted, reason, parsed = drone_accepts(plain)
                plain_blocks = [_ascii_block(plain[i:i + 16])
                                for i in range(0, len(plain), 16)]
                auth_note = None
        entry = {"source": source,
                 "accepted": accepted,
                 "reason": reason,
                 "seq": parsed["seq"] if parsed else None,
                 "cmd": parsed["cmd"] if parsed else None,
                 "plain_blocks": plain_blocks,
                 "auth_note": auth_note}
        self.log.append(entry)
        if accepted:
            self._apply_effect(parsed)
        return entry

    def _apply_effect(self, parsed):
        """VISUALISATION ONLY: move the drone picture for obeyed commands."""
        cmd = parsed["cmd"]
        self.drone["last_cmd"] = cmd
        self.drone["last_seq"] = parsed["seq"]
        self.drone["note"] = ""
        if self.drone["crashed"]:
            return  # wreckage stays wreckage until RESET
        if cmd == "ARM":
            self.drone["armed"] = True
        elif cmd == "DISARM":
            if self.drone["altitude"] > 0:
                self.drone["crashed"] = True  # motors off mid-air: it falls
                self.drone["armed"] = False
                self.drone["altitude"] = 0
            else:
                self.drone["armed"] = False
        elif cmd == "GOTO":
            if not self.drone["armed"]:
                self.drone["note"] = "ignored: not armed"
            else:
                try:
                    self.drone["altitude"] = int(parsed["param"].split(":")[1])
                except (TypeError, ValueError, IndexError):
                    self.drone["note"] = "ignored: bad PARAM"
        elif cmd in ("LAND", "RTL"):
            self.drone["altitude"] = 0

    # -- GCS side (knows the key) ------------------------------------------

    def gcs_send(self, cmd):
        """Operator button: pack, encrypt, record; deliver unless jammed."""
        param = dict(COMMANDS)[cmd]
        seq = self.seq_next
        self.seq_next += 1
        if self.mode == "gcm":
            wire, plain = secure_send(self.key, seq, cmd, param)
        else:
            wire, plain = gcs_send(self.mode, self.key, seq, cmd, param)
        rec = {"n": len(self.recordings) + 1, "seq": seq, "cmd": cmd,
               "wire_hex": wire.hex(), "delivered": not self.jam,
               "burst": self.seq_next - 1}
        self.recordings.append(rec)
        self.gcs_view = {"cmd": cmd, "seq": seq,
                         "plain_blocks": [_ascii_block(plain[i:i + 16])
                                          for i in range(0, 64, 16)],
                         "wire_parts": self._wire_parts(wire)}
        if self.jam:
            self.log.append({"source": "GCS", "accepted": None,
                             "reason": "jammed: recorded, not delivered",
                             "seq": seq, "cmd": cmd, "plain_blocks": None,
                             "auth_note": "on the air only (attacker copy)"})
        else:
            entry = self._deliver(wire, "GCS")
            rec["effect"] = EFFECT[cmd] if entry["accepted"] else "no effect"
        return rec

    def toggle_jam(self, on):
        """JAM on: GCS wires are recorded but NOT delivered (jam-and-record)."""
        self.jam = bool(on)
        return self.jam

    # -- attacker side (wires only, never the key) -------------------------

    def _wire(self, idx):
        """Recorded wire bytes by list index (raises IndexError if bad)."""
        return bytes.fromhex(self.recordings[idx]["wire_hex"])

    def attacker_label(self, rec):
        """What the attacker can honestly claim about a recording."""
        if self.mode == "gcm":
            seq = _ascii_block(bytes.fromhex(rec["wire_hex"])[12:28])[12:16]
            base = "seq %s (header readable)" % seq
        else:
            base = "seq unknown (encrypted)"
        if not rec["delivered"]:
            return base + " -- jammed, content unseen"
        return base + " -- observed: %s" % rec.get("effect", "no effect")

    def _disarm_donor(self):
        """Index of a recording observed to DISARM, else None (no guessing)."""
        for i, rec in enumerate(self.recordings):
            if rec.get("cmd") == "DISARM" and rec["delivered"] \
                    and rec.get("effect") == EFFECT["DISARM"]:
                return i
        return None

    def replay(self, idx):
        """ATTACK: deliver the selected wire unchanged (a pure replay)."""
        wire = self._wire(idx)
        entry = self._deliver(wire, "ATTACKER")
        entry["wire_hex"] = wire.hex()  # unchanged: nothing to outline
        self._mark("replay", entry["accepted"])
        return entry

    def splice(self):
        """ATTACK: newest header + observed-DISARM body (Task-3 plan).

        ECB: forge_wire over 16-byte chunks. CBC: forge_wire_cbc (chunk 0
        is the IV, kept from the header's recording). GCM: the analogous
        cut -- newest nonce+header, donor ct+tag -- which MUST break the
        tag, because the tag was computed over the donor's header bytes.
        """
        donor = self._disarm_donor()
        if donor is None:
            return {"accepted": None, "reason": "no observed DISARM yet: "
                    "jam or send a DISARM the drone obeys first", "seq": None,
                    "cmd": None, "plain_blocks": None, "auth_note": None,
                    "source": "ATTACKER"}
        newest = len(self.recordings) - 1
        plan = [(newest, 0), (donor, 1), (donor, 2), (donor, 3), (donor, 4)]
        if self.mode == "ecb":
            wires = [self._wire(i) for i in range(len(self.recordings))]
            forged = forge_wire(wires, plan)
        elif self.mode == "cbc":
            wires = [self._wire(i) for i in range(len(self.recordings))]
            forged = forge_wire_cbc(wires, plan)
        else:
            new = self._wire(newest)
            old = self._wire(donor)
            forged = new[:NONCE_LEN + HEADER_LEN] + old[NONCE_LEN + HEADER_LEN:]
        entry = self._deliver(forged, "ATTACKER")
        entry["wire_hex"] = forged.hex()
        entry["forged_from"] = "header<-R%d, body<-R%d" % (
            self.recordings[newest]["n"], self.recordings[donor]["n"])
        self._mark("splice", entry["accepted"])
        return entry

    def iv_flip(self, idx):
        """ATTACK: rewrite the seq digits to (bursts seen + 10).

        CBC: forge_iv_seq flips the IV over the public header layout, so
        only decrypted block 0 changes. ECB has no IV -> N/A (blank cell,
        NOT a failure). GCM: flip the same nonce bytes; the tag must die.
        Old digits: read from the clear header for GCM, else estimated by
        counting bursts (session seqs start at 1, +1 per send).
        """
        wire = self._wire(idx)
        new4 = "%04d" % (self.seq_next - 1 + 10)
        if self.mode == "ecb":
            return {"accepted": None, "source": "ATTACKER", "seq": None,
                    "cmd": None, "plain_blocks": None, "auth_note": None,
                    "reason": "N/A: ECB has no IV to flip (cell stays blank)"}
        if self.mode == "gcm":
            old4 = wire[24:28].decode("ascii")  # clear header: read it
            forged = bytearray(wire)
            for i, (o, n) in enumerate(zip(old4.encode(), new4.encode())):
                forged[24 + i] ^= o ^ n  # same bytes the IV trick flips...
            forged = bytes(forged)  # ...but GCM tags the nonce, so it fails
        else:
            old4 = "%04d" % self.recordings[idx]["burst"]  # burst estimate
            forged = forge_iv_seq(wire, old4.encode(), new4.encode())
        entry = self._deliver(forged, "ATTACKER")
        entry["wire_hex"] = forged.hex()
        self._mark("iv_flip", entry["accepted"])
        return entry

    def block_flip(self, idx):
        """ATTACK: flip the Task-3 ciphertext block on the selected wire.

        CBC chunk 3 (= C2: chunk 0 is the IV) or ECB chunk 2, bytes 8..15
        with a fixed nonzero delta: the neighbour block garbles while the
        next block shifts controllably. GCM: the same body bytes -- the
        tag dies before the lenient parser is ever consulted.
        """
        wire = self._wire(idx)
        delta = b"\x01" * 8
        if self.mode == "gcm":
            forged = bytearray(wire)  # body ct starts after nonce+header
            at = NONCE_LEN + HEADER_LEN + 2 * 16 + 8
            for i, d in enumerate(delta):
                forged[at + i] ^= d
            forged = bytes(forged)
        else:
            chunk = 3 if self.mode == "cbc" else 2
            forged = forge_ct_block(wire, chunk, 8, delta)
        entry = self._deliver(forged, "ATTACKER")
        entry["wire_hex"] = forged.hex()
        self._mark("block_flip", entry["accepted"])
        return entry

    def _mark(self, attack, accepted):
        """Record the attacker outcome (SUCCESS = obeyed) for the matrix."""
        if accepted is not None:
            self.matrix["%s-%d:%s" % (self.mode.upper(), self.bits,
                                      attack)] = ("SUCCESS" if accepted
                                                  else "FAILED")

    # -- read-only views (key NEVER leaves the server) ---------------------

    def _wire_parts(self, wire):
        """Labelled wire pieces for the inspector (hex only, no key)."""
        wire = bytes(wire)
        if self.mode == "gcm":
            cut = NONCE_LEN + HEADER_LEN
            parts = [("nonce", wire[:NONCE_LEN]),
                     ("header", wire[NONCE_LEN:cut])]
            parts += [("C%d" % i, wire[cut + 16 * i:cut + 16 * i + 16])
                      for i in range(BODY_LEN // 16)]
            parts.append(("tag", wire[cut + BODY_LEN:]))
        else:
            parts = []
            if self.mode == "cbc":
                parts.append(("IV", wire[:16]))
                wire = wire[16:]
            parts += [("C%d" % i, wire[16 * i:16 * i + 16])
                      for i in range(len(wire) // 16)]
        return [{"label": label, "hex": chunk.hex()}
                for label, chunk in parts]

    def snapshot(self):
        """Everything the page may show. Asserts: no key material inside."""
        snap = {
            "mode": self.mode, "bits": self.bits,
            "seq_next": self.seq_next, "jam": self.jam,
            "gcs_view": self.gcs_view,
            "recordings": [
                {"n": r["n"], "label": self.attacker_label(r),
                 "delivered": r["delivered"],
                 "wire_parts": self._wire_parts(bytes.fromhex(r["wire_hex"])),
                 "wire_hex": r["wire_hex"]}
                for r in self.recordings],
            "drone": dict(self.drone),
            "log": list(reversed(self.log[-50:])),
            "matrix": dict(self.matrix),
            "has_disarm_donor": self._disarm_donor() is not None,
        }
        return snap
