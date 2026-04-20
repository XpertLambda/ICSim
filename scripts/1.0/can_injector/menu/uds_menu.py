"""UDS Diagnostic submenu."""
from __future__ import annotations

import os
import socket
import time

from ..config import Config
from ..routine_scanner import HAVE_PYCAN, RoutineBruteForcer
from ..security.algorithms import AlgorithmRegistry
from ..ui import UI
from ..uds_client import UdsClient


class UdsMenu:
    def __init__(self, cfg: Config, uds: UdsClient):
        self.cfg = cfg
        self.uds = uds

    def run(self):
        C   = UI.C
        col = UI.col
        while True:
            os.system("clear")
            UI.banner(f"UDS DIAGNOSTIC — 0x{self.cfg.uds_tx:03X} → 0x{self.cfg.uds_rx:03X}", C.BLUE)

            names = {0x01: "Default", 0x02: "Extended", 0x03: "Secret/Programming"}
            print(f"  {col(C.CYAN,'◆')} Session: {col(C.BOLD, names.get(self.uds.session, f'0x{self.uds.session:02X}'))}")
            tp_s = (
                f"{col(C.GREEN,'● ACTIVE')} (0x{self.uds._tp_mode})"
                if self.uds.tp_active
                else col(C.DIM, "○ stopped")
            )
            print(f"  {col(C.CYAN,'◆')} TesterPresent: {tp_s}")

            UI.section("UDS MENU")
            tp_tag = col(C.GREEN, "[ON]") if self.uds.tp_active else col(C.DIM, "[auto]")
            for k, label in [
                ("1", "Open Default Session    (0x10 01)"),
                ("2", "Open Extended Session   (0x10 02)"),
                ("3", "Open Secret Session     (0x10 03)"),
                ("4", f"TesterPresent control   (0x3E) {tp_tag}"),
                ("5", "Read Vehicle Speed OBD  (0x01 0D)"),
                ("6", "Request VIN             (0x09 02)"),
                ("7", "SecurityAccess — seed   (0x27 01)"),
                ("8", "SecurityAccess — key    (0x27 01/02 auto)"),
                ("9", "RoutineControl scan     (0x31 XX YY ZZ)"),
                ("0", "Custom UDS payload"),
            ]:
                print(f"   {col(C.CYAN, f'[{k}]')} {label}")
            print()
            print(f"   {col(C.YELLOW,'[b]')} Back")
            print()

            ch = UI.prompt("Choice", "b")
            if ch is None or ch.lower() == "b":
                return
            elif ch == "1": self._session(0x01, "Default")
            elif ch == "2": self._session(0x02, "Extended")
            elif ch == "3": self._session(0x03, "Secret/Programming")
            elif ch == "4": self._tp()
            elif ch == "5": self._speed()
            elif ch == "6": self._vin()
            elif ch == "7": self._seed()
            elif ch == "8": self._key()
            elif ch == "9": self._routine()
            elif ch == "0": self._custom()
            else:
                UI.warn("Unknown option.")
            self._pause()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _pause(self):
        input(f"\n  {UI.C.DIM}Press Enter to continue...{UI.C.RESET}")

    # ── Session control ───────────────────────────────────────────────────────

    def _session(self, sub_fn: int, name: str):
        UI.section(f"DiagnosticSessionControl — {name}")
        tp_before = self.uds.tp_active
        ok, resp  = self.uds.session_ctrl(sub_fn)
        UI.print_resp(resp)
        if ok:
            UI.ok(f"Entered {name} session.")
            if sub_fn != 0x01 and self.uds.tp_active and not tp_before:
                UI.ok("TesterPresent keepalive auto-started.")
            elif sub_fn == 0x01 and tp_before and not self.uds.tp_active:
                UI.info("TesterPresent keepalive auto-stopped.")

    # ── TesterPresent ─────────────────────────────────────────────────────────

    def _tp(self):
        UI.section("TesterPresent — 0x3E")
        print()
        if self.uds.tp_active:
            for k, l in [("1", "Stop keepalive"), ("2", "Send single (0x3E 00)")]:
                print(f"   {UI.col(UI.C.CYAN, f'[{k}]')} {l}")
        else:
            for k, l in [
                ("1", "Start keepalive (suppressed, 0.9 s)"),
                ("2", "Start keepalive (with response)"),
                ("3", "Send single (0x3E 00)"),
            ]:
                print(f"   {UI.col(UI.C.CYAN, f'[{k}]')} {l}")
        print()
        ch = UI.prompt("Choice", "1")
        if self.uds.tp_active:
            if ch == "1":
                self.uds.tp_stop(); UI.ok("Keepalive stopped.")
            elif ch == "2":
                _, r = self.uds.tp_once(); UI.print_resp(r)
        else:
            if ch == "1":
                self.uds.tp_start(suppress=True);  UI.ok("Keepalive started (suppressed).")
            elif ch == "2":
                self.uds.tp_start(suppress=False); UI.ok("Keepalive started (with response).")
            elif ch == "3":
                _, r = self.uds.tp_once(); UI.print_resp(r)

    # ── OBD speed ─────────────────────────────────────────────────────────────

    def _speed(self):
        UI.section("OBD-II Speed — 0x01 0x0D (live)")
        UI.info("Press Ctrl+C to stop.")
        print()
        try:
            while True:
                resp = self.uds.obd_speed()
                if resp and len(resp) >= 3 and resp[0] == 0x41 and resp[1] == 0x0D:
                    speed  = resp[2]
                    filled = int(min(speed, 200) / 200 * 30)
                    bar    = UI.col(UI.C.GREEN, "█" * filled) + UI.col(UI.C.DIM, "░" * (30 - filled))
                    print(f"\r  [{time.strftime('%H:%M:%S')}]  [{bar}]  {speed:3d} km/h   ", end="", flush=True)
                else:
                    print(f"\r  [{time.strftime('%H:%M:%S')}]  No response...                              ", end="", flush=True)
                time.sleep(0.5)
        except KeyboardInterrupt:
            print()
            UI.ok("Stopped.")

    # ── VIN ───────────────────────────────────────────────────────────────────

    def _vin(self):
        UI.section("Request VIN — OBD 0x09 0x02")
        source, vin = self.uds.vin()
        if not source:
            UI.err("No VIN received.")
            return
        printable = "".join(ch for ch in vin if 32 <= ord(ch) <= 126)
        UI.ok(f"VIN via {source}: {UI.col(UI.C.GREEN, printable)}")
        if len(printable) != 17:
            UI.warn(f"VIN length = {len(printable)} (expected 17)")

    # ── Security access — seed ────────────────────────────────────────────────

    def _seed(self):
        UI.section("SecurityAccess — Seed (0x27 0x01)")
        self.uds.escalate()
        sub = UI.prompt_int("Seed sub-function (default 0x01)", 1, min_val=1, max_val=255)
        if sub is None:
            return
        ok, result = self.uds.sec_seed(sub)
        if ok:
            UI.ok(f"Seed: {UI.col(UI.C.GREEN, result.hex().upper())} ({len(result)} bytes)")
            UI.info("Use [8] to compute and send the key automatically.")
        else:
            UI.print_resp(result)
            if result and len(result) >= 3 and result[0] == 0x7F:
                msgs = {
                    0x7F: "Need Secret session (0x10 03) first.",
                    0x33: "securityAccessDenied.",
                    0x36: "Exceeded attempts — wait and retry.",
                    0x37: "Time delay not expired — wait ~10 s.",
                }
                if result[2] in msgs:
                    UI.err(msgs[result[2]])

    # ── Security access — key (auto-try) ─────────────────────────────────────

    def _key(self):
        UI.section("SecurityAccess — Auto Key (0x27 01/02)")
        self.uds.escalate()
        sub_seed = UI.prompt_int("Seed sub-function (odd, default 1)", 1, min_val=1, max_val=255)
        if sub_seed is None:
            return
        sub_key = sub_seed + 1

        ok, seed = self.uds.sec_seed(sub_seed)
        if not ok:
            UI.err("Could not obtain seed.")
            UI.print_resp(seed)
            return

        UI.ok(f"Seed: {UI.col(UI.C.GREEN, seed.hex().upper())} ({len(seed)} bytes)")
        if all(b == 0 for b in seed):
            UI.ok("All-zero seed — ECU already unlocked.")
            return

        algs = AlgorithmRegistry(self.cfg).build()
        UI.info(f"Trying {len(algs)} algorithms...")
        print()

        for name, fn in algs:
            try:
                key = fn(seed)
            except Exception as e:
                UI.dim(f"{name:<24} → error: {e}")
                continue

            if len(key) != len(seed):
                if len(key) < len(seed):
                    key = bytes(len(seed) - len(key)) + key
                else:
                    key = key[-len(seed):]

            ok_f, resp = self.uds.sec_key(key, sub_fn=sub_key)
            if ok_f:
                UI.ok(f"{UI.col(UI.C.GREEN,'🔓 MATCH:')} {UI.col(UI.C.BOLD, name)}")
                UI.ok(f"  seed={seed.hex().upper()}  key={key.hex().upper()}")
                return

            nrc = resp[2] if (resp and len(resp) >= 3 and resp[0] == 0x7F) else None
            UI.dim(f"{name:<24} key={key.hex().upper():<16} → {UI.fmt_nrc(nrc) if nrc else 'no resp'}")

            if nrc == 0x36:
                UI.warn("Exceeded attempts — waiting 10 s for fresh seed...")
                time.sleep(10)
                ok, seed = self.uds.sec_seed(sub_seed)
                if not ok:
                    UI.err("Fresh seed failed.")
                    return
                UI.info(f"New seed: {seed.hex().upper()}")

        UI.err("No algorithm matched. Add a custom plugin to inject_config.json.")

    # ── RoutineControl brute-force ────────────────────────────────────────────

    def _routine(self):
        UI.section("RoutineControl — 3-Byte Brute Forcer (0x31 XX YY ZZ)")
        if not HAVE_PYCAN:
            UI.err("python-can not installed: pip install python-can")
            return
        try:
            t = socket.socket(socket.AF_CAN, socket.SOCK_DGRAM, RoutineBruteForcer.CAN_ISOTP)
            t.close()
        except OSError:
            UI.err("Kernel module can_isotp not loaded: sudo modprobe can_isotp")
            return

        UI.info("Request: [0x31][XX][YY][ZZ]   Positive response: [0x71][XX][YY][ZZ]")
        UI.info("Extended session (0x02) opened automatically.")
        print()

        def _est(n: int) -> str:
            s = n * self.cfg.scan_timeout()
            return f"~{s:.0f}s" if s < 120 else f"~{s/60:.1f}min"

        presets = {
            "1": ("Quick",    self.cfg.scan_preset("quick")),
            "2": ("Standard", self.cfg.scan_preset("standard")),
            "3": ("Full",     self.cfg.scan_preset("full")),
        }
        for k, (label, p) in presets.items():
            n = (p["xx"][1]-p["xx"][0]+1) * (p["yy"][1]-p["yy"][0]+1) * (p["zz"][1]-p["zz"][0]+1)
            print(f"   {UI.col(UI.C.CYAN, f'[{k}]')} {label:<10} "
                  f"XX=0x{p['xx'][0]:02X}-0x{p['xx'][1]:02X}  "
                  f"YY=0x{p['yy'][0]:02X}-0x{p['yy'][1]:02X}  "
                  f"ZZ=0x{p['zz'][0]:02X}-0x{p['zz'][1]:02X}  ({_est(n)})")
        print(f"   {UI.col(UI.C.CYAN,'[4]')} Custom    — configure each byte range")
        print()

        ch = UI.prompt("Scan mode", "1")
        if ch in presets:
            p = presets[ch][1]
            xx_start, xx_end = p["xx"]
            yy_start, yy_end = p["yy"]
            zz_start, zz_end = p["zz"]
        elif ch == "4":
            print()
            UI.info("Enter hex values. Range is start–end inclusive.")
            xx_start = UI.prompt_hex("XX start", "40"); xx_end = UI.prompt_hex("XX end", "4F")
            yy_start = UI.prompt_hex("YY start", "00"); yy_end = UI.prompt_hex("YY end", "FF")
            zz_start = UI.prompt_hex("ZZ start", "01"); zz_end = UI.prompt_hex("ZZ end", "01")
            if any(v is None for v in (xx_start, xx_end, yy_start, yy_end, zz_start, zz_end)):
                return
            xx_start &= 0xFF; xx_end &= 0xFF
            yy_start &= 0xFF; yy_end &= 0xFF
            zz_start &= 0xFF; zz_end &= 0xFF
        else:
            UI.warn("Invalid choice.")
            return

        total_req = (xx_end-xx_start+1) * (yy_end-yy_start+1) * (zz_end-zz_start+1)
        print()
        UI.info(f"XX: 0x{xx_start:02X}–0x{xx_end:02X}   YY: 0x{yy_start:02X}–0x{yy_end:02X}   ZZ: 0x{zz_start:02X}–0x{zz_end:02X}")
        UI.info(f"Total: {total_req} requests  ({_est(total_req)})")
        print()
        if UI.prompt("Start scan?", "y") not in ("y", "yes", ""):
            return

        was_tp = self.uds.tp_active
        if was_tp:
            UI.info("Pausing main TesterPresent — brute-forcer has its own.")
            self.uds.tp_stop()

        bf         = RoutineBruteForcer(self.cfg)
        last_print = [time.time()]

        def progress(checked: int, total: int, n: int):
            now = time.time()
            if now - last_print[0] >= 1.0:
                pct = 100 * checked / total
                eta = (total - checked) * self.cfg.scan_timeout()
                print(f"\r  {UI.col(UI.C.DIM,'·')} {checked:6d}/{total} ({pct:5.1f}%)  hits={n}  ETA={eta:.0f}s   ",
                      end="", flush=True)
                last_print[0] = now

        try:
            confirmed, interesting, stats = bf.scan(
                xx_start=xx_start, xx_end=xx_end,
                yy_start=yy_start, yy_end=yy_end,
                zz_start=zz_start, zz_end=zz_end,
                progress_cb=progress,
            )
        except RuntimeError as e:
            UI.err(str(e))
            if was_tp:
                self.uds.tp_start()
            return
        print()

        if was_tp:
            self.uds.tp_start()
            UI.info("TesterPresent resumed.")

        UI.info(f"Session: 0x{stats['session']:02X}   Requests: {stats['checked']}   Time: {stats['scan_time']:.1f}s")
        print()

        if confirmed:
            print(f"  {UI.col(UI.C.GREEN,'╔══ Confirmed (0x71) ══╗')}")
            for xx, yy, zz, detail in confirmed:
                print(f"    {UI.col(UI.C.GREEN, f'31 {xx:02X} {yy:02X} {zz:02X}')}  →  "
                      f"{UI.col(UI.C.GREEN,'71')} {xx:02X} {yy:02X} {zz:02X}   raw={UI.col(UI.C.DIM, detail)}")
        else:
            UI.warn("No positive responses (0x71) found.")

        if interesting:
            print()
            print(f"  {UI.col(UI.C.YELLOW,'╔══ Interesting NRCs ══╗')}")
            for xx, yy, zz, detail in interesting[:20]:
                print(f"    {UI.col(UI.C.CYAN, f'31 {xx:02X} {yy:02X} {zz:02X}')}  →  "
                      f"{UI.col(UI.C.DIM, detail.replace('nrc:',''))}")
            if len(interesting) > 20:
                UI.dim(f"... and {len(interesting)-20} more")

    # ── Custom UDS payload ────────────────────────────────────────────────────

    def _custom(self):
        UI.section("Custom UDS Payload")
        UI.info("Example: '10 03' → open secret session")
        print()
        raw = UI.prompt("Hex payload", "10 03")
        if not raw:
            return
        try:
            payload = bytes(int(x, 16) for x in raw.split())
        except ValueError:
            UI.err("Invalid hex.")
            return
        UI.info(f"Sending → 0x{self.cfg.uds_tx:03X}: {' '.join(f'{b:02X}' for b in payload)}")
        UI.print_resp(self.uds.tx(payload), sid=payload[0] if payload else None)
