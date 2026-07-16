#!/usr/bin/env python3
"""
Standalone RoutineControl (0x31) 3-Byte Brute Forcer
====================================================

Hunts for hidden UDS RoutineControl routines on the ICSim CAN bus by trying
every `31 XX YY ZZ` request and watching which ones the ECU actually answers.

The scan runs in a few clear steps (see SECTION 5 · scan()):

    STEP 1  Open a raw CAN socket to the bus.
    STEP 2  Enter an extended diagnostic session (UDS 0x10).
    STEP 3  Start a TesterPresent keep-alive so the session stays open.
    STEP 4  Brute-force loop: send `31 XX YY ZZ` for every byte combination.
    STEP 5  Read each reply and sort it: hit (0x71) / interesting NRC / noise.
    STEP 6  Tear everything down and return the results.

Extracted from the main automation-scripts project.
"""

from __future__ import annotations

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 1 · IMPORTS & OPTIONAL DEPENDENCIES
#  The scan itself uses only the standard library. python-can is optional and
#  is used *only* by the TesterPresent keep-alive thread (see SECTION 5); if it
#  is missing the script still imports, it just refuses to scan.
# ═══════════════════════════════════════════════════════════════════════════

import json
import os
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Callable

try:
    import can
    HAVE_PYCAN = True
except ImportError:
    HAVE_PYCAN = False


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 2 · RAW CAN TRANSPORT  (the lowest layer — bytes on and off the wire)
#
#  A RoutineControl scan only ever exchanges single ISO-TP frames (<= 7 data
#  bytes), so we frame them by hand over a raw CAN_RAW socket instead of relying
#  on the kernel's can_isotp module. can_isotp is NOT present on Windows/WSL2
#  (Docker Desktop's kernel only gets vcan + can-raw side-loaded), whereas raw
#  CAN_RAW is available everywhere the lab runs. This is the exact technique
#  can_injector/uds_client.py already uses successfully against this same ECU.
# ═══════════════════════════════════════════════════════════════════════════

_CAN_FMT  = "=IB3x8s"   # struct layout of a CAN frame: can_id, dlc, 3 pad, 8 data
_CAN_SIZE = 16          # size in bytes of one packed frame
_SFF_MASK = 0x7FF       # 11-bit ID mask for the kernel receive filter


def _raw_open(iface: str, recv_id: int) -> socket.socket:
    """Open a raw CAN socket, kernel-filtered to a single response ID. The
    filter makes the socket behave like the old ISO-TP socket's rx binding:
    only frames from `recv_id` are delivered, so bus noise and our own tx
    echoes never reach us."""
    s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    flt = struct.pack("=II", recv_id, _SFF_MASK)            # (id, mask) filter pair
    s.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER, flt)
    s.bind((iface,))
    return s


def _raw_send(sock: socket.socket, can_id: int, data: bytes) -> None:
    """Send one CAN frame. `data` is right-padded to the fixed 8-byte field;
    the dlc we write is the real (unpadded) length."""
    padded = data.ljust(8, b"\x00")[:8]
    sock.send(struct.pack(_CAN_FMT, can_id, len(data), padded))


def _raw_recv(sock: socket.socket, timeout: float):
    """Read one CAN frame. Returns (can_id, dlc, data) or None on timeout."""
    sock.settimeout(timeout)
    try:
        raw = sock.recv(_CAN_SIZE)
    except (socket.timeout, OSError):
        return None
    can_id, dlc, data = struct.unpack(_CAN_FMT, raw)
    return can_id & 0x1FFFFFFF, dlc, bytes(data[:dlc])      # mask off CAN flag bits


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 3 · TERMINAL UI HELPERS  (colours, banners, prompts — cosmetic only)
#  Nothing in this section touches the CAN bus; it just makes the console
#  output readable. Safe to ignore when following the attack logic.
# ═══════════════════════════════════════════════════════════════════════════

class UI:
    class C:
        RED     = "\033[91m"
        GREEN   = "\033[92m"
        YELLOW  = "\033[93m"
        BLUE    = "\033[94m"
        MAGENTA = "\033[95m"
        CYAN    = "\033[96m"
        WHITE   = "\033[97m"
        BOLD    = "\033[1m"
        DIM     = "\033[2m"
        RESET   = "\033[0m"

    @staticmethod
    def col(color: str, text) -> str:
        return f"{color}{text}{UI.C.RESET}"

    @staticmethod
    def banner(text: str, color: str | None = None):
        color = color or UI.C.CYAN
        w = 60
        print(f"\n{color}{'═'*w}{UI.C.RESET}")
        print(f"{color}  {text}{UI.C.RESET}")
        print(f"{color}{'═'*w}{UI.C.RESET}")

    @staticmethod
    def section(text: str):
        pad = "-" * max(0, 50 - len(text))
        print(f"\n{UI.C.BOLD}{UI.C.WHITE}-- {text} {pad}{UI.C.RESET}")

    @staticmethod
    def ok(t):   print(f"  {UI.col(UI.C.GREEN,  '✔')} {t}")
    @staticmethod
    def warn(t): print(f"  {UI.col(UI.C.YELLOW, '⚠')} {t}")
    @staticmethod
    def err(t):  print(f"  {UI.col(UI.C.RED,    '✘')} {t}")
    @staticmethod
    def info(t): print(f"  {UI.col(UI.C.CYAN,   '→')} {t}")
    @staticmethod
    def dim(t):  print(f"  {UI.col(UI.C.DIM,    '-')} {t}")

    @staticmethod
    def prompt(text: str, default=None) -> str | None:
        suffix = f" [{default}]" if default is not None else ""
        try:
            v = input(f"  {UI.C.CYAN}>{UI.C.RESET} {text}{suffix}: ").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        return v if v else (str(default) if default is not None else "")

    @staticmethod
    def prompt_hex(text: str, default=None) -> int | None:
        while True:
            raw = UI.prompt(text, default)
            if raw is None:
                return None
            try:
                return int(raw, 16)
            except ValueError:
                UI.warn("Enter a valid hex value (e.g. 7E0).")


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 4 · CONFIGURATION  (interface, CAN IDs, scan ranges)
#  Built-in defaults live in _DEFAULTS below. If an inject_config.json sits next
#  to this script, its values are merged on top (so you can re-point IDs or
#  ranges without editing code). Hex strings like "0x7E0" in the JSON are
#  auto-converted to ints by _coerce().
# ═══════════════════════════════════════════════════════════════════════════

_DEFAULTS: dict = {
    "interface": "vcan0",
    "uds": {
        "tx_id": 0x7E0,            # tester -> ECU  (where we send requests)
        "rx_id": 0x7E8,            # ECU -> tester  (where we listen for replies)
    },
    "routine_scan": {
        "timeout_ms": 20,          # how long to wait for each routine's reply
        # Presets define the [start, end] range to sweep for each of the three
        # routine bytes XX, YY, ZZ. "quick" is a small slice; "full" is 0x00-0xFF.
        "presets": {
            "quick":    {"xx": [0x40, 0x4F], "yy": [0x00, 0xFF], "zz": [0x01, 0x01]},
            "standard": {"xx": [0x00, 0x7F], "yy": [0x00, 0xFF], "zz": [0x01, 0x01]},
            "full":     {"xx": [0x00, 0xFF], "yy": [0x00, 0xFF], "zz": [0x01, 0x01]},
        },
    },
}

_DEFAULT_CONFIG_PATH = Path(__file__).parent / "inject_config.json"

class Config:
    def __init__(self, path: Path | None = None):
        self._path = path or _DEFAULT_CONFIG_PATH
        self._data = self._merge(_DEFAULTS, self._load())   # defaults + JSON overrides

    def _load(self) -> dict:
        # Read the optional JSON file; on any error fall back to pure defaults.
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text())
                return self._coerce(raw)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    @staticmethod
    def _merge(base: dict, override: dict) -> dict:
        # Deep-merge override into base so nested dicts combine key-by-key.
        out = dict(base)
        for k, v in override.items():
            if isinstance(out.get(k), dict) and isinstance(v, dict):
                out[k] = Config._merge(out[k], v)
            else:
                out[k] = v
        return out

    @staticmethod
    def _coerce(node):
        # Recursively turn "0x.." hex strings from the JSON into real ints.
        if isinstance(node, dict):
            return {k: Config._coerce(v) for k, v in node.items()}
        if isinstance(node, list):
            return [Config._coerce(v) for v in node]
        if isinstance(node, str) and node.startswith("0x"):
            return int(node, 16)
        return node

    # --- Convenience accessors used by the scanner -------------------------
    @property
    def iface(self) -> str:
        return self._data["interface"]

    @property
    def uds_tx(self) -> int:
        return self._data["uds"]["tx_id"]

    @property
    def uds_rx(self) -> int:
        return self._data["uds"]["rx_id"]

    def scan_preset(self, name: str):
        return self._data["routine_scan"]["presets"].get(name)

    def scan_timeout(self) -> float:
        return self._data["routine_scan"]["timeout_ms"] / 1000.0   # ms -> seconds


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 5 · THE SCANNER  (the actual attack engine)
#
#  RoutineBruteForcer.scan() drives the whole attack. The small methods above
#  scan() are its building blocks (open / send / receive / classify); scan()
#  itself is annotated with the STEP 1..6 flow from the top of this file.
# ═══════════════════════════════════════════════════════════════════════════

class RoutineBruteForcer:

    def __init__(self, cfg: Config):
        self._cfg     = cfg
        self._stop_tp = threading.Event()      # set this to stop the keep-alive thread

    # --- Building block: open the response socket --------------------------
    def _open(self) -> socket.socket:
        return _raw_open(self._cfg.iface, self._cfg.uds_rx)

    # --- Building block: send one UDS request ------------------------------
    def _send_uds(self, sock: socket.socket, payload: bytes):
        """Transmit a UDS payload as one ISO-TP single frame: a PCI length byte
        (high nibble 0 = single frame, low nibble = length) followed by the
        payload. This is the framing the kernel ISO-TP layer used to add for us."""
        _raw_send(sock, self._cfg.uds_tx, bytes([len(payload)]) + payload)

    # --- Building block: throw away any buffered frames --------------------
    def _drain(self, sock: socket.socket):
        while _raw_recv(sock, 0.005) is not None:
            pass

    # --- Building block: receive and de-frame one reply --------------------
    def _recv_sf(self, sock: socket.socket, deadline: float):
        """De-frame the next ISO-TP single frame on the response ID, or None at
        the deadline. Returns the UDS payload with the PCI byte stripped — the
        exact bytes the old kernel ISO-TP socket's recv() returned."""
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                return None
            r = _raw_recv(sock, rem)
            if r is None:
                return None
            _cid, _dlc, data = r
            if not data or (data[0] >> 4) != 0x0:
                continue                      # only single frames are expected
            payload = data[1:1 + (data[0] & 0x0F)]
            if payload:
                return payload

    # --- Building block: the TesterPresent keep-alive (runs in a thread) ---
    def _keepalive(self, bus):
        # Repeatedly send TesterPresent (3E 80, suppress-response) so the ECU
        # does not time the diagnostic session out while the scan is running.
        msg = can.Message(
            arbitration_id=self._cfg.uds_tx,
            data=[0x02, 0x3E, 0x80],
            is_extended_id=False,
        )
        while not self._stop_tp.is_set():
            try:
                bus.send(msg)
            except can.CanError:
                break
            time.sleep(0.9)

    # --- Building block: try to open a diagnostic session ------------------
    def _open_session(self, sock: socket.socket, sub: int) -> bool:
        # Send DiagnosticSessionControl (0x10 sub) and report whether the ECU
        # answered positively (0x50).
        try:
            self._send_uds(sock, bytes([0x10, sub]))
        except OSError:
            return False
        r = self._recv_sf(sock, time.monotonic() + 0.3)
        return bool(r and r[0] == 0x50)

    # --- Building block: classify a routine reply --------------------------
    @staticmethod
    def _is_positive(resp, xx: int, yy: int, zz: int) -> bool:
        # A real hit: positive RoutineControl reply (0x71) echoing our XX YY ZZ.
        return (
            resp is not None
            and len(resp) >= 4
            and resp[0] == 0x71
            and resp[1] == xx
            and resp[2] == yy
            and resp[3] == zz
        )

    @staticmethod
    def _is_noise(resp) -> bool:
        # Boring rejections we want to ignore: NRC for RoutineControl (7F 31 ..)
        # with a "not supported / wrong format / out of range" code.
        return (
            resp is not None
            and len(resp) >= 3
            and resp[0] == 0x7F
            and resp[1] == 0x31
            and resp[2] in (0x11, 0x12, 0x31)
        )

    # --- The attack itself -------------------------------------------------
    def scan(
        self,
        xx_start: int = 0x00, xx_end: int = 0xFF,
        yy_start: int = 0x00, yy_end: int = 0xFF,
        zz_start: int = 0x01, zz_end: int = 0x01,
        progress_cb: Callable[[int, int, int], None] | None = None,
    ) -> tuple[list, list, dict]:
        # The keep-alive needs python-can; refuse early if it is missing.
        if not HAVE_PYCAN:
            raise RuntimeError("python-can not installed: pip install python-can")

        # ---- STEP 1 · Open the raw CAN socket -----------------------------
        try:
            sock = self._open()
        except OSError as e:
            raise RuntimeError(
                f"Cannot open raw CAN socket on {self._cfg.iface}: {e}\n"
                f"Is the interface up?  ip link show {self._cfg.iface}"
            ) from e

        # ---- STEP 2 · Enter an extended diagnostic session ----------------
        # Most routines are locked behind a non-default session. Try extended
        # (0x02), then extended-2 (0x03); fall back to default (0x01) if neither
        # opens. The reply to session-control is then drained so it can't be
        # mistaken for a routine reply later.
        bus     = can.interface.Bus(channel=self._cfg.iface, interface="socketcan")
        session = 0x01
        if self._open_session(sock, 0x02):
            session = 0x02
        elif self._open_session(sock, 0x03):
            session = 0x03
        self._drain(sock)

        # ---- STEP 3 · Start the TesterPresent keep-alive ------------------
        # A daemon thread pings 3E 80 every 0.9 s on a separate python-can bus
        # so the session we just opened does not lapse mid-scan.
        self._stop_tp.clear()
        tp = threading.Thread(target=self._keepalive, args=(bus,), daemon=True)
        tp.start()

        # ---- STEP 4 · Brute-force every XX YY ZZ combination --------------
        # Bookkeeping for the triple-nested sweep below.
        total   = (xx_end - xx_start + 1) * (yy_end - yy_start + 1) * (zz_end - zz_start + 1)
        checked = 0
        hits: list = []
        t0      = time.monotonic()
        per_req = max(self._cfg.scan_timeout(), 0.05)   # don't wait less than 50 ms

        def _recv_routine(deadline: float):
            # Wait until we see a reply that is relevant to a routine request:
            # a positive 0x71, or a RoutineControl NRC (7F 31 ..). Ignore the
            # rest (e.g. stray keep-alive echoes) until the deadline.
            while True:
                r = self._recv_sf(sock, deadline)
                if r is None:
                    return None
                if r[0] == 0x71:
                    return r
                if len(r) >= 3 and r[0] == 0x7F and r[1] == 0x31:
                    return r

        for xx in range(xx_start, xx_end + 1):
            for yy in range(yy_start, yy_end + 1):
                for zz in range(zz_start, zz_end + 1):
                    # Send the candidate routine: 31 XX YY ZZ (RoutineControl).
                    try:
                        self._send_uds(sock, bytes([0x31, xx, yy, zz]))
                    except OSError:
                        checked += 1
                        continue

                    # ---- STEP 5 · Read the reply and classify it ----------
                    # (runs once per iteration, right after each request)
                    resp = _recv_routine(time.monotonic() + per_req)
                    if self._is_positive(resp, xx, yy, zz):
                        hits.append((xx, yy, zz, resp.hex()))            # confirmed routine
                    elif resp is not None and not self._is_noise(resp):
                        hits.append((xx, yy, zz, f"nrc:{resp.hex()}"))   # unusual NRC -> note it
                    checked += 1
                    if progress_cb and checked % 128 == 0:
                        progress_cb(checked, total, len(hits))

        # ---- STEP 6 · Tear down and summarise -----------------------------
        # Stop the keep-alive, close the sockets, then split the hits into
        # confirmed routines vs. interesting-NRC leads and return the stats.
        self._stop_tp.set()
        tp.join(timeout=1.5)
        sock.close()
        bus.shutdown()

        confirmed   = [(x, y, z, d) for x, y, z, d in hits if not d.startswith("nrc:")]
        interesting = [(x, y, z, d) for x, y, z, d in hits if d.startswith("nrc:")]
        elapsed     = time.monotonic() - t0

        return confirmed, interesting, {
            "checked":   checked,
            "total":     total,
            "scan_time": elapsed,
            "session":   session,
        }


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 6 · INTERACTIVE MAIN  (menu → confirm → run → report)
#  Glue for running the scanner from a terminal. It walks the user through four
#  small steps and then hands off to RoutineBruteForcer.scan() above.
# ═══════════════════════════════════════════════════════════════════════════

def main():
    cfg = Config()

    os.system("clear")
    UI.banner(f"Standalone RoutineControl Scan - 0x{cfg.uds_tx:03X} → 0x{cfg.uds_rx:03X}", UI.C.BLUE)
    UI.section("RoutineControl - 3-Byte Brute Forcer (0x31 XX YY ZZ)")

    # ---- STEP 1 · Pre-flight checks -------------------------------------
    # Bail out early with a clear message if python-can is missing or the CAN
    # interface can't be opened — better here than deep inside the scan.
    if not HAVE_PYCAN:
        UI.err("python-can not installed: pip install python-can")
        return

    try:
        t = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        t.bind((cfg.iface,))
        t.close()
    except OSError as e:
        UI.err(f"Cannot open raw CAN on {cfg.iface}: {e}")
        UI.dim(f"Is the interface up?  ip link show {cfg.iface}")
        return

    UI.info("Request: [0x31][XX][YY][ZZ]   Positive response: [0x71][XX][YY][ZZ]")
    UI.info("Extended session (0x02) opened automatically.")
    print()

    # ---- STEP 2 · Choose what to scan -----------------------------------
    # Offer the three presets from the config, plus a custom range entered by
    # hand. The chosen ranges become the xx/yy/zz bounds passed to scan().
    presets = {
        "1": ("Quick",    cfg.scan_preset("quick")),
        "2": ("Standard", cfg.scan_preset("standard")),
        "3": ("Full",     cfg.scan_preset("full")),
    }
    for k, (label, p) in presets.items():
        print(f"   {UI.col(UI.C.CYAN, f'[{k}]')} {label:<10} "
              f"XX=0x{p['xx'][0]:02X}-0x{p['xx'][1]:02X}  "
              f"YY=0x{p['yy'][0]:02X}-0x{p['yy'][1]:02X}  "
              f"ZZ=0x{p['zz'][0]:02X}-0x{p['zz'][1]:02X}")
    print(f"   {UI.col(UI.C.CYAN,'[4]')} Custom    - configure each byte range")
    print()

    ch = UI.prompt("Scan mode", "1")
    if ch in presets:
        p = presets[ch][1]
        xx_start, xx_end = p["xx"]
        yy_start, yy_end = p["yy"]
        zz_start, zz_end = p["zz"]
    elif ch == "4":
        print()
        UI.info("Enter hex values. Range is start-end inclusive.")
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

    # ---- STEP 3 · Confirm and run ---------------------------------------
    # Show the resolved ranges + request count, ask for the go-ahead, then run
    # the scan while printing a throttled one-line progress indicator.
    total_req = (xx_end-xx_start+1) * (yy_end-yy_start+1) * (zz_end-zz_start+1)
    print()
    UI.info(f"XX: 0x{xx_start:02X}-0x{xx_end:02X}   YY: 0x{yy_start:02X}-0x{yy_end:02X}   ZZ: 0x{zz_start:02X}-0x{zz_end:02X}")
    UI.info(f"Total: {total_req} requests")
    print()
    if UI.prompt("Start scan?", "y") not in ("y", "yes", ""):
        return

    bf         = RoutineBruteForcer(cfg)
    last_print = [time.time()]

    def progress(checked: int, total: int, n: int):
        # Repaint the same line at most once per second so the scan stays fast.
        now = time.time()
        if now - last_print[0] >= 1.0:
            pct = 100 * checked / total
            print(f"\r  {UI.col(UI.C.DIM,'-')} {checked:6d}/{total} ({pct:5.1f}%)  hits={n}   ",
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
        return
    print()

    # ---- STEP 4 · Show the results --------------------------------------
    # Summary line, then the confirmed routines (0x71) and any interesting NRCs
    # that survived the noise filter.
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

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        UI.err("Scan aborted by user.")
