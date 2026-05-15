"""RoutineBruteForcer — 3-byte exhaustive scan of UDS RoutineControl (0x31)."""
from __future__ import annotations

import socket
import threading
import time
from typing import Callable

from .config import Config

try:
    import can
    HAVE_PYCAN = True
except ImportError:
    HAVE_PYCAN = False


class RoutineBruteForcer:
    CAN_ISOTP = 6

    def __init__(self, cfg: Config):
        self._cfg     = cfg
        self._stop_tp = threading.Event()

    # ── Socket helpers ────────────────────────────────────────────────────────

    def _open_isotp(self) -> socket.socket:
        s = socket.socket(socket.AF_CAN, socket.SOCK_DGRAM, self.CAN_ISOTP)
        s.bind((self._cfg.iface, self._cfg.uds_rx, self._cfg.uds_tx))
        s.settimeout(self._cfg.scan_timeout())
        return s

    def _drain(self, sock: socket.socket):
        sock.settimeout(0.005)
        while True:
            try:
                sock.recv(64)
            except socket.timeout:
                break
        sock.settimeout(self._cfg.scan_timeout())

    # ── TesterPresent keepalive (uses python-can) ─────────────────────────────

    def _keepalive(self, bus):
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

    # ── Session management ────────────────────────────────────────────────────

    def _open_session(self, sock: socket.socket, sub: int) -> bool:
        try:
            sock.send(bytes([0x10, sub]))
            r = sock.recv(64)
            return bool(r and r[0] == 0x50)
        except (socket.timeout, OSError):
            return False

    # ── Response classification ───────────────────────────────────────────────

    @staticmethod
    def _is_positive(resp, xx: int, yy: int, zz: int) -> bool:
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
        return (
            resp is not None
            and len(resp) >= 3
            and resp[0] == 0x7F
            and resp[1] == 0x31
            and resp[2] in (0x11, 0x12, 0x31)
        )

    # ── Main scan ─────────────────────────────────────────────────────────────

    def scan(
        self,
        xx_start: int = 0x00, xx_end: int = 0xFF,
        yy_start: int = 0x00, yy_end: int = 0xFF,
        zz_start: int = 0x01, zz_end: int = 0x01,
        progress_cb: Callable[[int, int, int], None] | None = None,
    ) -> tuple[list, list, dict]:
        """
        Scan RoutineControl (0x31 XX YY ZZ) over the configured ISO-TP socket.

        Returns (confirmed, interesting, stats) where:
          confirmed   — list of (xx, yy, zz, raw_hex) with positive 0x71 response
          interesting — list of (xx, yy, zz, "nrc:XX") with non-noise NRCs
          stats       — dict with checked, total, scan_time, session
        """
        if not HAVE_PYCAN:
            raise RuntimeError("python-can not installed: pip install python-can")

        try:
            sock = self._open_isotp()
        except OSError as e:
            raise RuntimeError(
                f"Cannot open ISO-TP socket: {e}\nRun: sudo modprobe can_isotp"
            ) from e

        bus     = can.interface.Bus(channel=self._cfg.iface, interface="socketcan")
        session = 0x01
        if self._open_session(sock, 0x02):
            session = 0x02
        elif self._open_session(sock, 0x03):
            session = 0x03
        self._drain(sock)

        self._stop_tp.clear()
        tp = threading.Thread(target=self._keepalive, args=(bus,), daemon=True)
        tp.start()

        total   = (xx_end - xx_start + 1) * (yy_end - yy_start + 1) * (zz_end - zz_start + 1)
        checked = 0
        hits: list = []
        t0      = time.monotonic()
        per_req = max(self._cfg.scan_timeout(), 0.05)

        def _recv_routine(deadline: float):
            while True:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    return None
                sock.settimeout(rem)
                try:
                    r = sock.recv(64)
                except (socket.timeout, OSError):
                    return None
                if not r:
                    return None
                if r[0] == 0x71:
                    return r
                if len(r) >= 3 and r[0] == 0x7F and r[1] == 0x31:
                    return r

        for xx in range(xx_start, xx_end + 1):
            for yy in range(yy_start, yy_end + 1):
                for zz in range(zz_start, zz_end + 1):
                    try:
                        sock.send(bytes([0x31, xx, yy, zz]))
                    except OSError:
                        checked += 1
                        continue
                    resp = _recv_routine(time.monotonic() + per_req)
                    if self._is_positive(resp, xx, yy, zz):
                        hits.append((xx, yy, zz, resp.hex()))
                    elif resp is not None and not self._is_noise(resp):
                        hits.append((xx, yy, zz, f"nrc:{resp.hex()}"))
                    checked += 1
                    if progress_cb and checked % 128 == 0:
                        progress_cb(checked, total, len(hits))

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
