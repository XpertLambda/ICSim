"""RoutineBruteForcer - 3-byte exhaustive scan of UDS RoutineControl (0x31).

The scan only ever exchanges single ISO-TP frames (<= 7 data bytes), so it
frames them by hand over a raw CAN_RAW socket (via can_bus) instead of the
kernel can_isotp module. can_isotp is absent on Windows/WSL2 — Docker Desktop's
kernel only gets vcan + can-raw side-loaded — whereas raw CAN works on every
host the lab supports. This mirrors uds_client.py, which already drives this
same ECU over raw CAN.
"""
from __future__ import annotations

import socket
import struct
import threading
import time
from typing import Callable

from .can_bus import can_open, can_recv, can_send
from .config import Config

try:
    import can
    HAVE_PYCAN = True
except ImportError:
    HAVE_PYCAN = False

_SFF_MASK = 0x7FF       # 11-bit ID mask for the kernel receive filter


class RoutineBruteForcer:

    def __init__(self, cfg: Config):
        self._cfg     = cfg
        self._stop_tp = threading.Event()

    # -- Raw CAN single-frame transport ----------------------------------------

    def _open(self) -> socket.socket:
        """Raw CAN socket kernel-filtered to the response ID, reproducing the
        old ISO-TP socket's rx binding (only uds_rx frames are delivered, so bus
        noise and our own tx echoes never reach the scan loop)."""
        s = can_open(self._cfg.iface)
        flt = struct.pack("=II", self._cfg.uds_rx, _SFF_MASK)
        s.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FILTER, flt)
        return s

    def _send_uds(self, sock: socket.socket, payload: bytes):
        """Send a UDS payload as one ISO-TP single frame: a PCI length byte
        (high nibble 0 = SF, low nibble = length) + the payload."""
        can_send(sock, self._cfg.uds_tx, bytes([len(payload)]) + payload)

    def _recv_sf(self, sock: socket.socket, deadline: float):
        """De-frame the next single frame on the response ID (PCI stripped), or
        None at the deadline — the exact bytes the old ISO-TP recv() returned."""
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                return None
            r = can_recv(sock, timeout=rem)
            if r is None:
                return None
            _cid, _dlc, data = r
            if not data or (data[0] >> 4) != 0x0:
                continue                      # only single frames are expected
            payload = data[1:1 + (data[0] & 0x0F)]
            if payload:
                return payload

    def _drain(self, sock: socket.socket):
        while can_recv(sock, timeout=0.005) is not None:
            pass

    # -- TesterPresent keepalive (uses python-can) -----------------------------

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

    # -- Session management ----------------------------------------------------

    def _open_session(self, sock: socket.socket, sub: int) -> bool:
        try:
            self._send_uds(sock, bytes([0x10, sub]))
        except OSError:
            return False
        r = self._recv_sf(sock, time.monotonic() + 0.3)
        return bool(r and r[0] == 0x50)

    # -- Response classification -----------------------------------------------

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

    # -- Main scan -------------------------------------------------------------

    def scan(
        self,
        xx_start: int = 0x00, xx_end: int = 0xFF,
        yy_start: int = 0x00, yy_end: int = 0xFF,
        zz_start: int = 0x01, zz_end: int = 0x01,
        progress_cb: Callable[[int, int, int], None] | None = None,
    ) -> tuple[list, list, dict]:
        """
        Scan RoutineControl (0x31 XX YY ZZ) over a raw CAN single-frame socket.

        Returns (confirmed, interesting, stats) where:
          confirmed   - list of (xx, yy, zz, raw_hex) with positive 0x71 response
          interesting - list of (xx, yy, zz, "nrc:XX") with non-noise NRCs
          stats       - dict with checked, total, scan_time, session
        """
        if not HAVE_PYCAN:
            raise RuntimeError("python-can not installed: pip install python-can")

        try:
            sock = self._open()
        except OSError as e:
            raise RuntimeError(
                f"Cannot open raw CAN socket on {self._cfg.iface}: {e}\n"
                f"Is the interface up?  ip link show {self._cfg.iface}"
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
                    try:
                        self._send_uds(sock, bytes([0x31, xx, yy, zz]))
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
