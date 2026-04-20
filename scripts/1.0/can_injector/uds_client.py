"""UDS client — ISO-TP framing over a raw CAN socket."""
from __future__ import annotations

import threading
import time

from .can_bus import can_open, can_send, can_recv
from .config import Config
from .ui import UI


class UdsClient:
    SID_SESSION = 0x10
    SID_TP      = 0x3E
    SID_READ    = 0x22
    SID_SEC     = 0x27
    SID_ROUTINE = 0x31

    def __init__(self, cfg: Config):
        self._cfg       = cfg
        self._sock      = can_open(cfg.iface)
        self._tp_stop   = threading.Event()
        self._tp_thread: threading.Thread | None = None
        self._tp_mode: str | None = None
        self.session    = 0x01

    # ── Transport layer ───────────────────────────────────────────────────────

    def _drain(self, window: float = 0.05):
        deadline = time.time() + window
        while time.time() < deadline:
            can_recv(self._sock, timeout=0.01)

    def _send(self, payload: bytes):
        if len(payload) > 7:
            raise ValueError("Payload > 7 bytes; multi-frame TX not supported")
        can_send(self._sock, self._cfg.uds_tx, bytes([len(payload)]) + payload)

    def _recv(self, timeout: float = 1.0) -> bytes | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = can_recv(self._sock, timeout=max(0.05, deadline - time.time()))
            if not r:
                continue
            can_id, _dlc, data = r
            if can_id != self._cfg.uds_rx or not data:
                continue
            # Drop TesterPresent echoes
            if len(data) >= 2 and data[0] == 0x02 and data[1] == self.SID_TP + 0x40:
                continue
            pci = data[0] >> 4
            if pci == 0x0:
                return data[1: 1 + (data[0] & 0x0F)]
            if pci == 0x1:
                total   = ((data[0] & 0x0F) << 8) | data[1]
                payload = bytearray(data[2:])
                can_send(self._sock, self._cfg.uds_tx, bytes([0x30, 0x00, 0x00]))
                while len(payload) < total and time.time() < deadline:
                    r2 = can_recv(self._sock, timeout=max(0.05, deadline - time.time()))
                    if r2 and r2[0] == self._cfg.uds_rx and r2[2] and (r2[2][0] >> 4) == 0x2:
                        payload.extend(r2[2][1:])
                return bytes(payload[:total])
        return None

    def tx(self, payload: bytes, timeout: float = 1.0) -> bytes | None:
        self._drain()
        self._send(payload)
        return self._recv(timeout)

    # ── TesterPresent keepalive ───────────────────────────────────────────────

    def tp_start(self, suppress: bool = True):
        if self._tp_thread and self._tp_thread.is_alive():
            return
        self._tp_stop.clear()
        self._tp_mode = "80" if suppress else "00"
        sub   = 0x80 if suppress else 0x00
        frame = bytes([0x02, self.SID_TP, sub])

        def _loop():
            s = can_open(self._cfg.iface)
            try:
                while not self._tp_stop.is_set():
                    try:
                        can_send(s, self._cfg.uds_tx, frame)
                    except OSError:
                        break
                    t = 0.0
                    while t < self._cfg.tp_period and not self._tp_stop.is_set():
                        time.sleep(0.05)
                        t += 0.05
            finally:
                s.close()

        self._tp_thread = threading.Thread(target=_loop, daemon=True)
        self._tp_thread.start()

    def tp_stop(self):
        self._tp_stop.set()
        if self._tp_thread:
            self._tp_thread.join(timeout=2)
        self._tp_thread = None
        self._tp_mode   = None

    @property
    def tp_active(self) -> bool:
        return self._tp_thread is not None and self._tp_thread.is_alive()

    # ── High-level services ───────────────────────────────────────────────────

    def session_ctrl(self, sub_fn: int) -> tuple[bool, bytes | None]:
        resp = self.tx(bytes([self.SID_SESSION, sub_fn]))
        if resp and resp[0] == self.SID_SESSION + 0x40:
            self.session = sub_fn
            if sub_fn == 0x01:
                if self.tp_active:
                    self.tp_stop()
            else:
                if not self.tp_active:
                    self.tp_start()
            return True, resp
        return False, resp

    def tp_once(self, suppress: bool = False) -> tuple[bool, bytes | None]:
        sub  = 0x80 if suppress else 0x00
        resp = self.tx(bytes([self.SID_TP, sub]), timeout=0.3 if suppress else 1.0)
        if suppress:
            return True, None
        return bool(resp and resp[0] == self.SID_TP + 0x40), resp

    def obd_speed(self, timeout: float = 0.5) -> bytes | None:
        return self.tx(bytes([0x01, 0x0D]), timeout=timeout)

    def vin(self) -> tuple[str | None, str | None]:
        for _ in range(2):
            resp = self.tx(bytes([0x09, 0x02]), timeout=2.0)
            if not resp or len(resp) < 4:
                continue
            if resp[0] == 0x49 and resp[1] == 0x02 and resp[2] == 0x01:
                chunk = resp[3:]
            elif resp[0] == 0x49 and resp[1] == 0x02:
                chunk = resp[2:]
            else:
                chunk = resp
            s = "".join(chr(b) for b in chunk[:17] if 32 <= b <= 126)
            if len(s) >= 10:
                return "OBD", s
        return None, None

    def sec_seed(self, sub_fn: int = 0x01) -> tuple[bool, bytes | None]:
        resp = self.tx(bytes([self.SID_SEC, sub_fn]))
        if resp and len(resp) >= 2 and resp[0] == self.SID_SEC + 0x40 and resp[1] == sub_fn:
            return True, resp[2:]
        return False, resp

    def sec_key(self, key: bytes, sub_fn: int = 0x02) -> tuple[bool, bytes | None]:
        resp = self.tx(bytes([self.SID_SEC, sub_fn]) + key)
        if resp and len(resp) >= 2 and resp[0] == self.SID_SEC + 0x40 and resp[1] == sub_fn:
            return True, resp
        return False, resp

    def escalate(self):
        """Try to escalate from Default session to a higher diagnostic session."""
        if self.session != 0x01:
            return
        for sf, name in [(0x03, "Secret/Programming"), (0x02, "Extended")]:
            ok, _ = self.session_ctrl(sf)
            if ok:
                UI.ok(f"Escalated to {name} session.")
                time.sleep(0.1)
                break

    def close(self):
        self.tp_stop()
        try:
            self._sock.close()
        except OSError:
            pass
