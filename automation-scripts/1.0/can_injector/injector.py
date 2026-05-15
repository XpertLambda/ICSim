"""Periodic CAN frame injector running in a background thread."""
from __future__ import annotations

import threading
import time

from .can_bus import can_send
from .config import Config


class Injector:
    def __init__(self, cfg: Config, sock):
        self._cfg    = cfg
        self._sock   = sock
        self._stop   = threading.Event()
        self._thread: threading.Thread | None = None
        self.desc    = ""

    @property
    def active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None
        self.desc    = ""

    # ── Internal loop ─────────────────────────────────────────────────────────

    def _loop(self, fn, rate_hz: float, duration_s: float):
        self._stop.clear()
        interval = 1.0 / rate_hz
        end      = time.time() + duration_s if duration_s > 0 else float("inf")
        while not self._stop.is_set() and time.time() < end:
            try:
                fn()
            except OSError:
                break
            time.sleep(interval)

    def _start(self, fn, rate_hz: float, duration_s: float, desc: str):
        self.stop()
        self.desc    = desc
        self._thread = threading.Thread(
            target=self._loop, args=(fn, rate_hz, duration_s), daemon=True
        )
        self._thread.start()

    # ── Public injection methods ──────────────────────────────────────────────

    def speed(self, kmh: float, rate_hz: int | None = None, duration_s: float = 0):
        rate_hz = rate_hz or self._cfg.inj("speed_hz")
        raw     = int(kmh * 100)
        data    = bytes([0, 0, 0, (raw >> 8) & 0xFF, raw & 0xFF])
        self._start(
            lambda: can_send(self._sock, self._cfg.can_id("speed"), data),
            rate_hz, duration_s,
            f"Speed {kmh:.1f} km/h @ {rate_hz} Hz",
        )

    def turn(self, side: str, rate_hz: int | None = None, duration_s: float = 0):
        rate_hz = rate_hz or self._cfg.inj("turn_hz")
        val     = {"left": 0x01, "right": 0x02, "warning": 0x03, "off": 0x00}.get(side, 0)
        state   = [val]

        def fn():
            can_send(self._sock, self._cfg.can_id("signal"), bytes([state[0]]))
            state[0] = 0 if state[0] else val

        self._start(fn, rate_hz, duration_s, f"Turn {side} @ {rate_hz} Hz")

    def door(self, mask: int):
        can_send(self._sock, self._cfg.can_id("door"), bytes([0, 0, mask & 0xFF]))

    def luminosity(self, level: int, rate_hz: int | None = None, duration_s: float = 0):
        rate_hz = rate_hz or self._cfg.inj("lum_hz")
        data    = bytes([0, 0, 0, level & 0xFF, 0])
        mode    = "DAY" if level >= self._cfg.light_threshold else "NIGHT"
        self._start(
            lambda: can_send(self._sock, self._cfg.can_id("luminosity"), data),
            rate_hz, duration_s,
            f"Luminosity 0x{level:02X} ({mode}) @ {rate_hz} Hz",
        )

    def headlights(self, on: bool, rate_hz: int | None = None, duration_s: float = 0):
        rate_hz = rate_hz or self._cfg.inj("hl_hz")
        data    = bytes([0, 0, 0, 0, 0, 0x01 if on else 0x00, 0, 0])
        self._start(
            lambda: can_send(self._sock, self._cfg.can_id("headlight"), data),
            rate_hz, duration_s,
            f"Headlights {'ON' if on else 'OFF'} @ {rate_hz} Hz",
        )

    def custom(self, can_id: int, data: bytes, rate_hz: int = 10, duration_s: float = 0):
        self._start(
            lambda: can_send(self._sock, can_id, data),
            rate_hz, duration_s,
            f"Custom 0x{can_id:03X} @ {rate_hz} Hz",
        )

    def send_once(self, can_id: int, data: bytes):
        can_send(self._sock, can_id, data)
