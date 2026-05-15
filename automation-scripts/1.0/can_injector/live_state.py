"""Passive CAN bus observer — decodes vehicle state from live frames."""
from __future__ import annotations

import threading

from .can_bus import can_open, can_recv
from .config import Config
from .ui import UI


class LiveState:
    def __init__(self, cfg: Config):
        self._cfg    = cfg
        self._lock   = threading.Lock()
        self._thread: threading.Thread | None = None
        self._sock   = None
        self.running = False

        # Observable fields
        self.speed_kmh:  float | None = None
        self.speed_idle: bool = True
        self.left    = self.right    = self.warning  = False
        self.doors:  list[bool] = [True] * 4
        self.lum_level: int | None = None
        self.lum_day    = True
        self.is_night   = False
        self.light_on   = False
        self.hl_inject  = False
        self.warn_state = False

    def start(self, iface: str) -> bool:
        try:
            self._sock   = can_open(iface)
            self.running = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            return True
        except OSError:
            return False

    def stop(self):
        self.running = False

    # ── Frame parsing ─────────────────────────────────────────────────────────

    def _loop(self):
        while self.running:
            r = can_recv(self._sock)
            if r:
                with self._lock:
                    self._update(*r)

    def _update(self, can_id: int, _dlc: int, data: bytes):
        cfg = self._cfg
        lt  = cfg.light_threshold

        if can_id == cfg.can_id("speed") and len(data) >= 5:
            hi = data[cfg.can_pos("speed")]
            lo = data[cfg.can_pos("speed") + 1]
            if hi == 0x01:
                self.speed_kmh, self.speed_idle = 0.0, True
            else:
                self.speed_kmh  = ((hi << 8) | lo) / 100.0
                self.speed_idle = False

        elif can_id == cfg.can_id("signal"):
            b = data[cfg.can_pos("signal")] if data else 0
            self.left    = bool(b & 1)
            self.right   = bool(b & 2)
            self.warning = b == 3

        elif can_id == cfg.can_id("door") and len(data) > cfg.can_pos("door"):
            b = data[cfg.can_pos("door")]
            self.doors = [bool(b & (1 << i)) for i in range(4)]

        elif can_id == cfg.can_id("luminosity") and len(data) > cfg.can_pos("luminosity"):
            lv = data[cfg.can_pos("luminosity")]
            self.lum_level = lv
            self.lum_day   = lv >= lt

        elif can_id == cfg.can_id("control") and len(data) >= 7:
            k = data[6]
            d0, d1, d2 = data[0] ^ k, data[1] ^ k, data[2] ^ k
            if (d0 + d1 + d2) % 256 == (data[3] ^ k) == (data[4] ^ k ^ (data[3] ^ k)):
                self.light_on = bool((d0 >> 6) & 1)
                self.is_night = bool((d0 >> 5) & 1)

        elif can_id == cfg.can_id("headlight"):
            p = cfg.can_pos("headlight")
            self.hl_inject = bool(data[p] & 1) if len(data) > p else False

        elif can_id == cfg.can_id("warning"):
            p = cfg.can_pos("warning")
            self.warn_state = bool(data[p] & 1) if len(data) > p else False

    # ── Derived properties ────────────────────────────────────────────────────

    @property
    def headlights(self) -> bool:
        lum_auto = self.lum_level is not None and self.lum_level < self._cfg.light_threshold
        return self.light_on or lum_auto or self.hl_inject

    # ── Display ───────────────────────────────────────────────────────────────

    def display(self):
        C   = UI.C
        col = UI.col
        lt  = self._cfg.light_threshold

        with self._lock:
            kmh, idle  = self.speed_kmh, self.speed_idle
            lvl, day   = self.lum_level, self.lum_day
            is_night   = self.is_night
            light_on   = self.light_on
            hl_inj     = self.hl_inject
            doors      = list(self.doors)
            left, right, warn = self.left, self.right, self.warning

        # Speed bar
        if kmh is not None:
            filled  = int(min(kmh, 200) / 200 * 20)
            bar     = col(C.GREEN, "█" * filled) + col(C.DIM, "░" * (20 - filled))
            spd_str = f"{kmh:6.1f} km/h{col(C.DIM, ' (idle)') if idle else ''}"
        else:
            bar, spd_str = "", col(C.DIM, "---")

        # Turn signal
        if warn:
            turn_str = col(C.RED, "⚠ WARNING / HAZARD ⚠")
        elif left and not right:
            turn_str = col(C.YELLOW, "◄◄ LEFT")
        elif right and not left:
            turn_str = col(C.YELLOW, "RIGHT ►►")
        else:
            turn_str = col(C.DIM, "---")

        # Luminosity
        lum_str = (
            f"0x{lvl:02X} → {col(C.YELLOW,'☀ bright') if day else col(C.MAGENTA,'☾ dark')}"
            if lvl is not None else col(C.DIM, "---")
        )
        env_str = col(C.MAGENTA, "☾ NIGHT") if is_night else col(C.YELLOW, "☀ DAY")

        # Headlights
        lum_auto = lvl is not None and lvl < lt
        hl_on    = light_on or lum_auto or hl_inj
        if hl_on:
            reasons = [s for s, cond in [("manual", light_on), ("auto", lum_auto), ("injected", hl_inj)] if cond]
            hl_str  = col(C.YELLOW, "◉ ON") + col(C.DIM, f" [{','.join(reasons)}]")
        else:
            hl_str = col(C.DIM, "○ off")

        # Doors
        door_str = "  ".join(
            col(C.CYAN, f"D{i+1}:LOCK") if d else col(C.RED, f"D{i+1}:OPEN")
            for i, d in enumerate(doors)
        )

        print(f"\n  {C.BOLD}{'─'*58}{C.RESET}")
        print(f"  {C.BOLD}  VEHICLE STATE (live){C.RESET}")
        print(f"  {'─'*58}")
        print(f"  SPEED       {bar} {spd_str}")
        print(f"  TURN        {turn_str}")
        print(f"  SENSOR      {lum_str}   (thresh=0x{lt:02X})")
        print(f"  ENVIRONMENT {env_str}")
        print(f"  HEADLIGHTS  {hl_str}")
        print(f"  DOORS       {door_str}")
        print(f"  {C.BOLD}{'─'*58}{C.RESET}")
