"""Main menu and vehicle injection submenus."""
from __future__ import annotations

import os
import time

from ..can_bus import can_send
from ..config import Config
from ..injector import Injector
from ..live_state import LiveState
from ..ui import UI
from ..uds_client import UdsClient
from .uds_menu import UdsMenu


class MainMenu:
    def __init__(
        self,
        cfg: Config,
        injector: Injector,
        state: LiveState,
        uds: UdsClient,
    ):
        self.cfg      = cfg
        self.injector = injector
        self.state    = state
        self.uds      = uds
        self._uds_menu = UdsMenu(cfg, uds)

    def run(self):
        C   = UI.C
        col = UI.col
        while True:
            os.system("clear")
            UI.banner("CAN INJECTOR — CH-Workshop / ICSim", C.RED)
            self.state.display()

            status = (
                col(C.GREEN, f"⚡ {self.injector.desc}")
                if self.injector.active
                else col(C.DIM, "○  No active injection")
            )
            print(f"\n  {status}")
            if self.uds.tp_active:
                print(f"  {col(C.GREEN, '📡 TesterPresent keepalive active')}")

            UI.section("INJECTION MENU")
            print(f"   {col(C.CYAN,'[1]')} Spoof Speed           — 0x{self.cfg.can_id('speed'):03X}")
            print(f"   {col(C.CYAN,'[2]')} Door Lock / Unlock    — 0x{self.cfg.can_id('door'):03X}")
            print(f"   {col(C.CYAN,'[3]')} Inject Turn Signal    — 0x{self.cfg.can_id('signal'):03X}")
            print(f"   {col(C.CYAN,'[4]')} Spoof Luminosity      — 0x{self.cfg.can_id('luminosity'):03X}")
            print(f"   {col(C.CYAN,'[5]')} Override Headlights   — 0x{self.cfg.can_id('headlight'):03X}")
            print(f"   {col(C.CYAN,'[6]')} UDS Diagnostic        — 0x{self.cfg.uds_tx:03X} → 0x{self.cfg.uds_rx:03X}")
            print(f"   {col(C.CYAN,'[7]')} Custom Frame")
            print()
            print(f"   {col(C.YELLOW,'[s]')} Stop injection   {col(C.RED,'[q]')} Quit")
            print()

            ch = UI.prompt("Choice", "q")
            if ch is None or ch.lower() == "q":
                break
            elif ch.lower() == "s":
                self.injector.stop(); UI.ok("Stopped."); time.sleep(0.5)
            elif ch == "1": self._speed();  time.sleep(1)
            elif ch == "2": self._doors();  time.sleep(1)
            elif ch == "3": self._turn();   time.sleep(1)
            elif ch == "4": self._lum();    time.sleep(1)
            elif ch == "5": self._hl();     time.sleep(1)
            elif ch == "6": self._uds_menu.run()
            elif ch == "7": self._custom(); time.sleep(1)
            else:
                UI.warn("Unknown option."); time.sleep(0.5)

    # ── Vehicle injection submenus ────────────────────────────────────────────

    def _speed(self):
        UI.section(f"SPEED SPOOF — 0x{self.cfg.can_id('speed'):03X}")
        if self.state.speed_kmh is not None:
            UI.info(f"Current speed: {self.state.speed_kmh:.1f} km/h")
        kmh = UI.prompt_float("Target speed (km/h)", 150.0, min_val=0, max_val=600)
        if kmh is None:
            return
        rate = UI.prompt_int("Rate (Hz, ≥100 to dominate)", self.cfg.inj("speed_hz"), min_val=1, max_val=1000)
        if rate is None:
            return
        self.injector.speed(kmh, rate_hz=rate, duration_s=UI.prompt_duration())
        UI.ok(f"Injecting {kmh:.1f} km/h @ {rate} Hz")

    def _doors(self):
        UI.section(f"DOOR LOCK/UNLOCK — 0x{self.cfg.can_id('door'):03X}")
        cur = " ".join(f"D{i+1}:{'LOCK' if d else 'OPEN'}" for i, d in enumerate(self.state.doors))
        UI.info(f"Current: {cur}")
        print()
        for key, label in [
            ("1", "Lock all    → 0x0F"),
            ("2", "Unlock all  → 0x00"),
            ("3", "Unlock D1   → 0x0E"),
            ("4", "Unlock D2   → 0x0D"),
            ("5", "Custom bitmask"),
        ]:
            print(f"   {UI.col(UI.C.CYAN, f'[{key}]')} {label}")
        print()
        ch    = UI.prompt("Choice", "1")
        masks = {"1": 0x0F, "2": 0x00, "3": 0x0E, "4": 0x0D}
        if ch in masks:
            mask = masks[ch]
        elif ch == "5":
            mask = UI.prompt_hex("Bitmask (hex)", "0F")
            if mask is None:
                return
        else:
            UI.warn("Invalid choice.")
            return
        n = UI.prompt_int("Frames to send", 3, min_val=1, max_val=20)
        if n is None:
            return
        for _ in range(n):
            self.injector.door(mask)
            time.sleep(0.05)
        UI.ok(f"Sent {n} door frame(s).")

    def _turn(self):
        UI.section(f"TURN SIGNAL — 0x{self.cfg.can_id('signal'):03X}")
        print()
        for key, label in [
            ("1", "Left    (0x01 ↔ 0x00)"),
            ("2", "Right   (0x02 ↔ 0x00)"),
            ("3", "Warning (0x03 ↔ 0x00)"),
            ("4", "Off"),
        ]:
            print(f"   {UI.col(UI.C.CYAN, f'[{key}]')} {label}")
        print()
        side = {"1": "left", "2": "right", "3": "warning", "4": "off"}.get(UI.prompt("Choice", "1"), "left")
        rate = UI.prompt_int("Toggle rate (Hz)", self.cfg.inj("turn_hz"), min_val=1, max_val=20)
        if rate is None:
            return
        self.injector.turn(side, rate_hz=rate, duration_s=UI.prompt_duration())
        UI.ok(f"Injecting turn {side} @ {rate} Hz")

    def _lum(self):
        UI.section(f"LUMINOSITY SPOOF — 0x{self.cfg.can_id('luminosity'):03X}")
        UI.info(f"Threshold = 0x{self.cfg.light_threshold:02X}. Below → headlights ON.")
        print()
        for key, label in [("1", "DAY → 0xC5"), ("2", "NIGHT → 0x22"), ("3", "Custom")]:
            print(f"   {UI.col(UI.C.CYAN, f'[{key}]')} {label}")
        print()
        ch = UI.prompt("Choice", "1")
        if ch == "1":
            level = 0xC5
        elif ch == "2":
            level = 0x22
        elif ch == "3":
            level = UI.prompt_hex("Value (hex 00–FF)", "C5")
            if level is None:
                return
            level &= 0xFF
        else:
            UI.warn("Invalid choice.")
            return
        rate = UI.prompt_int("Rate (Hz)", self.cfg.inj("lum_hz"), min_val=1, max_val=50)
        if rate is None:
            return
        self.injector.luminosity(level, rate_hz=rate, duration_s=UI.prompt_duration())

    def _hl(self):
        UI.section(f"HEADLIGHTS — 0x{self.cfg.can_id('headlight'):03X}")
        UI.info(f"Current: {'ON' if self.state.headlights else 'OFF'}")
        print()
        for key, label in [("1", "Force ON"), ("2", "Force OFF")]:
            print(f"   {UI.col(UI.C.CYAN, f'[{key}]')} {label}")
        print()
        ch   = UI.prompt("Choice", "1")
        rate = UI.prompt_int("Rate (Hz)", self.cfg.inj("hl_hz"), min_val=1, max_val=50)
        if rate is None:
            return
        self.injector.headlights(ch != "2", rate_hz=rate, duration_s=UI.prompt_duration())

    def _custom(self):
        UI.section("CUSTOM FRAME INJECTION")
        print()
        can_id = UI.prompt_hex("CAN ID (hex)", "244")
        if can_id is None:
            return
        raw = UI.prompt("Data bytes (hex, space-separated)", "00")
        if not raw:
            return
        try:
            data = bytes(int(x, 16) for x in raw.split())
        except ValueError:
            UI.err("Invalid hex.")
            return
        print()
        for key, label in [("1", "Send once"), ("2", "Send continuously")]:
            print(f"   {UI.col(UI.C.CYAN, f'[{key}]')} {label}")
        print()
        ch = UI.prompt("Choice", "1")
        if ch == "1":
            n = UI.prompt_int("Times to send", 1, min_val=1, max_val=1000)
            if n is None:
                return
            for _ in range(n):
                self.injector.send_once(can_id, data)
                time.sleep(0.01)
            UI.ok(f"Sent {n}×")
        elif ch == "2":
            rate = UI.prompt_int("Rate (Hz)", 10, min_val=1, max_val=1000)
            if rate is None:
                return
            self.injector.custom(can_id, data, rate_hz=rate, duration_s=UI.prompt_duration())
