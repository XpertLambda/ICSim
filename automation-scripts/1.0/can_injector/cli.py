"""Command-line entry point."""
from __future__ import annotations

import argparse
import sys
import time

from .can_bus import can_open
from .config import Config
from .injector import Injector
from .live_state import LiveState
from .menu import MainMenu
from .ui import UI
from .uds_client import UdsClient


def main():
    parser = argparse.ArgumentParser(description="CAN Injection Tool — ICSim BarbHack fork")
    parser.add_argument("interface", nargs="?", help="CAN interface (overrides config)")
    args = parser.parse_args()

    cfg = Config()
    if args.interface:
        cfg._data["interface"] = args.interface

    try:
        sock = can_open(cfg.iface)
    except OSError as e:
        UI.err(f"Cannot open {cfg.iface}: {e}")
        UI.err("Is the interface up?  sudo ip link set up vcan0")
        sys.exit(1)

    UI.ok(f"Connected to {cfg.iface}")

    state = LiveState(cfg)
    if state.start(cfg.iface):
        UI.ok("Live state reader started.")
    else:
        UI.warn("Live state reader failed — state display will not update.")

    time.sleep(0.3)

    injector = Injector(cfg, sock)
    uds      = UdsClient(cfg)

    try:
        MainMenu(cfg, injector, state, uds).run()
    except KeyboardInterrupt:
        pass
    finally:
        injector.stop()
        state.stop()
        uds.close()
        sock.close()
        print(f"\n{UI.col(UI.C.GREEN, 'Goodbye.')}")
