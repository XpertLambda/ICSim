#!/usr/bin/env python3
"""CAN Bus Injection Tool — backward-compatible entry point.

Usage:  python3 inject.py [interface]
Config: inject_config.json
"""
from can_injector.cli import main

if __name__ == "__main__":
    main()
