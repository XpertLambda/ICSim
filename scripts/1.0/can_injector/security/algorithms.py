"""Built-in security key algorithms and the AlgorithmRegistry.

Built-ins cover identity, bitwise, rotation, XOR/ADD families, and
BarbHack-specific variants. The registry also loads extra constants
from inject_config.json and plugin files at runtime.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Callable

from .base import BaseAlgorithm
from ..config import Config
from ..ui import UI

AlgEntry = tuple[str, Callable[[bytes], bytes]]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _s2i(seed: bytes) -> int:
    return int.from_bytes(seed, "big")


def _i2b(k: int, n: int) -> bytes:
    return (k & ((1 << (n * 8)) - 1)).to_bytes(n, "big")


def _rol(seed: bytes, n: int) -> bytes:
    bits = len(seed) * 8
    v    = _s2i(seed)
    mask = (1 << bits) - 1
    return _i2b(((v << n) | (v >> (bits - n))) & mask, len(seed))


# ── Built-in algorithm table ──────────────────────────────────────────────────

_BUILTINS: list[AlgEntry] = [
    ("identity",       lambda s: bytes(s)),
    ("bitwise_not",    lambda s: bytes((~b) & 0xFF for b in s)),
    ("nibble_swap",    lambda s: bytes(((b << 4) | (b >> 4)) & 0xFF for b in s)),
    ("byte_reverse",   lambda s: bytes(reversed(s))),
    ("swap16",         lambda s: bytes(s[i ^ 1] if (i ^ 1) < len(s) else s[i] for i in range(len(s)))),
    ("xor_reverse",    lambda s: bytes(a ^ b for a, b in zip(s, reversed(s)))),
    # BarbHack ICSim CH-Workshop: sessionKey = last 2 chars of VIN "WBARBHACKFA149850" → "50"
    ("barbhack_vin50", lambda s: bytes(b ^ (0x35 if i % 2 == 0 else 0x30) for i, b in enumerate(s))),
    # (seed XOR 0x12345678) + 1, truncated to seed length
    ("barbhack_a",     lambda s: _i2b(((_s2i(s) ^ 0x12345678) + 1) & 0xFFFFFFFF, max(len(s), 4))[-len(s):]),
]

# XOR families
for _k in (0xFF, 0xA5, 0x5A, 0x55, 0xAA, 0x3E):
    _BUILTINS.append((f"xor_{_k:02X}", lambda s, c=_k: bytes(b ^ c for b in s)))

# ADD / SUB families
for _k in (0xC3, 0x42, 0x10):
    _BUILTINS.append((f"add_{_k:02X}", lambda s, c=_k: bytes((b + c) & 0xFF for b in s)))
    _BUILTINS.append((f"sub_{_k:02X}", lambda s, c=_k: bytes((b - c) & 0xFF for b in s)))

# Rotate-left family
for _n in (1, 3, 5, 7):
    _BUILTINS.append((f"rol_{_n}", lambda s, n=_n: _rol(s, n)))

# 32-bit ADD family
for _k in (0x12345678, 0xDEADBEEF, 0xCAFEBABE, 0xA5A5A5A5):
    _BUILTINS.append((
        f"add32_{_k:08X}",
        lambda s, c=_k: _i2b((_s2i(s) + c) & 0xFFFFFFFF, max(len(s), 4))[-len(s):],
    ))

# 32-bit XOR family
for _k in (0x12345678, 0xDEADBEEF, 0xCAFEBABE):
    _BUILTINS.append((
        f"xor32_{_k:08X}",
        lambda s, c=_k: _i2b(_s2i(s) ^ c, max(len(s), 4))[-len(s):],
    ))

# Alternating 2-byte XOR family (covers common VIN-derived session keys)
for _k0, _k1 in [(0x30, 0x35), (0x31, 0x32), (0x41, 0x42), (0x46, 0x41), (0x34, 0x39)]:
    _BUILTINS.append((
        f"xor2_{_k0:02X}{_k1:02X}",
        lambda s, a=_k0, b=_k1: bytes(byte ^ (a if i % 2 == 0 else b) for i, byte in enumerate(s)),
    ))


# ── Registry ──────────────────────────────────────────────────────────────────

class AlgorithmRegistry:
    """Assembles the full list of algorithms from built-ins, config constants, and plugins."""

    def __init__(self, cfg: Config):
        self._cfg = cfg

    def build(self) -> list[AlgEntry]:
        algs: list[AlgEntry] = list(_BUILTINS)
        algs.extend(self._from_custom_config())
        algs.extend(self._from_plugins())
        return self._apply_filters(algs)

    # ── Sources ───────────────────────────────────────────────────────────────

    def _from_custom_config(self) -> list[AlgEntry]:
        """Generate parameterised algorithms from constants declared in config."""
        extras: list[AlgEntry] = []
        custom = self._cfg.get("security", "algorithms", "custom", default={})

        def _hex(v):
            return int(v, 16) if isinstance(v, str) else int(v)

        for k in custom.get("xor_keys", []):
            k = _hex(k)
            extras.append((f"xor_{k:02X}", lambda s, c=k: bytes(b ^ c for b in s)))

        for k in custom.get("add_keys", []):
            k = _hex(k)
            extras.append((f"add_{k:02X}", lambda s, c=k: bytes((b + c) & 0xFF for b in s)))
            extras.append((f"sub_{k:02X}", lambda s, c=k: bytes((b - c) & 0xFF for b in s)))

        for n in custom.get("rol_bits", []):
            n = int(n)
            extras.append((f"rol_{n}", lambda s, n=n: _rol(s, n)))

        for pair in custom.get("xor2_pairs", []):
            if len(pair) == 2:
                k0, k1 = _hex(pair[0]), _hex(pair[1])
                extras.append((
                    f"xor2_{k0:02X}{k1:02X}",
                    lambda s, a=k0, b=k1: bytes(byte ^ (a if i % 2 == 0 else b) for i, byte in enumerate(s)),
                ))

        return extras

    def _from_plugins(self) -> list[AlgEntry]:
        """Load algorithms from external plugin files listed in config."""
        loaded: list[AlgEntry] = []
        for path in self._cfg.get("security", "plugins", default=[]):
            try:
                p    = Path(path)
                spec = importlib.util.spec_from_file_location(p.stem, p)
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if not hasattr(mod, "algorithms"):
                    UI.warn(f"Plugin {path}: missing algorithms() function — skipped")
                    continue
                for item in mod.algorithms():
                    if isinstance(item, BaseAlgorithm):
                        loaded.append((item.name, item.compute))
                    else:
                        loaded.append(item)
            except Exception as e:
                UI.warn(f"Plugin {path}: {e}")
        return loaded

    # ── Filtering ─────────────────────────────────────────────────────────────

    def _apply_filters(self, algs: list[AlgEntry]) -> list[AlgEntry]:
        enabled  = self._cfg.get("security", "algorithms", "enabled",  default=["all"])
        disabled = self._cfg.get("security", "algorithms", "disabled", default=[])

        if "all" not in enabled:
            enabled_set = set(enabled)
            algs = [(n, f) for n, f in algs if n in enabled_set]

        if disabled:
            disabled_set = set(disabled)
            algs = [(n, f) for n, f in algs if n not in disabled_set]

        return algs
