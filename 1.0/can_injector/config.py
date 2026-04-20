from __future__ import annotations

import json
from pathlib import Path

_DEFAULTS: dict = {
    "interface": "vcan0",
    "light_threshold": 0x60,
    "can_ids": {
        "speed": 0x244,
        "signal": 0x188,
        "door": 0x19B,
        "luminosity": 0x39C,
        "headlight": 0x340,
        "warning": 0x42A,
        "control": 0x007,
    },
    "can_positions": {
        "speed": 3,
        "signal": 0,
        "door": 2,
        "luminosity": 3,
        "headlight": 5,
        "warning": 2,
    },
    "uds": {
        "tx_id": 0x7E0,
        "rx_id": 0x7E8,
        "tp_period": 0.9,
    },
    "injection": {
        "speed_hz": 100,
        "lum_hz": 4,
        "hl_hz": 4,
        "turn_hz": 2,
    },
    "routine_scan": {
        "timeout_ms": 20,
        "presets": {
            "quick":    {"xx": [0x40, 0x4F], "yy": [0x00, 0xFF], "zz": [0x01, 0x01]},
            "standard": {"xx": [0x00, 0x7F], "yy": [0x00, 0xFF], "zz": [0x01, 0x01]},
            "full":     {"xx": [0x00, 0xFF], "yy": [0x00, 0xFF], "zz": [0x01, 0x01]},
        },
    },
    "security": {
        "plugins": [],
        "algorithms": {
            # "all" enables every built-in; replace with a list of names to whitelist.
            "enabled": ["all"],
            # Names listed here are skipped even if in "enabled".
            "disabled": [],
            # Extra constants injected into the built-in parameterised families.
            "custom": {
                "xor_keys":   [],   # e.g. ["0xB2", "0x7C"]
                "add_keys":   [],   # e.g. ["0x20"]
                "rol_bits":   [],   # e.g. [2, 4]
                "xor2_pairs": [],   # e.g. [["0x12", "0x34"]]
            },
        },
    },
}

# Path resolution: inject_config.json lives one level up from this package.
_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "inject_config.json"


class Config:
    def __init__(self, path: Path | None = None):
        self._path = path or _DEFAULT_CONFIG_PATH
        self._data = self._merge(_DEFAULTS, self._load())

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load(self) -> dict:
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text())
                return self._coerce(raw)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    @staticmethod
    def _merge(base: dict, override: dict) -> dict:
        out = dict(base)
        for k, v in override.items():
            if isinstance(out.get(k), dict) and isinstance(v, dict):
                out[k] = Config._merge(out[k], v)
            else:
                out[k] = v
        return out

    @staticmethod
    def _coerce(node):
        if isinstance(node, dict):
            return {k: Config._coerce(v) for k, v in node.items()}
        if isinstance(node, list):
            return [Config._coerce(v) for v in node]
        if isinstance(node, str) and node.startswith("0x"):
            return int(node, 16)
        return node

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self):
        self._path.write_text(json.dumps(self._data, indent=2))

    # ── Generic accessor ──────────────────────────────────────────────────────

    def get(self, *keys, default=None):
        node = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    # ── Typed shortcuts ───────────────────────────────────────────────────────

    @property
    def iface(self) -> str:
        return self._data["interface"]

    @property
    def light_threshold(self) -> int:
        return self._data["light_threshold"]

    @property
    def uds_tx(self) -> int:
        return self._data["uds"]["tx_id"]

    @property
    def uds_rx(self) -> int:
        return self._data["uds"]["rx_id"]

    @property
    def tp_period(self) -> float:
        return self._data["uds"]["tp_period"]

    def can_id(self, name: str) -> int:
        return self._data["can_ids"][name]

    def can_pos(self, name: str) -> int:
        return self._data["can_positions"][name]

    def inj(self, key: str):
        return self._data["injection"][key]

    def scan_preset(self, name: str):
        return self._data["routine_scan"]["presets"].get(name)

    def scan_timeout(self) -> float:
        return self._data["routine_scan"]["timeout_ms"] / 1000.0
