"""Example security algorithm plugin for the CAN injector.

To activate, add the path to this file in inject_config.json:

    "security": {
        "plugins": ["plugins/example_plugin.py"],
        ...
    }

A plugin must expose an algorithms() function that returns a list of either:
  - BaseAlgorithm instances  (recommended — see MyCustomAlgorithm below)
  - (name, callable) tuples  (quick option — see the lambda examples)

The callable receives a bytes seed and must return a bytes key.
"""
from can_injector.security.base import BaseAlgorithm


# ── Option A: subclass BaseAlgorithm (recommended) ───────────────────────────

class XorBeef(BaseAlgorithm):
    """XOR each seed byte with 0xBE alternating with 0xEF."""

    name        = "xor_beef"
    description = "Alternating XOR with 0xBE / 0xEF"

    def compute(self, seed: bytes) -> bytes:
        return bytes(b ^ (0xBE if i % 2 == 0 else 0xEF) for i, b in enumerate(seed))


class ReflectThenXor(BaseAlgorithm):
    """Reverse bytes then XOR each with its original index."""

    name        = "reflect_xor_idx"
    description = "byte_reverse then XOR with index"

    def compute(self, seed: bytes) -> bytes:
        rev = bytes(reversed(seed))
        return bytes(b ^ i for i, b in enumerate(rev))


# ── Option B: plain (name, callable) tuple ────────────────────────────────────

_LAMBDA_EXAMPLES = [
    ("xor_0xDC", lambda s: bytes(b ^ 0xDC for b in s)),
    ("rol_2",    lambda s: _rol(s, 2)),
]


def _s2i(seed: bytes) -> int:
    return int.from_bytes(seed, "big")


def _i2b(k: int, n: int) -> bytes:
    return (k & ((1 << (n * 8)) - 1)).to_bytes(n, "big")


def _rol(seed: bytes, n: int) -> bytes:
    bits = len(seed) * 8
    v    = _s2i(seed)
    mask = (1 << bits) - 1
    return _i2b(((v << n) | (v >> (bits - n))) & mask, len(seed))


# ── Required export ───────────────────────────────────────────────────────────

def algorithms():
    return [XorBeef(), ReflectThenXor()] + _LAMBDA_EXAMPLES
