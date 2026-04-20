"""Abstract base class for security key algorithms.

To write a plugin, subclass BaseAlgorithm and implement `name` and `compute`,
then expose an `algorithms()` function that returns a list of instances:

    from can_injector.security.base import BaseAlgorithm

    class MyAlgo(BaseAlgorithm):
        name = "my_algo"
        description = "XOR each byte with 0xBE"

        def compute(self, seed: bytes) -> bytes:
            return bytes(b ^ 0xBE for b in seed)

    def algorithms():
        return [MyAlgo()]

Alternatively, return plain (name, callable) tuples — both formats are accepted.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseAlgorithm(ABC):
    description: str = ""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique algorithm identifier (no spaces, used in logging)."""
        ...

    @abstractmethod
    def compute(self, seed: bytes) -> bytes:
        """Return the security key computed from *seed*."""
        ...

    def __call__(self, seed: bytes) -> bytes:
        return self.compute(seed)

    def __repr__(self) -> str:
        return f"<Algorithm name={self.name!r}>"
