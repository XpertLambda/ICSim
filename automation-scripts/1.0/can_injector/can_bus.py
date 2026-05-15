"""Low-level CAN socket helpers (PF_CAN / SOCK_RAW)."""
from __future__ import annotations

import socket
import struct

_CAN_FMT  = "=IB3x8s"
_CAN_SIZE = 16


def can_open(iface: str) -> socket.socket:
    s = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def can_send(sock: socket.socket, can_id: int, data: bytes) -> None:
    padded = data.ljust(8, b"\x00")[:8]
    sock.send(struct.pack(_CAN_FMT, can_id, len(data), padded))


def can_recv(sock: socket.socket, timeout: float = 0.1):
    """Return (can_id, dlc, data) or None on timeout."""
    sock.settimeout(timeout)
    try:
        raw = sock.recv(_CAN_SIZE)
    except socket.timeout:
        return None
    can_id, dlc, data = struct.unpack(_CAN_FMT, raw)
    return can_id & 0x1FFFFFFF, dlc, bytes(data[:dlc])
