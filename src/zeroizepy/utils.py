"""
zeroizepy.utils

Convenience utilities for secure memory operations.
"""

from __future__ import annotations

import hmac
import ctypes
from typing import Union


BytesLike = Union[bytes, bytearray, memoryview]


def secure_compare(a: BytesLike, b: BytesLike) -> bool:
    """
    Constant-time comparison of two byte sequences.

    Uses hmac.compare_digest (C-accelerated) to reduce timing side-channels.
    Note: length differences are still inherently observable in most real systems,
    but compare_digest is the best available primitive in Python stdlib.
    """
    # Normalize to bytes-like objects compare_digest accepts
    if isinstance(a, memoryview):
        a = a.tobytes()
    if isinstance(b, memoryview):
        b = b.tobytes()
    return hmac.compare_digest(a, b)


def secure_clear(buf: Union[bytearray, memoryview]) -> None:
    """
    Securely zero a mutable buffer in-place.

    Supports:
    - bytearray
    - writable memoryview

    Raises TypeError if wrong type, ValueError if memoryview is read-only.
    """
    if isinstance(buf, memoryview):
        if buf.readonly:
            raise ValueError("memoryview is read-only")
        # Ensure we're operating on bytes view
        mv = buf.cast("B")
        if len(mv) == 0:
            return
        # Fast in-place slice fill
        mv[:] = b"\x00" * len(mv)
        return

    if isinstance(buf, bytearray):
        n = len(buf)
        if n == 0:
            return
        # Deterministic in-place overwrite via ctypes on underlying storage
        try:
            c_arr = (ctypes.c_char * n).from_buffer(buf)
            ctypes.memset(ctypes.addressof(c_arr), 0, n)
        except Exception:
            # Fallback: slice fill (still in-place)
            buf[:] = b"\x00" * n
        return

    raise TypeError("buf must be bytearray or memoryview")