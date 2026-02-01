# zeroizepy/memory.py
"""
zeroizepy.memory
----------------

High-level secure memory API used by tests.

Public API:
- SecureMemory(size) / SecureMemory.alloc(size)
- SecureMemory.from_bytes(data) and secret_bytes(data)
- secure_alloc(size) context manager
- close(), zero(), read(), write(), get_bytes()
- Raises SecureMemoryClosed after close()

Implementation:
- Prefer libsodium if _sodium.have_libsodium() is True.
- Fallback: bytearray-backed buffer exposed via memoryview (writable).
- Deterministic zeroing via sodium_memzero (when available) or ctypes/memoryview writes.

Reality check:
- If you pass secrets in as `bytes`, they already exist in normal Python memory.
  Prefer passing `bytearray`/`memoryview` if you want to wipe inputs later upstream.
"""

from __future__ import annotations

import typing as _typing
import logging
import contextlib
import ctypes

from . import _sodium

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# Public exceptions
class SecureMemoryError(Exception):
    pass


class SecureMemoryClosed(SecureMemoryError):
    pass


class _FallbackBuffer:
    """
    Internal fallback buffer backed by bytearray and exposed via writable memoryview.
    Provides deterministic in-place zeroing where possible.
    """

    def __init__(self, size: int):
        if size < 0:
            raise ValueError("size must be >= 0")
        self._buf = bytearray(size)
        self._mv = memoryview(self._buf).cast("B")
        self._closed = False

    def _ensure_open(self) -> None:
        if self._closed:
            raise SecureMemoryClosed("buffer closed")

    @property
    def mv(self) -> memoryview:
        self._ensure_open()
        return self._mv

    def write(self, offset: int, data: _typing.Union[bytes, bytearray, memoryview]) -> None:
        self._ensure_open()
        self._mv[offset : offset + len(data)] = data

    def read(self, offset: int, length: int) -> bytes:
        self._ensure_open()
        return bytes(self._mv[offset : offset + length])

    def zero(self) -> None:
        if self._closed:
            return
        if len(self._buf) == 0:
            return

        # Best-effort deterministic in-place zero using ctypes on bytearray storage
        try:
            buf_len = len(self._buf)
            c_arr = (ctypes.c_char * buf_len).from_buffer(self._buf)
            ctypes.memset(ctypes.addressof(c_arr), 0, buf_len)
            return
        except Exception:
            pass

        # Fallback: in-place memoryview write
        try:
            self._mv[:] = b"\x00" * len(self._mv)
            return
        except Exception:
            pass

        # Last resort: byte-by-byte
        try:
            for i in range(len(self._mv)):
                self._mv[i] = 0
        except Exception:
            logger.error("FallbackBuffer: final zero fallback failed", exc_info=True)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.zero()
        except Exception:
            pass
        try:
            self._mv.release()
        except Exception:
            pass

        # Make object safe to call methods on accidentally without crashing unpredictably.
        self._closed = True
        self._buf = bytearray(0)
        self._mv = memoryview(self._buf).cast("B")


class SecureMemory:
    """
    Secure memory buffer.

    - alloc(size) / from_bytes(data)
    - write(data, offset=0)
    - read(length=None, offset=0)
    - get_bytes()
    - zero(), close()
    - context manager
    """

    def __init__(self, size: int):
        self.size = int(size)
        if self.size < 0:
            raise ValueError("size must be >= 0")

        self._closed = False
        self._use_sodium = False
        self._ptr = None
        self._fallback: _FallbackBuffer | None = None
        self._mv: memoryview | None = None

        # Prefer libsodium allocation (only if we can get a REAL Python-visible view).
        try:
            if _sodium.have_libsodium():
                ptr, buf_like = _sodium.sodium_alloc_buf(self.size)

                if buf_like is None:
                    # Do NOT create a separate Python bytearray here.
                    # That would desync writes/reads from the sodium pointer.
                    raise RuntimeError("sodium_alloc_buf returned no buffer view")

                self._use_sodium = True
                self._ptr = ptr
                self._mv = memoryview(buf_like).cast("B")

                # Best-effort mlock (some wrappers expose it, some don't)
                try:
                    mlock = getattr(_sodium, "sodium_mlock", None)
                    if mlock is not None:
                        mlock(ptr, self.size)
                except Exception:
                    logger.debug("sodium_mlock failed or not available")

                return
        except Exception:
            logger.debug("libsodium not available or failed; falling back to bytearray buffer")

        # Fallback: bytearray-backed buffer exposed by memoryview
        self._fallback = _FallbackBuffer(self.size)
        self._mv = self._fallback.mv

    def _ensure_open(self) -> None:
        if self._closed:
            raise SecureMemoryClosed("buffer closed")
        if self._mv is None:
            raise SecureMemoryError("internal buffer missing")

    # --- Basic operations ---
    def write(self, data: _typing.Union[bytes, bytearray, memoryview], offset: int = 0) -> None:
        self._ensure_open()

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        if offset < 0:
            raise ValueError("offset must be >= 0")

        n = len(data)
        if offset + n > self.size:
            raise ValueError("write out of bounds")

        self._mv[offset : offset + n] = data

    def read(self, length: int | None = None, offset: int = 0) -> bytes:
        self._ensure_open()

        if offset < 0:
            raise ValueError("offset must be >= 0")
        if length is None:
            length = self.size - offset
        if length < 0:
            raise ValueError("length must be >= 0")
        if offset + length > self.size:
            raise ValueError("read out of bounds")

        return bytes(self._mv[offset : offset + length])

    def get_bytes(self) -> bytes:
        """Return a copy of the secure data as bytes."""
        return self.read()

    # --- Zeroing ---
    def zero(self) -> None:
        # zero() is safe to call after close; it just becomes a no-op
        if self._closed:
            return

        # Prefer libsodium memzero if used
        if self._use_sodium and self._ptr is not None:
            try:
                _sodium.sodium_memzero(self._ptr, self.size)
            except Exception as e:
                logger.debug("sodium_memzero failed: %s", e)

            # Also zero the Python-visible view to ensure reads observe zeros.
            # This should alias the same underlying region if buf_like was correct.
            try:
                if self._mv is not None and self.size:
                    self._mv[:] = b"\x00" * self.size
                return
            except Exception:
                # If we can't write through the view, we still did ptr memzero best-effort.
                return

        # Fallback path
        try:
            if self._fallback is not None:
                self._fallback.zero()
                return
        except Exception:
            logger.debug("fallback.zero() failed; trying memoryview slice")

        # Last resort: in-place memoryview write
        try:
            if self._mv is not None and self.size:
                self._mv[:] = b"\x00" * len(self._mv)
                return
        except Exception as e:
            logger.debug("memoryview slice zero failed: %s", e)

        # Very slow but reliable fallback: byte-by-byte
        try:
            if self._mv is not None:
                for i in range(len(self._mv)):
                    self._mv[i] = 0
        except Exception:
            logger.error("SecureMemory: final zero fallback failed", exc_info=True)

    # --- Close / free ---
    def close(self) -> None:
        if self._closed:
            return

        # Zero first
        try:
            self.zero()
        except Exception:
            pass

        if self._use_sodium and self._ptr is not None:
            # Best-effort munlock + free
            try:
                munlock = getattr(_sodium, "sodium_munlock", None)
                if munlock is not None:
                    try:
                        munlock(self._ptr, self.size)
                    except Exception:
                        pass
                _sodium.sodium_free(self._ptr)
            except Exception:
                logger.debug("sodium_free/sodium_munlock failed (best-effort)")

            # Release view
            try:
                if self._mv is not None:
                    self._mv.release()
            except Exception:
                pass

            self._mv = None
            self._ptr = None
            self._use_sodium = False

        else:
            # Fallback cleanup
            if self._fallback is not None:
                try:
                    self._fallback.close()
                except Exception:
                    pass
                self._fallback = None

            try:
                if self._mv is not None:
                    self._mv.release()
            except Exception:
                pass
            self._mv = None

        self._closed = True

    # Context manager
    def __enter__(self) -> "SecureMemory":
        if self._closed:
            raise SecureMemoryClosed("buffer closed")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # Convenience factories
    @classmethod
    def alloc(cls, size: int) -> "SecureMemory":
        return cls(size)

    @classmethod
    def from_bytes(cls, data: _typing.Union[bytes, bytearray, memoryview]) -> "SecureMemory":
        sm = cls(len(data))
        if len(data):
            sm.write(data, 0)
        return sm


# ---- Convenience helpers ----
@contextlib.contextmanager
def secure_alloc(size: int) -> _typing.Iterator[SecureMemory]:
    sm = SecureMemory.alloc(size)
    try:
        yield sm
    finally:
        sm.close()


def secret_bytes(data: _typing.Union[bytes, bytearray, memoryview]) -> SecureMemory:
    return SecureMemory.from_bytes(data)