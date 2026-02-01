"""
zeroizepy._sodium
------------------

Shim for libsodium allocation functions.

Provides:
- have_libsodium()
- sodium_init()
- sodium_malloc, sodium_free
- sodium_mlock, sodium_munlock
- sodium_memzero
- sodium_alloc_buf(size) -> (ptr, memoryview)

Notes:
- If libsodium unavailable, provides fallback using ctypes buffers.
- Fallback does NOT provide guard pages or strong anti-swap guarantees.
- On POSIX, fallback tries libc mlock/munlock when available.
- On Windows, fallback uses VirtualLock/VirtualUnlock when available.
- All functions are best-effort; failures are logged but not fatal (except malloc failures).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import logging
from typing import Optional, Tuple, Union, Any

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

c_void_p = ctypes.c_void_p
c_size_t = ctypes.c_size_t

_libsodium: Optional[ctypes.CDLL] = None
_have_sodium: bool = False

_libc: Optional[ctypes.CDLL] = None
_have_mlock: bool = False


def _try_load_libsodium() -> Optional[ctypes.CDLL]:
    for name in ("sodium", "libsodium"):
        libname = ctypes.util.find_library(name)
        if not libname:
            continue
        try:
            return ctypes.CDLL(libname)
        except Exception:
            continue
    return None


def _try_load_libc() -> Optional[ctypes.CDLL]:
    if os.name != "posix":
        return None
    # Common libc candidates; find_library("c") usually works on Linux.
    for candidate in ("c", "libc.so.6", "libc.dylib"):
        try:
            return ctypes.CDLL(ctypes.util.find_library(candidate) or candidate)
        except Exception:
            continue
    return None


def _addr(ptr: Any) -> int:
    """
    Normalize pointer-like input to an integer address.
    Supports int, c_void_p, and ctypes instances.
    """
    if ptr is None:
        return 0
    if isinstance(ptr, int):
        return ptr
    if isinstance(ptr, ctypes.c_void_p):
        return int(ptr.value or 0)
    # ctypes instances (including create_string_buffer result)
    try:
        return ctypes.addressof(ptr)
    except Exception:
        pass
    # last resort: try treating as having .value
    try:
        return int(ptr.value)
    except Exception:
        return 0


def _load_windows_kernel32() -> Optional[Any]:
    try:
        return ctypes.windll.kernel32
    except Exception:
        return None


# ---- Load libsodium if present ----
_libsodium = _try_load_libsodium()
if _libsodium:
    try:
        if hasattr(_libsodium, "sodium_init"):
            _libsodium.sodium_init.restype = ctypes.c_int
            rc = _libsodium.sodium_init()
            # sodium_init returns 0 on success, 1 if already initialized, -1 on failure
            if rc < 0:
                raise RuntimeError("sodium_init failed")
        _have_sodium = True
    except Exception:
        _have_sodium = False
        _libsodium = None

# ---- Load libc for mlock/munlock fallback on POSIX ----
if not _have_sodium and os.name == "posix":
    _libc = _try_load_libc()
    if _libc:
        try:
            _libc.mlock.argtypes = (c_void_p, c_size_t)
            _libc.mlock.restype = ctypes.c_int
            _libc.munlock.argtypes = (c_void_p, c_size_t)
            _libc.munlock.restype = ctypes.c_int
            _have_mlock = True
        except Exception:
            _have_mlock = False


# --- Public API -----------------------------------------------------------
def have_libsodium() -> bool:
    return _have_sodium


def sodium_init() -> bool:
    """
    Best-effort initializer. Returns True if libsodium is present and initialized.
    """
    return _have_sodium


if _have_sodium:
    # Bind required libsodium functions
    sodium_malloc = _libsodium.sodium_malloc
    sodium_malloc.argtypes = (c_size_t,)
    sodium_malloc.restype = c_void_p

    sodium_free = _libsodium.sodium_free
    sodium_free.argtypes = (c_void_p,)
    sodium_free.restype = None

    sodium_mlock = getattr(_libsodium, "sodium_mlock", None)
    if sodium_mlock is not None:
        sodium_mlock.argtypes = (c_void_p, c_size_t)
        sodium_mlock.restype = ctypes.c_int

    sodium_munlock = getattr(_libsodium, "sodium_munlock", None)
    if sodium_munlock is not None:
        sodium_munlock.argtypes = (c_void_p, c_size_t)
        sodium_munlock.restype = ctypes.c_int

    sodium_memzero = _libsodium.sodium_memzero
    sodium_memzero.argtypes = (c_void_p, c_size_t)
    sodium_memzero.restype = None

    def sodium_alloc_buf(size: int) -> Tuple[c_void_p, memoryview]:
        """
        Allocate `size` bytes using libsodium and return:
        - ptr: c_void_p (must be freed with sodium_free)
        - mv:  memoryview that ALIASES the sodium allocation (no copying)

        IMPORTANT:
        - The returned memoryview becomes invalid after sodium_free(ptr).
        """
        n = int(size)
        if n < 0:
            raise ValueError("size must be >= 0")

        ptr = sodium_malloc(n)
        if not ptr:
            raise MemoryError("sodium_malloc failed")

        # Create a ctypes array view directly on the allocated address.
        # This aliases the libsodium memory instead of copying it.
        addr = int(ptr.value)
        arr_type = ctypes.c_ubyte * n
        arr = arr_type.from_address(addr)
        mv = memoryview(arr)  # writable, zero-copy view

        return ptr, mv

else:
    # --- Fallback implementations (no libsodium) ---

    # Fallback memory uses ctypes buffers (still better than lying about it).
    def sodium_memzero(ptr: Union[int, ctypes.c_void_p, Any], size: int) -> None:
        try:
            n = int(size)
            if n <= 0:
                return

            a = _addr(ptr)
            if a:
                ctypes.memset(a, 0, n)
                return

            # If ptr is a ctypes buffer object, try buffer protocol
            mv = memoryview(ptr)
            mv[:n] = b"\x00" * n
        except Exception as e:
            logger.debug("Fallback sodium_memzero failed: %s", e)

    def sodium_mlock(ptr: Union[int, ctypes.c_void_p, Any], size: int) -> int:
        n = int(size)
        if n <= 0:
            return 0

        a = _addr(ptr)
        if not a:
            return -1

        if os.name == "nt":
            try:
                k32 = _load_windows_kernel32()
                if not k32:
                    return 0
                k32.VirtualLock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
                k32.VirtualLock.restype = ctypes.c_int
                return int(k32.VirtualLock(ctypes.c_void_p(a), ctypes.c_size_t(n)))
            except Exception as e:
                logger.debug("Fallback VirtualLock failed: %s", e)
                return 0

        if _have_mlock and _libc is not None:
            try:
                return int(_libc.mlock(ctypes.c_void_p(a), ctypes.c_size_t(n)))
            except Exception as e:
                logger.debug("Fallback mlock failed: %s", e)
                return -1

        return -1

    def sodium_munlock(ptr: Union[int, ctypes.c_void_p, Any], size: int) -> int:
        n = int(size)
        if n <= 0:
            return 0

        a = _addr(ptr)
        if not a:
            return -1

        if os.name == "nt":
            try:
                k32 = _load_windows_kernel32()
                if not k32:
                    return 0
                k32.VirtualUnlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
                k32.VirtualUnlock.restype = ctypes.c_int
                return int(k32.VirtualUnlock(ctypes.c_void_p(a), ctypes.c_size_t(n)))
            except Exception as e:
                logger.debug("Fallback VirtualUnlock failed: %s", e)
                return 0

        if _have_mlock and _libc is not None:
            try:
                return int(_libc.munlock(ctypes.c_void_p(a), ctypes.c_size_t(n)))
            except Exception as e:
                logger.debug("Fallback munlock failed: %s", e)
                return -1

        return -1

    def sodium_malloc(size: int) -> Any:
        n = int(size)
        if n < 0:
            raise ValueError("size must be >= 0")
        # Writable buffer living in Python-managed memory.
        return ctypes.create_string_buffer(n)

    def sodium_free(buf: Any) -> None:
        # Best-effort zero the ctypes buffer; then GC handles freeing.
        try:
            mv = memoryview(buf)
            mv[:] = b"\x00" * len(mv)
        except Exception as e:
            logger.debug("Fallback sodium_free zero failed: %s", e)

    def sodium_alloc_buf(size: int) -> Tuple[Any, memoryview]:
        n = int(size)
        if n < 0:
            raise ValueError("size must be >= 0")
        buf = ctypes.create_string_buffer(n)
        mv = memoryview(buf)  # writable view onto ctypes buffer
        return buf, mv


__all__ = [
    "have_libsodium",
    "sodium_init",
    "sodium_malloc",
    "sodium_free",
    "sodium_mlock",
    "sodium_munlock",
    "sodium_memzero",
    "sodium_alloc_buf",
]