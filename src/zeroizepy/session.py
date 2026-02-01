from __future__ import annotations

import os
import tempfile
from pathlib import Path
from contextlib import contextmanager
import logging
from typing import Optional, Union

from .file import secure_delete
from .memory import SecureMemory

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class SecureSession:
    """
    Context manager for a secure session.
    Tracks temporary files and secure memory allocations.
    """

    def __init__(self) -> None:
        self._temp_files: list[Path] = []
        self._secrets: list[SecureMemory] = []
        self._closed: bool = False

    def create_temp_file(
        self,
        suffix: str = "",
        prefix: str = "tmp",
        dir: str | None = None,
    ) -> Path:
        """
        Create a temporary file and track it for secure deletion on exit.

        Notes:
        - On POSIX, attempts to restrict permissions to 0600.
        - On Windows, chmod is not a reliable permission mechanism (ACLs apply).
        """
        self._ensure_open()

        fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)

        try:
            if os.name != "nt":
                try:
                    os.fchmod(fd, 0o600)
                except AttributeError:
                    os.chmod(path, 0o600)
        finally:
            os.close(fd)

        p = Path(path)
        self._temp_files.append(p)
        logger.debug("Created temporary file %s", p)
        return p

    def create_secret(
        self,
        data: Union[bytes, bytearray, memoryview],
        *,
        wipe_input: bool = False,
    ) -> SecureMemory:
        """
        Allocate a secure memory buffer and track it for cleanup.

        Security reality check:
        - If `data` is `bytes`, it already exists in normal Python memory.
        - Prefer passing `bytearray` or `memoryview` if you want the option to wipe input.

        If wipe_input=True and the input is mutable (bytearray/memoryview),
        the input buffer will be zeroed after copying.
        """
        self._ensure_open()

        # Normalize to bytes-like for SecureMemory.from_bytes
        if isinstance(data, memoryview):
            raw = data.tobytes()
            mutable_view = data if data.readonly is False else None
        else:
            raw = bytes(data)
            mutable_view = None

        sec = SecureMemory.from_bytes(raw)
        self._secrets.append(sec)

        if wipe_input:
            # Only wipe mutable sources we can actually modify
            if isinstance(data, bytearray):
                for i in range(len(data)):
                    data[i] = 0
            elif mutable_view is not None:
                mutable_view[:] = b"\x00" * len(mutable_view)

        logger.debug("Allocated SecureMemory of size %d bytes", len(raw))
        return sec

    def close(self) -> None:
        """Idempotent cleanup."""
        if self._closed:
            return
        self._closed = True

        # Wipe memory first
        for sec in self._secrets:
            try:
                sec.close()
                logger.debug("SecureMemory buffer closed and zeroed")
            except Exception as e:
                logger.warning("Failed to close SecureMemory buffer: %s", e)
        self._secrets.clear()

        # Shred temp files
        for path in self._temp_files:
            try:
                secure_delete(str(path), passes=3)
                logger.debug("Temporary file %s securely deleted", path)
            except Exception as e:
                logger.warning("Secure delete failed for %s: %s", path, e)
                # Fallback: at least try removing it
                try:
                    path.unlink(missing_ok=True)  # py3.8+: missing_ok supported
                except TypeError:
                    # missing_ok not available in older versions
                    try:
                        if path.exists():
                            path.unlink()
                    except Exception:
                        pass
                except Exception:
                    pass
        self._temp_files.clear()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("SecureSession is closed")

    def __enter__(self) -> "SecureSession":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


@contextmanager
def secure_session() -> SecureSession:
    """
    Convenience context manager for SecureSession.

    Usage:
        with secure_session() as sess:
            tmp = sess.create_temp_file()
            secret = sess.create_secret(bytearray(b"my secret"), wipe_input=True)
    """
    with SecureSession() as sess:
        yield sess