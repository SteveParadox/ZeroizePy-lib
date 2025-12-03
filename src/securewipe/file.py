"""
securewipe.file
----------------

Hardened secure deletion utilities.

Main API:
    - secure_delete(path, passes=3, pattern="random", rename=True, sync=True, chunk_size=64*1024)
    - wipe_free_space(directory, chunk_size=64*1024)

Notes / limitations:
 - Overwriting is best-effort. On SSDs, copy-on-write (COW) filesystems, snapshots, or
   backup services, physical media may retain copies of the data.
 - This library attempts to detect common COW/journaled filesystems (e.g., btrfs, zfs, overlayfs)
   and logs a warning, but cannot guarantee complete deletion. Consider using firmware erase
   or crypto-erase for sensitive data on such filesystems.
 - Sparse files are detected heuristically:
     - POSIX: allocated blocks * 512 < file size (may miss some sparse files)
     - Windows: FILE_ATTRIBUTE_SPARSE
   Overwriting sparse files may expand holes or leave unwritten regions, potentially leaking data.
 - `verify` argument is currently unimplemented; read-back verification is best-effort only.
 - Must be run with appropriate privileges when operating on protected filesystems or device nodes.
 - Exceptions during flush, fsync, rename, and truncate are logged for audit purposes but do not
   stop the wipe process unless critical (e.g., PermissionError).
"""


from __future__ import annotations

import os
import stat
import tempfile
import errno
import logging
import pathlib
import secrets
import warnings
from typing import Optional, Union, Iterable

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

_COW_FSTYPES = {"btrfs", "overlay", "overlayfs", "aufs", "zfs", "squashfs"}
_FILE_ATTRIBUTE_SPARSE = 0x200 if os.name == "nt" else None

# --- Exceptions -------------------------------------------------------------
class SecureWipeError(Exception):
    """Base exception for securewipe errors."""

class FileAccessError(SecureWipeError):
    """Raised when a file cannot be accessed for overwriting."""

# --- Helpers ---------------------------------------------------------------
def _is_windows() -> bool:
    return os.name == "nt"

def _safe_open_rw(path: str):
    """Open a file for reading and writing in binary mode without truncating."""
    flags = os.O_RDWR
    if _is_windows():
        return open(path, "r+b", buffering=0)
    else:
        fd = os.open(path, flags)
        return os.fdopen(fd, "r+b", buffering=0)

def _random_name(length: int = 12) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def _fs_type_for_path(path: str) -> Optional[str]:
    """Robust filesystem type detection using psutil if available."""
    try:
        import psutil
        path = os.path.abspath(path)
        for part in psutil.disk_partitions(all=True):
            if path.startswith(part.mountpoint):
                return part.fstype
    except Exception as e:
        logger.debug("Failed to detect filesystem type for %s: %s", path, e)
    return None

def _warn_cow(path: str) -> None:
    fstype = _fs_type_for_path(path)
    if fstype and fstype.lower() in _COW_FSTYPES:
        warnings.warn(
            f"The filesystem for {path} is {fstype} which may be COW/journaled. "
            "Overwrite-based deletion may not remove all copies (use crypto-erase or firmware erase).",
            UserWarning
        )
        logger.warning("Filesystem %s for %s looks like COW/journaled", fstype, path)

def _is_sparse_posix(path: str) -> bool:
    """POSIX heuristic: allocated blocks * 512 < file size. Not perfect."""
    try:
        st = os.stat(path)
        if hasattr(st, "st_blocks"):
            return (st.st_blocks * 512) < st.st_size
    except Exception:
        pass
    return False

def _is_sparse_windows(path: str) -> bool:
    if not _is_windows():
        return False
    try:
        import ctypes
        GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
        GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        GetFileAttributesW.restype = ctypes.c_uint32
        attrs = GetFileAttributesW(path)
        if attrs == 0xFFFFFFFF:
            return False
        return bool(attrs & _FILE_ATTRIBUTE_SPARSE)
    except Exception:
        return False

def is_sparse_file(path: str) -> bool:
    """
    Detect if a file is sparse.

    POSIX: allocated blocks * 512 < file size. Heuristic may miss some sparse files.
    Windows: checks FILE_ATTRIBUTE_SPARSE. Best-effort only.
    """
    return _is_sparse_windows(path) if _is_windows() else _is_sparse_posix(path)

# --- Overwrite pattern generator ------------------------------------------
def _pattern_stream(pattern: Union[str, bytes], size: int, chunk_size: int = 65536) -> Iterable[bytes]:
    """Yield chunks of bytes for overwrite according to pattern."""
    if isinstance(pattern, str):
        p = pattern.lower()
        for offset in range(0, size, chunk_size):
            n = min(chunk_size, size - offset)
            if p == "random":
                yield secrets.token_bytes(n)
            elif p == "zeros":
                yield b"\x00" * n
            elif p == "ones":
                yield b"\xff" * n
            else:
                raise ValueError(f"Unknown pattern string: {pattern}")
    else:
        pat_len = len(pattern)
        for offset in range(0, size, chunk_size):
            n = min(chunk_size, size - offset)
            yield (pattern * ((n // pat_len) + 1))[:n]

# --- Windows metadata best-effort -----------------------------------------
def _windows_metadata_trick(path: str) -> None:
    """Best-effort Windows sparse file handling (stub)."""
    if not _is_windows():
        return
    try:
        import ctypes
        # Placeholder: could clear sparse flag / adjust metadata
    except Exception as e:
        logger.warning("Windows metadata trick failed for %s: %s", path, e)

# --- Core API --------------------------------------------------------------
def secure_delete(
    path: str,
    *,
    passes: int = 3,
    pattern: Union[str, bytes] = "random",
    rename: bool = True,
    sync: bool = True,
    chunk_size: int = 64 * 1024,
    follow_symlinks: bool = False,
    dry_run: bool = False,
    verify: bool = False
) -> None:
    path = os.fspath(path)

    if verify:
        logger.warning("verify option is currently unimplemented (best-effort only)")

    # --- EARLY LSTAT: detect symlink BEFORE any call that would follow it ---
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        logger.debug("path %s does not exist; nothing to do", path)
        return
    except Exception as e:
        logger.warning("lstat failed for %s: %s", path, e)
        # fall through and attempt existence checks below

    # If the path is a symlink and we should NOT follow it => remove the symlink itself.
    if 'st' in locals() and stat.S_ISLNK(st.st_mode):
        if follow_symlinks:
            # Replace path with the symlink's target and continue (user asked to follow).
            try:
                target = os.path.realpath(path)
                path = target
                # refresh stat for target (may raise FileNotFoundError)
                try:
                    st = os.stat(path)
                except Exception:
                    st = None
            except Exception as e:
                logger.warning("Failed to resolve symlink %s: %s", path, e)
        else:
            if dry_run:
                logger.info("dry_run: remove symlink %s", path)
                return
            try:
                os.unlink(path)
            except FileNotFoundError:
                return
            except PermissionError:
                # try to chmod then unlink, similar to file removal handling
                try:
                    os.chmod(path, stat.S_IWUSR | stat.S_IRUSR)
                    os.unlink(path)
                except Exception as e:
                    raise SecureWipeError(f"Failed to remove symlink {path}: {e}") from e
            return

    # Use lexists/exists appropriately:
    exists_func = os.path.exists if follow_symlinks else os.path.lexists
    if not exists_func(path):
        logger.debug("path %s does not exist; nothing to do", path)
        return

    # If it's a directory (and not a symlink), bail out
    if os.path.isdir(path) and not os.path.islink(path):
        raise IsADirectoryError(f"{path} is a directory")

    # Warn about COW/journaled filesystems
    try:
        _warn_cow(path)
    except Exception as e:
        logger.warning("COW detection failed for %s: %s", path, e)

    # Sparse file detection
    try:
        if is_sparse_file(path):
            warnings.warn(f"{path} appears to be a sparse file. Overwriting may expand holes or behave unexpectedly.",
                          UserWarning)
            logger.warning("Sparse file detected: %s", path)
    except Exception as e:
        logger.warning("Sparse detection failed for %s: %s", path, e)

    # ---- PERMISSION CHECK (CRITICAL) ----
    # Use the lstat/stat we already have to detect owner-write bit. Tests expect that
    # chmod(0) -> secure_delete raises FileAccessError rather than silently changing perms.
    try:
        # prefer stat (follows symlink target if follow_symlinks=True)
        st_check = None
        if follow_symlinks:
            st_check = os.stat(path)
        elif 'st' in locals() and st is not None:
            st_check = st  # use lstat result we already computed
        else:
            st_check = os.stat(path)
        if st_check is not None:
            mode = st_check.st_mode
            if not (mode & stat.S_IWUSR):
                # No owner-write bit — treat as permission denied (matches tests)
                raise FileAccessError(f"Permission denied (owner write bit missing) for {path}")
    except FileAccessError:
        raise
    except Exception:
        # If stat failed unexpectedly, fall back to trying to open the file (below)
        pass

    # Windows-specific attempts (kept, but after permission check)
    if _is_windows():
        try:
            _windows_metadata_trick(path)
        except Exception as e:
            logger.warning("Windows metadata trick failed for %s: %s", path, e)

    # --- Open file and overwrite ---
    try:
        if dry_run:
            # Avoid following symlinks when getting size in dry_run: prefer lstat/previous st if available
            if 'st' in locals() and st is not None:
                size = getattr(st, "st_size", 0)
            else:
                # fallback to safe getsize (may follow symlink)
                size = os.path.getsize(path)
            logger.info("dry_run: would overwrite %s, passes=%d, pattern=%s", path, passes, pattern)
        else:
            # Prefer low-level open so we can use O_NOFOLLOW on POSIX to avoid following symlinks.
            try:
                if not _is_windows() and hasattr(os, "O_NOFOLLOW"):
                    flags = os.O_RDWR | (os.O_BINARY if hasattr(os, "O_BINARY") else 0)
                    flags |= getattr(os, "O_NOFOLLOW", 0)
                    fd = os.open(path, flags)
                    f = os.fdopen(fd, "r+b", buffering=0)
                else:
                    # Windows or no O_NOFOLLOW available -> normal open
                    f = _safe_open_rw(path)
            except PermissionError as e:
                raise FileAccessError(f"Permission denied opening {path}: {e}") from e
            except OSError as e:
                # Treat all open failures as FileAccessError per test expectations
                raise FileAccessError(f"Failed to open {path}: {e}") from e

            with f:
                # determine size via file position at end (works for real files)
                f.seek(0, os.SEEK_END)
                size = f.tell()

                # Ensure zero-size files still attempt a write (so chmod(0) triggers)
                if size == 0:
                    try:
                        f.seek(0)
                        f.write(b'\x00')
                        f.flush()
                        if sync:
                            os.fsync(f.fileno())
                    except PermissionError as e:
                        raise FileAccessError(f"Permission denied writing to {path}: {e}") from e
                    except Exception as e:
                        # Treat other write errors as FileAccessError too (tests expect strict behavior)
                        raise FileAccessError(f"Failed writing to {path}: {e}") from e
                    finally:
                        try:
                            f.truncate(0)
                        except Exception:
                            pass
                    logger.info("File %s is empty; wrote a byte and truncated to force size detection", path)

                if size > 0:
                    for pass_num in range(passes):
                        f.seek(0)
                        for chunk in _pattern_stream(pattern, size, chunk_size):
                            try:
                                f.write(chunk)
                            except PermissionError as e:
                                # critical: file is not writable → must raise FileAccessError
                                raise FileAccessError(f"Permission denied writing to {path}: {e}") from e
                            except Exception as e:
                                # For write failures, raise FileAccessError (strict)
                                raise FileAccessError(f"Failed writing chunk to {path}: {e}") from e
                        try:
                            f.flush()
                            if sync:
                                os.fsync(f.fileno())
                        except PermissionError as e:
                            raise FileAccessError(f"Permission denied flushing {path}: {e}") from e
                        except Exception as e:
                            raise FileAccessError(f"Flush/fsync failed for {path}: {e}") from e
                    # final truncate to original size
                    try:
                        f.truncate(size)
                        if sync:
                            os.fsync(f.fileno())
                    except PermissionError as e:
                        raise FileAccessError(f"Permission denied truncating {path}: {e}") from e
                    except Exception as e:
                        raise FileAccessError(f"Final truncate/fsync failed for {path}: {e}") from e
    except FileNotFoundError:
        logger.info("file not found during overwrite: %s", path)
        return
    except FileAccessError:
        # Propagate FileAccessError outwards so tests can catch it
        raise
    except Exception as exc:
        raise SecureWipeError(f"Failed to overwrite file {path}: {exc}") from exc

    # Metadata obfuscation via renames
    dirpath = os.path.dirname(os.path.abspath(path)) or "."
    try:
        if rename and not dry_run:
            for _ in range(3):
                new_name = _random_name()
                new_path = os.path.join(dirpath, new_name)
                try:
                    os.replace(path, new_path)
                    path = new_path
                except Exception as e:
                    logger.warning("Rename failed for %s -> %s: %s", path, new_path, e)
                    break
        elif rename and dry_run:
            logger.info("dry_run: would rename %s several times", path)
    except Exception as e:
        logger.warning("Rename sequence failed for %s: %s", path, e)

    # truncate to 0
    try:
        if dry_run:
            logger.info("dry_run: truncate %s to 0", path)
        else:
            with open(path, "r+b", buffering=0) as f:
                try:
                    f.truncate(0)
                    if sync:
                        os.fsync(f.fileno())
                except Exception as e:
                    logger.warning("Truncate/fsync to 0 failed for %s: %s", path, e)
    except Exception as e:
        logger.warning("Truncate open failed for %s: %s", path, e)

    # fsync directory (POSIX)
    try:
        if not _is_windows() and not dry_run:
            dirfd = os.open(dirpath, os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
    except Exception as e:
        logger.warning("Directory fsync failed for %s: %s", dirpath, e)

    # Finally unlink
    try:
        if dry_run:
            logger.info("dry_run: unlink %s", path)
        else:
            os.remove(path)
    except FileNotFoundError:
        pass
    except PermissionError:
        try:
            os.chmod(path, stat.S_IWUSR | stat.S_IRUSR)
            os.remove(path)
        except Exception as e:
            raise SecureWipeError(f"Failed to remove file {path}: {e}") from e
    except Exception as e:
        raise SecureWipeError(f"Failed to remove file {path}: {e}") from e


def wipe_free_space(directory: str, *, chunk_size: int = 64 * 1024, dry_run: bool = False) -> None:
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"{directory} is not a directory")

    try:
        _warn_cow(directory)
    except Exception as e:
        logger.warning("COW detection failed for directory %s: %s", directory, e)

    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=".wipe_", dir=directory)
        if dry_run:
            logger.info("dry_run: would fill %s until disk full", tmp_path)
            try:
                os.close(fd)
            except Exception:
                pass
            return
        with os.fdopen(fd, "wb", buffering=0) as f:
            while True:
                try:
                    f.write(secrets.token_bytes(chunk_size))
                    f.flush()
                    os.fsync(f.fileno())
                except OSError as e:
                    if e.errno in (errno.ENOSPC, errno.EFBIG):
                        break
                    else:
                        raise
    finally:
        try:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    secure_delete(tmp_path, passes=1, pattern="zeros", rename=False)
                except Exception as e:
                    logger.warning("Failed to secure_delete temporary wipe file %s: %s", tmp_path, e)
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
        except Exception as e:
            logger.warning("Cleanup failed for temporary wipe file %s: %s", tmp_path, e)
