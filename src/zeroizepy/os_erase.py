"""
zeroizepy.os_erase
------------------

Wrappers for OS-level secure erase operations.

This module intentionally DOES NOT execute destructive commands.
It only provides:
- OS checks
- tool availability checks
- input validation
- structured warnings/errors

Why? Because one bug here can destroy a user's system.

Advanced users should run vendor/OS commands manually and carefully.
"""

from __future__ import annotations

import logging
import platform
import re
import shutil
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

_SYSTEM = platform.system()


# ------------------- Exceptions -------------------

class OSEraseError(RuntimeError):
    """Base error for os_erase module."""


class OSEraseUnsupported(OSEraseError):
    """Raised when the current OS is unsupported for an operation."""


class OSEraseToolMissing(OSEraseError):
    """Raised when a required OS tool/CLI is missing."""


class OSEraseValidationError(ValueError):
    """Raised when user input fails validation."""


class OSEraseNotImplemented(OSEraseError):
    """Raised because this module intentionally refuses to run destructive operations."""


# ------------------- Helpers -------------------

@dataclass(frozen=True)
class EraseRequest:
    """
    Structured request description (non-executable).
    """
    os: str
    method: str
    target: str
    notes: str


def _require_os(expected: str) -> None:
    if _SYSTEM != expected:
        raise OSEraseUnsupported(f"This function only runs on {expected} (current: {_SYSTEM})")


def _require_tool(tool: str) -> None:
    if not shutil.which(tool):
        raise OSEraseToolMissing(f"Required tool not found: {tool}")


def _validate_raw_device_path(device_path: str) -> None:
    # Keep this strict. No relative paths. No weird whitespace.
    if not isinstance(device_path, str) or not device_path:
        raise OSEraseValidationError("device_path must be a non-empty string")
    if any(ch.isspace() for ch in device_path):
        raise OSEraseValidationError("device_path must not contain whitespace")
    if not device_path.startswith("/dev/"):
        raise OSEraseValidationError("device_path must be a raw device like /dev/sda")
    # Disallow obviously dangerous patterns like partitions? Up to you.
    # We'll allow partitions but validate basic shape.
    if not re.fullmatch(r"/dev/[A-Za-z0-9._-]+", device_path):
        raise OSEraseValidationError("device_path contains invalid characters")


def _validate_nvme_device_path(device_path: str) -> None:
    _validate_raw_device_path(device_path)
    # Typical NVMe namespace path: /dev/nvme0n1 or /dev/nvme0n1p1
    if not device_path.startswith("/dev/nvme"):
        raise OSEraseValidationError("device_path must look like /dev/nvme0n1 (NVMe device)")


def _validate_macos_disk(disk: str) -> None:
    if not isinstance(disk, str) or not disk:
        raise OSEraseValidationError("disk must be a non-empty string")
    if any(ch.isspace() for ch in disk):
        raise OSEraseValidationError("disk must not contain whitespace")
    if not disk.startswith("/dev/disk"):
        raise OSEraseValidationError("disk must look like /dev/diskX")
    if not re.fullmatch(r"/dev/disk\d+", disk):
        raise OSEraseValidationError("disk must be a whole disk like /dev/disk2 (not a slice/partition)")


def _validate_windows_volume(volume: str) -> None:
    if not isinstance(volume, str) or not volume:
        raise OSEraseValidationError("volume must be a non-empty string")
    # Accept "C:" or "C:\\" but normalize mentally to "C:"
    v = volume.strip()
    if not re.fullmatch(r"[A-Za-z]:\\?", v):
        raise OSEraseValidationError('volume must look like "C:"')
    # Avoid network paths and nonsense
    if v.startswith("\\\\"):
        raise OSEraseValidationError("volume must not be a UNC/network path")


def _refuse_execution(req: EraseRequest) -> None:
    logger.warning(
        "DANGEROUS OPERATION REQUESTED: method=%s target=%s os=%s. Refusing to execute.",
        req.method, req.target, req.os
    )
    raise OSEraseNotImplemented(
        "This module does not execute secure-erase operations. "
        "It only validates inputs and logs warnings. "
        "Run destructive OS/vendor commands manually."
    )


# ------------------- Linux -------------------

def linux_hdparm_secure_erase(device_path: str) -> None:
    """
    Validate a Linux ATA secure erase request (hdparm).
    Refuses to execute destructive commands.
    """
    _require_os("Linux")
    _require_tool("hdparm")
    _validate_raw_device_path(device_path)

    req = EraseRequest(
        os="Linux",
        method="hdparm_secure_erase",
        target=device_path,
        notes="ATA Secure Erase is destructive and device-dependent. Manual execution required."
    )

    logger.warning(
        "!!! DANGER !!! Requested hdparm secure erase of %s. Manual execution required.",
        device_path
    )
    _refuse_execution(req)


def linux_nvme_secure_erase(device_path: str) -> None:
    """
    Validate a Linux NVMe secure erase request (nvme-cli).
    Refuses to execute destructive commands.
    """
    _require_os("Linux")
    _require_tool("nvme")
    _validate_nvme_device_path(device_path)

    req = EraseRequest(
        os="Linux",
        method="nvme_secure_erase",
        target=device_path,
        notes="NVMe sanitize/format options are destructive and vary by device. Manual execution required."
    )

    logger.warning(
        "!!! DANGER !!! Requested NVMe secure erase of %s. Manual execution required.",
        device_path
    )
    _refuse_execution(req)


# ------------------- macOS -------------------

def macos_diskutil_secure_erase(disk: str, level: int = 0) -> None:
    """
    Validate a macOS diskutil secure erase request.
    Refuses to execute destructive commands.
    """
    _require_os("Darwin")
    _require_tool("diskutil")
    _validate_macos_disk(disk)

    if not isinstance(level, int) or level < 0:
        raise OSEraseValidationError("level must be a non-negative integer")

    req = EraseRequest(
        os="Darwin",
        method="diskutil_secure_erase",
        target=disk,
        notes=f"Secure erase levels are destructive; behavior varies. Requested level={level}. Manual execution required."
    )

    logger.warning(
        "!!! DANGER !!! Requested diskutil secure erase of %s at level %d. Manual execution required.",
        disk, level
    )
    _refuse_execution(req)


# ------------------- Windows -------------------

def windows_bitlocker_destroy_volume_keys(volume: str) -> None:
    """
    Validate a Windows BitLocker key-destruction request.
    Refuses to execute destructive commands.
    """
    _require_os("Windows")
    _require_tool("manage-bde")
    _validate_windows_volume(volume)

    req = EraseRequest(
        os="Windows",
        method="bitlocker_destroy_keys",
        target=volume,
        notes="Key destruction is irreversible for practical purposes. Manual execution required."
    )

    logger.warning(
        "!!! DANGER !!! Requested BitLocker key destruction for %s. Manual execution required.",
        volume
    )
    _refuse_execution(req)


__all__ = [
    "OSEraseError",
    "OSEraseUnsupported",
    "OSEraseToolMissing",
    "OSEraseValidationError",
    "OSEraseNotImplemented",
    "EraseRequest",
    "linux_hdparm_secure_erase",
    "linux_nvme_secure_erase",
    "macos_diskutil_secure_erase",
    "windows_bitlocker_destroy_volume_keys",
]