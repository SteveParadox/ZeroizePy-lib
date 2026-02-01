"""
Zeroizepy: Secure file deletion, memory zeroization, and cryptographic erasure tools.
"""

from __future__ import annotations

from .file import secure_delete, wipe_free_space
from .memory import SecureMemory, secure_alloc, secret_bytes
from .crypto import CryptoKey, encrypt_data, decrypt_data, cryptographic_erase_key
from .session import secure_session
from .utils import secure_compare, secure_clear
from .os_erase import (
    linux_hdparm_secure_erase,
    linux_nvme_secure_erase,
    macos_diskutil_secure_erase,
    windows_bitlocker_destroy_volume_keys,
)

# Friendly aliases (so users don't have to remember internal naming)
encrypt = encrypt_data
decrypt = decrypt_data
destroy_key = cryptographic_erase_key

__all__ = [
    # file
    "secure_delete",
    "wipe_free_space",

    # memory
    "SecureMemory",
    "secure_alloc",
    "secret_bytes",

    # crypto
    "CryptoKey",
    "encrypt_data",
    "decrypt_data",
    "cryptographic_erase_key",
    "encrypt",
    "decrypt",
    "destroy_key",

    # session
    "secure_session",

    # utils
    "secure_compare",
    "secure_clear",

    # os_erase
    "linux_hdparm_secure_erase",
    "linux_nvme_secure_erase",
    "macos_diskutil_secure_erase",
    "windows_bitlocker_destroy_volume_keys",
]

__version__ = "1.1.5"
__author__ = "Ordu Stephen Chinedu"
__license__ = "MIT"
__copyright__ = "2025 Ordu Stephen Chinedu"