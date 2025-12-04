# ZeroizePy

High-assurance secure deletion, secure memory handling and cryptographic erasure for Python.

ZeroizePy provides a modern, cross-platform suite of primitives for handling sensitive data safely.
It is designed for applications that require defense-in-depth: password managers, HSM glue code, data-at-rest protection, secure messaging and high-security Python systems.

It includes:

* Locked, zeroizable RAM (SecureMemory)
* Secure file wiping (multi-pass overwrite, free-space wiping)
* Cryptographic erasure (destroy a key → destroy the data)
* AES-GCM authenticated encryption helpers
* Secure temporary sessions (auto-delete on exit)

---

## Installation

```bash
pip install zeroizepy
```

---

# Quick Start (Hello World)

```python
from zeroizepy.file import secure_delete
from zeroizepy.crypto import CryptoKey, encrypt_data

# Securely delete a file
secure_delete("secret.txt", passes=3)

# Encrypt something with a secure key
key = CryptoKey.generate(32)
ct = encrypt_data(b"hello world", key)
print("Encrypted:", ct.ciphertext.hex())
```

---

# Overview of Protection Layers

ZeroizePy implements five protection layers:

1. **Secure Memory**
   * Explicitly zeroizable buffers
   * Locked RAM (non-swappable when libsodium is available)
   * Safe handling for sensitive in-process secrets
   * Guaranteed wipe on .close() or context exit

2. **File Wiping**
   * Multi-pass secure deletion: random or fixed patterns (`secure_delete()`)
   * Full overwrite of file contents before unlinking
   * Free-space wiping (`wipe_free_space()`) to overwrite unallocated disk blocks
   * Symlink-aware deletion controls

3. **Cryptographic Erasure**
   * AES-GCM encryption with authenticated metadata (`CryptoKey`)
   * `CryptoKey` objects that can be destroyed in memory
   * Destroy the key → all encrypted data irreversibly lost
   * Designed for SSDs, COW filesystems, and other overwrite-hostile storage

4. **Secure Temporary Sessions**
   * `SecureSession` tracks temporary files, memory regions and secrets
   * Automatically zeroes memory and deletes files on exit
   * Ideal for one-shot secure operations

5. **OS-Level Erase Wrappers (Advanced)**
   * Interfaces for: hdparm, NVMe Secure Erase, APFS diskutil, BitLocker
   * Extremely dangerous and destructive if misused — disabled by default
   * Intended for expert operators only

---

# Quick Examples

## Cryptography Module

### Generate Key, Encrypt, and Cryptographically Erase

```python
from zeroizepy.crypto import CryptoKey, encrypt_data, decrypt_data, cryptographic_erase_key
from zeroizepy.utils import secure_clear

key = CryptoKey.generate(32)

with open("secret.txt", "rb") as f:
    plaintext = bytearray(f.read())

ct = encrypt_data(plaintext, key)

with open("secret.enc", "wb") as f:
    f.write(ct.nonce + ct.ciphertext)

secure_clear(plaintext)

recovered = decrypt_data(ct, key)
print("Recovered:", recovered.decode())

cryptographic_erase_key(key)
```

### Encrypt/Decrypt with AAD

```python
key = CryptoKey.generate()
pt = b"SENSITIVE-DATA"
aad = b"context-info"

ct = encrypt_data(pt, key, associated_data=aad)
recovered = decrypt_data(ct, key, associated_data=aad)
print(recovered)
```

---

## Secure Memory

```python
from zeroizepy.memory import SecureMemory, secret_bytes

s = SecureMemory.alloc(32)
s.write(b"supersecret")
print(s.read(11))
s.zero()
s.close()

sec = secret_bytes(b"topsecret")
print(sec.read(9))
sec.close()
```

---

## File Wiping

```python
from zeroizepy.file import secure_delete, wipe_free_space

secure_delete("secret.txt", passes=3, pattern="random")
wipe_free_space("/tmp", dry_run=True)
```

---

## Secure Session

```python
from zeroizepy.session import SecureSession

with SecureSession() as session:
    temp_file = session.create_temp_file(".txt")
    secret = session.create_secret(b"password123")

    with open(temp_file, "wb") as f:
        f.write(secret.get_bytes())
# On exit: memory zeroed, temp files deleted
```

---

# Limitations & Security Notes

## Cross-Platform Notes

| Feature                        | POSIX (Linux/macOS)                            | Windows                                                                        |
| ------------------------------ | ---------------------------------------------- | ------------------------------------------------------------------------------ |
| Symlink Handling               | Fully supported; `follow_symlinks` honored     | Some behaviors differ; tests skipped where behavior differs                    |
| Sparse File Detection          | Heuristics applied                             | Sparse heuristics differ; warnings may differ                                  |
| `chmod(0)` Permission Model    | Enforced; deletion may raise `FileAccessError` | Behavior differs; some tests skipped                                           |
| SecureMemory Zeroing           | Zeroing observable in tests                    | Observing zeroing is unreliable due to Python memory copies and OS protections |
| Memory Locking                 | `mlock` available (libsodium recommended)      | `VirtualLock` less effective; libsodium strongly preferred                     |

* Immutable Python objects (`bytes`, `str`) cannot be zeroed. Prefer `bytearray` or `memoryview`
* Libsodium recommended for locked memory
* Always use `.close()` or context manager for memory zeroing
* File system or OS limitations may prevent complete erasure on SSDs or COW filesystems

---

# Threat Model

ZeroizePy provides high-assurance secure deletion primitives, but only within realistic limits of modern operating systems.

### ZeroizePy Defends Against:

* Forensic recovery of overwritten files
* Accidental retention of plaintext in process memory
* Recovery after cryptographic key destruction
* Undeleted temp files and leaked memory buffers
* Users mistakenly loading sensitive data into Python `bytes`

### ZeroizePy cannot defend against:

* Full-disk snapshots (btrfs, ZFS, VM snapshots)
* SSD wear-leveling remapping (overwriting does not guarantee physical erasure)
* Kernel-level memory scanners
* DMA attacks or root access attackers
* Malware that runs inside the same Python process
* Cloud-provider persistent block-level backups you do not control

### Partial Mitigations

| Risk                     | What ZeroizePy Does                        |
|---------------------------|-------------------------------------------|
| SSD wear-leveling         | Recommend crypto-erasure                  |
| Python copies memory      | Encourages bytearray/memoryview           |
| OS won’t allow locked pages | Falls back with warnings                 |
| Hard failures during deletion | Raises FileAccessError                  |

---

# Testing

```bash
pytest
```

Some tests skip on Windows due to OS differences.

---

# License

MIT License — free for commercial, open-source, academic, and integrated use.
