# SecureWipe

High-assurance secure deletion, secure memory handling, and cryptographic erasure for Python.

SecureWipe provides a full suite of secure-by-design primitives:
- Locked, zeroizable memory
- File wiping & free-space wiping
- Cryptographic erasure (destroy a key → destroy the data)
- AES-GCM authenticated encryption helpers
- Secure temporary sessions

---

## Installation

```bash
pip install securewipe
```

---

# Quick Overview

SecureWipe provides three layers of protection:

1. **Secure Memory**  
   Data stored in locked RAM (`SecureMemory`), explicitly zeroized on close.

2. **File Wiping**  
   Multi-pass secure deletion and free-space wiping (`secure_delete()`, `wipe_free_space()`).

3. **Cryptographic Erasure**  
   AES-GCM encryption + key destruction (`CryptoKey`, `encrypt_data()`, `decrypt_data()`).

---

# Cryptography Module Examples

## Generate a Key, Encrypt, Write Encrypted File, Securely Erase Plaintext

```python
from securewipe.crypto import CryptoKey, encrypt_data, decrypt_data, cryptographic_erase_key
from securewipe.utils import secure_clear

def demo():
    # Generate AES-256 key stored in SecureMemory
    key = CryptoKey.generate(32)

    # Load plaintext into a mutable buffer
    with open("secret.txt", "rb") as f:
        plaintext = bytearray(f.read())

    # Encrypt using AES-GCM
    ct = encrypt_data(plaintext, key)

    # Write encrypted bytes to disk
    with open("secret.enc", "wb") as f:
        f.write(ct.nonce + ct.ciphertext)

    # Securely erase plaintext from RAM
    secure_clear(plaintext)

    # Demonstrate decryption while key still exists
    recovered = decrypt_data(ct, key)
    print("Recovered:", recovered.decode())

    # Cryptographically erase data by destroying the key
    cryptographic_erase_key(key)
```

---

## Simple Encrypt/Decrypt With Additional Authenticated Data (AAD)

```python
from securewipe.crypto import CryptoKey, encrypt_data, decrypt_data

key = CryptoKey.generate()

pt = b"SENSITIVE-DATA"
aad = b"context-info"

ct = encrypt_data(pt, key, associated_data=aad)
print("Ciphertext:", ct.ciphertext.hex())

recovered = decrypt_data(ct, key, associated_data=aad)
print("Recovered:", recovered)
```

---

## Cryptographic Erasure Demonstration

Once you call:

```python
key.destroy()
```

All data encrypted with that key becomes permanently lost, even if `secret.enc` still exists.

---

# Secure Memory Examples

```python
from securewipe.memory import SecureMemory, secret_bytes

# Allocate 32 bytes of secure memory
s = SecureMemory.alloc(32)
s.write(b"supersecret")
print(s.read(11))  # b'supersecret'
s.zero()
s.close()

# Convenience wrapper
sec = secret_bytes(b"topsecret")
print(sec.read(9))
sec.close()
```

---

# Secure File Wiping

```python
from securewipe.file import secure_delete

# Multi-pass overwrite + unlink
secure_delete("secret.txt", passes=3, pattern="random")
```

### Free-Space Wiping

```python
from securewipe.file import wipe_free_space

wipe_free_space("/tmp", dry_run=True)
```

---

# Secure Session Usage

Temporary secrets, temp files, and auto-cleanup:

```python
from securewipe.session import SecureSession

with SecureSession() as session:
    temp_file = session.create_temp_file(".txt")
    secret = session.create_secret(b"password123")

    with open(temp_file, "wb") as f:
        f.write(secret.get_bytes())

# On exit:
# - Secret wiped
# - Temp files securely deleted
```

---

# Limitations & Important Security Notes

## Python Object Copies
Python duplicates immutable objects (`bytes`, `str`), which cannot be securely zeroed.

To minimize exposure:
- Prefer `bytearray` or `memoryview`
- Avoid long-lived plaintext copies
- Minimize use of `.get_bytes()` on `CryptoKey` or `SecureMemory`

---

## Libsodium Recommended
If available, SecureWipe uses libsodium’s hardened memory primitives:
- `sodium_malloc()` guarded pages
- `sodium_mlock()` secure locking
- `sodium_memzero()`

Install on Linux:

```bash
sudo apt install libsodium23 libsodium-dev
```

---

## Windows Memory-Locking Limitations
Windows has no true mlock equivalent.

Fallback behavior:
- Memory is zeroed properly
- Pages cannot be made non-swappable at the OS level
- Installing libsodium on Windows improves security

---

## Garbage Collector Timing
Python’s garbage collector may temporarily hold:
- Intermediate buffers
- Copies made by internal operations
- Bytes objects created implicitly

Mitigation:
- Use `bytearray` for plaintext
- Avoid converting secrets to `str`
- Keep sensitive data in secure buffers

---

## System Privileges for Locked Memory
Some OSes restrict locked memory usage.

Linux may require:

```bash
ulimit -l
```

Increase if needed.

---

# Testing

```bash
pytest
```

Some tests are skipped on Windows due to OS behavior differences.

---

# License

MIT License — free for commercial use, open-source projects, academic work, and integration into products.
