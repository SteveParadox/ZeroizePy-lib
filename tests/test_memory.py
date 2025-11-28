import os
from securewipe.memory import SecureMemory, secret_bytes, secure_alloc

def test_secure_memory_write_and_zero():
    s = SecureMemory.alloc(32)
    try:
        s.write(b"hello-world", 0)
        assert s.read(11) == b"hello-world"
        # zero and check
        s.zero()
        assert s.read(11) == b"\x00" * 11
    finally:
        s.close()

def test_secret_bytes_contextmgr():
    with secure_alloc(16) as s:
        s.write(b"password123", 0)
        assert s.read(11) == b"password123"
    # after context exit buffer is closed; ensure close didn't raise
    assert s._closed