import os
import tempfile
from pathlib import Path
from securewipe.session import SecureSession
from securewipe.utils import secure_compare

def test_secure_session_temp_file_cleanup():
    with SecureSession() as s:
        temp_file = s.create_temp_file(suffix=".txt")
        assert Path(temp_file).exists()
        # write some data
        with open(temp_file, "wb") as f:
            f.write(b"secret-data")
    # After context exit, file should be gone
    assert not Path(temp_file).exists()

def test_secure_session_secret_memory_cleanup():
    secret_data = b"supersecret"
    with SecureSession() as s:
        sec = s.create_secret(secret_data)
        assert sec.read(len(secret_data)) == secret_data
    # After exit, memory should be zeroed (best-effort)
    # Reading after close raises exception
    try:
        sec.read(1)
        assert False, "Should raise SecureMemoryClosed"
    except Exception:
        pass

def test_secure_session_combined_usage():
    data = b"password123"
    with SecureSession() as s:
        temp_file = s.create_temp_file()
        secret = s.create_secret(data)
        with open(temp_file, "wb") as f:
            f.write(secret.get_bytes())
        # File exists during session
        assert Path(temp_file).exists()
    # File deleted after session
    assert not Path(temp_file).exists()
    # Secret memory closed after session
    try:    
        secret.read(1)
        assert False, "Should raise SecureMemoryClosed" 
    except Exception:
        pass
