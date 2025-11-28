import os
from pathlib import Path
import tempfile

from securewipe.file import secure_delete, wipe_free_space

def test_secure_delete_creates_no_file(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_bytes(b"super-secret-data")
    secure_delete(str(p), passes=2, pattern="random", dry_run=True)  # dry run should not remove in dry mode
    assert p.exists()

def test_secure_delete_removes_file(tmp_path):
    p = tmp_path / "secret2.txt"
    p.write_bytes(b"hello-world")
    secure_delete(str(p), passes=1, pattern="zeros", dry_run=False)
    assert not p.exists()

def test_wipe_free_space_dry(tmp_path):
    # create some files so directory is valid
    (tmp_path / "a").write_text("x")
    wipe_free_space(str(tmp_path), chunk_size=4096, dry_run=True)
    # No exception means success    
    