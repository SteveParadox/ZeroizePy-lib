import pytest
from securewipe.crypto import CryptoKey, encrypt_data, decrypt_data, cryptographic_erase_key
from securewipe.memory import SecureMemoryClosed

def test_crypto_key_generation():
    key = CryptoKey.generate()
    key_bytes = key.get_bytes()
    assert isinstance(key_bytes, bytes)
    assert len(key_bytes) == 32  # AES-256 default
    key.destroy()
    # After destruction, accessing memory should raise
    with pytest.raises(SecureMemoryClosed):
        key.get_bytes()

def test_encrypt_decrypt_buffer():
    key = CryptoKey.generate()
    data = b"top-secret-data"
    ciphertext = encrypt_data(data, key)
    assert isinstance(ciphertext, bytes)
    plaintext = decrypt_data(ciphertext, key)
    assert plaintext == data
    key.destroy()

def test_encrypt_decrypt_with_associated_data():
    key = CryptoKey.generate()
    data = b"confidential"
    aad = b"metadata"
    ciphertext = encrypt_data(data, key, associated_data=aad)
    decrypted = decrypt_data(ciphertext, key, associated_data=aad)
    assert decrypted == data
    key.destroy()

def test_cryptographic_erase_key():
    key = CryptoKey.generate()
    key_bytes_before = key.get_bytes()
    assert key_bytes_before != b"\x00" * 32
    cryptographic_erase_key(key)
    # Attempting to access key should raise SecureMemoryClosed
    with pytest.raises(SecureMemoryClosed):
        key.get_bytes()
