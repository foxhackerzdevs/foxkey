# core/crypto.py
import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12

def derive_key(master_password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derives a key from password using Argon2id, generating salt if missing."""
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    kdf = Argon2id(
        length=KEY_SIZE,
        salt=salt,
        iterations=2,
        memory_cost=64 * 1024,  # 64 MiB (safe for mobile load profiles)
        lanes=4
    )
    key = kdf.derive(master_password.encode('utf-8'))
    return key, salt

def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypts payload using ChaCha20Poly1305 AEAD."""
    nonce = os.urandom(NONCE_SIZE)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt(encrypted: bytes, key: bytes) -> bytes:
    """Decrypts payload using ChaCha20Poly1305 AEAD."""
    nonce = encrypted[:NONCE_SIZE]
    ciphertext = encrypted[NONCE_SIZE:]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, None)
