# core/totp.py
import hashlib
import hmac
import struct
import time
from base64 import b32decode

_ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

def generate_totp(secret: str, time_step: int = 30, digits: int = 6, algorithm: str = "SHA1") -> str:
    """Generates an RFC 6238 TOTP token with clean base32 padding."""
    clean_secret = secret.upper().replace(' ', '')
    missing_padding = len(clean_secret) % 8
    if missing_padding:
        clean_secret += '=' * (8 - missing_padding)

    key = b32decode(clean_secret)
    counter = int(time.time()) // time_step
    return hotp(key, counter, digits, algorithm)

def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    """Generates an RFC 4226 HOTP token value."""
    digestmod = _ALGORITHMS.get(algorithm.upper())
    if digestmod is None:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. Choose from: {', '.join(_ALGORITHMS)}"
        )
    counter_bytes = struct.pack('>Q', counter)
    hmac_hash = hmac.new(key, counter_bytes, digestmod).digest()
    offset = hmac_hash[-1] & 0x0F
    binary = struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)
