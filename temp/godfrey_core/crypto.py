"""Crypto helpers for Godfrey core logic."""

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

AES_GCM_HEADER = b"GCM1"


def derive_aes_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data: str, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_aes_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data.encode("utf-8"), None)
    return AES_GCM_HEADER + salt + nonce + ciphertext


def decrypt_data_legacy_cbc(encrypted: bytes, password: str) -> str:
    if len(encrypted) < 32:
        raise ValueError("Corrupted encrypted payload.")

    salt = encrypted[:16]
    iv = encrypted[16:32]
    ciphertext = encrypted[32:]
    key = derive_aes_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode("utf-8")


def decrypt_data(encrypted: bytes, password: str) -> str:
    if not encrypted:
        return ""

    if encrypted.startswith(AES_GCM_HEADER):
        if len(encrypted) < 4 + 16 + 12 + 16:
            raise ValueError("Corrupted GCM payload.")

        salt = encrypted[4:20]
        nonce = encrypted[20:32]
        ciphertext = encrypted[32:]
        key = derive_aes_key(password, salt)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    # Backward compatibility for old CBC payloads.
    return decrypt_data_legacy_cbc(encrypted, password)
