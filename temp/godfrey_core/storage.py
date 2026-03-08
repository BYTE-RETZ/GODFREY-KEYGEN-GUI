"""Encrypted storage helpers for Godfrey core logic."""

import os
import tempfile
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag

from .crypto import AES_GCM_HEADER, decrypt_data, encrypt_data


class DecryptionError(Exception):
    """Raised when encrypted payload cannot be decrypted."""


class StorageWriteError(Exception):
    """Raised when an encrypted file cannot be written."""


@dataclass(frozen=True)
class StoragePaths:
    data_dir: str
    master_key_file: str
    password_store_file: str


def resolve_data_dir(base_dir: str | None = None) -> str:
    script_dir = base_dir or os.getcwd()
    fallback_dir = os.path.join(os.path.expanduser("~"), ".godfrey")

    for candidate in (script_dir, fallback_dir):
        try:
            os.makedirs(candidate, exist_ok=True)
            test_path = os.path.join(candidate, ".godfrey_write_test")
            with open(test_path, "wb") as handle:
                handle.write(b"ok")
            os.remove(test_path)
            return candidate
        except OSError:
            continue

    return script_dir


def build_storage_paths(base_dir: str | None = None) -> StoragePaths:
    data_dir = resolve_data_dir(base_dir)
    return StoragePaths(
        data_dir=data_dir,
        master_key_file=os.path.join(data_dir, "master.key"),
        password_store_file=os.path.join(data_dir, "passwords.enc"),
    )


def write_encrypted_file(path: str, plaintext: str, password: str) -> None:
    encrypted = encrypt_data(plaintext, password)
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(
        prefix=f"{os.path.basename(path)}.",
        suffix=".tmp",
        dir=directory,
    )

    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encrypted)

        try:
            os.replace(temp_path, path)
        except PermissionError:
            if os.path.exists(path):
                os.chmod(path, 0o666)
                os.replace(temp_path, path)
            else:
                raise
    except OSError as exc:
        raise StorageWriteError(str(exc)) from exc
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def read_encrypted_file(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def save_master_password(master_key_file: str, password: str) -> None:
    write_encrypted_file(master_key_file, password, password)


def verify_master_password(master_key_file: str, password: str) -> bool:
    if not password or not os.path.exists(master_key_file):
        return False

    encrypted = read_encrypted_file(master_key_file)
    try:
        is_valid = decrypt_data(encrypted, password) == password
        if is_valid and not encrypted.startswith(AES_GCM_HEADER):
            save_master_password(master_key_file, password)
        return is_valid
    except (ValueError, InvalidTag, UnicodeDecodeError, OSError):
        return False


def read_password_store(password_store_file: str, master_password: str) -> str:
    if not os.path.exists(password_store_file):
        return ""

    encrypted = read_encrypted_file(password_store_file)
    if not encrypted:
        return ""

    try:
        content = decrypt_data(encrypted, master_password)
    except (ValueError, InvalidTag, UnicodeDecodeError) as exc:
        raise DecryptionError(str(exc)) from exc

    if not encrypted.startswith(AES_GCM_HEADER):
        write_encrypted_file(password_store_file, content, master_password)

    return content


def write_password_store(password_store_file: str, content: str, master_password: str) -> None:
    write_encrypted_file(password_store_file, content, master_password)


def encrypt_existing_passwords(password_store_file: str, old_password: str, new_password: str) -> None:
    if not os.path.exists(password_store_file):
        return

    try:
        old_data = read_password_store(password_store_file, old_password)
    except DecryptionError:
        old_data = ""

    write_password_store(password_store_file, old_data, new_password)
