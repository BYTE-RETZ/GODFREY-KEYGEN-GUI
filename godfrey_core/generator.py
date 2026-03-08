"""Password-generation helpers for Godfrey core logic."""

import base91
from argon2.low_level import Type, hash_secret_raw

SALT_MIN_LENGTH = 8


def validate_password_inputs(word: str, salt: str) -> None:
    if not word or not salt:
        raise ValueError("PLEASE ENTER BOTH WORD AND SALT.")

    if len(salt.encode("utf-8")) < SALT_MIN_LENGTH:
        raise ValueError("SALT MUST BE AT LEAST 8 CHARACTERS.")


def generate_password_artifacts(word: str, salt: str) -> dict[str, str]:
    validate_password_inputs(word, salt)

    hashed = hash_secret_raw(
        secret=word.encode("utf-8"),
        salt=salt.encode("utf-8"),
        time_cost=15,
        memory_cost=2**17,
        parallelism=4,
        hash_len=17,
        type=Type.I,
    )
    hex_hash = hashed.hex()
    reversed_hex = hex_hash[::-1]
    b91_encoded = base91.encode(reversed_hex.encode("utf-8"))
    final_password = b91_encoded[::-1]

    return {
        "hex_hash": hex_hash,
        "reversed_hex": reversed_hex,
        "base91_encoded": b91_encoded,
        "final_password": final_password,
    }


def generate_password_from_inputs(word: str, salt: str) -> str:
    return generate_password_artifacts(word, salt)["final_password"]
