from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def b64d(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt.encode("utf-8"))


def new_salt(length: int = 16) -> bytes:
    return os.urandom(length)


def derive_fernet_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a Fernet key from a master password using scrypt.
    Returns a urlsafe base64-encoded 32-byte key, suitable for Fernet().
    """
    if not master_password:
        raise ValueError("Master password cannot be empty")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def encrypt_json(data: Dict[str, Any], fernet_key: bytes) -> str:
    f = Fernet(fernet_key)
    raw = json.dumps(data, sort_keys=True).encode("utf-8")
    token = f.encrypt(raw)
    return token.decode("utf-8")


def decrypt_json(token: str, fernet_key: bytes) -> Dict[str, Any]:
    f = Fernet(fernet_key)
    try:
        raw = f.decrypt(token.encode("utf-8"))
    except InvalidToken as e:
        raise ValueError("Invalid master password (or corrupted vault).") from e
    return json.loads(raw.decode("utf-8"))
