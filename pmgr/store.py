from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

from .crypto import b64e, b64d, new_salt, derive_fernet_key, encrypt_json, decrypt_json


def default_vault_path() -> Path:
    # Store in the user's home directory by default
    return Path.home() / ".pmgr" / "vault.pmgr"


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def vault_exists(path: Path) -> bool:
    return path.exists() and path.is_file()


def init_vault(path: Path, master_password: str) -> None:
    """
    Create a new vault file containing:
      - version
      - kdf salt (base64)
      - encrypted data blob (Fernet token)
    """
    ensure_parent_dir(path)
    salt = new_salt()
    key = derive_fernet_key(master_password, salt)
    data = {"items": {}}  # plaintext structure (will be encrypted)
    token = encrypt_json(data, key)

    vault = {
        "version": 1,
        "kdf": {"name": "scrypt", "salt": b64e(salt)},
        "data": token,
    }
    path.write_text(json.dumps(vault, indent=2) + "\n", encoding="utf-8")


def load_vault(path: Path, master_password: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Returns (vault_header, decrypted_data)
    - vault_header: the outer JSON including kdf info + encrypted token
    - decrypted_data: the decrypted inner dict (e.g., {"items": {...}})
    """
    if not vault_exists(path):
        raise FileNotFoundError(f"Vault not found at: {path}")

    vault = json.loads(path.read_text(encoding="utf-8"))
    if vault.get("version") != 1:
        raise ValueError("Unsupported vault version")

    salt_b64 = vault["kdf"]["salt"]
    salt = b64d(salt_b64)
    key = derive_fernet_key(master_password, salt)

    decrypted = decrypt_json(vault["data"], key)
    if "items" not in decrypted or not isinstance(decrypted["items"], dict):
        raise ValueError("Vault data is malformed")
    return vault, decrypted


def save_vault(path: Path, vault_header: Dict[str, Any], master_password: str, decrypted_data: Dict[str, Any]) -> None:
    salt_b64 = vault_header["kdf"]["salt"]
    salt = b64d(salt_b64)
    key = derive_fernet_key(master_password, salt)

    vault_header["data"] = encrypt_json(decrypted_data, key)
    path.write_text(json.dumps(vault_header, indent=2) + "\n", encoding="utf-8")
