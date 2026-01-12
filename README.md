# Password Manager (pmgr)

A small password manager built to practice secure local storage, encryption, and a clean CLI workflow.

## Features
- Encrypted vault stored locally (no plaintext secrets written to disk)
- Master password required to unlock the vault
- Simple commands: init, add, get, list, delete
- Safe output defaults (passwords are masked unless you explicitly reveal them)

## How it works (high level)
- A vault file is created in `~/.pmgr/`
- A key is derived from your master password using a KDF (scrypt)
- Vault contents are encrypted using Fernet (symmetric authenticated encryption)

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
Initialize a vault:
```bash
python -m pmgr init
```

Add or update an entry:
```bash
python -m pmgr add github -u harshit@example.com
```

List entries (no passwords shown):
```bash
python -m pmgr list
```

Get an entry (masked by default):
```bash
python -m pmgr get github
```

Reveal the password:
```bash
python -m pmgr get github --show
```

Delete an entry:
```bash
python -m pmgr delete github
```

## Project structure
- `pmgr/cli.py` CLI commands and user interaction
- `pmgr/crypto.py` key derivation and encryption helpers
- `pmgr/store.py` vault read and write logic

## Security notes
This is a learning project, not a production password manager.
- Use a strong master password
- Treat your machine account as part of the security boundary
- Back up your vault carefully (if you lose it, you lose the secrets)

## Roadmap
- Add tests and CI
- Add password generator command
- Add entry notes and tags
- Add export and import (encrypted) and a vault lock timeout

## License
MIT