# 🦊 FoxKey — Secure TOTP Manager

Minimalist, secure terminal 2FA client with strong defaults and zero footguns.

## Features
- Encrypted vault (Argon2id + ChaCha20-Poly1305)
- Plaintext label index (list without password)
- otpauth:// URI support
- Clipboard auto-clear + live countdown
- Export / Import encrypted backups
- Change master password
- BusyBox-style single script

## Installation

**From PyPI**
```bash
pip install foxkey
```

**Single binary (recommended)**
```bash
pip install pyinstaller
pyinstaller --onefile --name foxkey foxkey.py
# Move dist/foxkey to ~/bin or /usr/local/bin
```

**Development**
```bash
git clone ... && cd foxkey
pip install -e .
```

## Usage
```bash
foxkey add github otpauth://totp/...
foxkey list
foxkey get github
foxkey export --file backup.enc
foxkey import backup.enc
foxkey change-password
```

## Security Notes
- Master password never touches CLI args
- Vault refuses weak operations
- Clipboard cleared after token lifetime

---
