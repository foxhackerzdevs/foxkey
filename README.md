# 🦊 FoxKey — Secure TOTP Manager

Minimalist, secure terminal 2FA client with strong defaults and zero footguns.

**More about me / other projects:** [abhrankan.netlify.app](https://abhrankan.netlify.app)

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
git clone https://github.com/foxhackerzdevs/foxkey.git && cd foxkey
pip install -e .
```

## Usage
```bash
foxkey add github                          # prompts for the secret (recommended)
foxkey add github otpauth://totp/...       # also accepted, but exposes the secret
                                            # in shell history and `ps` -- scripting only
foxkey list
foxkey get github
foxkey export --file backup.enc
foxkey import backup.enc
foxkey change-password
```

## Security Notes
- Master password never touches CLI args
- The service secret (`add`'s second argument) is optional and prompted via `getpass` when omitted — same reasoning as the master password: passing it directly leaks it into shell history and `ps`. The positional form still works for scripted use.
- `import` always re-encrypts the vault under its current live master password, even when restoring a backup that was encrypted under a different (e.g. older) password. Importing an old backup can never silently change your master password to match it.
- Vault refuses weak operations
- Clipboard cleared after token lifetime

---
