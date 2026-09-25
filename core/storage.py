# core/storage.py
import json
import os
import struct
import shutil
from pathlib import Path
from cryptography.exceptions import InvalidTag
from .crypto import derive_key, encrypt, decrypt, SALT_SIZE

VAULT_PATH = Path.home() / ".foxkey" / "vault.enc"

class Vault:
    def __init__(self):
        self.entries = {}

    def get_public_labels(self) -> list[str]:
        if not VAULT_PATH.exists():
            return []
        try:
            payload = VAULT_PATH.read_bytes()
            if len(payload) < SALT_SIZE + 4:
                return []
            header_len = struct.unpack('>I', payload[SALT_SIZE:SALT_SIZE+4])[0]
            header_bytes = payload[SALT_SIZE+4 : SALT_SIZE+4+header_len]
            return json.loads(header_bytes.decode('utf-8'))
        except Exception:
            return []

    def load(self, master_password: str, path: Path = None) -> bool:
        path = path or VAULT_PATH
        if not path.exists():
            return True
        payload = path.read_bytes()
        if len(payload) < SALT_SIZE + 4:
            raise ValueError("Corrupt vault file.")

        salt = payload[:SALT_SIZE]
        header_len = struct.unpack('>I', payload[SALT_SIZE:SALT_SIZE+4])[0]
        encrypted_data = payload[SALT_SIZE + 4 + header_len:]

        if not encrypted_data:
            raise ValueError("Corrupt vault file: ciphertext block missing.")

        key, _ = derive_key(master_password, salt)
        try:
            decrypted = decrypt(encrypted_data, key)
            self.entries = json.loads(decrypted.decode('utf-8'))
            return True
        except InvalidTag:
            return False

    def save(self, master_password: str):
        key, salt = derive_key(master_password, None)
        labels = list(self.entries.keys())
        header_bytes = json.dumps(labels).encode('utf-8')
        header_len_bytes = struct.pack('>I', len(header_bytes))

        raw_json = json.dumps(self.entries).encode('utf-8')
        encrypted_data = encrypt(raw_json, key)

        VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
        VAULT_PATH.write_bytes(salt + header_len_bytes + header_bytes + encrypted_data)

    def export_backup(self, backup_path: Path):
        """Simple secure export - just copy the encrypted vault."""
        if not VAULT_PATH.exists():
            raise FileNotFoundError("Nothing to export.")
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(VAULT_PATH, backup_path)
        print(f"✅ Vault exported to: {backup_path}")

    def import_backup(self, backup_path: Path, backup_password: str, save_password: str):
        """
        Import entries from a backup and re-encrypt the live vault under
        save_password -- the vault's actual current master password.

        backup_password and save_password are intentionally separate: a
        backup made before a password change (or restored during disaster
        recovery) may be encrypted under a different password than the
        live vault. Re-encrypting under backup_password unconditionally
        would silently change the vault's master password to whatever
        the backup happened to use. Always saving under save_password
        keeps that a deliberate, explicit action instead.
        """
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        temp = Vault()
        success = temp.load(backup_password, path=backup_path)

        if not success:
            raise ValueError("Invalid master password for this backup.")

        self.entries = temp.entries
        self.save(save_password)
        print(f"✅ Successfully imported from {backup_path}")
