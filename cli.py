# cli.py
import argparse
import getpass
import sys
import time
import subprocess
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from base64 import b32decode
import binascii

from core.storage import Vault
from core.totp import generate_totp

def sanitize_and_validate_secret(secret_input: str) -> dict:
    """Returns {'secret': str, 'algorithm': str, 'digits': int, 'period': int}."""
    cleaned = secret_input.strip()
    config = {"algorithm": "SHA1", "digits": 6, "period": 30}

    if cleaned.lower().startswith("otpauth://"):
        try:
            parsed_url = urlparse(cleaned)
            query_params = parse_qs(parsed_url.query)
            if 'secret' not in query_params:
                raise ValueError("The provided otpauth URI is missing a '?secret=' parameter.")
            cleaned = query_params['secret'][0]
            if 'algorithm' in query_params:
                config["algorithm"] = query_params['algorithm'][0].upper()
            if 'digits' in query_params:
                config["digits"] = int(query_params['digits'][0])
            if 'period' in query_params:
                config["period"] = int(query_params['period'][0])
        except Exception as e:
            raise ValueError(f"Failed parsing token URI schema: {e}")

    validation_target = cleaned.upper().replace(' ', '').replace('-', '')
    missing_padding = len(validation_target) % 8
    if missing_padding:
        validation_target += '=' * (8 - missing_padding)

    try:
        b32decode(validation_target)
    except binascii.Error:
        raise ValueError(
            f"Invalid character signature found!\n"
            f"Expected standard Base32 layout (A-Z, 2-7).\n"
            f"Supplied raw string input was: {secret_input[:15]}..."
        )

    if config["algorithm"] not in ("SHA1", "SHA256", "SHA512"):
        raise ValueError(f"Unsupported algorithm '{config['algorithm']}'.")
    if not (6 <= config["digits"] <= 10):
        raise ValueError("Digits must be between 6 and 10.")
    if config["period"] <= 0:
        raise ValueError("Period must be a positive number of seconds.")

    config["secret"] = cleaned
    return config

def copy_to_clipboard(text: str):
    try:
        if sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        elif sys.platform == "linux":
            if subprocess.run(["which", "termux-clipboard-set"], capture_output=True).returncode == 0:
                subprocess.run(["termux-clipboard-set", text], check=True)
            else:
                subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=True)
        elif sys.platform == "win32":
            subprocess.run(["clip"], input=text.encode(), check=True)
    except Exception:
        pass

def clear_clipboard():
    copy_to_clipboard("")

def draw_progress_bar(remaining_seconds: int, total_steps: int = 30, bar_width: int = 20):
    """Renders a clean standard output carriage-return visual progress monitor."""
    remaining_seconds = max(0, remaining_seconds)
    filled_length = int(round(bar_width * remaining_seconds / total_steps))
    bar = '█' * filled_length + '-' * (bar_width - filled_length)
    sys.stdout.write(f"\rTime Remaining: [{bar}] {remaining_seconds:2d}s before auto-wipe...")
    sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(prog="foxkey", description="Secure terminal 2FA manager.")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    subparsers.add_parser("list", help="List all vault service names.")
    
    add_p = subparsers.add_parser("add", help="Add a new 2FA service credential.")
    add_p.add_argument("name", help="Account or provider tracking name.")
    add_p.add_argument("secret", help="Base32 seed or full otpauth:// URI.")
    add_p.add_argument("--algorithm", choices=["SHA1", "SHA256", "SHA512"],
                        help="Override HMAC algorithm (default: SHA1, or value from otpauth URI).")
    add_p.add_argument("--digits", type=int,
                        help="Override token length (default: 6, or value from otpauth URI).")
    add_p.add_argument("--period", type=int,
                        help="Override time step in seconds (default: 30, or value from otpauth URI).")

    get_p = subparsers.add_parser("get", help="Generate code and copy to clipboard.")
    get_p.add_argument("name", help="Name of account target.")

    rem_p = subparsers.add_parser("remove", help="Permanently drop a service key.")
    rem_p.add_argument("name", help="Name of target account profile to erase.")

    # NEW: Added change-password subparser
    subparsers.add_parser("change-password", help="Update vault master password key.")

    exp_p = subparsers.add_parser("export", help="Export encrypted vault backup.")
    exp_p.add_argument("--file", default=str(Path.home() / "foxkey-backup.enc"))

    imp_p = subparsers.add_parser("import", help="Import from encrypted backup.")
    imp_p.add_argument("file", help="Backup file path.")

    args = parser.parse_args()

    if args.cmd == "add":
        try:
            totp_config = sanitize_and_validate_secret(args.secret)
        except ValueError as err:
            print(f"Validation Error: {err}", file=sys.stderr)
            sys.exit(1)
        if args.algorithm:
            totp_config["algorithm"] = args.algorithm
        if args.digits:
            totp_config["digits"] = args.digits
        if args.period:
            totp_config["period"] = args.period

    vault = Vault()

    if args.cmd == "list":
        labels = vault.get_public_labels()
        if not labels:
            print("Vault is entirely empty.")
        for service in labels:
            print(f"- {service}")
        sys.exit(0)

    # Prompt for current password first to unlock entries database
    password = getpass.getpass("Master Password: ")
    if not vault.load(password):
        print("Error: Invalid master password.", file=sys.stderr)
        sys.exit(1)

    if args.cmd == "add":
        if args.name in vault.entries:
            confirm = input(f"'{args.name}' already exists — overwrite? [y/N]: ").strip().lower()
            if confirm != "y":
                print("Aborted: existing entry left unchanged.")
                sys.exit(0)
        vault.entries[args.name] = totp_config
        vault.save(password)
        print(f"Success: Validated credential for '{args.name}' successfully archived.")

    elif args.cmd == "remove":
        if args.name not in vault.entries:
            print(f"Error: Profile name '{args.name}' not found.", file=sys.stderr)
            sys.exit(1)
        del vault.entries[args.name]
        vault.save(password)
        print(f"Success: Key profile '{args.name}' has been permanently dropped.")

    # NEW: Added password mutation execution branch
    elif args.cmd == "change-password":
        new_password = getpass.getpass("Enter New Master Password: ")
        confirm_password = getpass.getpass("Confirm New Master Password: ")
        
        if new_password != confirm_password:
            print("Error: Passwords do not match. Aborting mutation.", file=sys.stderr)
            sys.exit(1)
            
        if not new_password.strip():
            print("Error: Password cannot be blank.", file=sys.stderr)
            sys.exit(1)
            
        # Write out using the confirmed new encryption key profile
        vault.save(new_password)
        print("Success: Vault re-encrypted under your fresh master password blueprint.")

    elif args.cmd == "export":
        try:
            vault.export_backup(Path(args.file))
        except FileNotFoundError as err:
            print(f"Error: {err}", file=sys.stderr)
            sys.exit(1)

    elif args.cmd == "import":
        existing_count = len(vault.entries)
        if existing_count:
            confirm = input(
                f"Importing will overwrite your current vault ({existing_count} entries) "
                f"with the contents of the backup. Continue? [y/N]: "
            ).strip().lower()
            if confirm != "y":
                print("Aborted: current vault left unchanged.")
                sys.exit(0)
        try:
            vault.import_backup(Path(args.file), password)
        except ValueError:
            # Backup may be encrypted under a different password than the
            # current vault (e.g. disaster recovery, or a stale backup).
            backup_password = getpass.getpass("Backup Master Password: ")
            try:
                vault.import_backup(Path(args.file), backup_password)
            except (FileNotFoundError, ValueError) as err:
                print(f"Error: {err}", file=sys.stderr)
                sys.exit(1)
        except FileNotFoundError as err:
            print(f"Error: {err}", file=sys.stderr)
            sys.exit(1)

    elif args.cmd == "get":
        if args.name not in vault.entries:
            print(f"Error: Profile name '{args.name}' not found.", file=sys.stderr)
            sys.exit(1)

        entry = vault.entries[args.name]
        secret = entry["secret"]
        algorithm = entry.get("algorithm", "SHA1")
        digits = entry.get("digits", 6)
        time_step = entry.get("period", 30)

        token = generate_totp(secret, time_step=time_step, digits=digits, algorithm=algorithm)

        copy_to_clipboard(token)
        print(f"Token: {token}")
        print("Note: Token copied directly to your clipboard ecosystem.")

        try:
            while True:
                now = int(time.time())
                remaining = time_step - (now % time_step)
                draw_progress_bar(remaining, total_steps=time_step)

                if remaining <= 1:
                    time.sleep(0.5)
                    draw_progress_bar(0, total_steps=time_step)
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            clear_clipboard()
            print("\nClipboard cleared. Token cycle window has successfully closed.")
