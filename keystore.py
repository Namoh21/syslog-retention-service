"""
OS-native storage for the SECRET_KEY root secret.

Windows : DPAPI (CryptProtectData / CryptUnprotectData) — the encrypted blob is
          tied to the Windows user account. Copying the file to another machine
          or account produces an unreadable blob.

Linux   : A chmod-600 file in /etc/syslog-retention/ owned by the service user.
          Separating it from the database directory means exfiltrating the DB
          file alone is not enough to decrypt its contents.

Both platforms fall back gracefully to .env so existing installs keep working.
"""
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger("keystore")

# --- Platform-specific storage paths ----------------------------------------

def _key_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
        return base / "SyslogRetentionService" / "secret.key"
    return Path("/etc/syslog-retention/secret.key")


# --- Public API --------------------------------------------------------------

def store_secret(secret: str) -> None:
    """Encrypt and persist SECRET_KEY in the OS keystore."""
    path = _key_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform == "win32":
        import win32crypt
        blob = win32crypt.CryptProtectData(
            secret.encode(),
            "SyslogRetentionService-SecretKey",
            None, None, None, 0,
        )
        path.write_bytes(blob)
        # Restrict file permissions to current user via icacls
        import subprocess, os as _os
        user = _os.environ.get("USERNAME", "Administrator")
        subprocess.run(["icacls", str(path), "/inheritance:r"], capture_output=True)
        subprocess.run(["icacls", str(path), "/grant:r", f"{user}:(R,W)"], capture_output=True)
    else:
        path.write_text(secret, encoding="utf-8")
        os.chmod(path, 0o600)

    logger.info("SECRET_KEY stored in OS keystore at %s", path)


def load_secret() -> str | None:
    """Read and decrypt SECRET_KEY from the OS keystore. Returns None if absent."""
    path = _key_path()
    if not path.exists():
        return None

    try:
        if sys.platform == "win32":
            import win32crypt
            blob = path.read_bytes()
            _, decrypted = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
            return decrypted.decode()
        else:
            return path.read_text(encoding="utf-8").strip()
    except Exception as exc:
        logger.error("Failed to read SECRET_KEY from OS keystore (%s): %s", path, exc)
        return None


def is_stored() -> bool:
    return _key_path().exists()
