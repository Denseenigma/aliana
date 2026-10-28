"""
vault.py - encrypts secrets (RMM API keys etc.) before they touch the database.

Secrets are stored in aliana.db as "enc:v1:<Fernet token>" (AES-128-CBC +
HMAC-SHA256 from the `cryptography` package). The encryption key lives in a
separate file OUTSIDE the repo folder, so neither the repo nor a copy of the
database on its own gives away the credentials:

    ~/.config/aliana/secret.key      (owner-only, 0600; created on first use)

Override the location with ALIANA_KEY_FILE. Deleting the key file makes the
stored secrets unreadable -- just re-enter them on the Settings page.

Nothing in here ever falls back to storing plaintext: if `cryptography` is
missing or the key can't be created, saving a secret fails with a message.
"""
import os

PREFIX = "enc:v1:"

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:          # setup.sh installs it; see requirements.txt
    Fernet = None
    InvalidToken = Exception


class VaultError(Exception):
    pass


def key_path():
    return os.path.expanduser(os.environ.get("ALIANA_KEY_FILE") or "~/.config/aliana/secret.key")


def available():
    return Fernet is not None


def _load_key(create):
    if Fernet is None:
        raise VaultError("Secret storage needs the 'cryptography' package -- run setup.sh "
                         "(or ./venv/bin/pip install -r requirements.txt) and restart Aliana.")
    path = key_path()
    try:
        with open(path, "rb") as f:
            return f.read().strip()
    except FileNotFoundError:
        if not create:
            return None
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    key = Fernet.generate_key()
    try:
        # O_EXCL: never overwrite a key that appeared in the meantime
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "rb") as f:
            return f.read().strip()
    except OSError as e:
        raise VaultError(f"Couldn't create the key file {path}: {e}")
    with os.fdopen(fd, "wb") as f:
        f.write(key + b"\n")
    return key


def is_encrypted(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt(value):
    """'' / None stay as they are; already-encrypted values pass through."""
    if not value or is_encrypted(value):
        return value
    token = Fernet(_load_key(create=True)).encrypt(str(value).encode())
    return PREFIX + token.decode()


def decrypt(value):
    """Plain values (legacy) pass through. Raises VaultError if the key is
    missing or doesn't match."""
    if not is_encrypted(value):
        return value
    key = _load_key(create=False)
    if not key:
        raise VaultError(f"The encryption key ({key_path()}) is missing, so the saved credentials "
                         "can't be read. Re-enter them on the Settings page.")
    try:
        return Fernet(key).decrypt(value[len(PREFIX):].encode()).decode()
    except (InvalidToken, ValueError):
        raise VaultError("The saved credentials don't match the encryption key "
                         f"({key_path()}). Re-enter them on the Settings page.")
