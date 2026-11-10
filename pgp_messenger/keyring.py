"""Local key storage.

Layout (default root: $XDG_CONFIG_HOME/pgp-messenger, i.e. ~/.config/pgp-messenger):

    private_key.asc          your keypair; secret parts are passphrase-encrypted
    contacts.json            {"contacts": {"Alice": "<FINGERPRINT>", ...}}
    contacts/<FPR>.asc       one public key per contact

Override the location with the PGP_MESSENGER_HOME environment variable.
The directory is created 0700 and every file 0600.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from . import crypto
from .crypto import CryptoError, PGPKey

APP_DIR_NAME = "pgp-messenger"
MAX_NAME_LEN = 64


def default_root() -> Path:
    override = os.environ.get("PGP_MESSENGER_HOME")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / APP_DIR_NAME


def _atomic_write(path: Path, data: str) -> None:
    """Write via temp file + rename so a crash never leaves a half-written key."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class Keyring:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root else default_root()
        self.contacts_dir = self.root / "contacts"
        self.identity_path = self.root / "private_key.asc"
        self.index_path = self.root / "contacts.json"
        for d in (self.root, self.contacts_dir):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    # ---------------------------------------------------------------- identity

    def has_identity(self) -> bool:
        return self.identity_path.exists()

    def load_identity(self) -> PGPKey | None:
        if not self.has_identity():
            return None
        return crypto.parse_key(self.identity_path.read_text(encoding="utf-8"))

    def save_identity(self, key: PGPKey) -> None:
        if key.is_public:
            raise CryptoError("Your identity must be a private key.")
        if not key.is_protected:
            raise CryptoError("Refusing to store an unprotected private key.")
        _atomic_write(self.identity_path, str(key))

    def delete_identity(self) -> None:
        self.identity_path.unlink(missing_ok=True)

    # ---------------------------------------------------------------- contacts

    def _read_index(self) -> dict[str, str]:
        if not self.index_path.exists():
            return {}
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
            return dict(data.get("contacts", {}))
        except (OSError, ValueError) as exc:
            raise CryptoError(f"Contact list is corrupted: {self.index_path}") from exc

    def _write_index(self, index: dict[str, str]) -> None:
        payload = {"version": 1, "contacts": dict(sorted(index.items(), key=lambda kv: kv[0].lower()))}
        _atomic_write(self.index_path, json.dumps(payload, indent=2) + "\n")

    def _contact_path(self, fingerprint: str) -> Path:
        return self.contacts_dir / f"{fingerprint}.asc"

    def contact_names(self) -> list[str]:
        return sorted(self._read_index(), key=str.lower)

    def contacts(self) -> dict[str, PGPKey]:
        """All contacts, name -> public key. Missing/broken files are skipped."""
        result: dict[str, PGPKey] = {}
        for name, fpr in self._read_index().items():
            path = self._contact_path(fpr)
            try:
                result[name] = crypto.parse_key(path.read_text(encoding="utf-8"))
            except (OSError, CryptoError):
                continue
        return dict(sorted(result.items(), key=lambda kv: kv[0].lower()))

    def get_contact(self, name: str) -> PGPKey:
        fpr = self._read_index().get(name)
        if fpr is None:
            raise CryptoError(f"No contact named '{name}'.")
        return crypto.parse_key(self._contact_path(fpr).read_text(encoding="utf-8"))

    def add_contact(self, name: str, armored: str) -> PGPKey:
        name = name.strip()
        if not name:
            raise CryptoError("Give this contact a name.")
        if len(name) > MAX_NAME_LEN:
            raise CryptoError(f"Name is too long (max {MAX_NAME_LEN} characters).")

        key = crypto.parse_key(armored)
        if not key.is_public:
            raise CryptoError(
                "That's a PRIVATE key. Only import other people's PUBLIC keys. "
                "If this is someone else's private key, it has been exposed."
            )

        index = self._read_index()
        if any(existing.lower() == name.lower() for existing in index):
            raise CryptoError(f"You already have a contact named '{name}'.")
        fpr = str(key.fingerprint).replace(" ", "")
        for existing, existing_fpr in index.items():
            if existing_fpr == fpr:
                raise CryptoError(f"This key is already saved as '{existing}'.")

        _atomic_write(self._contact_path(fpr), str(key))
        index[name] = fpr
        self._write_index(index)
        return key

    def remove_contact(self, name: str) -> None:
        index = self._read_index()
        fpr = index.pop(name, None)
        if fpr is None:
            raise CryptoError(f"No contact named '{name}'.")
        self._write_index(index)
        self._contact_path(fpr).unlink(missing_ok=True)
