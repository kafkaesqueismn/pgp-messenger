"""Thin, friendly wrapper around PGPy.

Nothing in this module implements cryptography. Every real operation
(RSA, AES, hashing, signatures, packet formats) is done by PGPy, which in
turn uses the `cryptography` library. This module only:

  * picks sensible defaults (RSA-3072, AES-256, SHA-256/512),
  * glues PGPy calls together into the handful of actions the app needs,
  * converts PGPy's exceptions into short messages a human can act on.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from datetime import datetime

# PGPy emits a lot of noisy warnings (e.g. about deprecated ciphers it
# *knows* about but we never use). Keep the console clean.
warnings.filterwarnings("ignore", module=r"pgpy(\..*)?")
# PGPy attributes some warnings to the caller (us) rather than itself.
warnings.filterwarnings("ignore", category=UserWarning, message=r"Selected compression algorithm")
try:  # pragma: no cover - depends on cryptography version
    from cryptography.utils import CryptographyDeprecationWarning

    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:  # pragma: no cover
    pass

import pgpy  # noqa: E402
from pgpy.constants import (  # noqa: E402
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)
from pgpy.errors import PGPDecryptionError, PGPError  # noqa: E402

PGPKey = pgpy.PGPKey

DEFAULT_KEY_BITS = 3072
SESSION_CIPHER = SymmetricKeyAlgorithm.AES256


class CryptoError(Exception):
    """An error with a message that is safe and useful to show the user."""


# --------------------------------------------------------------------------
# Data returned to the GUI
# --------------------------------------------------------------------------


@dataclass
class KeyInfo:
    user_id: str
    fingerprint: str  # pretty, grouped in blocks of 4
    key_id: str  # last 16 hex chars
    created: datetime
    bits: int
    is_private: bool


@dataclass
class SignatureStatus:
    """Outcome of checking signatures on a message."""

    signed: bool = False
    valid: bool = False
    signer_name: str | None = None  # contact name (or "you") if we know the key
    signer_key_ids: list[str] = field(default_factory=list)

    def describe(self) -> str:
        if not self.signed:
            return "Not signed."
        ids = ", ".join(self.signer_key_ids)
        if self.signer_name is None:
            return f"Signed by an unknown key ({ids}). Import the sender's public key to verify it."
        if self.valid:
            return f"Good signature from {self.signer_name}."
        return f"BAD signature claiming to be from {self.signer_name}. The message may have been altered!"


@dataclass
class DecryptResult:
    text: str
    signature: SignatureStatus


@dataclass
class VerifyResult:
    text: str
    signature: SignatureStatus


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------


def generate_keypair(
    name: str, email: str, passphrase: str, bits: int = DEFAULT_KEY_BITS
) -> PGPKey:
    """Create a new RSA keypair, protected with `passphrase`.

    Structure follows standard OpenPGP practice:
      * a primary key used to sign and to certify (vouch for) subkeys,
      * a separate subkey used only for encryption.
    """
    if not name.strip():
        raise CryptoError("Please enter a name for your key.")
    if not passphrase:
        raise CryptoError("A passphrase is required to protect your private key.")

    primary = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, bits)
    uid = pgpy.PGPUID.new(name.strip(), email=email.strip() or None)
    primary.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA512, HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.Uncompressed],
    )

    enc_subkey = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, bits)
    primary.add_subkey(
        enc_subkey,
        usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
    )

    # Encrypt the secret key material (primary + subkeys) at rest.
    # PGPy derives the key-encryption key from the passphrase with an
    # iterated+salted S2K, then encrypts with AES-256.
    primary.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return primary


def parse_key(armored: str) -> PGPKey:
    """Parse an ASCII-armored key block (public or private)."""
    text = armored.strip()
    if not text:
        raise CryptoError("No key provided.")
    try:
        key, _ = pgpy.PGPKey.from_blob(text)
    except Exception as exc:  # PGPy raises a mix of ValueError/PGPError/etc.
        raise CryptoError(
            "That doesn't look like a valid PGP key. It should start with "
            "'-----BEGIN PGP PUBLIC KEY BLOCK-----'."
        ) from exc
    return key


def key_info(key: PGPKey) -> KeyInfo:
    uid = key.userids[0] if key.userids else None
    if uid is None:
        user_id = "(no user ID)"
    elif uid.email:
        user_id = f"{uid.name} <{uid.email}>"
    else:
        user_id = uid.name

    fpr = str(key.fingerprint).replace(" ", "")
    pretty = " ".join(fpr[i : i + 4] for i in range(0, len(fpr), 4))
    return KeyInfo(
        user_id=user_id,
        fingerprint=pretty,
        key_id=fpr[-16:],
        created=key.created,
        bits=key.key_size,
        is_private=not key.is_public,
    )


def _key_ids(key: PGPKey) -> set[str]:
    """All key IDs (primary + subkeys) belonging to `key`."""
    ids = {key.fingerprint.keyid}
    ids.update(key.subkeys.keys())
    return ids


def _unlock_error(exc: Exception) -> CryptoError:
    return CryptoError("Wrong passphrase.") if isinstance(exc, PGPDecryptionError) else CryptoError(str(exc))


# --------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------


# First armor header line, e.g. "-----BEGIN PGP PUBLIC KEY BLOCK-----" -> "PUBLIC KEY BLOCK".
_ARMOR_BEGIN_RE = re.compile(r"^-----BEGIN PGP ([A-Z0-9 ,/]+)-----\s*$", re.MULTILINE)

# Armor types that are valid PGP but not something you can decrypt:
# block type -> (what it is, optional tip about where it belongs).
_NOT_A_MESSAGE = {
    "PUBLIC KEY BLOCK": ("a PGP public key", "To save someone's public key, use the Contacts tab."),
    "PRIVATE KEY BLOCK": ("a PGP private key", "Keep private keys to yourself; never paste them into chats or emails."),
    "SIGNATURE": ("a PGP signature", None),
    "SIGNED MESSAGE": ("a signed message (signed, not encrypted)", "To check its signature, use the Sign & Verify tab."),
}


def require_message_block(armored: str) -> None:
    """Reject PGP blocks that aren't messages with an error naming what they are.

    Text with no PGP armor at all passes through, so _parse_message's generic
    "doesn't look like a PGP message" error still covers it.
    """
    match = _ARMOR_BEGIN_RE.search(armored.replace("\r\n", "\n"))
    if match is None:
        return
    block_type = match[1].strip()
    if block_type.startswith("MESSAGE"):  # includes multi-part "MESSAGE, PART 1/2"
        return
    what, tip = _NOT_A_MESSAGE.get(block_type, (f"a PGP {block_type.lower()}", None))
    error = (
        f"That's {what}, not an encrypted message. "
        "Paste a block that starts with -----BEGIN PGP MESSAGE-----."
    )
    raise CryptoError(f"{error} {tip}" if tip else error)


# RFC 4880 section 7 "cleartext signature framework":
#   -----BEGIN PGP SIGNED MESSAGE-----
#   Hash: SHA512            (armor headers)
#   <blank line>
#   <dash-escaped text>
#   -----BEGIN PGP SIGNATURE----- ... -----END PGP SIGNATURE-----
_CLEARTEXT_RE = re.compile(
    r"-----BEGIN PGP SIGNED MESSAGE-----\n"
    r"(?:[^\n]+\n)*"  # armor headers
    r"\n"
    r"(?P<body>.*?)\n"
    r"(?P<sig>-----BEGIN PGP SIGNATURE-----\n.*?-----END PGP SIGNATURE-----)",
    re.DOTALL,
)


def _parse_cleartext(text: str) -> pgpy.PGPMessage:
    """Split a cleartext-signed message into text + signature ourselves.

    PGPy's own parser mixes byte and character offsets, so any non-ASCII
    character (é, £, emoji) makes it silently drop the signature. This only
    does text framing; hashing and signature checks are still done by PGPy.
    """
    match = _CLEARTEXT_RE.search(text.replace("\r\n", "\n"))
    if match is None:
        raise CryptoError("This signed message is incomplete or damaged.")
    lines = match["body"].split("\n")
    body = "\n".join(line[2:] if line.startswith("- ") else line for line in lines)
    message = pgpy.PGPMessage.new(body, cleartext=True)
    message |= pgpy.PGPSignature.from_blob(match["sig"])
    return message


def _parse_message(armored: str) -> pgpy.PGPMessage:
    text = armored.strip()
    if not text:
        raise CryptoError("Paste a PGP message first.")
    try:
        if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
            return _parse_cleartext(text)
        return pgpy.PGPMessage.from_blob(text)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(
            "That doesn't look like a PGP message. Make sure you copied everything "
            "including the '-----BEGIN PGP ...-----' and '-----END PGP ...-----' lines."
        ) from exc


def encrypt(
    text: str,
    recipients: list[PGPKey],
    signer: PGPKey | None = None,
    passphrase: str | None = None,
) -> str:
    """Encrypt `text` to every key in `recipients`; optionally sign it first.

    Hybrid encryption: we generate ONE random AES-256 session key, encrypt
    the message with it once, and then wrap that session key separately with
    each recipient's RSA public key. Any recipient can unwrap it.
    """
    if not text:
        raise CryptoError("Type a message to encrypt.")
    if not recipients:
        raise CryptoError("Choose at least one recipient.")

    message = pgpy.PGPMessage.new(text)

    if signer is not None:
        try:
            with signer.unlock(passphrase or ""):
                message |= signer.sign(message)
        except (PGPError, PGPDecryptionError) as exc:
            raise _unlock_error(exc) from exc

    session_key = SESSION_CIPHER.gen_key()  # random bytes from the OS CSPRNG
    try:
        for key in recipients:
            pub = key.pubkey if not key.is_public else key
            try:
                message = pub.encrypt(message, cipher=SESSION_CIPHER, sessionkey=session_key)
            except PGPError as exc:
                raise CryptoError(
                    f"Can't encrypt to {key_info(key).user_id}: this key has no usable encryption key."
                ) from exc
    finally:
        del session_key
    return str(message)


def decrypt(
    armored: str,
    private_key: PGPKey,
    passphrase: str,
    known_keys: dict[str, PGPKey] | None = None,
) -> DecryptResult:
    """Decrypt an armored message, and check any signature inside it."""
    require_message_block(armored)
    message = _parse_message(armored)
    if not message.is_encrypted:
        raise CryptoError(
            "This message isn't encrypted. If it's a signed message, use the Sign & Verify tab."
        )
    if not (set(message.encrypters) & _key_ids(private_key)):
        raise CryptoError("This message wasn't encrypted to your key, so you can't decrypt it.")

    try:
        with private_key.unlock(passphrase):
            plain = private_key.decrypt(message)
    except PGPDecryptionError as exc:
        raise _unlock_error(exc) from exc
    except PGPError as exc:
        raise CryptoError(f"Decryption failed: {exc}") from exc

    status = _check_signatures(plain, known_keys or {})
    return DecryptResult(text=_as_text(plain.message), signature=status)


def sign(text: str, private_key: PGPKey, passphrase: str) -> str:
    """Produce a cleartext-signed message (readable text + signature block)."""
    if not text:
        raise CryptoError("Type a message to sign.")
    message = pgpy.PGPMessage.new(text, cleartext=True)
    try:
        with private_key.unlock(passphrase):
            message |= private_key.sign(message)
    except (PGPError, PGPDecryptionError) as exc:
        raise _unlock_error(exc) from exc
    return str(message)


def verify(armored: str, known_keys: dict[str, PGPKey]) -> VerifyResult:
    """Verify a signed (cleartext or inline) message against known keys."""
    message = _parse_message(armored)
    if message.is_encrypted:
        raise CryptoError("This message is encrypted. Use the Decrypt tab instead.")
    status = _check_signatures(message, known_keys)
    if not status.signed:
        raise CryptoError("This message has no signature to verify.")
    return VerifyResult(text=_as_text(message.message), signature=status)


def _check_signatures(message: pgpy.PGPMessage, known_keys: dict[str, PGPKey]) -> SignatureStatus:
    signer_ids = sorted({sig.signer for sig in message.signatures})
    if not signer_ids:
        return SignatureStatus(signed=False)

    status = SignatureStatus(signed=True, signer_key_ids=signer_ids)
    for name, key in known_keys.items():
        if not (_key_ids(key) & set(signer_ids)):
            continue
        status.signer_name = name
        pub = key.pubkey if not key.is_public else key
        try:
            status.valid = bool(pub.verify(message))
        except PGPError:
            status.valid = False
        return status
    return status


def _as_text(payload: str | bytes | bytearray) -> str:
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload).decode("utf-8", errors="replace")
    return payload
