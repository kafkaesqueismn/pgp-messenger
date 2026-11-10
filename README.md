# PGP Messenger

A small, friendly desktop app for **encrypting, decrypting, signing and verifying text messages**
with OpenPGP. It works with GnuPG, Thunderbird, Kleopatra, ProtonMail and other OpenPGP tools.
It covers the common tasks and skips the rest.

- Real OpenPGP via [PGPy](https://github.com/SecurityInnovation/PGPy) (which uses the `cryptography` library).
  No hand-rolled crypto.
- GUI built with PySide6 (Qt 6).
- Text messages only, not files.

## Features

| Tab | What it does |
|---|---|
| **My Key** | Generate your RSA keypair (3072 or 4096-bit) protected by a passphrase. Copy or save your public key to share, back up your private key, or delete it. |
| **Contacts** | A local keyring of other people's **public** keys, stored by a name you choose. Paste or load a `.asc` file; remove contacts. |
| **Encrypt** | Pick a contact, type a message, get ASCII-armored output ready to paste anywhere. Optionally also encrypt to yourself and sign it. |
| **Decrypt** | Paste a `-----BEGIN PGP MESSAGE-----` block, enter your passphrase, read the message. Any signature inside is checked against your contacts. |
| **Sign & Verify** | Make a cleartext-signed message (still readable, but tamper-evident), or verify one somebody sent you. |

## Install (Arch Linux)

You need Python 3.11+ (Arch's `python` package is fine). Pick one of the two setups.

**Option A: reuse Arch's Qt (fast, recommended on Arch).** PySide6 is a large download from pip,
so let pacman provide it:

```bash
sudo pacman -S --needed pyside6 python-cryptography
cd pgp-messenger
python -m venv --system-site-packages .venv   # venv can see pacman's PySide6
source .venv/bin/activate
pip install PGPy13==0.6.1rc1                  # only the small OpenPGP library comes from pip
```

**Option B: everything from pip (any distro).**

```bash
cd pgp-messenger
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> **Why `PGPy13` and not `PGPy`?** Upstream PGPy 0.6.0 imports the `imghdr` module, which was
> removed in Python 3.13, so it crashes on import on current Arch. `PGPy13` is the maintained fork
> with that fixed. It installs the same `pgpy` module, so nothing else changes.

## Run

```bash
source .venv/bin/activate
python -m pgp_messenger
```

Run the tests (no GUI needed). If `gpg` is installed, they also check that GnuPG can read
what this app produces, and the other way round:

```bash
python -m unittest -v
```

## How to use it

1. **My Key → Generate my key.** Choose a passphrase you will remember. If you lose it, the key can't be recovered.
2. **Share your public key.** Click *Copy public key* and send it to your friend however you like.
   Public keys aren't secret.
3. **Add your friend.** In **Contacts**, paste their public key, give it a name, and click *Add contact*.
   Then check the fingerprint shown with them over a separate channel (phone, in person). This is
   how you know the key really belongs to them and not to someone in the middle.
4. **Encrypt.** Pick them in the *To* box, type, click *Encrypt*, then *Copy*. Paste it into an email or chat.
5. **Decrypt.** Paste what they send you into **Decrypt**, click *Decrypt*, and enter your passphrase.
   The banner tells you whether it was signed and by whom.

Signature results:
- 🟩 **Good signature from Alice**: the message is from Alice's key and has not been altered.
- 🟥 **BAD signature**: the text was changed after signing, or the signature is forged. Don't trust it.
- 🟨 **Signed by an unknown key**: add the sender's public key to Contacts to check it.

## Where keys are stored

```
~/.config/pgp-messenger/          (or $XDG_CONFIG_HOME/pgp-messenger)
├── private_key.asc               your keypair; secret parts encrypted with your passphrase
├── contacts.json                 name → fingerprint index
└── contacts/<FINGERPRINT>.asc    one public key per contact
```

- The directory is `0700` and every file is `0600`. Writes are atomic (temp file + rename).
- Set `PGP_MESSENGER_HOME=/some/path` to use a different location, for example a throwaway test keyring.
- The private key is **never stored unencrypted**. Your passphrase is asked for each time it's needed and is never saved.
- These are standard armored OpenPGP files, so `gpg --import ~/.config/pgp-messenger/private_key.asc` works too.

## How hybrid encryption works under the hood

RSA is good at one job: anyone with your **public** key can lock a small piece of data that only your
**private** key can unlock. But RSA is slow and can only encrypt a few hundred bytes at a time. AES is
very fast and handles data of any size, but it's *symmetric*: the same key locks and unlocks, so you
would need a way to share that key secretly.

OpenPGP combines the two:

```
             ┌─────────────────────── sender ───────────────────────┐
 message ──► │ 1. generate a random 256-bit AES "session key"       │
             │ 2. AES-256 encrypt (compressed) message ─────────────┼──► encrypted data packet
             │ 3. RSA-encrypt the session key with Bob's PUBLIC key ┼──► "for Bob" key packet
             │    (and again with Alice's own key, if "also me")    ┼──► "for Alice" key packet
             └──────────────────────────────────────────────────────┘
                                   ASCII armor (base64) ──► -----BEGIN PGP MESSAGE-----

             ┌─────────────────────── recipient ────────────────────┐
             │ 1. unlock private key with passphrase                │
             │ 2. RSA-decrypt own key packet → session key          │
             │ 3. AES-decrypt the data packet → message             │
             └──────────────────────────────────────────────────────┘
```

- **The session key is new for every message** and thrown away afterwards. Two encryptions of the same text look completely different.
- **Multiple recipients cost almost nothing.** The message body is encrypted once; only the small session key is wrapped again for each extra recipient. That's how *Also encrypt to me* works.
- **Integrity**: the encrypted data includes a SHA-1 based "modification detection code" (MDC). A message that was changed in transit fails to decrypt instead of producing silently altered text.
- **Signing** runs in the other direction. The sender hashes the message (SHA-256/512) and transforms the hash with their **private** key. Anyone with the sender's **public** key can check that the hash matches. For sign+encrypt, the signature is made first and placed *inside* the encrypted envelope, so only the recipient sees who signed it.
- **Your private key at rest**: the secret RSA numbers are themselves AES-256 encrypted, under a key derived from your passphrase with a salted, iterated hash (OpenPGP "S2K"). A stolen `private_key.asc` file is useless without the passphrase, but only if the passphrase is strong.
- Your generated key is really two RSA keys: a **primary key** for signing and certifying, and an **encryption subkey**. This is standard OpenPGP practice and lets the two roles be managed separately.

## Limitations (v1)

- No importing an existing private key from GnuPG yet (exporting/backing up works).
- No key expiry, revocation certificates, or web-of-trust/keyserver lookups. Verify fingerprints by hand.
  PGPy itself doesn't check whether an imported key has been revoked.
- PGPy's parser drops the signature from cleartext-signed messages containing non-ASCII text
  (é, £, emoji). `crypto.py` works around this by splitting the message text from the signature
  block itself before handing both to PGPy. Tests cover this, including against real GnuPG.
- Python can't reliably wipe secrets from memory, so passphrases and decrypted text may linger in RAM while the app runs.
- PGPy implements RFC 4880 (OpenPGP v4). Newer RFC 9580 (v6) keys from very recent tools may not import.
- This is a learning- and convenience-oriented tool, not an audited security product.

## Project layout

```
pgp_messenger/
├── crypto.py    thin wrapper over PGPy: keygen, encrypt, decrypt, sign, verify, friendly errors
├── keyring.py   on-disk storage of your key + contacts
├── gui.py       PySide6 window and the five tabs
└── __main__.py  `python -m pgp_messenger`
tests/test_core.py   round-trip tests (no GUI)
```
