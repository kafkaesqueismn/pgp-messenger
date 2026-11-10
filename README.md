# PGP Messenger

[![tests](https://github.com/kafkaesqueismn/pgp-messenger/actions/workflows/tests.yml/badge.svg)](https://github.com/kafkaesqueismn/pgp-messenger/actions/workflows/tests.yml)

A small, friendly desktop app for **encrypting, decrypting, signing and verifying text messages and
files** with OpenPGP. It works with GnuPG, Thunderbird, Kleopatra, ProtonMail and other OpenPGP tools.
It covers the common tasks and skips the rest.

- Real OpenPGP via [PGPy](https://github.com/SecurityInnovation/PGPy) (which uses the `cryptography` library).
  No hand-rolled crypto.
- GUI built with PySide6 (Qt 6).
- Text messages *and* files: photos, PDFs, anything binary.

## Features

| Tab | What it does |
|---|---|
| **My Key** | Generate your RSA keypair (3072 or 4096-bit) protected by a passphrase. Copy or save your public key to share, back up your private key, or delete it. |
| **Contacts** | A local keyring of other people's **public** keys, stored by a name you choose. Paste or load a `.asc` file; remove contacts. |
| **Encrypt** | Pick a contact, type a message, get ASCII-armored output ready to paste anywhere. Optionally also encrypt to yourself and sign it. |
| **Decrypt** | Paste a `-----BEGIN PGP MESSAGE-----` block, enter your passphrase, read the message. Any signature inside is checked against your contacts. |
| **Files** | Encrypt any file (image, PDF, archive…) for a contact. The output is a signed, binary `.pgp` file saved next to the original or wherever you choose. Decrypt a `.pgp` file to restore the original, with the sender's signature checked. Asks before anything over 100 MB, shows a working indicator, and never overwrites a file without asking. |
| **Sign & Verify** | Make a cleartext-signed message (still readable, but tamper-evident), or verify one somebody sent you. |

## Install

Works on **Linux** and **Windows** with Python 3.11 or newer. The test suite runs on both
(see the badge above).

### Linux (Arch)

Arch's `python` package is fine. Pick one of the two setups.

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

### Windows

1. Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/).
   In the installer, tick **"Add python.exe to PATH"**.
2. Install [Git for Windows](https://git-scm.com/download/win), or download this repo as a ZIP
   from GitHub (*Code → Download ZIP*) and unzip it.
3. Open **PowerShell** and run:

```powershell
git clone https://github.com/kafkaesqueismn/pgp-messenger
cd pgp-messenger
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell refuses to run `Activate.ps1` ("running scripts is disabled on this system"), allow
local scripts for your user once with
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use **Command Prompt** (`cmd`) instead,
where the activate command is `.venv\Scripts\activate.bat`.

Everything comes from pip, including Qt, so there's nothing else to install. GnuPG is **not** needed.

## Run

From the `pgp-messenger` folder, activate the venv, then start the app:

```bash
source .venv/bin/activate          # Linux
python -m pgp_messenger
```

```powershell
.venv\Scripts\Activate.ps1         # Windows (PowerShell)
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

### Files

6. **Encrypt a file.** In **Files → Encrypt a file**, click *Browse…*, pick e.g. `photo.png`, choose the
   contact, and click *Encrypt and sign file*. Enter your passphrase, which is needed because files are
   always signed. You get `photo.png.pgp` next to the original. Use *Change…* to save it somewhere else.
   Send the `.pgp` file however you like: email attachment, USB stick, cloud drive.
7. **Decrypt a file.** In **Files → Decrypt a file**, pick the `.pgp` file and click *Decrypt file*.
   `photo.png.pgp` is restored as `photo.png` in the same folder. If the file was renamed and doesn't
   end in `.pgp`/`.gpg`/`.asc`, the sender's original filename (stored inside the encryption) is used.
   The banner shows where it was saved and whose signature it carries.

Large files:
- Anything **over 100 MB** brings up a warning before any work starts. It shows the file size,
  roughly how much RAM the job needs (about 8× the file size) next to how much is free right now,
  and a rough time estimate. Choose *Yes* to go ahead or *Cancel* (the default) to stop. Nothing is
  asked or written until you decide. This applies to decrypting too, which needs even more memory.
- The hard limit is **1 GB**. Bigger files are refused straight away, before you type a passphrase.
- While a file is being processed you see a moving bar and an elapsed-time counter
  (*Encrypting holiday.mov (150 MB)… 12 s*). The Files tab's buttons are locked so you can't start a
  second job, but the other tabs keep working. There's no percentage because PGPy doesn't report
  progress, but the timer shows the app hasn't frozen.
- Closing the window mid-job asks first. If you quit anyway, nothing is saved and no existing file is
  touched, because files are only written after a job completes.

Safety rules for files:
- **Nothing is overwritten without asking.** If the target already exists you get a *Replace file?*
  prompt (default *No*). The final write also refuses to replace a file that appeared in the meantime.
- **A BAD signature means the file isn't saved** unless you explicitly click *Save* in the warning.
- Picking the wrong file gives an error saying what it actually is (*a PGP public key*, *a signed PGP
  file, but it isn't encrypted*, or *isn't a PGP-encrypted file*). The app checks the OpenPGP packet
  header itself first, because PGPy alone mistakes about 5% of random files for PGP data.
- The sender's stored filename is treated as untrusted. Folders (`../`), hidden names (`.bashrc`)
  and control characters are stripped, and the file is only ever written next to the `.pgp` or where you chose.
- Writes go to a temporary file first, then get renamed, so a crash never leaves a half-written file.
  On Linux, saved files are readable only by you (`0600`).

Signature results:
- 🟩 **Good signature from Alice**: the message or file is from Alice's key and has not been altered.
- 🟥 **BAD signature**: the contents were changed after signing, or the signature is forged. Don't trust it.
- 🟨 **Signed by an unknown key**: add the sender's public key to Contacts to check it.

## Where keys are stored

| OS | Location |
|---|---|
| Linux | `~/.config/pgp-messenger` (or `$XDG_CONFIG_HOME/pgp-messenger`) |
| Windows | `%APPDATA%\pgp-messenger`, i.e. `C:\Users\<you>\AppData\Roaming\pgp-messenger` |

```
pgp-messenger/
├── private_key.asc               your keypair; secret parts encrypted with your passphrase
├── contacts.json                 name → fingerprint index
└── contacts/<FINGERPRINT>.asc    one public key per contact
```

- On Linux the directory is `0700` and every file `0600` (only you can read them). On Windows,
  `%APPDATA%` is private to your user account by default. Writes are atomic (temp file + rename).
- Set `PGP_MESSENGER_HOME=/some/path` to use a different location, for example a throwaway test keyring.
- The private key is **never stored unencrypted**. Your passphrase is asked for each time it's needed and is never saved.
- These are standard armored OpenPGP files, so `gpg --import ~/.config/pgp-messenger/private_key.asc` works too.

### Moving your key to another computer (e.g. Linux → Windows)

1. On the old computer: **My Key → Back up private key…** and save the file somewhere you can carry it,
   like a USB stick. The file stays locked with your passphrase, but treat it as sensitive anyway.
2. On the new computer: run the app once so it creates its folder, then close it.
3. Copy the backup into that folder (see the table above) and name it exactly `private_key.asc`.
4. Start the app. **My Key** shows your key with the same fingerprint. Use your existing passphrase.

Contacts don't move automatically. Copy `contacts.json` and the `contacts` folder across the same
way, or just re-add people's public keys.

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
- **Files use exactly the same scheme.** Only the packaging differs. A message is wrapped in *ASCII armor*
  (the `-----BEGIN PGP MESSAGE-----` base64 text), so it survives being pasted into email or chat.
  A file is saved as raw binary OpenPGP packets. Armor would only make it ~33% bigger, and an
  attachment doesn't need to be text. The data is marked as *binary* so no tool ever rewrites its line endings.
  The original filename and timestamp travel *inside* the encrypted part, invisible to anyone else.
- **Signing** runs in the other direction. The sender hashes the message (SHA-256/512) and transforms the hash with their **private** key. Anyone with the sender's **public** key can check that the hash matches. For sign+encrypt, the signature is made first and placed *inside* the encrypted envelope, so only the recipient sees who signed it.
- **Your private key at rest**: the secret RSA numbers are themselves AES-256 encrypted, under a key derived from your passphrase with a salted, iterated hash (OpenPGP "S2K"). A stolen `private_key.asc` file is useless without the passphrase, but only if the passphrase is strong.
- Your generated key is really two RSA keys: a **primary key** for signing and certifying, and an **encryption subkey**. This is standard OpenPGP practice and lets the two roles be managed separately.

## Limitations (v1)

- No *Import private key* button yet. Exporting/backing up works, and you can move a key by copying
  the file (see *Moving your key to another computer*).
- No key expiry, revocation certificates, or web-of-trust/keyserver lookups. Verify fingerprints by hand.
  PGPy itself doesn't check whether an imported key has been revoked.
- PGPy's parser drops the signature from cleartext-signed messages containing non-ASCII text
  (é, £, emoji). `crypto.py` works around this by splitting the message text from the signature
  block itself before handing both to PGPy. Tests cover this, including against real GnuPG.
- Files are processed **in memory**, because PGPy can't stream. Measured peak RAM is about 5.5× the
  file size when encrypting and 7.5× when decrypting. A 100 MB file took ~10 s to encrypt and ~2 s to
  decrypt on a desktop PC. Hence the warning over 100 MB and the hard limit at 1 GB (≈ 8 GB of RAM).
  For bigger files, use GnuPG (`gpg --encrypt --sign`), which streams. Its output is compatible
  with this app's.
- Python can't reliably wipe secrets from memory, so passphrases and decrypted text or files may linger in RAM while the app runs.
- PGPy implements RFC 4880 (OpenPGP v4). Newer RFC 9580 (v6) keys from very recent tools may not import.
- This is a learning- and convenience-oriented tool, not an audited security product.

## Project layout

```
pgp_messenger/
├── crypto.py    thin wrapper over PGPy: keygen, encrypt, decrypt, sign, verify, friendly errors
├── keyring.py   on-disk storage of your key + contacts
├── fileops.py   output file names and safe, no-overwrite writing for the Files tab
├── gui.py       PySide6 window and the six tabs
└── __main__.py  `python -m pgp_messenger`
tests/test_core.py    keys, messages, signatures, keyring (no GUI)
tests/test_files.py   file encryption, size limits, filename safety, no-overwrite writes, GnuPG interop
tests/test_gui.py     Files tab, offscreen: large-file warning, working state, overwrite and bad-signature prompts
.github/workflows/tests.yml   CI: runs the tests on Linux + Windows, Python 3.11 and 3.14
```
