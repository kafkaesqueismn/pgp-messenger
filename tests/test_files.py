"""Tests for file encryption (crypto.encrypt_file/decrypt_file) and fileops.

Run with:  python -m unittest -v
"""

import os
import random
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pgpy

from pgp_messenger import crypto, fileops
from pgp_messenger.crypto import CryptoError

BITS = 2048

# A few bytes that look like a real PNG, followed by random binary data.
PNG = b"\x89PNG\r\n\x1a\n" + os.urandom(4096)


class FileCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = crypto.generate_keypair("Alice", "", "alice-pass", BITS)
        cls.bob = crypto.generate_keypair("Bob", "", "bob-pass", BITS)
        cls.mallory = crypto.generate_keypair("Mallory", "", "m-pass", BITS)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, name, data):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def encrypt_to_bob(self, path):
        out = self.dir / (path.name + ".pgp")
        out.write_bytes(crypto.encrypt_file(path, [self.bob.pubkey], self.alice, "alice-pass"))
        return out

    def test_roundtrip_is_byte_exact(self):
        # binary, CRLF text (must not be "fixed" to LF), non-UTF-8, empty
        cases = {
            "photo.png": PNG,
            "data.csv": b"a,b\r\n1,2\r\n",
            "latin1.txt": "café".encode("latin-1"),
            "empty.bin": b"",
        }
        for name, data in cases.items():
            with self.subTest(name):
                enc = self.encrypt_to_bob(self.make(name, data))
                result = crypto.decrypt_file(enc, self.bob, "bob-pass", {"Alice": self.alice.pubkey})
                self.assertEqual(result.data, data)
                self.assertEqual(result.original_name, name)
                self.assertTrue(result.signature.valid)
                self.assertEqual(result.signature.signer_name, "Alice")

    def test_output_is_binary_not_armor(self):
        enc = self.encrypt_to_bob(self.make("photo.png", PNG)).read_bytes()
        self.assertFalse(enc.startswith(b"-----BEGIN"))
        self.assertNotIn(b"photo.png", enc)  # filename is inside the encryption, not visible
        self.assertNotIn(PNG[:64], enc)

    def test_also_encrypt_to_self(self):
        src = self.make("photo.png", PNG)
        enc = self.dir / "x.pgp"
        enc.write_bytes(crypto.encrypt_file(src, [self.bob.pubkey, self.alice], self.alice, "alice-pass"))
        self.assertEqual(crypto.decrypt_file(enc, self.alice, "alice-pass").data, PNG)
        self.assertEqual(crypto.decrypt_file(enc, self.bob, "bob-pass").data, PNG)

    def test_signer_unknown_to_recipient(self):
        enc = self.encrypt_to_bob(self.make("photo.png", PNG))
        status = crypto.decrypt_file(enc, self.bob, "bob-pass", {}).signature
        self.assertTrue(status.signed)
        self.assertIsNone(status.signer_name)
        self.assertFalse(status.valid)

    def test_errors(self):
        enc = self.encrypt_to_bob(self.make("photo.png", PNG))
        with self.assertRaisesRegex(CryptoError, "Wrong passphrase"):
            crypto.decrypt_file(enc, self.bob, "nope")
        with self.assertRaisesRegex(CryptoError, "wasn't encrypted to your key"):
            crypto.decrypt_file(enc, self.mallory, "m-pass")
        with self.assertRaisesRegex(CryptoError, "Wrong passphrase"):
            crypto.encrypt_file(self.dir / "photo.png", [self.bob.pubkey], self.alice, "bad")
        with self.assertRaisesRegex(CryptoError, "File not found"):
            crypto.encrypt_file(self.dir / "missing.png", [self.bob.pubkey], self.alice, "alice-pass")
        with self.assertRaisesRegex(CryptoError, "File not found"):
            crypto.decrypt_file(self.dir / "missing.pgp", self.bob, "bob-pass")

    def test_not_an_encrypted_file(self):
        for name, data in {"notes.pgp": b"hello world", "photo.png": PNG, "empty.pgp": b""}.items():
            with self.subTest(name), self.assertRaisesRegex(CryptoError, "isn't a PGP-encrypted file"):
                crypto.decrypt_file(self.make(name, data), self.bob, "bob-pass")

    def test_random_junk_is_never_mistaken_for_pgp(self):
        # PGPy's parser alone "accepts" ~5% of random files as some kind of PGP
        # data (and returns empty keys for ~half). Fixed seed: same 500 files every run.
        rng = random.Random(20261110)
        junk = self.dir / "junk.pgp"
        for i in range(500):
            junk.write_bytes(rng.randbytes(rng.randint(1, 4000)))
            with self.subTest(i=i), self.assertRaisesRegex(CryptoError, "^junk.pgp isn't a PGP-encrypted file"):
                crypto.decrypt_file(junk, self.bob, "bob-pass")

    def test_names_other_pgp_file_types(self):
        cases = {
            "key.pgp": (bytes(self.alice.pubkey), "is a PGP public key, not an encrypted file"),
            "secret.pgp": (bytes(self.alice), "is a PGP private key, not an encrypted file"),
            "key.asc": (str(self.alice.pubkey).encode(), "contains a PGP public key, not an encrypted file"),
        }
        for name, (data, expected) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(CryptoError, expected):
                crypto.decrypt_file(self.make(name, data), self.bob, "bob-pass")

    def test_signed_but_not_encrypted(self):
        msg = pgpy.PGPMessage.new(PNG, format="b")
        with self.alice.unlock("alice-pass"):
            msg |= self.alice.sign(msg)
        with self.assertRaisesRegex(CryptoError, "is a signed PGP file, but it isn't encrypted"):
            crypto.decrypt_file(self.make("signed.pgp", bytes(msg)), self.bob, "bob-pass")

    def test_armored_file_also_decrypts(self):
        src = self.make("photo.png", PNG)
        armored = pgpy.PGPMessage.from_blob(crypto.encrypt_file(src, [self.bob.pubkey], self.alice, "alice-pass"))
        result = crypto.decrypt_file(self.make("photo.png.asc", str(armored).encode()), self.bob, "bob-pass")
        self.assertEqual(result.data, PNG)

    def test_size_limit(self):
        src = self.make("big.bin", b"x" * 100)
        with mock.patch.object(crypto, "MAX_FILE_BYTES", 50):
            with self.assertRaisesRegex(CryptoError, "Files up to"):
                crypto.encrypt_file(src, [self.bob.pubkey], self.alice, "alice-pass")
            with self.assertRaisesRegex(CryptoError, "Files up to"):
                crypto.decrypt_file(src, self.bob, "bob-pass")
        with mock.patch.object(crypto, "MAX_FILE_BYTES", 90):
            # encrypted files get 25% slack (headers/armor): 100 > 90 but <= 112
            self.assertEqual(crypto.check_file_size(src, decrypting=True), 100)
            with self.assertRaises(CryptoError):
                crypto.check_file_size(src)

    def test_large_file_threshold_is_below_hard_limit(self):
        self.assertEqual(crypto.LARGE_FILE_BYTES, 100 * 2**20)
        self.assertLess(crypto.LARGE_FILE_BYTES, crypto.MAX_FILE_BYTES)

    def test_sender_filename_is_sanitized(self):
        cases = {
            "../../.ssh/authorized_keys": "authorized_keys",
            "C:\\Windows\\evil.exe": "evil.exe",
            ".bashrc": "",
            "..": "",
            "_CONSOLE": "",
            "a\x00b\nc.txt": "abc.txt",
            "": "",
            None: "",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(crypto._safe_filename(raw), expected)


class FileOpsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_output_names(self):
        d = self.dir
        self.assertEqual(fileops.encrypted_path_for(d / "photo.png"), d / "photo.png.pgp")
        self.assertEqual(fileops.decrypted_path_for(d / "photo.png.pgp"), d / "photo.png")
        self.assertEqual(fileops.decrypted_path_for(d / "photo.png.GPG"), d / "photo.png")
        self.assertEqual(fileops.decrypted_path_for(d / "blob.bin", "photo.png"), d / "photo.png")
        self.assertEqual(fileops.decrypted_path_for(d / "blob.bin"), d / "blob.bin.decrypted")
        self.assertEqual(fileops.decrypted_path_for(d / ".pgp", "x.png"), d / "x.png")

    def test_never_overwrites_without_permission(self):
        target = self.dir / "photo.png"
        target.write_bytes(b"precious")
        with self.assertRaises(FileExistsError):
            fileops.write_file(target, b"new")
        self.assertEqual(target.read_bytes(), b"precious")
        fileops.write_file(target, b"new", overwrite=True)
        self.assertEqual(target.read_bytes(), b"new")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["photo.png"])  # no temp files left

    def test_writes_new_file(self):
        target = self.dir / "new.bin"
        fileops.write_file(target, PNG)
        self.assertEqual(target.read_bytes(), PNG)

    def test_available_memory(self):
        free = fileops.available_memory()
        if os.name == "nt" or os.path.exists("/proc/meminfo"):
            self.assertIsInstance(free, int)
            self.assertGreater(free, 0)
        else:
            self.assertTrue(free is None or free > 0)

    def test_filesystem_without_hard_links(self):
        # e.g. FAT/exFAT USB sticks: os.link fails with a generic OSError
        target = self.dir / "usb.bin"
        with mock.patch.object(fileops.os, "link", side_effect=OSError("not supported")):
            fileops.write_file(target, PNG)
            self.assertEqual(target.read_bytes(), PNG)
            with self.assertRaises(FileExistsError):
                fileops.write_file(target, b"other")
        self.assertEqual(target.read_bytes(), PNG)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["usb.bin"])


@unittest.skipUnless(shutil.which("gpg"), "GnuPG not installed")
class GnuPGFileInteropTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = crypto.generate_keypair("Interop", "", "pw", BITS)
        cls.home = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.home.name)
        cls.env = dict(os.environ, GNUPGHOME=str(cls.dir / "gnupg"))
        (cls.dir / "gnupg").mkdir(mode=0o700)
        try:
            cls.gpg("--import", input=str(cls.key).encode())
        except subprocess.CalledProcessError as exc:
            cls.home.cleanup()
            detail = exc.stderr.decode(errors="replace").strip().splitlines()[-1:] or ["no output"]
            raise unittest.SkipTest(f"gpg found but unusable here: {detail[0]}")

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    @classmethod
    def gpg(cls, *args, input=b""):
        return subprocess.run(
            ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "pw",
             "--trust-model", "always", *args],
            input=input, env=cls.env, capture_output=True, check=True,
        )

    def test_gpg_decrypts_our_file(self):
        src = self.dir / "photo.png"
        src.write_bytes(PNG)
        enc = self.dir / "photo.png.pgp"
        enc.write_bytes(crypto.encrypt_file(src, [self.key.pubkey], self.key, "pw"))
        out = self.dir / "from-gpg.png"
        result = self.gpg("-o", str(out), "--decrypt", str(enc))
        self.assertEqual(out.read_bytes(), PNG)
        self.assertIn(b"Good signature", result.stderr)

    def test_we_decrypt_gpg_file(self):
        src = self.dir / "scan.pdf"
        src.write_bytes(b"%PDF-1.7\r\n" + os.urandom(2048))
        fpr = str(self.key.fingerprint).replace(" ", "")
        enc = self.dir / "scan.pdf.gpg"
        self.gpg("-r", fpr, "--sign", "--encrypt", "-o", str(enc), str(src))
        result = crypto.decrypt_file(enc, self.key, "pw", {"Interop": self.key.pubkey})
        self.assertEqual(result.data, src.read_bytes())
        self.assertEqual(result.original_name, "scan.pdf")
        self.assertTrue(result.signature.valid)


if __name__ == "__main__":
    unittest.main()
