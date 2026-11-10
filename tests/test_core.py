"""Round-trip tests for crypto.py and keyring.py (no GUI needed).

Run with:  python -m unittest -v
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pgpy

from pgp_messenger import crypto
from pgp_messenger.crypto import CryptoError
from pgp_messenger import keyring as keyring_mod
from pgp_messenger.keyring import Keyring

BITS = 2048  # small keys keep the tests fast; the app offers 3072/4096


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = crypto.generate_keypair("Alice", "alice@example.org", "alice-pass", BITS)
        cls.bob = crypto.generate_keypair("Bob", "", "bob-pass", BITS)
        cls.mallory = crypto.generate_keypair("Mallory", "", "mallory-pass", BITS)

    def test_keys_are_protected(self):
        self.assertTrue(self.alice.is_protected)
        self.assertFalse(self.alice.is_unlocked)

    def test_encrypt_decrypt_roundtrip_unicode(self):
        text = "Meet at 6. Café ✓ 🔐\nSecond line."
        armored = crypto.encrypt(text, [self.bob.pubkey])
        self.assertIn("-----BEGIN PGP MESSAGE-----", armored)
        result = crypto.decrypt(armored, self.bob, "bob-pass")
        self.assertEqual(result.text, text)
        self.assertFalse(result.signature.signed)

    def test_multiple_recipients_share_one_session_key(self):
        armored = crypto.encrypt("hi both", [self.bob.pubkey, self.alice.pubkey])
        self.assertEqual(crypto.decrypt(armored, self.bob, "bob-pass").text, "hi both")
        self.assertEqual(crypto.decrypt(armored, self.alice, "alice-pass").text, "hi both")

    def test_wrong_passphrase(self):
        armored = crypto.encrypt("x", [self.bob.pubkey])
        with self.assertRaisesRegex(CryptoError, "Wrong passphrase"):
            crypto.decrypt(armored, self.bob, "nope")

    def test_not_for_me(self):
        armored = crypto.encrypt("x", [self.bob.pubkey])
        with self.assertRaisesRegex(CryptoError, "wasn't encrypted to your key"):
            crypto.decrypt(armored, self.mallory, "mallory-pass")

    def test_signed_and_encrypted(self):
        armored = crypto.encrypt("signed secret", [self.bob.pubkey], signer=self.alice, passphrase="alice-pass")
        result = crypto.decrypt(armored, self.bob, "bob-pass", {"Alice": self.alice.pubkey})
        self.assertEqual(result.text, "signed secret")
        self.assertTrue(result.signature.valid)
        self.assertEqual(result.signature.signer_name, "Alice")

    def test_signed_by_unknown(self):
        armored = crypto.encrypt("s", [self.bob.pubkey], signer=self.alice, passphrase="alice-pass")
        result = crypto.decrypt(armored, self.bob, "bob-pass", {})
        self.assertTrue(result.signature.signed)
        self.assertIsNone(result.signature.signer_name)
        self.assertFalse(result.signature.valid)

    def test_sign_verify(self):
        signed = crypto.sign("I owe Bob £5.\nSigned, Alice", self.alice, "alice-pass")
        self.assertIn("-----BEGIN PGP SIGNED MESSAGE-----", signed)
        result = crypto.verify(signed, {"Alice": self.alice.pubkey, "Bob": self.bob.pubkey})
        self.assertTrue(result.signature.valid)
        self.assertEqual(result.signature.signer_name, "Alice")
        self.assertEqual(result.text, "I owe Bob £5.\nSigned, Alice")

    def test_sign_verify_tricky_text(self):
        # non-ASCII (PGPy parser bug), dash-escaped lines, and CRLF from Windows/clipboards
        text = "café ✓ 🔐\n- a list item\n-----not a header\n\nend"
        signed = crypto.sign(text, self.alice, "alice-pass")
        for variant in (signed, signed.replace("\n", "\r\n")):
            result = crypto.verify(variant, {"Alice": self.alice.pubkey})
            self.assertTrue(result.signature.valid)
            self.assertEqual(result.text, text)

    def test_decrypt_names_the_wrong_block_type(self):
        want_message = "Paste a block that starts with -----BEGIN PGP MESSAGE-----"
        detached_sig = str(self.alice_unlocked_sign("hello"))
        cases = {
            "public key": str(self.alice.pubkey),
            "private key": str(self.alice),
            "signature": detached_sig,
            # surrounding junk (e.g. quoted from an email) must not hide the block type
            "public key, not": "Here's my key!\r\n\r\n" + str(self.alice.pubkey).replace("\n", "\r\n") + "\nthanks",
        }
        for label, block in cases.items():
            with self.subTest(label), self.assertRaises(CryptoError) as ctx:
                crypto.decrypt(block, self.bob, "bob-pass")
            msg = str(ctx.exception)
            self.assertIn(f"That's a PGP {label}", msg)
            self.assertIn(want_message, msg)

    def test_decrypt_keeps_generic_error_for_non_pgp_text(self):
        for text in ("hello", "-----BEGIN SOMETHING ELSE-----\nabc\n-----END SOMETHING ELSE-----"):
            with self.subTest(text), self.assertRaisesRegex(CryptoError, "doesn't look like a PGP message"):
                crypto.decrypt(text, self.bob, "bob-pass")

    def test_decrypt_unencrypted_message_block(self):
        # a real "BEGIN PGP MESSAGE" that is only signed keeps the "isn't encrypted" error
        msg = pgpy.PGPMessage.new("inline signed")
        with self.alice.unlock("alice-pass"):
            msg |= self.alice.sign(msg)
        with self.assertRaisesRegex(CryptoError, "isn't encrypted"):
            crypto.decrypt(str(msg), self.bob, "bob-pass")

    def alice_unlocked_sign(self, text):
        with self.alice.unlock("alice-pass"):
            return self.alice.sign(text)

    def test_tampered_signature_fails(self):
        signed = crypto.sign("I owe Bob 5 dollars.", self.alice, "alice-pass")
        tampered = signed.replace("5 dollars", "500 dollars")
        result = crypto.verify(tampered, {"Alice": self.alice.pubkey})
        self.assertFalse(result.signature.valid)

    def test_sign_wrong_passphrase(self):
        with self.assertRaisesRegex(CryptoError, "Wrong passphrase"):
            crypto.sign("x", self.alice, "bad")

    def test_garbage_input(self):
        with self.assertRaises(CryptoError):
            crypto.decrypt("hello", self.bob, "bob-pass")
        with self.assertRaises(CryptoError):
            crypto.parse_key("not a key")

    def test_wrong_tab_hints(self):
        signed = crypto.sign("plain", self.alice, "alice-pass")
        with self.assertRaisesRegex(CryptoError, r"That's a signed message .*Sign & Verify"):
            crypto.decrypt(signed, self.bob, "bob-pass")
        enc = crypto.encrypt("x", [self.bob.pubkey])
        with self.assertRaisesRegex(CryptoError, "encrypted"):
            crypto.verify(enc, {})


@unittest.skipUnless(shutil.which("gpg"), "GnuPG not installed")
class GnuPGInteropTests(unittest.TestCase):
    """Prove our output is real OpenPGP by round-tripping through GnuPG."""

    @classmethod
    def setUpClass(cls):
        cls.key = crypto.generate_keypair("Interop", "", "pw", BITS)
        cls.home = tempfile.TemporaryDirectory()
        cls.env = dict(os.environ, GNUPGHOME=cls.home.name)
        cls.gpg("--import", input=str(cls.key))

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    @classmethod
    def gpg(cls, *args, input=""):
        return subprocess.run(
            ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "pw", *args],
            input=input.encode(), env=cls.env, capture_output=True, check=True,
        ).stdout.decode()

    def test_gpg_decrypts_our_message(self):
        text = "from PGPy, café ✓"
        out = self.gpg("--decrypt", input=crypto.encrypt(text, [self.key.pubkey], self.key, "pw"))
        self.assertEqual(out, text)

    def test_we_decrypt_gpg_message(self):
        fpr = str(self.key.fingerprint).replace(" ", "")
        armored = self.gpg("--armor", "--trust-model", "always", "-r", fpr, "--sign", "--encrypt", input="from gpg ✓")
        result = crypto.decrypt(armored, self.key, "pw", {"Interop": self.key.pubkey})
        self.assertEqual(result.text, "from gpg ✓")
        self.assertTrue(result.signature.valid)

    def test_we_verify_gpg_cleartext_signature(self):
        signed = self.gpg("--clearsign", input="signed by gpg, £5\n- dash line\n")
        result = crypto.verify(signed, {"Interop": self.key.pubkey})
        self.assertTrue(result.signature.valid)

    def test_gpg_verifies_our_cleartext_signature(self):
        self.gpg("--verify", input=crypto.sign("signed by us, £5\n- dash", self.key, "pw"))  # check=True


class KeyringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.me = crypto.generate_keypair("Me", "", "my-pass", BITS)
        cls.alice = crypto.generate_keypair("Alice", "", "a", BITS)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ring = Keyring(Path(self.tmp.name) / "ring")

    def tearDown(self):
        self.tmp.cleanup()

    def test_identity_persists(self):
        self.assertFalse(self.ring.has_identity())
        self.ring.save_identity(self.me)
        loaded = Keyring(self.ring.root).load_identity()
        self.assertEqual(loaded.fingerprint, self.me.fingerprint)
        self.assertTrue(loaded.is_protected)

    @unittest.skipIf(os.name == "nt", "Windows uses per-user ACLs, not POSIX mode bits")
    def test_files_are_owner_only(self):
        self.ring.save_identity(self.me)
        self.ring.add_contact("Alice", str(self.alice.pubkey))
        for path in (self.ring.identity_path, self.ring.index_path, *self.ring.contacts_dir.iterdir()):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
        for d in (self.ring.root, self.ring.contacts_dir):
            self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700, d)

    def test_default_location_per_platform(self):
        env = {"APPDATA": r"C:\Users\x\AppData\Roaming", "XDG_CONFIG_HOME": "/xdg"}
        with mock.patch.dict(os.environ, env):
            os.environ.pop("PGP_MESSENGER_HOME", None)
            self.assertEqual(keyring_mod.default_root("nt"), Path(env["APPDATA"]) / "pgp-messenger")
            self.assertEqual(keyring_mod.default_root("posix"), Path("/xdg") / "pgp-messenger")
        with mock.patch.dict(os.environ, {"PGP_MESSENGER_HOME": "/custom"}):
            self.assertEqual(keyring_mod.default_root(), Path("/custom"))

    def test_contacts_add_list_remove(self):
        self.ring.add_contact("Alice", str(self.alice.pubkey))
        self.assertEqual(self.ring.contact_names(), ["Alice"])
        self.assertEqual(self.ring.get_contact("Alice").fingerprint, self.alice.fingerprint)
        with self.assertRaisesRegex(CryptoError, "already have"):
            self.ring.add_contact("alice", str(self.me.pubkey))
        with self.assertRaisesRegex(CryptoError, "already saved"):
            self.ring.add_contact("Alice 2", str(self.alice.pubkey))
        self.ring.remove_contact("Alice")
        self.assertEqual(self.ring.contact_names(), [])
        self.assertEqual(list(self.ring.contacts_dir.iterdir()), [])

    def test_rejects_private_key_as_contact(self):
        with self.assertRaisesRegex(CryptoError, "PRIVATE"):
            self.ring.add_contact("Oops", str(self.alice))


if __name__ == "__main__":
    unittest.main()
