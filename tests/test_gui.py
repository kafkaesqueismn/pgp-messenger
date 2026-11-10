"""Files tab behaviour, driven offscreen with dialogs mocked.

Skipped automatically if PySide6 isn't installed.
Run with:  python -m unittest -v
"""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
try:
    from PySide6.QtWidgets import QApplication, QMessageBox
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("PySide6 not installed")

from pgp_messenger import crypto, gui
from pgp_messenger.keyring import Keyring

BITS = 2048
YES, NO = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
CANCEL = QMessageBox.StandardButton.Cancel


class FilesTabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.me = crypto.generate_keypair("Me", "", "pw", BITS)
        cls.alice = crypto.generate_keypair("Alice", "", "a", BITS)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        ring = Keyring(self.dir / "ring")
        ring.save_identity(self.me)
        ring.add_contact("Alice", str(self.alice.pubkey))
        self.win = gui.MainWindow(ring)
        self.files = self.win.pages[4]
        self.assertIsInstance(self.files, gui.FilesTab)

        self.passphrase = mock.patch.object(gui, "ask_passphrase", return_value="pw").start()
        self.warning = mock.patch.object(gui.QMessageBox, "warning", return_value=YES).start()
        self.question = mock.patch.object(gui.QMessageBox, "question", return_value=NO).start()
        self.addCleanup(mock.patch.stopall)

        self.src = self.dir / "photo.png"
        self.src.write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(2000))

    def tearDown(self):
        self.wait()
        self.win.close()
        self.win.deleteLater()
        self.tmp.cleanup()

    def wait(self, timeout=60):
        deadline = time.time() + timeout
        while self.files.is_busy() and time.time() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        self.app.processEvents()
        self.assertFalse(self.files.is_busy(), "background job did not finish")

    def encrypt(self, src=None):
        src = src or self.src
        self.files.enc_src.setText(str(src))
        self.files.enc_dst.setText(str(src) + ".pgp")
        self.files._encrypt()
        self.wait()
        return Path(str(src) + ".pgp")

    # --------------------------------------------------------------- basics

    def test_small_file_roundtrip_without_warning(self):
        enc = self.encrypt()
        self.warning.assert_not_called()
        self.assertTrue(enc.exists())
        self.assertIn("Encrypted and signed photo.png for Alice", self.files.enc_banner.text())

        self.src.unlink()
        self.files.dec_src.setText(str(enc))
        self.files.dec_dst.setText(str(self.src))
        self.files._decrypt()
        self.wait()
        self.assertTrue(self.src.exists())
        self.assertIn("Good signature from you", self.files.dec_banner.text())

    # --------------------------------------------------------------- large files

    def test_large_file_cancel_does_nothing(self):
        self.warning.return_value = CANCEL
        with mock.patch.object(crypto, "LARGE_FILE_BYTES", 100):
            enc = self.encrypt()
        text = self.warning.call_args.args[2]
        self.assertIn("photo.png is", text)
        self.assertIn("RAM", text)
        self.assertIn("Continue?", text)
        self.passphrase.assert_not_called()
        self.assertFalse(enc.exists())
        self.assertIn("Cancelled", self.files.enc_banner.text())

    def test_large_file_continue_shows_working_state(self):
        real = crypto.encrypt_file

        def slow(*args, **kwargs):
            time.sleep(1.0)
            return real(*args, **kwargs)

        with mock.patch.object(crypto, "LARGE_FILE_BYTES", 100), mock.patch.object(crypto, "encrypt_file", slow):
            self.files.enc_src.setText(str(self.src))
            self.files.enc_dst.setText(str(self.src) + ".pgp")
            self.files._encrypt()
            self.app.processEvents()
            # mid-run: busy bar visible, every control in the tab locked, rest of app usable
            self.assertTrue(self.files.is_busy())
            self.assertTrue(self.files.enc_busy.isVisibleTo(self.files))
            self.assertIn("Encrypting photo.png", self.files.enc_busy.label.text())
            self.assertFalse(any(w.isEnabled() for w in self.files._controls))
            self.assertTrue(self.win.pages[2].isEnabled())
            self.wait()
        self.warning.assert_called_once()
        self.assertFalse(self.files.enc_busy.isVisibleTo(self.files))
        self.assertTrue(all(w.isEnabled() for w in self.files._controls))
        self.assertTrue(Path(str(self.src) + ".pgp").exists())

    def test_large_file_warning_on_decrypt_too(self):
        enc = self.encrypt()
        self.warning.return_value = CANCEL
        self.passphrase.reset_mock()
        with mock.patch.object(crypto, "LARGE_FILE_BYTES", 100):
            self.files.dec_src.setText(str(enc))
            self.files.dec_dst.setText(str(self.dir / "out.png"))
            self.files._decrypt()
        self.assertIn("Decrypting it loads", self.warning.call_args.args[2])
        self.passphrase.assert_not_called()

    def test_over_hard_limit_rejected_before_passphrase(self):
        with mock.patch.object(crypto, "MAX_FILE_BYTES", 100):
            enc = self.encrypt()
        self.passphrase.assert_not_called()
        self.warning.assert_not_called()
        self.assertFalse(enc.exists())
        self.assertIn("Files up to", self.files.enc_banner.text())

    def test_quit_while_busy_asks_first(self):
        self.files._run(lambda: time.sleep(0.5), lambda r: None,
                        self.files.enc_banner, self.files.enc_busy, "Encrypting…")
        self.question.return_value = NO
        self.assertFalse(self.win.close())  # refused: still open
        self.assertIn("still being encrypted", self.question.call_args.args[2])
        self.wait()
        self.question.reset_mock()
        self.assertTrue(self.win.close())  # idle: closes without asking
        self.question.assert_not_called()

    # --------------------------------------------------------------- overwriting

    def test_never_overwrites_when_declined(self):
        enc = Path(str(self.src) + ".pgp")
        enc.write_bytes(b"precious")
        self.question.return_value = NO
        self.encrypt()
        self.assertEqual(enc.read_bytes(), b"precious")
        self.passphrase.assert_not_called()  # asked before doing any work
        self.assertIn("Not saved", self.files.enc_banner.text())

        self.question.return_value = YES
        self.encrypt()
        self.assertNotEqual(enc.read_bytes(), b"precious")

    def test_decrypt_does_not_overwrite_original_when_declined(self):
        enc = self.encrypt()
        original = self.src.read_bytes()
        self.src.write_bytes(b"edited since")
        self.question.return_value = NO
        self.files.dec_src.setText(str(enc))
        self.files.dec_dst.setText(str(self.src))
        self.files._decrypt()
        self.wait()
        self.assertEqual(self.src.read_bytes(), b"edited since")
        self.assertNotEqual(original, b"edited since")

    # --------------------------------------------------------------- signatures

    def test_bad_signature_not_saved_unless_confirmed(self):
        bad = crypto.SignatureStatus(signed=True, valid=False, signer_name="Alice", signer_key_ids=["X"])
        fake = crypto.DecryptedFile(b"tampered", "doc.pdf", bad)
        src = self.dir / "doc.pdf.pgp"
        src.write_bytes(b"x")
        out = self.dir / "doc.pdf"
        with mock.patch.object(crypto, "decrypt_file", return_value=fake):
            for answer, saved in ((QMessageBox.StandardButton.Discard, False), (QMessageBox.StandardButton.Save, True)):
                self.warning.return_value = answer
                self.files.dec_src.setText(str(src))
                self.files._dec_dst_custom = False
                self.files._decrypt()
                self.wait()
                self.assertEqual(out.exists(), saved, answer)
                self.assertIn("BAD signature", self.files.dec_banner.text())


if __name__ == "__main__":
    unittest.main()
