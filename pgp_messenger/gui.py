"""PySide6 user interface.

Five tabs, each a small self-contained widget:
    My Key | Contacts | Encrypt | Decrypt | Sign & Verify

All crypto goes through `crypto.py`; all storage through `keyring.py`.
Passphrases are asked for at the moment they're needed and never stored.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtGui import QFontDatabase, QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from . import crypto
from .crypto import CryptoError
from .keyring import Keyring

MIN_PASSPHRASE_LEN = 8
SELF_NAME = "you"

# --------------------------------------------------------------------------
# Small shared helpers
# --------------------------------------------------------------------------


def mono_edit(placeholder: str = "", read_only: bool = False) -> QPlainTextEdit:
    edit = QPlainTextEdit()
    edit.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    edit.setPlaceholderText(placeholder)
    edit.setReadOnly(read_only)
    edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap if read_only else QPlainTextEdit.LineWrapMode.WidgetWidth)
    return edit


def text_edit(placeholder: str = "", read_only: bool = False) -> QPlainTextEdit:
    edit = QPlainTextEdit()
    edit.setPlaceholderText(placeholder)
    edit.setReadOnly(read_only)
    return edit


def copy_button(source: QPlainTextEdit, label: str = "Copy") -> QPushButton:
    btn = QPushButton(label)

    def do_copy():
        text = source.toPlainText()
        if text:
            QGuiApplication.clipboard().setText(text)
            btn.setText("Copied ✓")
        else:
            btn.setText("Nothing to copy")

    btn.clicked.connect(do_copy)
    source.textChanged.connect(lambda: btn.setText(label))
    return btn


class StatusBanner(QLabel):
    """A coloured one-line message: ok / warn / error / info."""

    STYLES = {
        "ok": "rgba(46,160,67,0.18)",
        "warn": "rgba(210,153,34,0.22)",
        "error": "rgba(218,54,51,0.22)",
        "info": "rgba(56,139,253,0.15)",
    }

    def __init__(self):
        super().__init__()
        self.setWordWrap(True)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.clear()

    def show_message(self, kind: str, text: str) -> None:
        self.setStyleSheet(f"background:{self.STYLES[kind]}; padding:8px; border-radius:6px;")
        self.setText(text)
        self.setVisible(True)

    def clear(self) -> None:  # type: ignore[override]
        super().clear()
        self.setVisible(False)


def hint(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setStyleSheet("color: palette(placeholder-text);")
    return label


def ask_passphrase(parent: QWidget, why: str) -> str | None:
    text, ok = QInputDialog.getText(
        parent, "Passphrase", f"{why}\n\nEnter the passphrase for your private key:", QLineEdit.EchoMode.Password
    )
    return text if ok else None


class _TaskSignals(QObject):
    done = Signal(object)
    failed = Signal(object)


class BackgroundTask(QRunnable):
    """Run a slow function (e.g. key generation) off the UI thread."""

    def __init__(self, fn):
        super().__init__()
        self.fn = fn
        self.signals = _TaskSignals()

    def run(self):
        try:
            result = self.fn()
        except Exception as exc:  # noqa: BLE001 - reported to the user
            self.signals.failed.emit(exc)
        else:
            self.signals.done.emit(result)


# --------------------------------------------------------------------------
# Tabs
# --------------------------------------------------------------------------


class Tab(QWidget):
    """Base class: every tab can access the keyring and announce changes."""

    keys_changed = Signal()

    def __init__(self, keyring: Keyring):
        super().__init__()
        self.keyring = keyring

    def refresh(self) -> None:
        """Called whenever keys change anywhere in the app."""

    def identity_or_warn(self, banner: StatusBanner):
        key = self.keyring.load_identity()
        if key is None:
            banner.show_message("warn", "You don't have a key yet. Create one in the My Key tab first.")
        return key


class MyKeyTab(Tab):
    def __init__(self, keyring: Keyring):
        super().__init__(keyring)
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_create_page())
        self.stack.addWidget(self._build_show_page())
        layout = QVBoxLayout(self)
        layout.addWidget(self.stack)
        self._task = None
        self.refresh()

    # -- page 0: create a key
    def _build_create_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("<h2>Create your key</h2>"))
        layout.addWidget(
            hint(
                "Your key has two halves. The <b>public key</b> is what you give to others so they can "
                "send you encrypted messages and check your signatures. The <b>private key</b> stays on "
                "this computer, locked with a passphrase. Nobody, including you, can recover it if you forget the passphrase."
            )
        )

        form = QFormLayout()
        self.name_in = QLineEdit()
        self.name_in.setPlaceholderText("e.g. Alex Doe")
        self.email_in = QLineEdit()
        self.email_in.setPlaceholderText("optional")
        self.pass_in = QLineEdit()
        self.pass_in.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass2_in = QLineEdit()
        self.pass2_in.setEchoMode(QLineEdit.EchoMode.Password)
        self.bits_in = QComboBox()
        self.bits_in.addItem("RSA 3072 (recommended)", 3072)
        self.bits_in.addItem("RSA 4096 (slower)", 4096)
        form.addRow("Name", self.name_in)
        form.addRow("Email", self.email_in)
        form.addRow("Passphrase", self.pass_in)
        form.addRow("Repeat passphrase", self.pass2_in)
        form.addRow("Key type", self.bits_in)
        layout.addLayout(form)

        self.generate_btn = QPushButton("Generate my key")
        self.generate_btn.clicked.connect(self._generate)
        layout.addWidget(self.generate_btn, alignment=Qt.AlignmentFlag.AlignLeft)
        self.create_banner = StatusBanner()
        layout.addWidget(self.create_banner)
        layout.addStretch()
        return page

    # -- page 1: show the existing key
    def _build_show_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("<h2>Your key</h2>"))
        self.info_label = QLabel()
        self.info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.info_label)

        layout.addWidget(QLabel("<b>Your public key</b>: share this with people who want to message you:"))
        self.pub_out = mono_edit(read_only=True)
        layout.addWidget(self.pub_out, stretch=1)

        row = QHBoxLayout()
        row.addWidget(copy_button(self.pub_out, "Copy public key"))
        save_pub = QPushButton("Save public key…")
        save_pub.clicked.connect(self._save_public)
        row.addWidget(save_pub)
        backup = QPushButton("Back up private key…")
        backup.setToolTip("Saves your private key (still locked with your passphrase) to a file of your choice.")
        backup.clicked.connect(self._backup_private)
        row.addWidget(backup)
        row.addStretch()
        delete = QPushButton("Delete my key…")
        delete.setStyleSheet("color: #d03030;")
        delete.clicked.connect(self._delete)
        row.addWidget(delete)
        layout.addLayout(row)
        return page

    def refresh(self) -> None:
        key = self.keyring.load_identity()
        if key is None:
            self.stack.setCurrentIndex(0)
            return
        info = crypto.key_info(key)
        self.info_label.setText(
            f"<b>{info.user_id}</b><br>"
            f"Fingerprint: <code>{info.fingerprint}</code><br>"
            f"RSA {info.bits}-bit · created {info.created:%Y-%m-%d}<br>"
            f"Stored in: <code>{self.keyring.identity_path}</code>"
        )
        self.pub_out.setPlainText(str(key.pubkey))
        self.stack.setCurrentIndex(1)

    def _generate(self) -> None:
        name, email = self.name_in.text().strip(), self.email_in.text().strip()
        pw, pw2 = self.pass_in.text(), self.pass2_in.text()
        if not name:
            return self.create_banner.show_message("error", "Please enter your name.")
        if len(pw) < MIN_PASSPHRASE_LEN:
            return self.create_banner.show_message(
                "error", f"Use a passphrase of at least {MIN_PASSPHRASE_LEN} characters. A few random words works well."
            )
        if pw != pw2:
            return self.create_banner.show_message("error", "The passphrases don't match.")

        bits = self.bits_in.currentData()
        self.generate_btn.setEnabled(False)
        self.create_banner.show_message("info", "Generating your key… this can take a few seconds.")
        self._task = BackgroundTask(lambda: crypto.generate_keypair(name, email, pw, bits))
        self._task.signals.done.connect(self._on_generated)
        self._task.signals.failed.connect(self._on_generate_failed)
        QThreadPool.globalInstance().start(self._task)

    def _on_generated(self, key) -> None:
        self.generate_btn.setEnabled(True)
        try:
            self.keyring.save_identity(key)
        except (OSError, CryptoError) as exc:
            return self.create_banner.show_message("error", f"Couldn't save key: {exc}")
        for w in (self.pass_in, self.pass2_in):
            w.clear()
        self.create_banner.clear()
        self.keys_changed.emit()

    def _on_generate_failed(self, exc) -> None:
        self.generate_btn.setEnabled(True)
        self.create_banner.show_message("error", f"Key generation failed: {exc}")

    def _save_public(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save public key", str(Path.home() / "public_key.asc"), "PGP key (*.asc)")
        if path:
            Path(path).write_text(self.pub_out.toPlainText(), encoding="utf-8")

    def _backup_private(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Back up private key", str(Path.home() / "private_key_backup.asc"), "PGP key (*.asc)"
        )
        if path:
            p = Path(path)
            p.write_text(self.keyring.identity_path.read_text(encoding="utf-8"), encoding="utf-8")
            p.chmod(0o600)

    def _delete(self) -> None:
        answer = QMessageBox.warning(
            self,
            "Delete your key?",
            "This permanently deletes your private key from this computer.\n\n"
            "You will no longer be able to decrypt messages sent to it, unless you have a backup.\n\n"
            "Delete it?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.keyring.delete_identity()
            self.keys_changed.emit()


class ContactsTab(Tab):
    def __init__(self, keyring: Keyring):
        super().__init__(keyring)
        layout = QHBoxLayout(self)

        # left: list
        left = QVBoxLayout()
        left.addWidget(QLabel("<h2>Contacts</h2>"))
        self.list = QListWidget()
        self.list.currentTextChanged.connect(self._show_details)
        left.addWidget(self.list, stretch=1)
        self.details = QLabel()
        self.details.setWordWrap(True)
        self.details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        left.addWidget(self.details)
        self.remove_btn = QPushButton("Remove contact…")
        self.remove_btn.clicked.connect(self._remove)
        left.addWidget(self.remove_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        # right: add
        right = QGroupBox("Add a contact")
        r = QVBoxLayout(right)
        r.addWidget(hint("Paste the person's <b>public</b> key (or load it from a .asc file) and give it a name you'll recognise."))
        form = QFormLayout()
        self.name_in = QLineEdit()
        self.name_in.setPlaceholderText("e.g. Alice")
        form.addRow("Name", self.name_in)
        r.addLayout(form)
        self.key_in = mono_edit("-----BEGIN PGP PUBLIC KEY BLOCK-----\n…")
        r.addWidget(self.key_in, stretch=1)
        row = QHBoxLayout()
        load = QPushButton("Load from file…")
        load.clicked.connect(self._load_file)
        add = QPushButton("Add contact")
        add.setDefault(True)
        add.clicked.connect(self._add)
        row.addWidget(load)
        row.addStretch()
        row.addWidget(add)
        r.addLayout(row)
        self.banner = StatusBanner()
        r.addWidget(self.banner)

        left_w = QWidget()
        left_w.setLayout(left)
        split = QSplitter()
        split.addWidget(left_w)
        split.addWidget(right)
        split.setStretchFactor(1, 2)
        layout.addWidget(split)
        self.refresh()

    def refresh(self) -> None:
        current = self.list.currentItem().text() if self.list.currentItem() else None
        self.list.clear()
        self.list.addItems(self.keyring.contact_names())
        matches = self.list.findItems(current, Qt.MatchFlag.MatchExactly) if current else []
        if matches:
            self.list.setCurrentItem(matches[0])
        self._show_details(current if matches else "")

    def _show_details(self, name: str) -> None:
        self.remove_btn.setEnabled(bool(name))
        if not name:
            self.details.setText("<i>Select a contact to see their key details.</i>")
            return
        try:
            info = crypto.key_info(self.keyring.get_contact(name))
        except (OSError, CryptoError) as exc:
            self.details.setText(f"Couldn't load key: {exc}")
            return
        self.details.setText(
            f"<b>{info.user_id}</b><br>Fingerprint:<br><code>{info.fingerprint}</code><br>"
            f"RSA {info.bits}-bit · created {info.created:%Y-%m-%d}<br>"
            "<i>Tip: confirm the fingerprint with them in person or by phone.</i>"
        )

    def _load_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open public key", str(Path.home()), "PGP keys (*.asc *.txt *.pub);;All files (*)")
        if not path:
            return
        try:
            self.key_in.setPlainText(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            self.banner.show_message("error", "Couldn't read that file. Is it an ASCII-armored (.asc) key?")
            return
        if not self.name_in.text().strip():
            try:
                uid = crypto.parse_key(self.key_in.toPlainText()).userids
                if uid:
                    self.name_in.setText(uid[0].name)
            except CryptoError:
                pass

    def _add(self) -> None:
        try:
            key = self.keyring.add_contact(self.name_in.text(), self.key_in.toPlainText())
        except (OSError, CryptoError) as exc:
            return self.banner.show_message("error", str(exc))
        info = crypto.key_info(key)
        self.banner.show_message("ok", f"Added {self.name_in.text().strip()} ({info.user_id}).")
        self.name_in.clear()
        self.key_in.clear()
        self.keys_changed.emit()

    def _remove(self) -> None:
        item = self.list.currentItem()
        if not item:
            return
        name = item.text()
        if (
            QMessageBox.question(self, "Remove contact", f"Remove '{name}' and their public key?")
            == QMessageBox.StandardButton.Yes
        ):
            self.keyring.remove_contact(name)
            self.keys_changed.emit()


class EncryptTab(Tab):
    def __init__(self, keyring: Keyring):
        super().__init__(keyring)
        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        top.addWidget(QLabel("<b>To:</b>"))
        self.to_in = QComboBox()
        self.to_in.setMinimumWidth(220)
        top.addWidget(self.to_in)
        self.self_in = QCheckBox("Also encrypt to me (so I can read it later)")
        self.self_in.setChecked(True)
        self.sign_in = QCheckBox("Sign it (proves it's from me)")
        self.sign_in.setChecked(True)
        top.addWidget(self.self_in)
        top.addWidget(self.sign_in)
        top.addStretch()
        layout.addLayout(top)

        layout.addWidget(QLabel("Message"))
        self.msg_in = text_edit("Type your secret message here…")
        layout.addWidget(self.msg_in, stretch=1)

        btn = QPushButton("Encrypt")
        btn.setDefault(True)
        btn.clicked.connect(self._encrypt)
        layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignLeft)
        self.banner = StatusBanner()
        layout.addWidget(self.banner)

        layout.addWidget(QLabel("Encrypted message: copy this and send it any way you like (email, chat, …)"))
        self.out = mono_edit(read_only=True)
        layout.addWidget(self.out, stretch=1)
        layout.addWidget(copy_button(self.out), alignment=Qt.AlignmentFlag.AlignLeft)
        self.refresh()

    def refresh(self) -> None:
        current = self.to_in.currentText()
        self.to_in.clear()
        names = self.keyring.contact_names()
        if names:
            self.to_in.addItems(names)
            if current in names:
                self.to_in.setCurrentText(current)
        else:
            self.to_in.addItem("(no contacts: add one in Contacts)")
        self.to_in.setEnabled(bool(names))
        has_key = self.keyring.has_identity()
        self.self_in.setEnabled(has_key)
        self.sign_in.setEnabled(has_key)

    def _encrypt(self) -> None:
        self.banner.clear()
        if not self.to_in.isEnabled():
            return self.banner.show_message("warn", "Add a contact first, in the Contacts tab.")
        try:
            recipients = [self.keyring.get_contact(self.to_in.currentText())]
            me = self.keyring.load_identity()
            want_self = me is not None and self.self_in.isChecked()
            want_sign = me is not None and self.sign_in.isChecked()
            if want_self:
                recipients.append(me)
            passphrase = None
            if want_sign:
                passphrase = ask_passphrase(self, "Signing needs your private key.")
                if passphrase is None:
                    return
            result = crypto.encrypt(
                self.msg_in.toPlainText(), recipients, signer=me if want_sign else None, passphrase=passphrase
            )
        except (OSError, CryptoError) as exc:
            return self.banner.show_message("error", str(exc))
        self.out.setPlainText(result)
        self.banner.show_message("ok", f"Encrypted for {self.to_in.currentText()}" + (" and signed." if want_sign else "."))


def _known_keys(keyring: Keyring) -> dict:
    """Contacts plus your own key, for signature checking."""
    keys = dict(keyring.contacts())
    me = keyring.load_identity()
    if me is not None:
        keys[SELF_NAME] = me
    return keys


def _banner_for_signature(banner: StatusBanner, status: crypto.SignatureStatus, prefix: str = "") -> None:
    kind = "ok" if status.valid else ("error" if status.signer_name else "warn")
    if not status.signed:
        kind = "info"
    banner.show_message(kind, prefix + status.describe())


class DecryptTab(Tab):
    def __init__(self, keyring: Keyring):
        super().__init__(keyring)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Paste an encrypted message you received:"))
        self.msg_in = mono_edit("-----BEGIN PGP MESSAGE-----\n…\n-----END PGP MESSAGE-----")
        layout.addWidget(self.msg_in, stretch=1)
        row = QHBoxLayout()
        btn = QPushButton("Decrypt")
        btn.setDefault(True)
        btn.clicked.connect(self._decrypt)
        paste = QPushButton("Paste from clipboard")
        paste.clicked.connect(lambda: self.msg_in.setPlainText(QGuiApplication.clipboard().text()))
        row.addWidget(btn)
        row.addWidget(paste)
        row.addStretch()
        layout.addLayout(row)
        self.banner = StatusBanner()
        layout.addWidget(self.banner)
        layout.addWidget(QLabel("Decrypted message"))
        self.out = text_edit(read_only=True)
        layout.addWidget(self.out, stretch=1)
        layout.addWidget(copy_button(self.out), alignment=Qt.AlignmentFlag.AlignLeft)

    def _decrypt(self) -> None:
        self.banner.clear()
        self.out.clear()
        me = self.identity_or_warn(self.banner)
        if me is None:
            return
        try:  # catch a pasted key/signature before asking for the passphrase
            crypto.require_message_block(self.msg_in.toPlainText())
        except CryptoError as exc:
            return self.banner.show_message("error", str(exc))
        passphrase = ask_passphrase(self, "Decrypting needs your private key.")
        if passphrase is None:
            return
        try:
            result = crypto.decrypt(self.msg_in.toPlainText(), me, passphrase, _known_keys(self.keyring))
        except (OSError, CryptoError) as exc:
            return self.banner.show_message("error", str(exc))
        self.out.setPlainText(result.text)
        _banner_for_signature(self.banner, result.signature, "Decrypted. ")


class SignVerifyTab(Tab):
    def __init__(self, keyring: Keyring):
        super().__init__(keyring)
        split = QSplitter()

        # sign
        sign_box = QGroupBox("Sign a message")
        s = QVBoxLayout(sign_box)
        s.addWidget(hint("Anyone can still read a signed message; the signature proves it came from you, unchanged."))
        self.sign_in = text_edit("Message to sign…")
        s.addWidget(self.sign_in, stretch=1)
        sign_btn = QPushButton("Sign")
        sign_btn.clicked.connect(self._sign)
        s.addWidget(sign_btn, alignment=Qt.AlignmentFlag.AlignLeft)
        self.sign_banner = StatusBanner()
        s.addWidget(self.sign_banner)
        self.sign_out = mono_edit(read_only=True)
        s.addWidget(self.sign_out, stretch=1)
        s.addWidget(copy_button(self.sign_out), alignment=Qt.AlignmentFlag.AlignLeft)

        # verify
        verify_box = QGroupBox("Verify a signed message")
        v = QVBoxLayout(verify_box)
        v.addWidget(hint("Paste a signed message. It's checked against your contacts' public keys."))
        self.verify_in = mono_edit("-----BEGIN PGP SIGNED MESSAGE-----\n…")
        v.addWidget(self.verify_in, stretch=1)
        verify_btn = QPushButton("Verify")
        verify_btn.clicked.connect(self._verify)
        v.addWidget(verify_btn, alignment=Qt.AlignmentFlag.AlignLeft)
        self.verify_banner = StatusBanner()
        v.addWidget(self.verify_banner)
        v.addWidget(QLabel("Signed text"))
        self.verify_out = text_edit(read_only=True)
        v.addWidget(self.verify_out, stretch=1)

        split.addWidget(sign_box)
        split.addWidget(verify_box)
        QVBoxLayout(self).addWidget(split)

    def _sign(self) -> None:
        self.sign_banner.clear()
        me = self.identity_or_warn(self.sign_banner)
        if me is None:
            return
        passphrase = ask_passphrase(self, "Signing needs your private key.")
        if passphrase is None:
            return
        try:
            self.sign_out.setPlainText(crypto.sign(self.sign_in.toPlainText(), me, passphrase))
        except CryptoError as exc:
            return self.sign_banner.show_message("error", str(exc))
        self.sign_banner.show_message("ok", "Signed.")

    def _verify(self) -> None:
        self.verify_banner.clear()
        self.verify_out.clear()
        try:
            result = crypto.verify(self.verify_in.toPlainText(), _known_keys(self.keyring))
        except (OSError, CryptoError) as exc:
            return self.verify_banner.show_message("error", str(exc))
        self.verify_out.setPlainText(result.text)
        _banner_for_signature(self.verify_banner, result.signature)


# --------------------------------------------------------------------------
# Main window
# --------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self, keyring: Keyring):
        super().__init__()
        self.setWindowTitle("PGP Messenger")
        self.resize(960, 700)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.pages: list[Tab] = [
            MyKeyTab(keyring),
            ContactsTab(keyring),
            EncryptTab(keyring),
            DecryptTab(keyring),
            SignVerifyTab(keyring),
        ]
        for page, title in zip(self.pages, ["My Key", "Contacts", "Encrypt", "Decrypt", "Sign && Verify"]):
            page.keys_changed.connect(self.refresh_all)
            self.tabs.addTab(page, title)
        self.setCentralWidget(self.tabs)
        self.statusBar().showMessage(f"Keys stored in {keyring.root}")
        if not keyring.has_identity():
            self.tabs.setCurrentIndex(0)

    def refresh_all(self) -> None:
        for page in self.pages:
            page.refresh()


def run() -> int:
    import sys

    app = QApplication(sys.argv)
    app.setApplicationName("PGP Messenger")
    window = MainWindow(Keyring())
    window.show()
    return app.exec()
