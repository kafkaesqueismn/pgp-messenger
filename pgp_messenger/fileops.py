"""Output paths and safe writing for the Files tab.

Rules:
  * encrypting  photo.png      -> photo.png.pgp           (next to the original)
  * decrypting  photo.png.pgp  -> photo.png               (strip .pgp/.gpg/.asc)
                abc.bin        -> <sender's original name>, else abc.bin.decrypted
  * never replace an existing file unless the caller says the user confirmed it.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ENCRYPTED_SUFFIX = ".pgp"
KNOWN_ENCRYPTED_SUFFIXES = (".pgp", ".gpg", ".asc")


def encrypted_path_for(src: Path) -> Path:
    return src.with_name(src.name + ENCRYPTED_SUFFIX)


def decrypted_path_for(src: Path, original_name: str = "") -> Path:
    """Where to restore a decrypted file, next to the encrypted one.

    `original_name` must already be sanitized (see crypto._safe_filename).
    """
    if src.suffix.lower() in KNOWN_ENCRYPTED_SUFFIXES and src.stem and not src.stem.startswith("."):
        return src.with_name(src.stem)
    if original_name:
        return src.with_name(original_name)
    return src.with_name(src.name + ".decrypted")


def write_file(path: Path, data: bytes, overwrite: bool = False) -> None:
    """Write `data` to `path` without ever leaving a half-written file.

    With overwrite=False this raises FileExistsError if `path` exists, even
    if it appeared after the caller checked (no check-then-write race).
    """
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if overwrite:
            os.replace(tmp, path)
            return
        try:
            os.link(tmp, path)  # atomic "create only if it doesn't exist"
        except FileExistsError:
            raise
        except OSError:
            # Filesystem without hard links (e.g. FAT/exFAT USB sticks):
            # exclusive-create the target, then fill it from the temp file.
            with open(path, "xb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
    finally:
        Path(tmp).unlink(missing_ok=True)


def available_memory() -> int | None:
    """Bytes of RAM currently available, or None if we can't tell.

    Used only to make the large-file warning concrete ("needs ~3 GB, you
    have 7 GB free"). Never used to block anything.
    """
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/meminfo", encoding="ascii") as fh:
                for line in fh:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) * 1024  # value is in kB
        elif os.name == "nt":
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MEMORYSTATUSEX()
            status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullAvailPhys)
    except (OSError, ValueError, AttributeError):
        pass
    return None
