#!/usr/bin/env bash
# PGP Messenger launcher for Linux. Double-click it, or run ./run.sh
#
# First run: creates a virtual environment in .venv and installs the
# requirements (needs internet). Later runs start the app straight away, and
# re-install automatically if requirements.txt has changed.
#
#   ./run.sh --setup-only    set up / update, but don't start the app
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

VENV=.venv
VENV_PY=$VENV/bin/python
MARKER=$VENV/.requirements-installed   # copy of requirements.txt from the last good install
SETUP_ONLY=0
if [[ ${1:-} == --setup-only ]]; then
    SETUP_ONLY=1
    shift
fi

in_terminal() { [[ -t 0 || -t 1 ]]; }

needs_setup() {
    [[ ! -x $VENV_PY ]] || ! cmp -s requirements.txt "$MARKER"
}

fail() {
    echo >&2
    echo "ERROR: $*" >&2
    if in_terminal; then
        if [[ -n ${PGP_MESSENGER_OWN_TERMINAL:-} ]]; then
            read -rp "Press Enter to close this window. " _ || true
        fi
    elif command -v notify-send >/dev/null; then
        notify-send -i dialog-error "PGP Messenger" "$*" || true
    fi
    exit 1
}

# Double-clicked in a file manager: there's no terminal, so the first-run
# setup would be invisible. Re-open this script in a terminal window to show it.
# (Only in a desktop session: CI, cron or ssh pipes just carry on without one.)
if needs_setup && ! in_terminal && [[ -z ${PGP_MESSENGER_OWN_TERMINAL:-} ]] &&
   [[ -n ${DISPLAY:-}${WAYLAND_DISPLAY:-} ]]; then
    export PGP_MESSENGER_OWN_TERMINAL=1
    self=$(readlink -f "$0")
    for term in "${TERMINAL:-}" kgx gnome-terminal konsole xfce4-terminal alacritty kitty foot wezterm xterm; do
        [[ -n $term ]] && command -v "$term" >/dev/null || continue
        case $term in
            gnome-terminal|kgx) exec "$term" -- "$self" "$@" ;;
            xfce4-terminal)     exec "$term" -x "$self" "$@" ;;
            kitty|foot)         exec "$term" "$self" "$@" ;;
            wezterm)            exec "$term" start -- "$self" "$@" ;;
            *)                  exec "$term" -e "$self" "$@" ;;
        esac
    done
    # No terminal found: carry on without one (errors still go to notify-send).
fi

setup() {
    echo "Setting up PGP Messenger (first run, or requirements changed)..."

    local py=""
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null &&
           "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
            py=$candidate
            break
        fi
    done
    [[ -n $py ]] || fail "Python 3.11 or newer was not found. Install it (Arch: sudo pacman -S python) and try again."

    if [[ ! -x $VENV_PY ]]; then
        # If the system already has Qt for Python (Arch: pacman -S pyside6), let
        # the venv see it instead of downloading ~200 MB of Qt from pip.
        local venv_args=()
        if "$py" -c 'import PySide6.QtWidgets' 2>/dev/null; then
            venv_args=(--system-site-packages)
            echo "Using the system's PySide6 (Qt) package."
        fi
        echo "Creating virtual environment in $VENV ..."
        "$py" -m venv "${venv_args[@]}" "$VENV" ||
            fail "Couldn't create the virtual environment. On Debian/Ubuntu install python3-venv first."
    fi

    rm -f "$MARKER"
    echo "Installing requirements (this can take a few minutes the first time)..."
    if "$VENV_PY" -c 'import PySide6.QtWidgets' 2>/dev/null; then
        # Qt already available (system package or earlier install): skip that line.
        grep -viE '^[[:space:]]*pyside6' requirements.txt |
            "$VENV_PY" -m pip install --disable-pip-version-check -r /dev/stdin ||
            fail "Installing requirements failed. Check your internet connection and run this again."
    else
        "$VENV_PY" -m pip install --disable-pip-version-check -r requirements.txt ||
            fail "Installing requirements failed. Check your internet connection and run this again."
    fi
    cp requirements.txt "$MARKER"
    echo "Setup complete."
}

if needs_setup; then
    setup
fi

"$VENV_PY" -c 'import pgp_messenger.gui' ||
    fail "The app couldn't start (see the messages above). To rebuild from scratch, delete the .venv folder and run this again."

if (( SETUP_ONLY )); then
    echo "Ready. Start the app with ./run.sh"
    exit 0
fi

if [[ -n ${PGP_MESSENGER_OWN_TERMINAL:-} ]]; then
    # We opened this terminal just for setup: start the app on its own and let the window close.
    echo "Starting PGP Messenger..."
    setsid -f "$VENV_PY" -m pgp_messenger "$@" >/dev/null 2>&1
    sleep 1
    exit 0
fi
exec "$VENV_PY" -m pgp_messenger "$@"
