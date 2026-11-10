@echo off
rem PGP Messenger launcher for Windows. Double-click it.
rem
rem First run: creates a virtual environment in .venv and installs the
rem requirements (needs internet). Later runs start the app straight away,
rem and re-install automatically if requirements.txt has changed.
rem
rem   run.bat --setup-only    set up / update, but don't start the app
rem
rem Written with goto labels instead of ( ... ) blocks on purpose: a ")" in
rem the folder path (e.g. "Program Files (x86)") breaks parenthesised blocks.

setlocal
cd /d "%~dp0"

set "VENV_PY=.venv\Scripts\python.exe"
set "VENV_PYW=.venv\Scripts\pythonw.exe"
set "MARKER=.venv\.requirements-installed"

if not exist "%VENV_PY%" goto setup
rem fc sets errorlevel 0 only if the files are identical
fc /b "requirements.txt" "%MARKER%" >nul 2>&1
if errorlevel 1 goto setup
goto check

:setup
echo Setting up PGP Messenger (first run, or requirements changed)...
if exist "%VENV_PY%" goto install

rem Find Python 3.11+. Try "python" first, then the "py" launcher.
rem (The Microsoft Store "python" stub fails the version check, which is fine.)
set "PY="
python -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto make_venv
py -3 -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto make_venv
echo.
echo ERROR: Python 3.11 or newer was not found.
echo Install it from https://www.python.org/downloads/windows/
echo and tick "Add python.exe to PATH" in the installer. Then run this again.
goto fail

:make_venv
echo Creating virtual environment in .venv ...
%PY% -m venv .venv
if errorlevel 1 goto fail_venv

:install
if exist "%MARKER%" del "%MARKER%"
echo Installing requirements (this can take a few minutes the first time)...
"%VENV_PY%" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto fail_pip
copy /y "requirements.txt" "%MARKER%" >nul
echo Setup complete.

:check
"%VENV_PY%" -c "import pgp_messenger.gui"
if errorlevel 1 goto fail_import
if /i "%~1"=="--setup-only" goto setup_only

rem pythonw = no console window. "start" returns at once, so this window closes.
start "" "%VENV_PYW%" -m pgp_messenger
exit /b 0

:setup_only
echo Ready. Start the app by double-clicking run.bat
exit /b 0

:fail_venv
echo.
echo ERROR: Couldn't create the virtual environment in .venv
goto fail

:fail_pip
echo.
echo ERROR: Installing requirements failed. Check your internet connection and run this again.
goto fail

:fail_import
echo.
echo ERROR: The app couldn't start (see the messages above).
echo To rebuild from scratch, delete the .venv folder and run this again.
goto fail

:fail
echo.
if /i not "%~1"=="--setup-only" pause
exit /b 1
