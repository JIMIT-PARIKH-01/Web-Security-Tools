@echo off
REM Launch the Web-Security-Tools GUI (falls back to python if pythonw missing).
cd /d "%~dp0"
where pythonw >nul 2>nul && ( start "" pythonw -m websectools.gui & goto :eof )
python -m websectools.gui
