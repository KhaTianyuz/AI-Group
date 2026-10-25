@echo off
setlocal
cd /d "%~dp0"
title AI Collaboration Group Chat Studio (Python Desktop)

where python >nul 2>nul
if %errorlevel% equ 0 (
    python app.py
    goto :end
)

where py >nul 2>nul
if %errorlevel% equ 0 (
    py -3 app.py
    goto :end
)

echo [ERROR] Python 3 was not found in PATH.
echo Please install Python 3.9+ from https://www.python.org/ and check "Add Python to PATH".
pause

:end
