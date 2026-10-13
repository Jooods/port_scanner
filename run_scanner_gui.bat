@echo off
title Windows Port Scanner (Desktop GUI)
cd /d "%~dp0"
echo Starting Windows Port Scanner Desktop GUI...
python port_scanner_gui.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Error starting GUI. Make sure Python is in your PATH.
    pause
)
