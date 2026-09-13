@echo off
title AutoMail AI - Email Automation Service
cd /d "%~dp0"

echo =======================================================
echo          AutoMail AI - Email Automation Hub
echo =======================================================
echo [1/2] Checking Python environment...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not found on PATH. Please install Python 3.10+.
    pause
    exit /b 1
)

echo [2/2] Launching Email Automation Service at http://localhost:8000 ...
start "" "http://localhost:8000"

python -m email_service.server

if errorlevel 1 (
    echo.
    echo [ERROR] Service stopped with an error.
    pause
)
