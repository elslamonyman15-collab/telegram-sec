@echo off
:: Telegram Bot Monitor - Cyber Forensics Toolkit v8.0
:: This script starts the Telegram bot for remote monitoring and control

setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%A in ("%batchPath%") do set "batchPath=%%~fA"
setlocal EnableDelayedExpansion

:: Request administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting Administrator Privileges for Telegram Bot...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\GetAdminPriv.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""!batchPath!""", "", "runas", 1 >> "%temp%\GetAdminPriv.vbs"
    "%temp%\GetAdminPriv.vbs"
    exit /B
)
if exist "%temp%\GetAdminPriv.vbs" ( del "%temp%\GetAdminPriv.vbs" )
pushd "%~dp0"

title CYBER FORENSICS TOOLKIT - Telegram Bot Monitor v8.0
color 0A
cls

echo ===============================================================================
echo               TELEGRAM BOT MONITOR - CYBER FORENSICS TOOLKIT v8.0
echo ===============================================================================
echo  [+] Starting Telegram Bot for remote monitoring and control
echo  [+] Bot will run in background with polling mode
echo  [+] Press Ctrl+C to stop the bot
echo ===============================================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo [INFO] Please install Python 3.7 or higher
    pause
    exit /B 1
)

:: Check if telegram_bot.py exists
if not exist "telegram_bot.py" (
    echo [ERROR] telegram_bot.py not found in current directory
    echo [INFO] Please ensure all files are in the same directory
    pause
    exit /B 1
)

:: Check if required packages are installed
echo [+] Checking dependencies...
python -c "import telegram" >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] python-telegram-bot not installed
    echo [+] Installing dependencies...
    pip install python-telegram-bot==20.7
    if %errorLevel% neq 0 (
        echo [ERROR] Failed to install python-telegram-bot
        pause
        exit /B 1
    )
)

:: Check if configuration exists
if not exist "%USERPROFILE%\.cyber_forensics_telegram_config.json" (
    echo [WARNING] Telegram bot configuration not found
    echo [INFO] Please configure the bot in the GUI first:
    echo [INFO]   1. Run cyber_forensics_gui.py
    echo [INFO]   2. Go to Tools -> Telegram Bot Settings
    echo [INFO]   3. Enter your bot token and chat ID
    echo [INFO]   4. Click Save
    echo.
    echo [INFO] Or create configuration manually:
    echo [INFO]   Create %USERPROFILE%\.cyber_forensics_telegram_config.json
    echo [INFO]   with your bot token and authorized chat IDs
    echo.
    pause
)

:: Start the Telegram bot
echo [+] Starting Telegram bot...
echo [+] Bot is now running. Send /help to your bot to see available commands.
echo [+] Press Ctrl+C to stop the bot.
echo ===============================================================================
echo.

:: Run the bot in a loop (auto-restart on crash)
:bot_loop
python telegram_bot.py
if %errorLevel% neq 0 (
    echo [!] Bot crashed with error code %errorLevel%
    echo [+] Restarting bot in 5 seconds...
    timeout /t 5 /nobreak >nul
    goto bot_loop
)

echo [!] Bot stopped normally
pause
