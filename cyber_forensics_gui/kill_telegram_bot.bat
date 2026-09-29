@echo off
echo Killing Telegram Bot...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq Cyber Forensics Toolkit v8.0 - Telegram Bot*"
echo Bot stopped.
pause
