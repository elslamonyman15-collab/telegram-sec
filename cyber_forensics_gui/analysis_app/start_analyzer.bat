@echo off
:: Cyber Forensics Report Analyzer Launcher
:: User-friendly report analysis tool

title Cyber Forensics Report Analyzer v8.0
color 1F
cls

echo ===============================================================================
echo               CYBER FORENSICS REPORT ANALYZER v8.0
echo ===============================================================================
echo  User-friendly tool to analyze forensic reports
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

:: Check if report analyzer exists
if not exist "analysis_gui.py" (
    echo [ERROR] analysis_gui.py not found
    echo [INFO] Please ensure all files are in the same directory
    pause
    exit /B 1
)

:: Start the analyzer
echo [+] Starting Report Analyzer...
python analysis_gui.py

if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Report Analyzer encountered an error
    pause
)
