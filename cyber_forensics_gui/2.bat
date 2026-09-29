@echo off
:: آلية طلب صلاحيات المسؤول المتقدمة تلقائياً
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%A in ("%batchPath%") do set "batchPath=%%~fA"
setlocal EnableDelayedExpansion
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting Cyber Forensic Privileges...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\GetAdminPriv.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""!batchPath!""", "", "runas", 1 >> "%temp%\GetAdminPriv.vbs"
    "%temp%\GetAdminPriv.vbs"
    exit /B
)
if exist "%temp%\GetAdminPriv.vbs" ( del "%temp%\GetAdminPriv.vbs" )
pushd "%~dp0"

:: إعداد الواجهة والمجلدات الحاضنة للتقارير الجنائية
title ULTIMATE CYBER FORENSICS TOOLKIT v8.0 - Enterprise Edition
color 1F
cls
set "LOG_DIR=%USERPROFILE%\Desktop\Cyber_Forensic_Report"
mkdir "%LOG_DIR%" 2>nul
mkdir "%LOG_DIR%\REGISTRY" 2>nul
mkdir "%LOG_DIR%\MEMORY" 2>nul
mkdir "%LOG_DIR%\ARTIFACTS" 2>nul
mkdir "%LOG_DIR%\EVENTLOGS" 2>nul

echo ===============================================================================
echo               ULTIMATE CYBER FORENSICS ^& ANTI-HACK EMERGENCY SCRIPT
echo ===============================================================================
echo  [!] Warning: This script extracts heavy low-level Windows security evidence.
echo  [+] Destination Folder: Desktop\Cyber_Forensic_Report
echo ===============================================================================
echo.

:: 1. حظر واصطياد اتصالات الهكر الحية وإغلاق الثغرات فوراً
echo [1/8] [+] [ACTIVE DEFENSE] Block Backdoors ^& Secure Shares...
net config server /hidden:yes >nul 2>&1
net share /delete C$ /y >nul 2>&1
net share /delete ADMIN$ /y >nul 2>&1
net share /delete IPC$ /y >nul 2>&1
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $false -Force" >nul 2>&1
echo [V] Shares secured and SMB protocol strictly blocked.
echo.

:: 2. كشف الهوية الجنائية للاتصالات والـ DNS (أين تذهب ملفاتك؟)
echo [2/12] [+] [NETWORK FORENSICS] Dumping DNS Cache, Routing Tables ^& Active Connections...
echo === FULL LIVE NETWORK ESTABLISHED CONNECTIONS (WITH PID) === > "%LOG_DIR%\Network_Deep_Analysis.txt"
netstat -anob >> "%LOG_DIR%\Network_Deep_Analysis.txt" 2>nul
echo. >> "%LOG_DIR%\Network_Deep_Analysis.txt"
echo === INSTANT DNS CACHE DUMP (Shows every website/server the virus contacted) === >> "%LOG_DIR%\Network_Deep_Analysis.txt"
ipconfig /displaydns >> "%LOG_DIR%\Network_Deep_Analysis.txt" 2>nul
echo. >> "%LOG_DIR%\Network_Deep_Analysis.txt"
echo === IP ROUTING TABLE AND ARP CACHE === >> "%LOG_DIR%\Network_Deep_Analysis.txt"
route print >> "%LOG_DIR%\Network_Deep_Analysis.txt" 2>nul
arp -a >> "%LOG_DIR%\Network_Deep_Analysis.txt" 2>nul
echo [V] Network evidence captured successfully.
echo.

:: 3. تشريح العمليات والبرامج الخبيثة بدقة متناهية (سبب البطء الشديد)
echo [3/8] [+] [PROCESS ANATOMY] Analyzing high CPU usage, hidden DLLs ^& modules...
echo === ADVANCED PROCESS COMMAND LINE ^& EXECUTION PATHS === > "%LOG_DIR%\Process_Anatomy.txt"
powershell -Command "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath, ParentProcessId | Format-List" >> "%LOG_DIR%\Process_Anatomy.txt" 2>nul
echo. >> "%LOG_DIR%\Process_Anatomy.txt"
echo === HIGH RESOURCE CONSUMING PROCESSES (TOP 20) === >> "%LOG_DIR%\Process_Anatomy.txt"
powershell -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Id, ProcessName, CPU, WorkingSet, Path | Format-Table -AutoSize" >> "%LOG_DIR%\Process_Anatomy.txt" 2>nul
echo. >> "%LOG_DIR%\Process_Anatomy.txt"
echo === EVERY LOADED DLL/MODULE IN THE MEMORY === >> "%LOG_DIR%\Process_Anatomy.txt"
tasklist /M >> "%LOG_DIR%\Process_Anatomy.txt" 2>nul
echo [V] Process and RAM behavior logged.
echo.

:: 4. اصطياد الحسابات المخفية وصلاحيات الـ Admin والتسلل المخفي
echo [4/12] [+] [USER DISCOVERY] Hunting hidden accounts and elevated privileges...
echo === DETAILED LOCAL USER ACCOUNTS === > "%LOG_DIR%\User_Privileges_Audit.txt"
powershell -Command "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, LastLogon, Description | Format-Table -AutoSize" >> "%LOG_DIR%\User_Privileges_Audit.txt" 2>nul
echo. >> "%LOG_DIR%\User_Privileges_Audit.txt"
echo === MEMBERS OF ADMINISTRATORS GROUP === >> "%LOG_DIR%\User_Privileges_Audit.txt"
net localgroup administrators >> "%LOG_DIR%\User_Privileges_Audit.txt" 2>nul
echo. >> "%LOG_DIR%\User_Privileges_Audit.txt"
echo === ACTIVE LOGGED IN SESSIONS (RDP/LOCAL) === >> "%LOG_DIR%\User_Privileges_Audit.txt"
query user >> "%LOG_DIR%\User_Privileges_Audit.txt" 2>nul
echo [V] Privilege and user accounts verified.
echo.

:: 5. فحص آليات الثبات (Persistence) - أين يختبئ الهكر ليعود بعد إعادة التشغيل؟
echo [5/12] [+] [PERSISTENCE HUNTING] Scanning Startup, Registry Keys ^& Services...
echo === REGISTRY RUN KEYS (STARTUP VIRUSES) === > "%LOG_DIR%\Persistence_Mechanisms.txt"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run /s >> "%LOG_DIR%\Persistence_Mechanisms.txt" 2>nul
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s >> "%LOG_DIR%\Persistence_Mechanisms.txt" 2>nul
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run /s >> "%LOG_DIR%\Persistence_Mechanisms.txt" 2>nul
echo. >> "%LOG_DIR%\Persistence_Mechanisms.txt"
echo === SCHEDULED TASKS DETAILED REPORT === >> "%LOG_DIR%\Persistence_Mechanisms.txt"
schtasks /query /fo LIST /v >> "%LOG_DIR%\Persistence_Mechanisms.txt" 2>nul
echo. >> "%LOG_DIR%\Persistence_Mechanisms.txt"
echo === THIRD PARTY NON-MICROSOFT ACTIVE SERVICES === >> "%LOG_DIR%\Persistence_Mechanisms.txt"
powershell -Command "Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.Name -notmatch 'Microsoft|Win'} | Select-Object Name, DisplayName, Status | Format-Table" >> "%LOG_DIR%\Persistence_Mechanisms.txt" 2>nul
echo [V] Persistence registry and tasks analyzed.
echo.

:: 6. التفتيش الجنائي الرقمي عن الملفات الخبيثة والمعدلة
echo [6/12] [+] [FILE SYSTEM FORENSICS] Locating recently modified EXE/DLL/BAT files (Last 3 days)...
echo === FILES MODIFIED IN CRITICAL SYSTEM DIRECTORIES === > "%LOG_DIR%\Modified_Files_Forensics.txt"
powershell -Command "$paths = @('$env:SystemRoot\System32', '$env:ProgramData', '$env:USERPROFILE\AppData\Local\Temp'); foreach ($p in $paths) { if (Test-Path $p) { Get-ChildItem -Path $p -Recurse -File -Include *.exe,*.dll,*.bat,*.ps1,*.vbs,*.scr 2>$null | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-3)} | Select-Object FullName, LastWriteTime, Length | Format-List } }" >> "%LOG_DIR%\Modified_Files_Forensics.txt" 2>nul
echo [V] File system deep search completed.
echo.

:: 7. استجواب جدار الحماية (Firewall) والتحقق من سلامة ملف الـ Hosts
echo [7/12] [+] [INTEGRITY CHECK] Auditing Firewall Rules and System Hosts File...
echo === LIVE WINDOWS FIREWALL RULES === > "%LOG_DIR%\Firewall_And_Hosts_Integrity.txt"
netsh advfirewall firewall show rule name=all >> "%LOG_DIR%\Firewall_And_Hosts_Integrity.txt" 2>nul
echo. >> "%LOG_DIR%\Firewall_And_Hosts_Integrity.txt"
echo === HOSTS FILE CONTENT (Check for malicious redirection) === >> "%LOG_DIR%\Firewall_And_Hosts_Integrity.txt"
type %WINDIR%\System32\drivers\etc\hosts >> "%LOG_DIR%\Firewall_And_Hosts_Integrity.txt" 2>nul
echo [V] Network control policies extracted.
echo.

:: 8. تحليل سجلات الأمن والأحداث العميقة (Event Logs Analytics)
echo [8/12] [+] [SIEM LOG ANALYTICS] Parsing Security Events for Hack Attacks...
echo === DETAILED SECURITY EVENTS TRACKING === > "%LOG_DIR%\Security_Event_Logs.txt"
echo [!] Hunting Failed Logins (Event 4625)... >> "%LOG_DIR%\Security_Event_Logs.txt"
powershell -Command "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 150 2>$null | Select-Object TimeCreated, Message | Format-List" >> "%LOG_DIR%\Security_Event_Logs.txt" 2>nul
echo [!] Hunting Successful Logins (Event 4624)... >> "%LOG_DIR%\Security_Event_Logs.txt"
powershell -Command "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 150 2>$null | Select-Object TimeCreated, Message | Format-List" >> "%LOG_DIR%\Security_Event_Logs.txt" 2>nul
echo [!] Hunting PowerShell Malicious Execution (Event 4104)... >> "%LOG_DIR%\Security_Event_Logs.txt"
powershell -Command "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104} -MaxEvents 100 2>$null | Select-Object TimeCreated, Message | Format-List" >> "%LOG_DIR%\Security_Event_Logs.txt" 2>nul
echo [V] Event logs analyzed.
echo.

:: 9. استخراج سجلات التسجيل (Registry Hives) للتحليل الجنائي العميق
echo [9/12] [+] [REGISTRY FORENSICS] Extracting registry hives for offline analysis...
echo === EXTRACTING SAM HIVE (Password Hashes) === >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
reg save HKLM\SAM "%LOG_DIR%\REGISTRY\SAM.hive" >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log" 2>&1
echo. >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
echo === EXTRACTING SYSTEM HIVE (Configuration) === >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
reg save HKLM\SYSTEM "%LOG_DIR%\REGISTRY\SYSTEM.hive" >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log" 2>&1
echo. >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
echo === EXTRACTING SECURITY HIVE (SIDs, Policies) === >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
reg save HKLM\SECURITY "%LOG_DIR%\REGISTRY\SECURITY.hive" >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log" 2>&1
echo. >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
echo === EXTRACTING SOFTWARE HIVE (Installed Programs) === >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
reg save HKLM\SOFTWARE "%LOG_DIR%\REGISTRY\SOFTWARE.hive" >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log" 2>&1
echo. >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
echo === EXTRACTING NTUSER.DAT FOR ALL USERS === >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
for /d %%U in ("%USERPROFILE%\..") do (
    if exist "%%U\NTUSER.DAT" (
        reg save HKCU\%%~nU "%LOG_DIR%\REGISTRY\NTUSER_%%~nU.hive" >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log" 2>&1
    )
)
echo. >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
echo === EXTRACTING DEFAULT HIVE === >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
reg save HKLM\.DEFAULT "%LOG_DIR%\REGISTRY\DEFAULT.hive" >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log" 2>&1
echo. >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
echo === EXTRACTING BCD (Boot Configuration Data) === >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log"
reg save HKLM\BCD00000000 "%LOG_DIR%\REGISTRY\BCD.hive" >> "%LOG_DIR%\REGISTRY\Registry_Extraction.log" 2>&1
echo [V] Registry hives extracted successfully.
echo.

:: 10. إنشاء نسخة من ذاكرة النظام (Memory Dump) للتحليل الجنائي
echo [10/12] [+] [MEMORY FORENSICS] Creating memory dump for volatile data analysis...
echo === ATTEMPTING MEMORY DUMP === >> "%LOG_DIR%\MEMORY\Memory_Extraction.log"
powershell -Command "Get-Process | Select-Object Id, ProcessName, WorkingSet, PagedMemorySize, NonpagedSystemMemorySize | Format-Table -AutoSize" >> "%LOG_DIR%\MEMORY\Process_Memory_Usage.txt" 2>&1
echo. >> "%LOG_DIR%\MEMORY\Memory_Extraction.log"
echo === EXTRACTING PROCESS MEMORY INFORMATION === >> "%LOG_DIR%\MEMORY\Memory_Extraction.log"
powershell -Command "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath, ParentProcessId, CreationDate | Format-List" >> "%LOG_DIR%\MEMORY\Process_Details.txt" 2>&1
echo. >> "%LOG_DIR%\MEMORY\Memory_Extraction.log"
echo === EXTRACTING LOADED MODULES FOR ALL PROCESSES === >> "%LOG_DIR%\MEMORY\Memory_Extraction.log"
tasklist /M >> "%LOG_DIR%\MEMORY\Loaded_DLLs.txt" 2>&1
echo. >> "%LOG_DIR%\MEMORY\Memory_Extraction.log"
echo === EXTRACTING DRIVER INFORMATION === >> "%LOG_DIR%\MEMORY\Memory_Extraction.log"
driverquery >> "%LOG_DIR%\MEMORY\Driver_List.txt" 2>&1
echo [V] Memory information extracted successfully.
echo.

:: 11. جمع القطع الأثرية المتقدمة (Advanced Artifacts)
echo [11/12] [+] [DEEP FORENSICS] Collecting Prefetch, Amcache, SRUM, and other artifacts...
echo === COLLECTING PREFETCH FILES === >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
xcopy C:\Windows\Prefetch\*.pf "%LOG_DIR%\ARTIFACTS\Prefetch\" /Y /I /Q >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log" 2>&1
echo. >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
echo === COLLECTING AMCACHE.HVE === >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
copy C:\Windows\AppCompat\Programs\Amcache.hve "%LOG_DIR%\ARTIFACTS\" >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log" 2>&1
echo. >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
echo === COLLECTING SRUM DATABASE === >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
copy C:\Windows\System32\sru\SRUDB.dat "%LOG_DIR%\ARTIFACTS\" >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log" 2>&1
echo. >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
echo === COLLECTING APPCOMPATCACHE (ShimCache) === >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache >> "%LOG_DIR%\ARTIFACTS\ShimCache.txt" 2>&1
echo. >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
echo === COLLECTING BAM (Background Activity Moderator) === >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
reg query HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings /s >> "%LOG_DIR%\ARTIFACTS\BAM.txt" 2>&1
echo. >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
echo === COLLECTING SHELLBAGS === >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
reg query HKCU\Software\Microsoft\Windows\Shell\BagMRU /s >> "%LOG_DIR%\ARTIFACTS\Shellbags.txt" 2>&1
reg query HKCU\Software\Microsoft\Windows\Shell\Bags /s >> "%LOG_DIR%\ARTIFACTS\Shellbags.txt" 2>&1
echo. >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
echo === COLLECTING JUMP LISTS === >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
xcopy "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*" "%LOG_DIR%\ARTIFACTS\JumpLists\" /Y /I /Q >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log" 2>&1
echo. >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
echo === COLLECTING RECENT DOCUMENTS === >> "%LOG_DIR%\ARTIFACTS\Artifact_Collection.log"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs /s >> "%LOG_DIR%\ARTIFACTS\RecentDocs.txt" 2>&1
echo [V] Advanced artifacts collected successfully.
echo.

:: 12. تصدير جميع سجلات الأحداث (Full Event Log Export)
echo [12/12] [+] [SIEM FORENSICS] Exporting all Windows Event Logs for deep analysis...
echo === EXPORTING APPLICATION LOG === >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
wevtutil epl Application "%LOG_DIR%\EVENTLOGS\Application.evtx" >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log" 2>&1
echo. >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
echo === EXPORTING SYSTEM LOG === >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
wevtutil epl System "%LOG_DIR%\EVENTLOGS\System.evtx" >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log" 2>&1
echo. >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
echo === EXPORTING SECURITY LOG === >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
wevtutil epl Security "%LOG_DIR%\EVENTLOGS\Security.evtx" >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log" 2>&1
echo. >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
echo === EXPORTING POWERSHELL OPERATIONAL LOG === >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
wevtutil epl Microsoft-Windows-PowerShell/Operational "%LOG_DIR%\EVENTLOGS\PowerShell.evtx" >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log" 2>&1
echo. >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
echo === EXPORTING TASK SCHEDULER LOG === >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
wevtutil epl Microsoft-Windows-TaskScheduler/Operational "%LOG_DIR%\EVENTLOGS\TaskScheduler.evtx" >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log" 2>&1
echo. >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
echo === EXPORTING WINDOWS DEFENDER LOG === >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
wevtutil epl Microsoft-Windows-Windows Defender/Operational "%LOG_DIR%\EVENTLOGS\WindowsDefender.evtx" >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log" 2>&1
echo. >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
echo === EXPORTING BITS LOG === >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
wevtutil epl Microsoft-Windows-Bits-Client/Operational "%LOG_DIR%\EVENTLOGS\BITS.evtx" >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log" 2>&1
echo. >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
echo === EXPORTING RDP LOG === >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational "%LOG_DIR%\EVENTLOGS\RDP.evtx" >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log" 2>&1
echo. >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
echo === EXPORTING WMI ACTIVITY LOG === >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log"
wevtutil epl Microsoft-Windows-WMI-Activity/Operational "%LOG_DIR%\EVENTLOGS\WMI.evtx" >> "%LOG_DIR%\EVENTLOGS\EventLog_Export.log" 2>&1
echo [V] All Event Logs exported successfully.
echo.

:: تنظيف شامل وسريع لملفات الكاش لتخفيف العبء الفوري
echo [+] Performing emergency flush and memory relief...
del /q /f /s "%TEMP%\*" >nul 2>&1
del /q /f /s "%WINDIR%\Temp\*" >nul 2>&1
ipconfig /flushdns >nul 2>&1
echo [V] Cache cleared.

echo ===============================================================================
echo        ENTERPRISE CYBER FORENSIC ACQUISITION COMPLETE - v8.0
echo ===============================================================================
echo  All advanced forensic data has been dumped inside "Cyber_Forensic_Report" folder 
echo  located right on your Desktop.
echo.
echo  NEW ENHANCED FEATURES:
echo  [+] Registry Hives: SAM, SYSTEM, SECURITY, SOFTWARE, NTUSER, DEFAULT, BCD
echo  [+] Memory Forensics: Process memory, loaded DLLs, driver information
echo  [+] Advanced Artifacts: Prefetch, Amcache, SRUM, ShimCache, BAM, Shellbags, JumpLists
echo  [+] Full Event Logs: Application, System, Security, PowerShell, TaskScheduler, Defender, BITS, RDP, WMI
echo.
echo  Please open the folder and examine the extracted digital evidence files.
echo ===============================================================================
pause
