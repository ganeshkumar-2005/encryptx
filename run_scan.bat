@echo off
title ScopeX Toolkit Launcher
cls

echo =======================================================
echo               SCOPEX LAUNCHER & WIZARD
echo          Developed by Ganesh Kumar (Git Release)
echo =======================================================
echo.

set /p target="Enter target host or URL (e.g. google.com or https://example.com): "
if "%target%"=="" (
    echo [ERROR] Target target cannot be blank. Exiting...
    pause
    exit /b
)

echo.
echo Select scan mode:
echo   [1] Standard Scan (Ports, SSL, Headers, DNS, Core Vulns)
echo   [2] Full Scan (All 14 Scanners + Advanced Plugins - High Detail)
echo   [3] Deep Web Scan (SQLi, XSS, Cookies, WAF, API, Auth)
echo   [4] Plugins Only (Advanced Nessus-style vulnerability plugins)
echo.

set /p mode="Choose option (1-4): "

if "%mode%"=="1" (
    python scopex.py scan --target %target%
) else if "%mode%"=="2" (
    python scopex.py scan --target %target% --all
) else if "%mode%"=="3" (
    python scopex.py scan --target %target% --deep
) else if "%mode%"=="4" (
    python scopex.py scan --target %target% --plugins
) else (
    echo [!] Invalid option. Running standard scan...
    python scopex.py scan --target %target%
)

echo.
echo =======================================================
echo                  SCAN PROCESS COMPLETE
echo =======================================================
echo.
set /p make_report="Would you like to compile a PDF report now? (y/n): "
if /i "%make_report%"=="y" (
    echo.
    echo Looking for latest scan file in output/...
    for /f "delims=" %%i in ('dir output\scan_*.json /b /o-d 2^>nul') do (
        set "latest_scan=output\%%i"
        goto :generate
    )
    echo [ERROR] No scan results JSON files found in output/.
    goto :end
    
    :generate
    echo Latest scan found: %latest_scan%
    python scopex.py report --input %latest_scan%
)

:end
echo.
echo Press any key to close launcher...
pause >nul
