@echo off
REM Helper script to generate audit.inf for VulnMngSys
REM Run this as Administrator if you encounter issues with audit.inf during scanning

echo.
echo ============================================
echo VulnMngSys - Prepare Windows Security Policy
echo ============================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script requires Administrator privileges.
    echo Please run Command Prompt as Administrator and try again.
    echo.
    pause
    exit /b 1
)

echo Exporting Windows security policy to audit.inf...
echo This may take a few seconds...
echo.

setlocal enabledelayedexpansion
set "AUDIT_FILE=%TEMP%\audit.inf"

secedit /export /cfg "%AUDIT_FILE%" /areas SECURITYPOLICY

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to generate audit.inf
    echo secedit returned error code: %errorlevel%
    echo.
    echo Troubleshooting steps:
    echo 1. Ensure you are running this as Administrator
    echo 2. Verify TEMP directory exists and is writable
    echo 3. Check disk space is available
    echo 4. Try restarting the command prompt and trying again
    echo.
    pause
    exit /b 1
)

if exist "%AUDIT_FILE%" (
    echo.
    echo SUCCESS! audit.inf has been created at:
    echo %AUDIT_FILE%
    echo.
    echo File size: 
    for %%A in ("%AUDIT_FILE%") do echo %%~zA bytes
    echo.
    echo You can now run VulnMngSysDesktop.exe to scan Windows Server.
) else (
    echo.
    echo ERROR: secedit completed but audit.inf was not created
    echo Expected location: %AUDIT_FILE%
    echo.
    pause
    exit /b 1
)

echo.
pause
