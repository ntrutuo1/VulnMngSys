# Helper script to generate audit.inf for VulnMngSys
# Run this as Administrator if you encounter issues with audit.inf during scanning

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "VulnMngSys - Prepare Windows Security Policy" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Exporting Windows security policy to audit.inf..." -ForegroundColor Yellow
Write-Host "This may take a few seconds..." -ForegroundColor Yellow
Write-Host ""

$auditFile = "$env:TEMP\audit.inf"

try {
    # Run secedit to export security policy
    & secedit.exe /export /cfg $auditFile /areas SECURITYPOLICY 2>&1 | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Failed to generate audit.inf" -ForegroundColor Red
        Write-Host "secedit returned exit code: $LASTEXITCODE" -ForegroundColor Red
        Write-Host ""
        Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
        Write-Host "1. Ensure you are running this as Administrator" -ForegroundColor White
        Write-Host "2. Verify TEMP directory exists and is writable" -ForegroundColor White
        Write-Host "3. Check disk space is available" -ForegroundColor White
        Write-Host "4. Try restarting PowerShell and trying again" -ForegroundColor White
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Check if file was created
    if (Test-Path $auditFile) {
        Write-Host ""
        Write-Host "SUCCESS! audit.inf has been created." -ForegroundColor Green
        Write-Host "Location: $auditFile" -ForegroundColor Green
        Write-Host ""
        
        $fileSize = (Get-Item $auditFile).Length
        Write-Host "File size: $($fileSize) bytes" -ForegroundColor Green
        Write-Host ""
        Write-Host "You can now run VulnMngSysDesktop.exe to scan Windows Server." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "ERROR: secedit completed but audit.inf was not created" -ForegroundColor Red
        Write-Host "Expected location: $auditFile" -ForegroundColor Red
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }
}
catch {
    Write-Host ""
    Write-Host "ERROR: $_" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Read-Host "Press Enter to exit"
