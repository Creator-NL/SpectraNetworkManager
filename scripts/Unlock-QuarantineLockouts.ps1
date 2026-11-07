# SpectraNetworkManager Emergency IFEO Execution Lockout Cleaner
# Biohazard Corp / Creator-NL
# Run this script in an elevated PowerShell (Run as Administrator) to remove any orphaned
# Image File Execution Options (IFEO) redirects to systray.exe left behind by previous installations.

$ErrorActionPreference = "Continue"

$ifeoPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " SpectraNetworkManager - IFEO Execution Lockout Diagnostics" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$cleared = 0

foreach ($root in $ifeoPaths) {
    if (-not (Test-Path $root)) { continue }

    Write-Host "`nScanning root: $root" -ForegroundColor Yellow
    $keys = Get-ChildItem -Path $root -ErrorAction SilentlyContinue

    foreach ($k in $keys) {
        $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
        if ($props.Debugger -and ($props.Debugger -like "*systray.exe*")) {
            Write-Host "  [FOUND LOCKOUT] $($k.PSChildName) -> Debugger: $($props.Debugger)" -ForegroundColor Red
            try {
                Remove-ItemProperty -Path $k.PSPath -Name "Debugger" -Force -ErrorAction Stop
                Write-Host "    --> Successfully removed Debugger redirect." -ForegroundColor Green
                $cleared++

                # Remove the subkey if empty
                $remainingProps = (Get-ItemProperty -Path $k.PSPath).PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                if (-not $remainingProps -or $remainingProps.Count -eq 0) {
                    Remove-Item -Path $k.PSPath -Force -ErrorAction SilentlyContinue
                    Write-Host "    --> Cleaned up empty key: $($k.PSChildName)" -ForegroundColor DarkGray
                }
            }
            catch {
                Write-Host "    [!] Error clearing $($k.PSChildName): $_" -ForegroundColor DarkYellow
            }
        }
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
if ($cleared -gt 0) {
    Write-Host " Repaired $cleared execution lockout(s) successfully!" -ForegroundColor Green
    Write-Host " WebView2, Ollama, and dependent applications are now unblocked." -ForegroundColor Green
} else {
    Write-Host " No orphaned IFEO execution lockouts were found. Everything is clean!" -ForegroundColor Green
}
Write-Host "==========================================================" -ForegroundColor Cyan
