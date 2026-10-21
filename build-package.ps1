[CmdletBinding()]
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " SpectraNetworkManager Release and Packaging Pipeline" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Run all tests
Write-Host "`n[1/4] Running automated test suite..." -ForegroundColor Yellow
dotnet test SpectraNetworkManager.sln -c $Configuration
if ($LASTEXITCODE -ne 0) {
    Write-Error "Tests failed! Aborting package build."
    exit $LASTEXITCODE
}
Write-Host "All test suites passed cleanly." -ForegroundColor Green

# 2. Publish binaries
Write-Host "`n[2/4] Publishing application and engine binaries..." -ForegroundColor Yellow
if (Test-Path "publish") {
    Remove-Item -Recurse -Force "publish"
}

dotnet publish src/SpectraNetworkManager.App/SpectraNetworkManager.App.csproj -c $Configuration -r win-x64 --self-contained false -o publish/app
dotnet publish src/SpectraNetworkManager.Engine/SpectraNetworkManager.Engine.csproj -c $Configuration -r win-x64 --self-contained false -o publish/engine
Write-Host "Published win-x64 binaries to publish/." -ForegroundColor Green

# 3. Compile Inno Setup installer
Write-Host "`n[3/4] Compiling Inno Setup installer..." -ForegroundColor Yellow
$isccCandidates = @(
    "C:\Users\Creator\AppData\Local\Programs\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)

$isccPath = $null
foreach ($cand in $isccCandidates) {
    if (Test-Path $cand) {
        $isccPath = $cand
        break
    }
}

if (-not $isccPath) {
    $cmd = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        $isccPath = $cmd.Source
    }
}

if (-not $isccPath) {
    Write-Warning "Inno Setup compiler (ISCC.exe) not found. Skipping installer exe creation."
} else {
    Write-Host "Using Inno Setup compiler: $isccPath" -ForegroundColor DarkGray
    $proc = Start-Process -FilePath $isccPath -ArgumentList "installer\SpectraNetworkManager.iss" -Wait -NoNewWindow -PassThru
    if ($proc.ExitCode -eq 0) {
        Write-Host "Installer created at installer\output\SpectraNetworkManager-Setup-v1.0.0.exe" -ForegroundColor Green
    } else {
        Write-Error "Inno Setup compilation failed with exit code $($proc.ExitCode)."
        exit $proc.ExitCode
    }
}

# Create Portable ZIP package
Write-Host "`nCreating Portable ZIP package..." -ForegroundColor Yellow
$portableZip = "installer\output\SpectraNetworkManager-v1.0.0-Portable.zip"
if (Test-Path $portableZip) {
    Remove-Item -Force $portableZip
}
Compress-Archive -Path "publish\app\*" -DestinationPath $portableZip -CompressionLevel Optimal
Write-Host "Portable package created at $portableZip" -ForegroundColor Green

# 4. Compute SHA-256 checksums
Write-Host "`n[4/4] Generating SHA-256 checksums..." -ForegroundColor Yellow
$installerExe = "installer\output\SpectraNetworkManager-Setup-v1.0.0.exe"
$hashes = @()
if (Test-Path $installerExe) {
    $hash = Get-FileHash $installerExe -Algorithm SHA256
    $hashes += "$($hash.Hash)  $($hash.Path | Split-Path -Leaf)"
    Write-Host "Installer SHA-256: $($hash.Hash)" -ForegroundColor Cyan
}
if (Test-Path $portableZip) {
    $zipHash = Get-FileHash $portableZip -Algorithm SHA256
    $hashes += "$($zipHash.Hash)  $($zipHash.Path | Split-Path -Leaf)"
    Write-Host "Portable ZIP SHA-256: $($zipHash.Hash)" -ForegroundColor Cyan
}
if ($hashes.Count -gt 0) {
    Set-Content -Path "installer\output\SHA256SUMS.txt" -Value ($hashes -join "`r`n")
}

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host " Build and Packaging Complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
