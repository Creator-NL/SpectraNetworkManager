[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$env:DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = "1"
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
$env:DOTNET_NOLOGO = "1"

# Read version from Directory.Build.props
[xml]$props = Get-Content "Directory.Build.props"
$Version = $props.Project.PropertyGroup.Version
if (-not $Version) { $Version = "1.0.1" }

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " SpectraNetworkManager v$Version Release and Packaging Pipeline" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Run all tests
if (-not $SkipTests) {
    Write-Host "`n[1/4] Running automated test suite..." -ForegroundColor Yellow
    dotnet test SpectraNetworkManager.sln -c $Configuration
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Tests failed! Aborting package build."
        exit $LASTEXITCODE
    }
    Write-Host "All test suites passed cleanly." -ForegroundColor Green
} else {
    Write-Host "`n[1/4] Skipping automated test suite (-SkipTests specified)." -ForegroundColor DarkGray
}

# 2. Publish binaries
Write-Host "`n[2/4] Publishing application and engine binaries (Self-Contained win-x64)..." -ForegroundColor Yellow
if (Test-Path "publish") {
    Remove-Item -Recurse -Force "publish"
}

dotnet publish src/SpectraNetworkManager.App/SpectraNetworkManager.App.csproj -c $Configuration -r win-x64 --self-contained true --disable-build-servers -m:1 -o publish/app
if ($LASTEXITCODE -ne 0) { Write-Error "Publish App failed!"; exit $LASTEXITCODE }
dotnet publish src/SpectraNetworkManager.Engine/SpectraNetworkManager.Engine.csproj -c $Configuration -r win-x64 --self-contained true --disable-build-servers -m:1 -o publish/engine
if ($LASTEXITCODE -ne 0) { Write-Error "Publish Engine failed!"; exit $LASTEXITCODE }
Write-Host "Published self-contained win-x64 binaries to publish/." -ForegroundColor Green

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
        Write-Host "Installer created at installer\output\SpectraNetworkManager-v$Version-Setup.exe" -ForegroundColor Green
    } else {
        Write-Error "Inno Setup compilation failed with exit code $($proc.ExitCode)."
        exit $proc.ExitCode
    }
}

# Create Portable ZIP package
Write-Host "`nCreating Portable ZIP package..." -ForegroundColor Yellow
$portableZip = "installer\output\SpectraNetworkManager-v$Version-Portable.zip"
if (Test-Path $portableZip) {
    Remove-Item -Force $portableZip
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory((Resolve-Path "publish\app").Path, (Join-Path (Resolve-Path "installer\output").Path "SpectraNetworkManager-v$Version-Portable.zip"), [System.IO.Compression.CompressionLevel]::Optimal, $false)
Write-Host "Portable package created at $portableZip" -ForegroundColor Green

# 4. Compute SHA-256 checksums
Write-Host "`n[4/4] Generating SHA-256 checksums..." -ForegroundColor Yellow
$installerExe = "installer\output\SpectraNetworkManager-v$Version-Setup.exe"
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
Write-Host " Build and Packaging Complete for v$Version!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
