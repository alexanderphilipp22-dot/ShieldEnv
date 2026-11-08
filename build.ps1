#Requires -Version 7.0
<#
    Builds leakguard as a standalone, single-file Native AOT executable.

    Usage:
        .\build.ps1 [-Runtime win-x64] [-Configuration Release] [-OutputDir dist]

    Examples:
        .\build.ps1
        .\build.ps1 -Runtime win-arm64 -OutputDir dist-arm64
#>
param(
    [ValidateSet("win-x64", "win-arm64")]
    [string]$Runtime = "win-x64",

    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [string]$OutputDir = "dist"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Join-Path $root "ShieldEnv.csproj"
$output = Join-Path $root $OutputDir

if (-not (Test-Path $project)) {
    throw "Project file not found: $project"
}

Write-Host "Publishing leakguard (Native AOT) for '$Runtime' ($Configuration)..." -ForegroundColor Cyan

dotnet publish $project `
    --configuration $Configuration `
    --runtime $Runtime `
    --self-contained true `
    --output $output `
    -p:PublishAot=true `
    -p:PublishTrimmed=true `
    -p:InvariantGlobalization=true

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

$exeName = if ($Runtime.StartsWith("win")) { "leakguard.exe" } else { "leakguard" }
$exe = Join-Path $output $exeName

if (-not (Test-Path $exe)) {
    throw "Expected output not found: $exe"
}

$sizeMb = [math]::Round((Get-Item $exe).Length / 1MB, 2)

Write-Host ""
Write-Host "Build complete." -ForegroundColor Green
Write-Host "  Output : $exe"
Write-Host "  Size   : $sizeMb MB"
Write-Host "  Runtime: $Runtime"
