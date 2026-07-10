[CmdletBinding()]
param(
    [string]$Version = $env:AXIOM_VERSION,
    [string]$InstallDir = $env:AXIOM_INSTALL_DIR,
    [string]$DownloadBase = $env:AXIOM_DOWNLOAD_BASE,
    [string]$Repository = $env:AXIOM_REPOSITORY,
    [switch]$SkipPathUpdate,
    [switch]$SkipOpenCode
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($Version)) { $Version = "latest" }
if ([string]::IsNullOrWhiteSpace($Repository)) { $Repository = "astrea-foundation/axiomio" }
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $env:LOCALAPPDATA "Axiom\bin"
}

function Get-AxiomArchitecture {
    if (-not [string]::IsNullOrWhiteSpace($env:AXIOM_ARCH)) {
        $machine = $env:AXIOM_ARCH.ToLowerInvariant()
    } else {
        $machine = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    }
    switch ($machine) {
        { $_ -in @("x64", "x86_64", "amd64") } { return "x86_64" }
        { $_ -in @("arm64", "aarch64") } { return "aarch64" }
        default { throw "Unsupported Windows architecture: $machine" }
    }
}

function Get-ReleaseBase {
    if (-not [string]::IsNullOrWhiteSpace($DownloadBase)) {
        return $DownloadBase.TrimEnd("/")
    }
    if ($Version -eq "latest") {
        return "https://github.com/$Repository/releases/latest/download"
    }
    return "https://github.com/$Repository/releases/download/$Version"
}

function Install-AxiomFile {
    param([string]$Source, [string]$Destination)
    $temporary = "$Destination.tmp.$PID"
    Copy-Item -LiteralPath $Source -Destination $temporary -Force
    Move-Item -LiteralPath $temporary -Destination $Destination -Force
}

$architecture = Get-AxiomArchitecture
$asset = "axiom-proxy-windows-$architecture.zip"
$base = Get-ReleaseBase
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("axiom-install-" + [guid]::NewGuid())

try {
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    $archive = Join-Path $temporaryDirectory $asset
    $checksumFile = Join-Path $temporaryDirectory "SHA256SUMS"

    Write-Host "Downloading $asset"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $archive
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $checksumFile

    $escapedAsset = [regex]::Escape($asset)
    $checksumLine = Get-Content -LiteralPath $checksumFile |
        Where-Object { $_ -match "^([0-9A-Fa-f]{64})\s+\*?$escapedAsset$" } |
        Select-Object -First 1
    if ($null -eq $checksumLine) {
        throw "SHA256SUMS has no valid entry for $asset"
    }
    $expected = ([regex]::Match($checksumLine, "^[0-9A-Fa-f]{64}")).Value.ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch for $asset"
    }

    $extracted = Join-Path $temporaryDirectory "extracted"
    Expand-Archive -LiteralPath $archive -DestinationPath $extracted
    $axiomSource = Join-Path $extracted "axiom.exe"
    $proxySource = Join-Path $extracted "axiom-proxy-headless.exe"
    if (-not (Test-Path -LiteralPath $axiomSource -PathType Leaf)) {
        throw "$asset does not contain axiom.exe"
    }
    if (-not (Test-Path -LiteralPath $proxySource -PathType Leaf)) {
        throw "$asset does not contain axiom-proxy-headless.exe"
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $axiomDestination = Join-Path $InstallDir "axiom.exe"
    Install-AxiomFile -Source $axiomSource -Destination $axiomDestination
    Install-AxiomFile -Source $proxySource -Destination (Join-Path $InstallDir "axiom-proxy-headless.exe")

    if (-not $SkipPathUpdate) {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $pathEntries = @($userPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if (-not ($pathEntries | Where-Object { $_.TrimEnd("\") -ieq $InstallDir.TrimEnd("\") })) {
            $newUserPath = (@($pathEntries) + $InstallDir) -join ";"
            [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        }
        if (-not (($env:Path -split ";") | Where-Object { $_.TrimEnd("\") -ieq $InstallDir.TrimEnd("\") })) {
            $env:Path = "$InstallDir;$env:Path"
        }
    }

    Write-Host "Installed Axiom proxy tools to $InstallDir"
    if ($SkipOpenCode) {
        Write-Host "Skipping OpenCode configuration by request"
    } elseif ($null -ne (Get-Command opencode -ErrorAction SilentlyContinue)) {
        Write-Host "Configuring OpenCode"
        & $axiomDestination configure opencode
        if ($LASTEXITCODE -ne 0) {
            throw "Axiom could not configure OpenCode (exit $LASTEXITCODE)"
        }
    } else {
        Write-Host "OpenCode was not found; skipping OpenCode configuration"
    }
} finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
