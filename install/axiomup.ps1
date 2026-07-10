[CmdletBinding()]
param(
    [string]$Version = $env:AXIOM_VERSION,
    [string]$DownloadBase = $env:AXIOM_DOWNLOAD_BASE,
    [string]$Repository = $env:AXIOM_REPOSITORY,
    [string]$DesktopInstallDir = $env:AXIOM_DESKTOP_INSTALL_DIR,
    [string]$LegacyInstallDir = $env:AXIOM_INSTALL_DIR,
    [switch]$SkipPathUpdate,
    [switch]$SkipOpenCode,
    [switch]$SkipDesktopInstall
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($Version)) { $Version = "latest" }
if ([string]::IsNullOrWhiteSpace($Repository)) { $Repository = "astrea-foundation/axiomio" }
if ([string]::IsNullOrWhiteSpace($DesktopInstallDir)) {
    $DesktopInstallDir = Join-Path $env:LOCALAPPDATA "AxiomIO"
}
if ([string]::IsNullOrWhiteSpace($LegacyInstallDir)) {
    $LegacyInstallDir = Join-Path $HOME ".local\bin"
}

function Remove-LegacyAxiomInstall {
    $legacyCli = Join-Path $LegacyInstallDir "axiom.exe"
    $legacyProxy = Join-Path $LegacyInstallDir "axiom-proxy-headless.exe"
    if ((Test-Path -LiteralPath $legacyCli -PathType Leaf) -and
        (Test-Path -LiteralPath $legacyProxy -PathType Leaf)) {
        Remove-Item -LiteralPath $legacyCli, $legacyProxy -Force
        Write-Host "Removed the legacy two-binary AxiomIO installation"
    }
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

$architecture = Get-AxiomArchitecture
$asset = "axiomio-windows-$architecture-setup.exe"
$base = Get-ReleaseBase
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("axiomup-" + [guid]::NewGuid())

try {
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    $setup = Join-Path $temporaryDirectory $asset
    $checksumFile = Join-Path $temporaryDirectory "SHA256SUMS"

    Write-Host "Downloading $asset"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $setup
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $checksumFile

    $escapedAsset = [regex]::Escape($asset)
    $checksumLine = Get-Content -LiteralPath $checksumFile |
        Where-Object { $_ -match "^([0-9A-Fa-f]{64})\s+\*?$escapedAsset$" } |
        Select-Object -First 1
    if ($null -eq $checksumLine) {
        throw "SHA256SUMS has no valid entry for $asset"
    }
    $expected = ([regex]::Match($checksumLine, "^[0-9A-Fa-f]{64}")).Value.ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $setup).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch for $asset"
    }

    if (-not $SkipDesktopInstall) {
        $installerArguments = "/S /D=`"$DesktopInstallDir`""
        $process = Start-Process -FilePath $setup -ArgumentList $installerArguments -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "AxiomIO desktop installer failed (exit $($process.ExitCode))"
        }
    }

    $axiomio = Join-Path $DesktopInstallDir "axiomio.exe"
    if (-not (Test-Path -LiteralPath $axiomio -PathType Leaf)) {
        throw "AxiomIO desktop executable was not installed at $axiomio"
    }

    if (-not $SkipPathUpdate) {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $pathEntries = @($userPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if (-not ($pathEntries | Where-Object { $_.TrimEnd("\") -ieq $DesktopInstallDir.TrimEnd("\") })) {
            [Environment]::SetEnvironmentVariable("Path", ((@($pathEntries) + $DesktopInstallDir) -join ";"), "User")
        }
        if (-not (($env:Path -split ";") | Where-Object { $_.TrimEnd("\") -ieq $DesktopInstallDir.TrimEnd("\") })) {
            $env:Path = "$DesktopInstallDir;$env:Path"
        }
    }

    Remove-LegacyAxiomInstall
    Write-Host "AxiomIO desktop application is up to date at $DesktopInstallDir"
    if ($SkipOpenCode) {
        Write-Host "Skipping OpenCode configuration by request"
    } elseif ($null -ne (Get-Command opencode -ErrorAction SilentlyContinue)) {
        Write-Host "Configuring OpenCode"
        & $axiomio configure opencode
        if ($LASTEXITCODE -ne 0) {
            throw "AxiomIO could not configure OpenCode (exit $LASTEXITCODE)"
        }
    } else {
        Write-Host "OpenCode was not found; skipping OpenCode configuration"
    }
} finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
