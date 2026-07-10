# AxiomIO Desktop Installers

The bootstrap installers download and verify the native AxiomIO desktop
application from the public
[`astrea-foundation/axiomio`](https://github.com/astrea-foundation/axiomio)
releases. The application contains one executable named `axiomio`:

- Run `axiomio` with no arguments to open the desktop application.
- Run `axiomio --headless` to start only the TEE-attested provider-E2EE proxy.
- Run `axiomio configure opencode` to configure OpenCode.

Every downloaded artifact is verified against the release's `SHA256SUMS`
before installation.

## Linux

```bash
curl -fsSL https://axiom.stream/install.sh | bash
```

The installer places the AppImage under `~/.local/share/axiomio`, creates an
`axiomio` symlink in `~/.local/bin`, and installs a desktop entry and icon under
`~/.local/share`. Override these locations with `AXIOM_DESKTOP_DIR`,
`AXIOM_INSTALL_DIR`, `AXIOM_DESKTOP_ENTRY_DIR`, and `AXIOM_ICON_DIR`.

## macOS

```bash
curl -fsSL https://axiom.stream/install.sh | bash
```

The installer places `AxiomIO.app` in `~/Applications` and links its executable
as `~/.local/bin/axiomio`. Override these locations with
`AXIOM_APPLICATIONS_DIR` and `AXIOM_INSTALL_DIR`. Releases also include DMGs for
manual drag-and-drop installation.

The source-controlled Unix installer is available at:

```bash
curl -fsSL https://raw.githubusercontent.com/astrea-foundation/axiomio/main/install/install.sh | bash
```

## Windows

Run in PowerShell:

```powershell
irm https://axiom.stream/install.ps1 | iex
```

The installer runs the per-user NSIS setup and adds its AxiomIO directory to the
user `PATH`. The default location is `%LOCALAPPDATA%\AxiomIO`; override it with
`AXIOM_DESKTOP_INSTALL_DIR`.

The source-controlled PowerShell installer is available at:

```powershell
irm https://raw.githubusercontent.com/astrea-foundation/axiomio/main/install/install.ps1 | iex
```

## OpenCode

When `opencode` is on `PATH`, installation runs:

```text
axiomio configure opencode
```

The command asks OpenCode for its active config directory, prefers an existing
`opencode.jsonc` or `opencode.json`, creates a timestamped backup, and replaces
only `provider.axiom`. Comments, trailing commas, and unrelated configuration
are retained. If both config filenames exist, choose one explicitly:

```bash
axiomio configure opencode --config /path/to/opencode.jsonc
```

The generated provider uses `http://127.0.0.1:8484/v1`. Its placeholder API key
is intentionally not an Axiom relay credential; the `axm_` key remains local to
the AxiomIO process.

## Versions and mirrors

The default download follows the latest GitHub release. Pin a release with
`AXIOM_VERSION=v0.2.0`, or set `AXIOM_DOWNLOAD_BASE` to a mirror containing the
platform artifacts and `SHA256SUMS`.

Release asset names are stable:

```text
axiomio-linux-x86_64.AppImage
axiomio-linux-aarch64.AppImage
axiomio-macos-aarch64.app.tar.gz
axiomio-macos-aarch64.dmg
axiomio-macos-x86_64.app.tar.gz
axiomio-macos-x86_64.dmg
axiomio-windows-aarch64-setup.exe
axiomio-windows-x86_64-setup.exe
axiomio-icon.png
SHA256SUMS
```

Until credential enrollment is part of the desktop flow, headless startup is:

```bash
AXIOM_PROXY_API_KEY=axm_... axiomio --headless
```

The proxy remains bound to `127.0.0.1:8484`, and all remote inference continues
through verified NEAR provider E2EE v2.
