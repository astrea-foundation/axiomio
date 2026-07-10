# Axiom Proxy Installers

The installers download a prebuilt release archive containing:

- `axiom`: the local setup helper. It currently manages OpenCode configuration.
- `axiom-proxy-headless`: the TEE-attested provider-E2EE proxy.

Every archive is verified against the release's `SHA256SUMS` before either
binary is installed.

The release source defaults to the public
[`astrea-foundation/axiomio`](https://github.com/astrea-foundation/axiomio)
repository.

## Linux and macOS

```bash
curl -fsSL https://axiom.stream/install.sh | bash
```

The source-controlled fallback is:

```bash
curl -fsSL https://raw.githubusercontent.com/astrea-foundation/axiomio/main/install/install.sh | bash
```

The default install directory is `~/.local/bin`. Override it with
`AXIOM_INSTALL_DIR`. Linux x86-64/ARM64 and macOS x86-64/Apple Silicon are
packaged by the release workflow.

## Windows

Run in PowerShell:

```powershell
irm https://axiom.stream/install.ps1 | iex
```

The source-controlled fallback is:

```powershell
irm https://raw.githubusercontent.com/astrea-foundation/axiomio/main/install/install.ps1 | iex
```

The default install directory is `%LOCALAPPDATA%\Axiom\bin`. The installer adds
that directory to the user's `PATH`. Windows x86-64 and ARM64 archives are
packaged by the release workflow.

## OpenCode

When `opencode` is on `PATH`, the installer runs:

```text
axiom configure opencode
```

The helper asks OpenCode for its active config directory, prefers an existing
`opencode.jsonc` or `opencode.json`, creates a timestamped backup, and replaces
only `provider.axiom`. Comments, trailing commas, and unrelated configuration
are retained. If both config filenames exist, the helper stops and requires an
explicit choice:

```bash
axiom configure opencode --config /path/to/opencode.jsonc
```

The generated provider targets `http://127.0.0.1:8484/v1` through
`@ai-sdk/openai-compatible`. The placeholder provider key is not an Axiom relay
credential; the `axm_` key remains local to the proxy process.

## Versions and mirrors

The default download follows the latest GitHub release. Pin a release tag with:

```bash
AXIOM_VERSION=proxy-v0.1.0 ./install/install.sh
```

PowerShell accepts the same environment variable. `AXIOM_DOWNLOAD_BASE` may
point to a mirror directory containing the platform archive and `SHA256SUMS`.

Release asset names are stable:

```text
axiom-proxy-linux-x86_64.tar.gz
axiom-proxy-linux-aarch64.tar.gz
axiom-proxy-macos-aarch64.tar.gz
axiom-proxy-macos-x86_64.tar.gz
axiom-proxy-windows-aarch64.zip
axiom-proxy-windows-x86_64.zip
SHA256SUMS
```

## Current startup requirement

Until the future `axiom up` flow owns credentials and process lifecycle, start
the proxy explicitly:

```bash
AXIOM_PROXY_API_KEY=axm_... axiom-proxy-headless
```

The proxy remains bound to `127.0.0.1:8484` and all remote inference continues
through verified NEAR provider E2EE v2.
