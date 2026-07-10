# AxiomIO

A local OpenAI-compatible endpoint that gives any tool TEE-attested, end-to-end-encrypted access
to Axiom models. Point `OPENAI_BASE_URL` at `http://127.0.0.1:8484/v1` and set your `axm_…` key —
the proxy verifies the model TEE attestation on your machine and encrypts prompts to the attested
key, so plaintext and verification never leave your device.

This repository contains the complete proxy, desktop shell, setup helper,
installers, and release automation. The hosted Axiom service and its private
backend are maintained separately.

## Layout

```text
crates/axiom-core     E2EE + attestation verification + relay client (pure Rust, no Tauri)
crates/axiom-server   axum OpenAI-compatible HTTP surface + headless binary
src-tauri             Tauri v2 desktop app (tray, autostart, keyring)
ui                    React + Vite + Tailwind dashboard
cli                   `axiom` coding-agent setup helper
install               Linux, macOS, and Windows bootstrap installers
fixtures              committed cross-language E2EE protocol vectors
```

`axiom-core` and `axiom-server` build and test with no GUI toolchain:

```bash
cargo test -p axiom-core -p axiom-server
```

## Run headless (no GUI)

```bash
AXIOM_PROXY_API_KEY=axm_... AXIOM_PROXY_BACKEND=https://api.axiom.stream \
  cargo run -p axiom-server --bin axiom-proxy-headless
# then: OPENAI_BASE_URL=http://127.0.0.1:8484/v1 OPENAI_API_KEY=unused <your tool>
```

## Install

Linux and macOS:

```bash
curl -fsSL https://axiom.stream/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://axiom.stream/install.ps1 | iex
```

The branded scripts install checksummed binaries from this repository's public
GitHub Releases. See [`install/README.md`](install/README.md) for version pinning,
mirrors, and manual startup details.

## OpenCode tool calling (proxy only)

OpenCode must use its OpenAI-compatible provider so it calls
`/v1/chat/completions`. Do not configure the OpenAI Responses API: encrypted
input for that API is not supported. Tool execution stays inside OpenCode. The
local proxy encrypts message content, tool names and descriptions, parameter
schemas, named choices, arguments, and tool results to the model key accepted
from verified Ed25519 TEE attestation; the backend only relays provider
ciphertext. This does not add tools to Axiom's frontend path.

Start the proxy with the real relay credential only in the proxy environment:

```bash
AXIOM_PROXY_API_KEY=axm_... AXIOM_PROXY_BACKEND=https://api.axiom.stream \
  cargo run -p axiom-server --bin axiom-proxy-headless
```

An isolated OpenCode configuration can then point at the local endpoint. The
`apiKey` below is intentionally a dummy value; never put the Axiom relay key in
OpenCode configuration.

```json
{
  "provider": {
    "axiom": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Axiom Proxy",
      "options": {
        "baseURL": "http://127.0.0.1:8484/v1",
        "apiKey": "unused"
      },
      "models": {
        "glm-5-2": {
          "name": "Axiom GLM-5.2",
          "variants": {
            "low": { "reasoningEffort": "low" },
            "medium": { "reasoningEffort": "medium" },
            "high": { "reasoningEffort": "high" },
            "xhigh": { "reasoningEffort": "xhigh" }
          }
        }
      }
    }
  },
  "permission": {
    "*": "deny",
    "read": "allow",
    "edit": "allow",
    "write": "allow",
    "glob": "allow",
    "list": "allow",
    "external_directory": "deny",
    "bash": "deny",
    "task": "deny",
    "webfetch": "deny"
  }
}
```

Supply that JSON with `OPENCODE_CONFIG_CONTENT` (or an isolated config file),
then select `axiom/glm-5-2`. The repository's live harness does this without
reading or modifying normal OpenCode state:

```bash
AXIOM_PROXY_API_KEY=axm_... ./scripts/smoke_opencode_tools.sh
```

Use OpenCode's variant-cycle keybinding to switch between GLM-5.2's `low`,
`medium`, `high`, and `xhigh` variants. OpenCode serializes each variant's
`reasoningEffort` option as the OpenAI-compatible `reasoning_effort` request
field. The proxy validates it against the selected model before performing TEE
attestation or sending ciphertext. GPT-OSS 120B accepts `low`, `medium`, and
`high`; models with no advertised granular levels reject explicit values.

The harness creates a disposable workspace and XDG/HOME tree, denies shell,
sub-agent, web, and external-directory access, runs `opencode --pure` in JSON
mode, and requires ordered completed read/edit/read events, a later final text
event, and the exact expected file contents. It removes successful artifacts by
default and retains failures for diagnosis. Set `KEEP_SMOKE_ARTIFACTS=1` to keep
a successful capture, `AXIOM_OPENCODE_MODEL` to require a particular live
catalog model (otherwise the first model supporting the selected effort is used),
`AXIOM_OPENCODE_REASONING_EFFORT` to select the smoke's level (default `high`),
or `AXIOM_PROXY_PORT` if port 18484 is occupied.

## E2EE request history

The desktop app's **History** tab shows the newest 100 terminal proxy requests,
newest first, and refreshes while the tab is open. It separates completed,
failed, and cancelled requests and shows safe evidence such as the model,
provider, timestamps, duration, token counts, `near-v2` protocol/version,
attestation age and checks, and truncated SHA-256 model-key and TLS-SPKI
fingerprints.

“E2EE+TEE verified” is intentionally strict. A row receives that label only
when all of the following are true for the same request:

- terminal status is `completed`;
- a verified Ed25519 TEE attestation supplied the model key;
- the protocol is exactly `near-v2` with encryption version `2`;
- the request was encrypted with a fresh ephemeral client key;
- the backend accepted the attested key and encrypted request; and
- the encrypted provider response was processed and decrypted locally.

A completed row with missing evidence is shown as **Incomplete evidence**, not
verified. Failed and client/provider-cancelled requests retain their own status
and never count as completed or verified.

The same metadata is emitted through the structured `axiom.request_audit` log
target and persisted in `request-history.json` under the operating system's
local application-data directory for `axiom-proxy`. Desktop and headless modes
use the same location. The file is atomically replaced and capped to exactly
the newest 100 entries across restarts; persistence errors produce a warning
but never weaken attestation or E2EE enforcement.

The history contains metadata only. It never stores prompts, responses,
reasoning, tool names or schemas, tool arguments/results, provider ciphertext,
API keys, ephemeral client keys, or full model public keys. There is no
plaintext inference fallback.

## Desktop app (all platforms)

Requires Node and the Tauri prerequisites for your OS.

- **Linux**: `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libsoup-3.0-dev`
- **macOS**: Xcode command line tools (notarization needs an Apple developer account)
- **Windows**: WebView2 (preinstalled on Windows 11) + MSVC build tools

```bash
cargo tauri dev      # develop
cargo tauri build    # bundle for the current OS
```

CI (`.github/workflows/ci.yml`) builds Linux, macOS (aarch64 + x86_64), and Windows.

## E2EE vectors

The committed vectors under `fixtures/e2ee_vectors/` are generated from the
service implementation and intentionally vendored so this public repository
can verify protocol compatibility without access to the private backend. A
protocol update must update the vectors and both sides' tests together.

## Icons

`cargo tauri icon src-tauri/icons/source.png` regenerates the full icon set.
