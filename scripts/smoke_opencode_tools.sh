#!/usr/bin/env bash

# Live, isolated OpenCode read/edit/read smoke test through the Axiom E2EE proxy.
# The real relay credential is passed only to the proxy process. OpenCode gets
# an isolated HOME/XDG tree and an "unused" local-provider API key.

set +x
set -euo pipefail

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

for command_name in cmp curl find grep jq opencode timeout; do
  command -v "$command_name" >/dev/null 2>&1 || fail "missing required command: $command_name"
done

[[ -n "${AXIOM_PROXY_API_KEY:-}" ]] || fail "AXIOM_PROXY_API_KEY is required"
relay_api_key="$AXIOM_PROXY_API_KEY"
backend="${AXIOM_PROXY_BACKEND:-https://api.axiom.stream}"
unset AXIOM_PROXY_API_KEY AXIOM_PROXY_BACKEND

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
proxy_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
proxy_bin="${AXIOM_PROXY_BIN:-$proxy_root/target/debug/axiom-proxy-headless}"
port="${AXIOM_PROXY_PORT:-18484}"
requested_model="${AXIOM_OPENCODE_MODEL:-}"
reasoning_effort="${AXIOM_OPENCODE_REASONING_EFFORT:-high}"
model=""
timeout_seconds="${AXIOM_OPENCODE_TIMEOUT_SECONDS:-300}"
keep_artifacts="${KEEP_SMOKE_ARTIFACTS:-0}"

[[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)) \
  || fail "AXIOM_PROXY_PORT must be an integer from 1 through 65535"
[[ "$timeout_seconds" =~ ^[0-9]+$ ]] && ((timeout_seconds >= 1)) \
  || fail "AXIOM_OPENCODE_TIMEOUT_SECONDS must be a positive integer"
[[ "$reasoning_effort" =~ ^(low|medium|high|xhigh)$ ]] \
  || fail "AXIOM_OPENCODE_REASONING_EFFORT must be low, medium, high, or xhigh"

if [[ ! -x "$proxy_bin" ]]; then
  command -v cargo >/dev/null 2>&1 \
    || fail "proxy binary not found; set AXIOM_PROXY_BIN or install cargo"
  cargo build --manifest-path "$proxy_root/Cargo.toml" \
    -p axiom-server --bin axiom-proxy-headless
fi

if curl --silent --show-error --max-time 1 \
  "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
  fail "port $port is already serving HTTP; choose an isolated AXIOM_PROXY_PORT"
fi

artifact_root="$(mktemp -d "${TMPDIR:-/tmp}/axiom-opencode-tools.XXXXXX")"
workspace="$artifact_root/workspace"
events_file="$artifact_root/events.jsonl"
opencode_log="$artifact_root/opencode.stderr.log"
proxy_log="$artifact_root/proxy.log"
proxy_pid=""

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  if ((status != 0)) || [[ "$keep_artifacts" == "1" ]]; then
    printf 'Smoke artifacts retained at %s\n' "$artifact_root" >&2
  else
    rm -rf "$artifact_root"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p \
  "$workspace" \
  "$artifact_root/home" \
  "$artifact_root/xdg-config" \
  "$artifact_root/xdg-data" \
  "$artifact_root/xdg-cache" \
  "$artifact_root/xdg-state"
printf 'TOKEN=before\n' >"$workspace/target.txt"
printf 'TOKEN=after\n' >"$artifact_root/expected.txt"

AXIOM_PROXY_API_KEY="$relay_api_key" \
AXIOM_PROXY_BACKEND="$backend" \
AXIOM_PROXY_PORT="$port" \
  "$proxy_bin" >"$proxy_log" 2>&1 &
proxy_pid=$!

ready=0
for ((_attempt = 1; _attempt <= 60; _attempt++)); do
  if curl --fail --silent --show-error \
    "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  kill -0 "$proxy_pid" 2>/dev/null || fail "proxy exited before becoming ready"
  sleep 1
done
((ready == 1)) || fail "proxy did not become ready within 60 seconds"

models_json="$(
  curl --fail --silent --show-error "http://127.0.0.1:${port}/v1/models"
)" || fail "could not list models from the live relay"
if [[ -n "$requested_model" ]]; then
  jq -e --arg model "$requested_model" \
    'any(.data[]; .id == $model)' <<<"$models_json" >/dev/null \
    || fail "AXIOM_OPENCODE_MODEL is not present in the live relay catalog"
  model="$requested_model"
else
  model="$(
    jq -r --arg effort "$reasoning_effort" \
      '[.data[] | select((.supported_reasoning_efforts // []) | index($effort)) | .id][0] // empty' \
      <<<"$models_json"
  )"
  [[ -n "$model" ]] \
    || fail "the live relay returned no model supporting reasoning effort $reasoning_effort"
fi
jq -e --arg model "$model" --arg effort "$reasoning_effort" \
  'any(.data[]; .id == $model and ((.supported_reasoning_efforts // []) | index($effort)))' \
  <<<"$models_json" >/dev/null \
  || fail "model $model does not support reasoning effort $reasoning_effort"

config_json="$(
  jq -cn \
    --arg base_url "http://127.0.0.1:${port}/v1" \
    --arg model "$model" \
    --arg reasoning_effort "$reasoning_effort" \
    '{
      provider: {
        axiom: {
          npm: "@ai-sdk/openai-compatible",
          name: "Axiom Proxy",
          options: {baseURL: $base_url, apiKey: "unused"},
          models: {($model): {
            name: ("Axiom " + $model),
            options: {reasoningEffort: $reasoning_effort}
          }}
        }
      },
      permission: {
        "*": "deny",
        read: "allow",
        edit: "allow",
        write: "allow",
        glob: "allow",
        list: "allow",
        external_directory: "deny",
        bash: "deny",
        task: "deny",
        webfetch: "deny",
        question: "deny"
      }
    }'
)"
printf '%s\n' "$config_json" >"$artifact_root/opencode-config.json"

opencode_version="$(opencode --version)"
jq -n \
  --arg opencode_version "$opencode_version" \
  --arg model "axiom/$model" \
  --arg reasoning_effort "$reasoning_effort" \
  --arg backend "$backend" \
  '{opencode_version: $opencode_version, model: $model, reasoning_effort: $reasoning_effort, backend: $backend}' \
  >"$artifact_root/metadata.json"

prompt='Work only in this disposable workspace. You must complete this exact sequence with local tools: (1) use the read tool to read target.txt, (2) use edit or write to replace exactly TOKEN=before with TOKEN=after and make no other file changes, (3) use the read tool to read target.txt again, then report completion in a final text response. Do not use shell/bash, task/sub-agent, web/network, or any path outside this workspace.'

set +e
(
  cd "$workspace"
  export HOME="$artifact_root/home"
  export XDG_CONFIG_HOME="$artifact_root/xdg-config"
  export XDG_DATA_HOME="$artifact_root/xdg-data"
  export XDG_CACHE_HOME="$artifact_root/xdg-cache"
  export XDG_STATE_HOME="$artifact_root/xdg-state"
  export OPENCODE_CONFIG_CONTENT="$config_json"
  export OPENCODE_DISABLE_AUTOUPDATE=true
  unset AXIOM_PROXY_API_KEY AXIOM_PROXY_BACKEND
  timeout --signal=TERM --kill-after=10 "${timeout_seconds}s" \
    opencode run --pure --format json --model "axiom/$model" "$prompt"
) >"$events_file" 2>"$opencode_log"
opencode_status=$?
set -e

((opencode_status == 0)) \
  || fail "OpenCode exited with status $opencode_status"

jq -e . "$events_file" >/dev/null \
  || fail "OpenCode output was empty or contained invalid JSONL"
if jq -e 'select(.type == "error")' "$events_file" >/dev/null; then
  fail "OpenCode emitted an error event"
fi

jq -s -e '
  [to_entries[] |
    select(.value.type == "tool_use" and
      .value.part.tool == "read" and
      .value.part.state.status == "completed")] as $reads |
  [to_entries[] |
    select(.value.type == "tool_use" and
      (.value.part.tool == "edit" or .value.part.tool == "write") and
      .value.part.state.status == "completed")] as $edits |
  [to_entries[] |
    select(.value.type == "text" and
      (.value.part.text | type == "string") and
      (.value.part.text | length > 0))] as $texts |
  ($reads | length) >= 2 and
  ($edits | length) >= 1 and
  ($texts | length) >= 1 and
  $reads[0].key < $edits[0].key and
  $edits[0].key < $reads[-1].key and
  $reads[-1].key < $texts[-1].key
' "$events_file" >/dev/null \
  || fail "JSONL did not prove an ordered read/edit/read/final-text loop"

cmp -s "$workspace/target.txt" "$artifact_root/expected.txt" \
  || fail "target.txt does not contain exactly TOKEN=after followed by a newline"
extra_workspace_entry="$(
  find "$workspace" -mindepth 1 ! -path "$workspace/target.txt" -print -quit
)"
[[ -z "$extra_workspace_entry" ]] \
  || fail "OpenCode created an unexpected workspace entry"

if grep -Fq \
  -e 'TOKEN=before' \
  -e 'TOKEN=after' \
  -e 'target.txt' \
  "$proxy_log"; then
  fail "proxy operational logs reproduced a controlled message sentinel"
fi

if printf '%s\n' "$relay_api_key" \
  | grep -Fq -f - "$events_file" "$opencode_log" "$proxy_log"; then
  fail "the relay credential appeared in a captured artifact"
fi

printf 'OpenCode %s live E2EE tool smoke passed with axiom/%s at %s reasoning effort.\n' \
  "$opencode_version" "$model" "$reasoning_effort"
