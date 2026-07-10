# Agent Instructions

## Security Invariant

AxiomIO only supports TEE-attested provider E2EE for inference. All chat model
requests must use NEAR provider E2EE v2 (`provider_e2ee_v2` / `near-v2`) with a
model public key accepted only from verified Ed25519 TEE attestation evidence.

Do not add plaintext inference modes, TLS fallbacks, server-side prompt
construction, backend system-message injection, or plaintext message caches.
The local proxy owns model-message construction, attestation verification,
provider-E2EE encryption and decryption, and local credential handling.

Remote services may receive only provider ciphertext, attestation metadata,
run metadata, aggregate usage, and other non-message-secret operational
metadata. Any path that would send live prompt text, conversation history,
assistant deltas, or completion text through the backend must fail closed.

Tests and live scripts that exercise provider inference must use E2EE. Any
non-E2EE provider helper, fixture, or example is a bug unless it explicitly
tests rejection of legacy or plaintext input.
