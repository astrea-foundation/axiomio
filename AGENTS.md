# Agent Instructions

## Security Invariant

AxiomIO only supports TEE-attested provider E2EE for inference. Every chat model
request must use an explicitly registered provider-E2EE protocol, and recipient
key material may be accepted only from fresh, locally verified TEE attestation
evidence. Direct-model and attested-gateway-plus-worker chains are both allowed,
but ordinary TLS or an unauthenticated provider key is never sufficient.

For Phala ACI v2, the local proxy must verify the nonce-bound gateway TDX
evidence and its X25519 and Ed25519 keyset, pre-verify eligible
content-addressed worker sessions, require `aci_verified: true` and `zdr: true`,
and accept a response only after its receipt signature, request/response hashes,
model identity, session validity, and exact receipt-cited worker all verify. No
unverified provider, worker, session, key, response, or fallback may be
accepted.

Do not add plaintext inference modes, TLS fallbacks, server-side prompt
construction, backend system-message injection, or plaintext message caches.
The local proxy owns model-message construction, attestation verification,
provider-E2EE encryption and decryption, and local credential handling.

Remote services may receive only provider ciphertext, attestation metadata,
run metadata, aggregate usage, and other non-message-secret operational
metadata. Any path that would send live prompt text, conversation history,
assistant deltas, or completion text through the backend must fail closed.

Tests and live scripts that exercise provider inference must use the selected
provider's attested E2EE protocol. Any non-E2EE provider helper, fixture, or
example is a bug unless it explicitly tests rejection of legacy or plaintext
input.
