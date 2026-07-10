# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting for this repository so maintainers can investigate
without exposing users before a fix is available.

Include the affected version, reproduction steps, expected impact, and any
evidence needed to validate the report. Never include live Axiom credentials,
wallet keys, prompts, model responses, or other user secrets.

## Inference boundary

AxiomIO has no plaintext inference fallback. Reports involving attestation,
model-key acceptance, provider E2EE, local credential handling, or unintended
message disclosure are treated as security-sensitive.
