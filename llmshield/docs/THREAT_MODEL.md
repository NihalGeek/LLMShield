# Threat model

## Scope and assets

A single-user Windows training lab, bound to `127.0.0.1`. Assets are synthetic vault canaries, protected instruction markers, admin-classified incident notes, analyst permissions, assessment integrity, availability and the SQLite evidence trail. No real secrets or production records belong in this project.

## Actors and trust boundaries

The local operator is trusted to configure the model and access full audit evidence. The prompt author, retrieved context and model output are untrusted. Boundaries are browser → API; request/context → provider; model proposal → tool dispatcher; tool result → response; and evidence → report HTML. An analyst role is fixed in Python. There is no real identity federation or multi-user login.

A malicious local user who can edit Python, SQLite or test cases is outside the protection offered by this lab. Loopback is a network boundary, not authentication. Model weights and the local Ollama installation are trusted operator-managed components.

## Lightweight STRIDE analysis

| Threat | Example in this lab | Implemented control | Residual risk |
|---|---|---|---|
| Spoofing | Prompt says “I am admin” | Role comes from Python; API rejects role fields | No production authentication; any local operator can select vulnerable mode |
| Tampering | Retrieved log claims system priority | Context-aware input checks; tool/output enforcement | Rule evasion, paraphrases, indirect semantic attacks |
| Repudiation | Operator disputes a tool execution | Timestamped JSONL, immutable case snapshots, persisted traces | Local files can be edited; logs are not signed or append-only |
| Information disclosure | Vault, system marker or private incident leaked | Record authorization plus literal/normalized/one-level Base64 output inspection | Novel encodings and semantic disclosure; secrets intentionally placed in prompt for the lab |
| Denial of service | Huge prompt or concurrent inference | Input/schema limits, request body cap, one active job, inference timeout | Local model can consume CPU/RAM; no per-user quota or inference cancellation |
| Elevation of privilege | Model proposes admin_reset as analyst | Independent role/tool/resource policy, default deny | Vulnerable mode intentionally bypasses policy; tools still synthetic |
| Browser-origin abuse | Website sends local mutation requests | Exact Origin check, custom header, no CORS, Host allowlist, CSP | A local process can set headers; read-only API is an operator interface |
| Report injection | Model/test name contains HTML script | Jinja autoescaping; UI builds text nodes, never raw HTML | Dependency/browser vulnerabilities not assessed |

## Abuse cases covered

Direct instruction overrides; hostile retrieved notes; quoted-command confusion; system extraction by diagnostic/JSON pretext; plain and Base64 secret requests; restricted incident reads; role-play and emergency audit-policy exceptions; unauthorized admin operations; forged system delimiters; ambiguous authority claims.

## Important design decisions

- The provider only proposes actions. `authorize()` validates role, tool and resource before guarded execution.
- Tool names are dispatched from a closed Python allowlist. No shell, arbitrary file access, dynamic evaluation or arbitrary network tool exists.
- The Ollama endpoint is fixed numeric loopback, with redirects and proxy inheritance disabled. Cloud model names/metadata are rejected. The application does not download models.
- Protected raw responses exist in the local assessment audit so failures can be explained. Public chat returns filtered text and minimal tool metadata, excluding raw responses and results. Guardrail diagnostics do not repeat protected canaries.
- Guarded mode is the chat default. Selecting vulnerable mode is an explicit local lab feature.
- The CLI and web service are intended to be used one at a time against one database. API startup marks previously running records interrupted; stop the service before CLI assessments against the same data directory.

## Residual risk and production changes

These rules do not solve prompt injection generally. The mock is a deliberately gullible simulator. Qwen observations cover a small single-turn suite, one inference configuration and the installed model only. Canary detectors are not general DLP. A model may falsely claim a tool ran; only dispatcher traces establish execution. Exact output/refusal markers can miss paraphrases, which receive REVIEW.

A production design would remove secrets from model context, introduce authenticated identities and resource-level retrieval authorization, isolate tools, require human approval for consequential actions, protect audit integrity, evaluate multi-turn and retrieval attacks, and add broader detection and monitoring. It would never expose the vulnerable mode.
