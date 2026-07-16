# Standards-Valid Cryptographic Protocol Payload Contract

## Scope

- Branch: `codex/cryptographic-protocol-payload-contract`
- Base: `origin/dev` at `7742f667` (includes merged PR #362)
- Target: draft PR to `dev`
- No feature-branch version bump

This effort replaces synthetically shaped certificate-adjacent payloads with
deterministic, standards-valid canonical plans. It uses the existing assessment
findings as diagnostic evidence and reserves one `iteration-test-expanded` run
plus one independent blind panel for final acceptance.

## Milestone 1 — Canonical material and TLS presentation

- Added immutable certificate-authority, certificate-identity, TLS-presentation,
  DKIM-key, and OCSP-transaction types.
- Added `CryptographicMaterialRegistry` with deterministic RSA/ECDSA SPKI,
  certificate identity, DKIM key, and OCSP status ownership.
- Added `TlsCertificatePlanner`; direct TLS, proxy-origin TLS, and SMTP STARTTLS
  now share stable certificate identity and chain composition.
- Kept `SslContext`, `X509Context`, and chain fields as validated compatibility
  projections.
- Default presentations omit self-signed trust anchors.
- Added `cryptography` as a runtime dependency with `uv`.

## Milestone 2 — Standards-valid OCSP

- Added `OcspTransactionPlanner` and `OcspTransactionActionBundle`.
- Requests use `OCSPRequestBuilder.add_certificate_by_hash`, exact issuer-name
  DER, issuer subject-public-key bits, leaf serial, and configured SHA-1/SHA-256.
- Every request is DER round-tripped before full Base64 and percent encoding.
- HTTP, file-transfer, and OCSP contexts project one frozen transaction plan.
- OCSP DNS and transport use the canonical DNS/network/proxy contracts.
- Generic proxy synthesis cannot select OCSP payload templates; the templates
  remain available as source-native classification metadata.
- Ordinary actively served certificates resolve to `good`; non-good status is
  only available through explicit certificate-status profiles.

## Milestone 3 — DKIM and rendered enforcement

- Automatic/background DKIM answers use selector-stable RSA SPKI from the
  registry.
- Typed scenario DKIM answers are rejected unless `p=` contains parseable RSA
  DER; raw-log escape hatches are unchanged.
- Added rendered evaluator probes for DKIM parsing, OCSP request/response
  agreement, TLS presentation stability, and default trust-anchor omission.
- Retained legacy OCSP request-shape fields as accepted deprecated inputs; they
  no longer influence generated DER.

## Validation evidence

- Focused cryptographic, TLS/X.509, OCSP, DNS/DKIM, proxy, email, evaluator, and
  compatibility tests passed.
- Ruff check and format gates passed during implementation.
- Final complete non-slow suite: `4984 passed, 19 skipped` in 303.15 seconds.
- One unrelated install-skills assertion was made terminal-width independent
  because Rich could wrap `.codex/skills` across a newline.
- The first expanded eval exposed a probe-only source-field mismatch: rendered
  Zeek OCSP uses `hashAlgorithm`/`issuerNameHash`/`issuerKeyHash`/`serialNumber`,
  while the evaluator initially read compatibility snake_case names. The probe
  now accepts the source-native names, and its fixture uses those names.
- Final expanded evaluation: 80,054 records, score 95.5254, all hard acceptance
  criteria passed (parseability 100, plausibility 94.4031, causality 89.6306,
  timing 97.5849).
- Rendered probes: 46/46 OCSP GET requests parse and match their response hashes
  and serials; all 46 statuses are `good`; zero FUIDs are reused across sensors.
- Rendered DKIM probes: 11/11 keys parse as 2048-bit RSA SPKI with exponent 65537
  and zero selector-identity instability.
- Rendered TLS probes: 402 complete presentations, zero unstable compositions,
  and zero transmitted self-signed trust anchors.

## Blind acceptance panel

- Standalone verdicts and synthetic-confidence scores:
  - Threat Hunter: Synthetic, verdict confidence 94, synthetic-confidence 88.
  - Detection Engineer: Synthetic, verdict confidence 95, synthetic-confidence 91.
  - Network Forensics: Synthetic, verdict confidence 94, synthetic-confidence 89.
  - Host/EDR Forensics: Real, verdict confidence 84, synthetic-confidence 27.
- The standalone average was 73.75 (`likely synthetic`). Verdict disagreement
  and the 64-point spread triggered the required deliberation.
- After cross-specialty deliberation, the final synthetic-confidence scores were
  95, 96, 95, and 86, averaging 93.0 (`confidently synthetic`). The Host/EDR
  reviewer changed its verdict after distinguishing strong referential identity
  from implausible process/module and process/file semantic ownership.
- No reviewer found a defect in the new OCSP request construction, DKIM key
  material, TLS presentation stability, or trust-anchor policy. Network
  Forensics explicitly described TLS, OCSP, certificate, DNS, and proxy handling
  as strengths.
- The decisive remaining whole-corpus findings belong to other owning layers:
  Windows module/file semantic ownership, Zeek ICMP pseudo-port semantics, ASA
  PAT creation ordering, NTP wire-value semantics, durable PKINIT certificate
  lifecycle, and bounded session/thread distributions.

Assessment artifacts are under
`scenarios/iteration-test-expanded/blind-test/cryptographic-protocol-payload-contract/`.
