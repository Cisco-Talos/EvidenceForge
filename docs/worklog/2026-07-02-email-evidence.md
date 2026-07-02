# Email Evidence Integration

## Summary

Implemented V1 on-prem email evidence on branch `codex/email-evidence-design`.
The feature adds explicit `environment.email` topology, typed `email_message`
and `email_read` storyline events, canonical `EmailContext`/`SmtpContext`, SMTP
route planning, Zeek `smtp.json`, MIME-linked `files.json`, `.eml` artifact
generation, `EMAIL_ARTIFACTS.json`, validation, parser registration, evaluator
consistency checks, and repo-local docs/skill reference updates.

The second V1 pass filled the planned gaps: deterministic scenario-relative
email corpus loading, corpus-backed storyline/background content, explicit and
automatic opaque TLS mailbox reads, MIME-aware artifact rendering, plaintext
SMTP FUID linkage to `files.log`, STARTTLS visibility reduction, richer
internal/inbound/outbound background mail, and validation for corpus/read/MIME
error paths.

## Coverage Notes

- Unit/integration email coverage lives in `tests/unit/test_email_evidence.py`.
- The full non-coverage suite passed after implementation:
  `4622 passed, 41 skipped`.
- Ruff lint and format checks passed across the repository.

## 2026-07-02 Data-Driven Identity Pool Refactor

Moved email and related generated identity pools out of Python literals and
into overlay-aware `config/activity/*.yaml` files: baseline email domains and
local-parts, reserved public mail replacement domains, omitted storyline
external IP pools, suspicious-benign DNS/connection targets, and command
URL/host placeholder pools. Added cached loaders, `validate-config` schemas,
`eforge info identity_pools`, docs, repo-local skill references, and focused
unit/install-skill coverage.

Verification for this pass:

- `uv run pytest tests/unit/test_identity_pools.py tests/unit/test_install_skills.py --no-cov`
- `uv run pytest tests/unit/test_email_evidence.py tests/unit/test_activity_helpers.py tests/unit/test_application_catalog.py --no-cov`
- `uv run eforge validate-config`
- `uv run eforge info identity_pools --json`
- `uv run ruff check .`
- `uv run ruff format --check .`

Full `uv run pytest --no-cov` currently fails on 10 pre-existing standalone
tests unrelated to this refactor, including process spacing, DNS/FQDN/Kerberos
connection expectations, explicit proxy visibility, local_orig/local_resp, and
Zeek files timing. Two sampled failures reproduce when run alone.

## Follow-Up Candidates

- POP3/POP3S and semantic mailbox read modeling.
- DKIM/SPF/DMARC, retry queues, NDRs, and Exchange-native logs.
- Deeper evaluation scoring for route/content/artifact consistency beyond the
  current basic checks.
