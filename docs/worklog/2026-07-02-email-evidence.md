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

## Follow-Up Candidates

- POP3/POP3S and semantic mailbox read modeling.
- DKIM/SPF/DMARC, retry queues, NDRs, and Exchange-native logs.
- Deeper evaluation scoring for route/content/artifact consistency beyond the
  current basic checks.
