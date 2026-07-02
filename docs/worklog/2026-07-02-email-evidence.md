# Email Evidence Integration

## Summary

Implemented V1 on-prem email evidence on branch `codex/email-evidence-design`.
The feature adds explicit `environment.email` topology, typed `email_message`
storyline events, canonical `EmailContext`/`SmtpContext`, SMTP route planning,
Zeek `smtp.json`, `.eml` artifact generation, `EMAIL_ARTIFACTS.json`, validation,
parser registration, and repo-local docs/skill reference updates.

## Coverage Notes

- Unit/integration email coverage lives in `tests/unit/test_email_evidence.py`.
- The full non-coverage suite passed after implementation:
  `4618 passed, 41 skipped`.
- Ruff lint and format checks passed across the repository.

## Follow-Up Candidates

- MIME multipart richness beyond basic attachment metadata.
- POP3/POP3S and semantic mailbox read modeling.
- DKIM/SPF/DMARC, retry queues, NDRs, and Exchange-native logs.
- Deeper evaluation scoring for route/content/artifact consistency.
