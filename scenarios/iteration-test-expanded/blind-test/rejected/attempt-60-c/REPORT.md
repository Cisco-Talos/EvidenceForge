# Rejected Attempt 60-c

Rejected. The standalone blind-review average was 40.75, worse than the accepted loop-59 baseline of 38.25. Per the experiment protocol, no deliberation was run and the candidate fix is being reverted.

## Candidate

- Target finding: rejected attempt 60-b Detection Engineer Postfix/syslog source-native issues
- Candidate commit: `b89e744a fix: vary Postfix mail syslog lifecycles`
- Owning layer: `ActivityGenerator` Postfix receive/delivery/reject syslog helpers
- Family contract: Postfix queue lifecycle rows must preserve source-native ordering, `delays=` components should vary per queue/recipient, and rejected RCPT rows must render a 4xx/5xx SMTP reply rather than reusing unrelated STARTTLS success text.

## Verification

- `uv run pytest --no-cov tests/unit/test_email_evidence.py -k "postfix_delay_components or linux_mail_server_emits_postfix_syslog_lifecycle or rejected_email_stops"`: 3 passed
- `uv run pytest --no-cov tests/unit/test_email_evidence.py`: 37 passed
- `uv run ruff check .`: passed
- `uv run ruff format --check .`: passed
- `uv run pytest --no-cov`: 4,875 passed, 19 skipped
- `uv run eforge validate scenarios/iteration-test-expanded/scenario.yaml`: valid with the scenario's existing 26 warnings
- `uv run eforge generate scenarios/iteration-test-expanded/scenario.yaml --output scenarios/iteration-test-expanded/data --force`: complete
- `uv run eforge eval scenarios/iteration-test-expanded/data --scenario scenarios/iteration-test-expanded/scenario.yaml`: PASS, 95.90845223387653, 96,388 records
- Hard probe: 33 complete Postfix lifecycles, 33 ordered, zero ordering violations, zero bad RCPT reject replies, 45 distinct `delays=` ratio shapes, and zero legacy fixed-ratio tuples.

## Standalone Blind Scores

| Reviewer | Assessment | Verdict confidence | Synthetic-confidence |
|---|---|---:|---:|
| Threat Hunter | Inconclusive | 66 | 43 |
| Detection Engineer | Synthetic | 58 | 47 |
| Network Forensics | Real | 62 | 26 |
| Host/EDR | Inconclusive | 62 | 47 |

Average synthetic-confidence: 40.75.

## Decision

Rejected because `40.75 >= 38.25`. Automated eval is ignored for the monotonic decision except as a guardrail.

## Carry-Forward Findings

- Detection Engineer and Threat Hunter: `COLLECTION_PROFILE.json` advertises `mail_artifacts` / `eml` even though the neutral review dataset contains only rendered logs.
- Detection Engineer: Zeek and ASA contain post-window connection/build starts after the collection profile's primary window end.
- Threat Hunter: DC Security log-clear semantics are ambiguous because EventRecordIDs continue high after Event ID 1102.
- Host/EDR: Sysmon `ProcessGuid` and process hash texture look mechanically bucketed across Windows hosts, and one RDP session lacks expected source-side companion evidence.
- Network Forensics: remaining signals are low-impact long-tail texture concerns around collection-window neatness and repeated HTTP/TLS palettes.
