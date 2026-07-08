# Rejected Attempt 60-b

Rejected. The standalone blind-review average was 41.75, worse than the accepted loop-59 baseline of 38.25. Per the experiment protocol, no deliberation was run and the candidate fix is being reverted.

## Candidate

- Target finding: rejected attempt 60-a Network Forensics `mail-fin.meridianhcs.com` proxy-origin DNS/TLS/ASA identity mismatch
- Candidate commit: `5fc56088 fix: align proxy origin with scenario DNS identity`
- Owning layer: explicit proxy transaction action bundle plus DNS/identity handoff
- Family contract: proxy-origin egress for a named host must use the same scenario/email-owned IP identity that forced DNS evidence exposes for that host. Scenario network identities and configured email DNS ownership override preserved public fallback IPs; generic fallback resolution remains preserved when no scenario or email identity owns the hostname.

## Verification

- `uv run pytest --no-cov tests/unit/test_explicit_proxy.py`: 80 passed
- `uv run ruff check .`: passed
- `uv run ruff format --check .`: passed
- `uv run pytest --no-cov`: 4,876 passed, 19 skipped
- `uv run eforge validate scenarios/iteration-test-expanded/scenario.yaml`: valid with the scenario's existing 26 warnings
- `uv run eforge generate scenarios/iteration-test-expanded/scenario.yaml --output scenarios/iteration-test-expanded/data --force`: complete
- `uv run eforge eval scenarios/iteration-test-expanded/data --scenario scenarios/iteration-test-expanded/scenario.yaml`: PASS, 95.90804086572041, 96,399 records
- Hard probe: `mail-fin.meridianhcs.com` DNS answers remain internal, SSL destinations are 25/25 on `10.10.2.27`, ASA matches are 20/20 on `10.10.2.27`, and `public_ssl_mismatch_count` is 0.

## Standalone Blind Scores

| Reviewer | Assessment | Verdict confidence | Synthetic-confidence |
|---|---|---:|---:|
| Threat Hunter | Real | 58 | 34 |
| Detection Engineer | Synthetic | 67 | 63 |
| Network Forensics | Real | 72 | 24 |
| Host/EDR | Inconclusive | 64 | 46 |

Average synthetic-confidence: 41.75.

## Decision

Rejected because `41.75 >= 38.25`. Automated eval is ignored for the monotonic decision except as a guardrail.

## Carry-Forward Findings

- Detection Engineer: Postfix delivery `delays=` fields are formulaic, queue lifecycle ordering can place `qmgr queue active` before `cleanup message-id`, and one `NOQUEUE: reject: RCPT` row uses an invalid `220 2.0.0 TLS go ahead` status.
- Host/EDR: repeated Linux `sudo` PAM sessions open `admin(uid=1001)` as `by (uid=0)` without matching `sudo ... COMMAND=` lines, plus one `Accepted publickey` line lacks key type/fingerprint.
- Threat Hunter and Network Forensics: NTP visibility is sparse, DHCP is slightly too clean, and collection/profile mail-artifact declarations may not match the neutral copied dataset.
