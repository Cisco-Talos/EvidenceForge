# Monotonic Blind Loop Experiment

## Purpose

This branch tests a stricter assessment-loop policy on
`scenarios/iteration-test-expanded/` before changing the `eforge-assess` skill.
The goal is to keep accepted EvidenceForge realism-loop checkpoints
monotonically improving with respect to standalone blind-review
synthetic-confidence scores. Lower synthetic-confidence scores are better.

## Branch Policy

- Run the experiment on `codex/monotonic-blind-loop-experiment`, branched from
  `dev`.
- Do not push unless the experiment is worth preserving.
- Keep all protocol notes, loop artifacts, rejected-attempt artifacts, and any
  candidate fixes on this branch so the entire experiment can be discarded by
  deleting or abandoning the branch.
- Do not update `/Users/dabianco/.codex/skills/eforge-assess/SKILL.md` during
  the experiment.

## Scoring Policy

- Use only standalone blind reviewer `synthetic-confidence score` values.
- Do not run deliberation for this experiment, even when reviewers disagree or
  the reviewer score spread is large.
- Compute the decision score as the average of available standalone reviewer
  synthetic-confidence scores.
- If any reviewer omits a synthetic-confidence score, treat the attempt as
  invalid and rerun or replace that reviewer. Do not substitute verdict
  confidence.
- Automated eval remains a guardrail only. Do not accept or reject a candidate
  because the automated score improved or declined unless it fails the normal
  parser/acceptance guardrails.

## Acceptance Rule

Each candidate loop starts from the latest accepted checkpoint and must satisfy:

```text
candidate_average_synthetic_confidence < accepted_average_synthetic_confidence
```

If the candidate average is equal to or higher than the accepted average, reject
the candidate fix and revert it. A stricter margin can be added later if reviewer
variance makes the strict comparison too noisy, but the initial experiment uses
the simple strict-decrease rule.

Do not promote a candidate that introduces a new candidate-caused hard
contradiction, even if the average score technically decreases.

## Artifact Layout

Accepted loops stay in the normal canonical loop series:

```text
scenarios/iteration-test-expanded/blind-test/loop-N/
```

Rejected attempts stay outside the dashboard trend:

```text
scenarios/iteration-test-expanded/blind-test/rejected/attempt-N-a/
scenarios/iteration-test-expanded/blind-test/rejected/attempt-N-b/
```

Dashboards and rolling score tables should use accepted `loop-N/scores.json`
artifacts only. Rejected attempts are preserved for diagnosis but are not part
of the monotonic accepted-loop trend.

## Loop Procedure

For each candidate attempt:

1. Confirm the current branch and accepted baseline commit.
2. Read the latest accepted loop report and recent recurrence context.
3. Select one or two highest-leverage family-level targets.
4. Write the family contract before coding.
5. Implement the fix at the owning layer, with focused tests and probes.
6. Run relevant focused tests, `uv run ruff check .`, and
   `uv run ruff format --check .`.
7. Commit the candidate fix before regenerating and reviewing the output.
8. Regenerate, evaluate, and run the standalone blind panel.
9. Save candidate results in a rejected-attempt directory until accepted.
10. Compare the candidate standalone blind average to the latest accepted
    average.
11. If accepted, promote artifacts to the next `loop-N/`, update dashboard and
    worklog notes, and keep the candidate commit.
12. If rejected, preserve the rejected reports, revert the candidate commit, and
    select a new target from the latest accepted state plus rejected-review
    evidence.

## Attempt Log

Starting accepted baseline: `scenarios/iteration-test-expanded/blind-test/loop-59`.

- Baseline standalone blind average: 38.25
- Baseline reviewer scores: Threat Hunter 36, Detection Engineer 62, Network
  Forensics 28, Host/EDR 27
- Automated eval is ignored for acceptance, but loop 59 passed at 95.90845223387653
  over 96,389 records.

### Attempt 60-a — Rejected

- Candidate target: loop-59 Detection Engineer P1 ASA connection-ID hidden-volume
  model. The prior report found 6,048 built TCP/UDP connection IDs with adjacent
  visible gaps always in the 1-5 range.
- Candidate commit: `3b43c998 fix: add ASA hidden connection-id volume`
- Owning layer: Cisco ASA source-native emitter
- Family contract: visible ASA Built/Teardown IDs remain monotonic and paired,
  but adjacent visible IDs include deterministic hidden-volume gaps instead of
  exposing a tiny bounded synthetic increment range.
- Verification before review:
  - `uv run pytest --no-cov tests/unit/test_cisco_asa_emitter.py`
  - `uv run ruff check src/evidenceforge/generation/emitters/cisco_asa.py tests/unit/test_cisco_asa_emitter.py`
  - `uv run ruff format --check src/evidenceforge/generation/emitters/cisco_asa.py tests/unit/test_cisco_asa_emitter.py`
  - `uv run pytest --no-cov` before the same-second ordering correction: 4,875
    passed, 19 skipped
  - Regenerated and evaluated `scenarios/iteration-test-expanded/`: PASS,
    95.90845223387653, 96,389 records
  - Hard probe: 6,048 Built IDs, 0 nonpositive adjacent Built gaps, 194 distinct
    adjacent gaps, max gap 231, 6 expected dangling Built IDs at collection edge
- Standalone blind scores:
  - Threat Hunter: 45
  - Detection Engineer: 43
  - Network Forensics: 56
  - Host/EDR: 32
  - Average: 44.0
- Decision: rejected because 44.0 is not lower than the accepted baseline 38.25.
- Revert commit: `512a8304 Revert "fix: add ASA hidden connection-id volume"`
- Artifacts: `scenarios/iteration-test-expanded/blind-test/rejected/attempt-60-a/`

Carry-forward findings from the rejected blind reviews:

- Detection Engineer: eCAR FLOW timing repeatedly lags Zeek/syslog transport
  evidence, including SSH sessions and short DNS flows.
- Network Forensics: repeated `mail-fin.meridianhcs.com` proxy-origin path
  mismatch; DNS answers internal `10.10.2.27`, but proxy-origin TLS/ASA goes to
  `54.230.228.12`.
- Threat Hunter: one SSH tuple has endpoint session close roughly 15 minutes
  before Zeek TCP close, plus repeated rsyslog reload and Sysmon static registry
  texture.
- Host/EDR: endpoint telemetry remains mostly realistic; minor bash-history
  timestamp backstep and filtered Windows Security EventRecordID gaps.

### Attempt 60-b — Rejected

- Candidate target: rejected attempt 60-a Network Forensics finding that repeated
  `mail-fin.meridianhcs.com` proxy-origin TLS/ASA traffic went to public
  `54.230.228.12` while DNS answered internal `10.10.2.27`.
- Candidate commit: `5fc56088 fix: align proxy origin with scenario DNS identity`
- Owning layer: explicit proxy transaction action bundle plus DNS/identity
  handoff.
- Family contract: when the proxy bundle owns origin egress for a named host, the
  proxy-origin connection must use the same scenario/email-owned IP identity that
  forced DNS evidence exposes for that host. Scenario network identities and
  configured email DNS ownership override preserved public package/stable
  fallback IPs; generic fallback resolution remains preserved when no scenario
  or email identity owns the hostname.
- Verification before review:
  - `uv run pytest --no-cov tests/unit/test_explicit_proxy.py`: 80 passed
  - `uv run ruff check .`
  - `uv run ruff format --check .`
  - `uv run pytest --no-cov`: 4,876 passed, 19 skipped
  - Regenerated and evaluated `scenarios/iteration-test-expanded/`: PASS,
    95.90804086572041, 96,399 records
  - Hard probe for `mail-fin.meridianhcs.com`: DNS answers remain
    `10.10.2.27`/AAAA, SSL destinations are 25/25 on `10.10.2.27`, ASA matches
    are 20/20 on `10.10.2.27`, and `public_ssl_mismatch_count` is 0.
- Standalone blind scores:
  - Threat Hunter: 34
  - Detection Engineer: 63
  - Network Forensics: 24
  - Host/EDR: 46
  - Average: 41.75
- Decision: rejected because 41.75 is not lower than the accepted baseline 38.25.
- Revert commit: `315744fb Revert "fix: align proxy origin with scenario DNS identity"`
- Artifacts: `scenarios/iteration-test-expanded/blind-test/rejected/attempt-60-b/`

Carry-forward findings from the rejected blind reviews:

- Detection Engineer: Postfix delivery `delays=` fields are formulaic, queue
  lifecycle ordering can place `qmgr queue active` before `cleanup message-id`,
  and one `NOQUEUE: reject: RCPT` row uses an invalid `220 2.0.0 TLS go ahead`
  status.
- Host/EDR: repeated Linux `sudo` PAM sessions open `admin(uid=1001)` as
  `by (uid=0)` without matching `sudo ... COMMAND=` lines, plus one
  `Accepted publickey` line lacks key type/fingerprint.
- Threat Hunter and Network Forensics: NTP visibility is sparse, DHCP is
  slightly too clean, and collection/profile mail-artifact declarations may not
  match the neutral copied dataset.

### Attempt 60-c — Rejected

- Candidate target: rejected attempt 60-b Detection Engineer findings in Postfix
  syslog receive/delivery/reject evidence.
- Candidate commit: `b89e744a fix: vary Postfix mail syslog lifecycles`
- Owning layer: `ActivityGenerator` Postfix receive/delivery/reject syslog
  helpers.
- Family contract: Postfix queue lifecycle rows must preserve source-native
  ordering, `delays=` components should vary per queue/recipient, and rejected
  RCPT rows must render a 4xx/5xx SMTP reply rather than reusing unrelated
  STARTTLS success text.
- Verification before review:
  - `uv run pytest --no-cov tests/unit/test_email_evidence.py -k "postfix_delay_components or linux_mail_server_emits_postfix_syslog_lifecycle or rejected_email_stops"`:
    3 passed
  - `uv run pytest --no-cov tests/unit/test_email_evidence.py`: 37 passed
  - `uv run ruff check .`
  - `uv run ruff format --check .`
  - `uv run pytest --no-cov`: 4,875 passed, 19 skipped
  - Regenerated and evaluated `scenarios/iteration-test-expanded/`: PASS,
    95.90845223387653, 96,388 records
  - Hard probe: 33 complete Postfix lifecycles, 33 ordered, zero ordering
    violations, zero bad RCPT reject replies, 45 distinct `delays=` ratio
    shapes, and zero legacy fixed-ratio tuples.
- Standalone blind scores:
  - Threat Hunter: 43
  - Detection Engineer: 47
  - Network Forensics: 26
  - Host/EDR: 47
  - Average: 40.75
- Decision: rejected because 40.75 is not lower than the accepted baseline
  38.25.
- Revert commit: `a966eb1e Revert "fix: vary Postfix mail syslog lifecycles"`
- Artifacts: `scenarios/iteration-test-expanded/blind-test/rejected/attempt-60-c/`

Carry-forward findings from the rejected blind reviews:

- Detection Engineer and Threat Hunter: `COLLECTION_PROFILE.json` advertises
  `mail_artifacts` / `eml` even though the neutral review dataset contains only
  rendered logs.
- Detection Engineer: Zeek and ASA contain post-window connection/build starts
  after the collection profile's primary window end.
- Threat Hunter: DC Security log-clear semantics are ambiguous because
  EventRecordIDs continue high after Event ID 1102.
- Host/EDR: Sysmon `ProcessGuid` and process hash texture look mechanically
  bucketed across Windows hosts, and one RDP session lacks expected source-side
  companion evidence.
- Network Forensics: remaining signals are low-impact long-tail texture concerns
  around collection-window neatness and repeated HTTP/TLS palettes.

### Attempt 60-d — Accepted

- Candidate target: rejected attempt 60-c Detection Engineer and Threat Hunter
  finding that the neutral review dataset's `COLLECTION_PROFILE.json` advertised
  `mail_artifacts` / `email_artifacts` / `eml` even though reviewers were given
  only the rendered log tree.
- Candidate commit: `8ccc066b fix: limit collection profile to rendered logs`
- Owning layer: collection profile generation for the rendered review log tree.
- Family contract: `COLLECTION_PROFILE.json` inside the rendered review tree
  describes only files present in that tree. Packaged artifacts remain documented
  by the package-root artifact manifest instead of the log-tree collection
  profile.
- Verification before review:
  - `uv run pytest --no-cov tests/unit/test_collection_profile.py tests/unit/test_engine.py -k "collection_profile or generate_baseline_only_writes_ground_truth_and_manifest"`:
    2 passed
  - `uv run ruff check .`
  - `uv run ruff format --check .`
  - `uv run pytest --no-cov`: 4,875 passed, 19 skipped
  - `uv run eforge validate scenarios/iteration-test-expanded/scenario.yaml`:
    valid with the known 26 warnings
  - Regenerated and evaluated `scenarios/iteration-test-expanded/`: PASS,
    95.90845223387653, 96,389 records
  - Hard probe: zero `mail_artifacts` families, zero `email_artifacts` formats,
    zero `eml` formats, zero `.eml` files inside the review tree, package-root
    `ARTIFACTS_MANIFEST.json` present, and 30 package-root `.eml` artifacts.
- Panel note: the first attempt-60-d panel was invalidated because the shared
  temporary review copy was contaminated during review. The accepted score uses
  a clean rerun with four separate read-only temporary copies.
- Standalone blind scores:
  - Threat Hunter: 18
  - Detection Engineer: 35
  - Network Forensics: 24
  - Host/EDR: 72
  - Average: 37.25
- Decision: accepted because 37.25 is lower than the accepted baseline 38.25.
- Artifacts: `scenarios/iteration-test-expanded/blind-test/loop-60/`
- Stop condition: user instructed to stop after this loop; do not start 60-e.

Carry-forward findings if the experiment resumes:

- Host/EDR: Linux shell pipeline process lifecycles are impossible in multiple
  bash/eCAR examples because upstream `cat` processes outlive downstream
  `head`, `grep`, or `cut` consumers by many seconds.
- Host/EDR: short utility command durations such as `whoami` and simple
  `/proc` reads remain too long, likely sharing the command-duration owner with
  the pipeline lifecycle issue.
- Detection Engineer: proxy access timestamp semantics remain ambiguous when
  proxy access rows precede proxy-origin DNS/TLS by a few seconds.
- Detection Engineer: DC Security Event ID 1102 collection/export semantics
  remain ambiguous because later Security events continue with high
  EventRecordIDs.
- Network Forensics and Detection Engineer: NTP and OCSP long-tail collection
  texture remain weak but low impact.

### Loop 61 — Combined Fix-Forward Review

After concluding that the monotonic rejection rule was probably not useful, loop
61 re-applied the previously reverted 60-a, 60-b, and 60-c fixes together on top
of accepted loop 60 and ran a fresh standalone blind panel.

- Re-applied commits:
  - `00d8dd8a fix: add ASA hidden connection-id volume`
  - `564c4848 fix: align proxy origin with scenario DNS identity`
  - `c883a30d fix: vary Postfix mail syslog lifecycles`
- Verification before review:
  - `uv run pytest --no-cov -q tests/unit/test_cisco_asa_emitter.py tests/unit/test_explicit_proxy.py tests/unit/test_email_evidence.py`:
    177 passed
  - `uv run ruff check .`
  - `uv run ruff format --check .`
  - `uv run pytest --no-cov -q`: 4,880 passed, 19 skipped
  - `uv run eforge validate scenarios/iteration-test-expanded/scenario.yaml`:
    valid with the known 26 warnings
  - Regenerated and evaluated `scenarios/iteration-test-expanded/`: PASS,
    95.90804086572041, 96,398 records
  - Combined hard probe: ASA ID gaps remain varied, `mail-fin.meridianhcs.com`
    proxy-origin TLS/ASA traffic stays on `10.10.2.27`, Postfix lifecycles are
    ordered with varied `delays=` ratios, and the rendered review tree still
    excludes email artifact declarations.
- Standalone blind scores:
  - Threat Hunter: 36
  - Detection Engineer: 32
  - Network Forensics: 64
  - Host/EDR: 36
  - Average: 42.0
- Monotonic comparison: not accepted by the old monotonic rule because 42.0 is
  not lower than accepted loop 60's 37.25.
- Practical interpretation: the original 60-a/b/c findings did not recur as
  primary blind-review findings, which supports keeping these as real local
  improvements. The worse average was driven mainly by a new Network Forensics
  finding about Zeek TLSv1.2 `resumed:true` rows carrying full-handshake-style
  `ssl_history` without cert/file/x509 artifacts.
- Artifacts: `scenarios/iteration-test-expanded/blind-test/loop-61/`

Carry-forward findings after loop 61:

- Network Forensics: fix the Zeek TLS resumption contract first. TLSv1.2 resumed
  sessions should use abbreviated-session semantics; full-handshake histories
  should be `resumed:false` and emit consistent `cert_chain_fuids`, `files`, and
  `x509` rows.
- Threat Hunter: normalize APP-INT SSH publickey syslog rendering so pivotal
  root scp sessions include key type/fingerprint consistently with same-host
  peer sessions.
- Threat Hunter: close the DB-PROD root SSH session visibly when Zeek marks the
  transport `SF` inside the window, or model a coherent endpoint collection gap.
- Threat Hunter and Host/EDR: reduce repeated Linux admin/healthcheck command
  texture and make short command/process lifetimes more command-aware.
- Network Forensics: add plausible response-interval constraints for same-UID
  HTTP keep-alive transaction depth after large responses.
