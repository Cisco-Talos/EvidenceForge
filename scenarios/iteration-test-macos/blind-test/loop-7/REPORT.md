# Iterative assessment loop 7

## Outcome

This loop fixed two source-family defects selected from loop 6.

- **Runtime executable content identity:** `RuntimeContentIdentityManager` now assigns an unresolved executable a positive, deterministic size from a platform-specific profile before it creates the canonical content and binary identity. Explicit sizes and observed Mac file sizes remain authoritative; unknown non-executable file size remains zero/unknown. This is a family-level fix across runtime executable publications, with configuration loading and validation. Behavior revision 406 records both loop 7 behavior changes.
- **Failed Linux SSH authentication ordering:** the source timing planner now uses the exact admitted inbound TCP/22 eCAR FLOW as a lower bound for remote failed-SSH LOGIN evidence, just as it already did for modeled SSH sessions. This is shared by baseline and authored failed-logon calls; no eCAR row is rewritten after planning.

Focused tests passed: 94 runtime-content and source-timing tests. Ruff check and format checks passed for changed files. `eforge validate-config` reported 0 errors and 1 existing warning about the Chrome GPU helper; generation-behavior manifest validation passed at revision 406. Scenario validation remained valid with its existing noise-to-signal warning and informational notes.

Fresh generation completed at `/private/tmp/eforge-iteration-test-macos-loop-7`; the authoritative bundle contains 141,187 records. One JSON evaluation passed at **96.880514** (parseability 100, plausibility 96.7070, causality 97.0009, timing 92.2677). All applicable hard criteria passed.

## Family probes

The direct output probe in `root-cause-probes.json` found:

- **8/8** failed SSH eCAR logins matched their exact source tuple from the corresponding sshd syslog record and an inbound eCAR FLOW. Each auth appeared **11–98 ms after** that FLOW; there were no inversions.
- Both previously flagged Sysmon Event 1 images, `curl.exe` on WS-AJOHNSON-01 and `DeviceSyncSvc.exe` on DC-01, now carry non-empty SHA-1, MD5, and SHA-256 values.
- A data-only copy of **120 files** was SHA-256 verified against the bundle manifest before reviewers received it. Reviewer access was limited to that copy and the assessment instructions.

## Independent expert panel

| Expert | Verdict | Verdict confidence | Synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Synthetic | 63 | 64 |
| Detection Engineer | Synthetic | 78 | 62 |
| Network Forensics | Inconclusive | 67 | 37 |
| Host/EDR Forensics | Synthetic | 76 | 63 |
| **Mean** | **mixed/inconclusive** | **71.0** | **56.5** |

Deliberation ran because the verdicts split. No expert supplied a revised assessment, so the initial scores are carried forward unchanged. The mean synthetic-confidence score moved from 56.25 in loop 6 to 56.5 in loop 7 (+0.25); this is effectively flat. The loop 6 empty-hash and failed-auth-before-FLOW findings were not repeated, consistent with the direct probes. Reviewers found substantial coherent Windows, network, SSH, proxy, SMB, and Mac pivots.

## Prioritized findings

1. **P0 — APP-INT-01 successful root SSH lacks matching native auth/session-open records (`contract_gap`).** Threat Hunter verified two in-window eCAR SSH sessions with inbound FLOW, sshd process, successful root LOGIN and dependent activity, but APP-INT-01 syslog lacks the corresponding `Connection from`, `Accepted ...`, and PAM session-open lines; the second session has only a syslog close. Other users' SSH lifecycles are present. Verify the generation owner and the session-coherent syslog observation decision before loop 8.
2. **P0 — Mac eCAR compresses distinct Endpoint Security transitions to one millisecond (`contract_gap`).** Detection Engineer verified four MAC-MROSS-01 fork/exec transitions over about 59 ms whose normalized eCAR process records all use timestamp 1793624864584 ms, about 1.1 seconds later. Preserve native event order in the shared eCAR timing/normalization contract.
3. **P1 — Expired R3 intermediate appears in an established TLS session (`environment_or_collection_plausibility`).** Network Forensics verified the `www.reddit.com` chain contains an R3 certificate expired in September 2025 during a November 2026 completed session. Zeek does not establish client validation success, so treat as suspicious rather than impossible; inspect the owning TLS certificate profile.
4. **P1 — Repeated Mac command/document-operation texture and partial shell-history coverage (`distribution_texture`).** Host/EDR and Detection both note recurring inventory commands; Host/EDR additionally found `cat`/`tee` interactions with office-document paths that do not appear in nearby history. The prior scenario adjustment reduced command counts but did not remove the pattern. Keep engine and scenario ownership distinct; do not generalize exact commands into engine logic.
5. **P3 — Same opaque Unified Log trace ID and message on both Macs (`weak_signal`).** Detection Engineer found the repeated first loginwindow trace ID. No evidence established trace-ID uniqueness across hosts, so this remains low-confidence and is not a standalone fix target.

## Loop 8 candidate

First investigate the two repeated APP-INT-01 SSH lifecycle gaps at the SSH bundle and coherent source-observation boundary; verify whether source-level session drop/delay decisions can orphan authentication/open records while retaining close evidence. Also inspect the Mac eCAR timestamp mapping with a family-level probe. Keep the expired chain and command texture in the queue unless the owning-layer inspection finds a narrow, data-driven correction.

Artifacts: `family-contract.md`, four expert reports, `deliberation.md`, `automated-eval.json`, `evaluation-stderr.txt`, `root-cause-probes.json`, and `scores.json` are in this loop folder.
