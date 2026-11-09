# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 76  
**Synthetic-Confidence Score:** 26

## Executive Summary

Reviewed Windows, Linux, and macOS records show coherent process, session, and transport relationships. eCAR ordering and collection boundaries are weak texture signals, but no confirmed source-native contradiction was found.

## Evidence For Synthetic

- **[weak_signal]** Per-host eCAR timestamps are nondecreasing and millisecond precision is coarser than native Windows XML. This may reflect normalization/export and is not conclusive.
- The sampled files share a November 2 slice; window boundaries do not establish missing starts or endings.

## Evidence For Real

- WS-AJOHNSON-01 Security 4688 for `cmd.exe` PID 5292 at 13:13:52.344Z aligns with Sysmon 1 at 13:13:52.210Z and eCAR at 13:13:52.443Z. The child `ssh.exe` PID 5308 agrees across sources on parent, user, LogonId and command.
- APP-INT-01 syslog session close precedes logind session removal; eCAR termination/logout records align on user and session.
- MAC-MROSS-01 TCP/22 FLOW, Endpoint Security `sshd` transitions and Unified Log public-key acceptance agree on source tuple and order.
- Mac zsh history commands align to Endpoint Security/eCAR activity. Inspected Windows XML, syslog, Unified Log, Endpoint Security and eCAR records are plausible.

## Detailed Analysis

The Windows process tree, Linux session close, and macOS SSH sequence preserve matching identifiers and plausible source timing. Four Security 4688 records in one checked set lacked same-PID Sysmon 1, but the review did not establish a mandatory collection contract. Process terminations do not precede creates in inspected eCAR files. The MeetingAssist Unified Log event explicitly records a denial, so no child process is required. Sparse Unified Log coverage and start/end rows near the collection boundary were not treated as defects.

## Synthetic Indicator Summary

| Category | Finding |
|---|---|
| hard_contradiction | None confirmed |
| contract_gap | None confirmed |
| distribution_texture | Weak signal: per-host eCAR sorting/precision |
| schema_or_format | No confirmed defect |
| environment_or_collection_plausibility | No confirmed issue in examined host identity/source semantics |
| weak_signal | Slice-wide time coverage and normalization do not prove provenance |

## Realism Score by Category

- **Field format accuracy: 8/10** — Inspected XML, syslog, macOS, and eCAR fields are plausible.
- **Temporal patterns: 8/10** — Process, session, and SSH events are ordered with plausible offsets.
- **Cross-source correlation: 9/10** — Process IDs, LogonIds, SSH tuples and session IDs align in examples.
- **Behavioral realism: 7/10** — Visible user/service activity fits roles; broader behavior remains unmeasured.
- **Environmental consistency: 8/10** — Hostnames, identities, paths and network addresses align in examples.

## Recommendations

- Compare eCAR ordering with collector/export metadata if provenance is a concern.
- Preserve the cited process/session/SSH relationships as positive controls.
