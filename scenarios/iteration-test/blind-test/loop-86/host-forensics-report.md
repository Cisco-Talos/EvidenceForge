# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 72  
**Synthetic-Confidence Score:** 18

## Executive Summary

The inspected host records are internally coherent, with source-appropriate correlations across Windows EDR/events, macOS endpoint evidence, and Linux session records. No substantiated hard contradiction, schema defect, or lifecycle failure was found; the slice alone cannot establish origin.

## Evidence For Synthetic

No material evidence was established. A few macOS Unified Log records do not, by themselves, show deficient or synthetic coverage.

## Evidence For Real

- On WS-PPATEL-01, 108 Sysmon process create/terminate records matched eCAR PID/image records within three seconds; sampled LSASS access also aligned with eCAR PROCESS/OPEN.
- FILE-SRV-01's inbound SMB tuple precedes a Type 3 login; login/logout share session object, LogonID, source tuple and type.
- MAC-MROSS-01 shows inbound SSH transport, Endpoint Security sshd transitions, then Unified Log public-key acceptance from the same address/port.
- FILE-LNX-01 records sshd session close followed by logind session removal. Sampled XML, NDJSON and syslog records were parseable.

## Detailed Analysis

Sampled Windows process trees include plausible service and user-session relationships. Security/Sysmon/eCAR process activity and images align in checked records. Type 3 sessions correlate with SMB tuples while interactive and service logons use different semantics. macOS endpoint records retain audit tokens, parent tokens, PID versions, signing data and process transitions; the SSH path preserves transport-before-authentication order. Linux sshd close and logind removal ordering is plausible. The six-hour window limits lifecycle conclusions at its edges.

## Synthetic Indicator Summary

| Category | Finding |
|---|---|
| hard_contradiction | None substantiated |
| contract_gap | None substantiated |
| distribution_texture | None substantiated |
| schema_or_format | None substantiated |
| environment_or_collection_plausibility | None substantiated |
| weak_signal | Sparse macOS Unified Log; insufficient to infer a defect |

## Realism Score by Category

- **Field format accuracy: 8/10** — Inspected XML, NDJSON and syslog use plausible source-specific fields.
- **Temporal patterns: 8/10** — Process, transport, authentication and session-close order is plausible.
- **Cross-source correlation: 9/10** — PID/image, SMB/session and SSH correlations align.
- **Behavioral realism: 7/10** — Activity fits visible host roles; the slice limits broader conclusions.
- **Environmental consistency: 8/10** — Windows, Linux and macOS activity broadly fits host roles and identities.

## Recommendations

- No correction is indicated by the inspected host evidence.
- Compare sparse source coverage with collection configuration before drawing conclusions in a future full-bundle assessment.
