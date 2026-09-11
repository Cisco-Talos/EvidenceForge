# Iteration Test Blind Assessment — Loop 65

## Outcome

Loop 65 unified Linux transient PID identity and routed anacron through the canonical process
lifecycle. The automated evaluation scored 96.6689 PASS across 125,715 records. The blind panel
produced initial synthetic-confidence scores of 86, 67, 36, and 71 (mean 65.00), with three
Synthetic verdicts and one Real verdict. Required deliberation revised the scores to 92, 83, 58,
and 85 (mean 79.50), with three Synthetic verdicts and one Inconclusive verdict.

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 93 verdict confidence, 86 initial synthetic-confidence; revised to
Synthetic, 96 and 92. Strong volume, lifecycle, and multi-source pivots were outweighed by an RDP
Logon ID used before its Type 10 login, an Nmap command that could not explain a complete CIDR/port
product, and a PsExec authentication tuple absent from every network view.

**Detection Engineer:** Synthetic, 76 verdict confidence, 67 initial synthetic-confidence; revised
to Synthetic, 88 and 83. Source schemas and timing were strong, but 659/911 Sysmon Event 1 rows
blanked every PE resource field for broad inbox-binary families. Shallow recurring process-command
pools and a local PAM/KDC contract mix reinforced the verdict.

**Network Forensics:** Real, 64 verdict confidence, 36 initial synthetic-confidence; revised to
Inconclusive, 72 and 58. DNS, TLS, sensor separation, firewall accounting, and IDS correlation were
production-like. A repeated 600 ms proxy connection cadence, fully timestamp-sorted Zeek exports,
and five dangling HTTP FUIDs were the principal network-native concerns; the cross-domain RDP and
Nmap findings moved the final position.

**Host/EDR Forensics:** Synthetic, 84 verdict confidence, 71 initial synthetic-confidence; revised
to Synthetic, 91 and 85. Process, RDP transport, SSH, and cross-source lifecycle joins were strong.
Incomplete PE metadata, rotating workstation lock/unlock producer PIDs, cloned Linux hardware and
snap inventories, narrow UFW packet fields, and dense Type 5 service logons remained repeated tells.

## Deliberation Findings

The panel agreed that high protocol and correlation fidelity can coexist with narrow causal
contradictions. It accepted the RDP same-LUID process-before-login sequence and the command-aware
Nmap target expansion as the strongest findings, while preserving the network analyst's caution
that many protocol records are individually production-like. Weaker collection-sensitive findings
remain candidates for native-capture calibration rather than immediate broad fixes.

## Fix Verification

- All ten hosts that emitted anacron now use one PID across syslog start/job/exit rows and the
  matching eCAR process create and terminate; the rendered probe found zero contract violations.
- Linux transient PID slopes across eleven hosts range from 1.8850 to 3.4776 PIDs/second, a 1.8449x
  spread rather than the previous fleet-wide narrow slope band.
- Storyline shell commands retain viable authored anchors when later baseline reservations have
  already occupied the same shell; the formerly failing 17:56 APP-INT-01 command now generates.
- Behavior revision 29 records the family change with surface digest
  `df044281d87ab2a3adff9c8149d3a054a0e3397b4d091325091351ed4ed5a6cf`.
- The routine gate passed with 8,396 tests and 5 skips; repository-wide Ruff check and format check
  passed across 769 files.

## Prioritized Improvements

### P0 — Enforce RDP session creation before dependent activity

Make the RDP action bundle own a canonical order of transport, Type 10 login/session publication,
`userinit.exe`, `explorer.exe`, and user activity. No non-system process or side effect may use the
new LUID before the login exists in canonical state, and source timing must preserve that ordering
in Security, Sysmon, and eCAR.

### P1 — Make scan expansion obey visible Nmap semantics

Carry discovery options into the canonical scan plan. A full CIDR-by-port product must require
`-Pn`; otherwise discover hosts first and perform the port scan only against hosts whose discovery
result permits it. Add an end-to-end command/discovery/attempted-target assertion.

### P2 — Complete host-build-owned Windows PE metadata

Extend binary deployment identity to the remaining inbox and installed binary families so hashes
and all five Sysmon PE resource fields come from the same exact host-build/file identity. Model
metadata extraction loss as an occasional host/config/file condition rather than a deterministic
image-family placeholder.

### P3 — Bind remote administration and authentication companions

Use one canonical tuple and timing contract for explicit credentials, Type 3 login, SMB/RPC flows,
endpoint FLOW rows, Zeek, and service installation. Separately gate local PAM failures from KDC
evidence unless an explicit Kerberos PAM mechanism owns a real client tuple.

### P4 — Scope recurring inventories and timing texture

Replace fleet-wide device, snap, Windows command, shell-command, UFW fingerprint, and proxy timing
pools with host-, role-, user-, scanner-, and session-owned heavy-tailed state. Calibrate 4800/4801
producer PID and Type 5 session behavior against native captures before changing those contracts.

## Priority Rationale

RDP ordering is first because it is a same-identity causal impossibility visible in three endpoint
sources. Nmap semantics is the next independent hard contradiction but affects one scan family.
PE metadata has broader scope but lower logical severity, while remote-authentication and inventory
texture have plausible collection or environment explanations and therefore lower immediate score
leverage.

## Comparison with Quantitative Eval

The deterministic evaluator scored 96.6689: 99.9992 parseability, 96.8782 plausibility, 95.6657
causality, and 92.6659 timing. It confirmed broad schema conformance, intent reconciliation,
source-field agreement, IDS integrity, and plausible rates, but did not detect the RDP same-LUID
inversion, command-aware Nmap mismatch, incomplete binary metadata inventory, remote-admin tuple
gap, or repeated environmental/timing pools. Its one strict schema failure was eCAR `FILE/RENAME`,
while the panel emphasized higher-authenticity source semantics.
