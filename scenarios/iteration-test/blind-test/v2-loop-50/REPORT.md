# Iteration-Test Blind Assessment — Loop 50

## Outcome

- All four reviewers returned Synthetic verdicts.
- Synthetic-confidence scores were 74, 86, 58, and 74 (average 73; spread 28).
- Average verdict confidence was 82.5; no deliberation was required.
- The four visible RDP sessions now preserve SID/GUID, parent ancestry, and terminal-session
  identity across their login and bootstrap evidence.

## Deterministic Evaluation

- Overall score: 96.2705 across 114,409 records; all hard acceptance gates passed.
- Pillars: parseability 99.9991, plausibility 96.9156, causality 93.3705, timing 93.4960.

## Hard-Contract Result

All four Type 10 logons carried nonempty target SIDs and full nonzero GUIDs. Their twelve Sysmon
bootstrap process rows formed complete `System` → `winlogon.exe` → `userinit.exe` →
`explorer.exe` parent chains, with each triplet sharing one nonzero terminal-session ID.

## Newly Prioritized Findings

- One Teams utility process still emits six eCAR module loads after its eCAR termination. This
  repeats loop 49 and becomes loop 51.
- Eighteen of twenty conservatively matched Kerberos ticket/logon pairs place Event 4769 after
  Event 4624; all twenty disagree on `LogonGuid`.
- The high-value SCP session on APP-INT-01 removes a different systemd-logind session ID from the
  one carried by its eCAR login.
- Exchange Transport and IMAP4 singleton processes accumulate overlapping long-lived instances.
- ICMP payload sizes remain too random per host, SMB transports are over-fragmented, and no NTP
  traffic appears in the six-hour collection.

## Reports

- `threat-hunter.md`
- `detection-engineer.md`
- `network-forensics.md`
- `host-forensics.md`
