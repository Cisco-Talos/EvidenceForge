# Iteration-Test Blind Assessment — Loop 49

## Outcome

- All four reviewers returned Synthetic verdicts.
- Synthetic-confidence scores were 84, 66, 86, and 84 (average 80; spread 20).
- No deliberation was required.
- The prior 151-record SMB blank-field and receiver-owned workstation signature did not recur.

## Deterministic Evaluation

- Overall score: 96.2686 across 114,409 records; all hard acceptance gates passed.
- Pillars: parseability 99.9953, plausibility 96.9126, causality 93.3705, timing 93.4960.

## Hard-Contract Result

All 433 Type 3 logons had complete subject, target, GUID, authentication-process/package,
workstation, and endpoint fields. No remote Type 3 logon named its receiving host as the
workstation; Kerberos and NTLM combinations were internally coherent.

## Newly Prioritized Findings

- All four visible RDP logons omit target SID/GUID and produce incomplete process ancestry;
  their `userinit.exe` processes live for 49 minutes to 2.57 hours.
- All 14 visible `winlogon.exe` processes use Sysmon terminal session 0 while their direct
  `userinit.exe` children use the real nonzero terminal session.
- Two TCP DNS flows still claim `SF` with payload-only histories and one packet each way.
- Every one-query UDP DNS record is timestamped after the packet that opened its connection.
- Nikto mutates a random six-digit `Test:` token on every request from the dominant scanner.
- One Teams process still loads modules after its visible termination.

## Reports

- `threat-hunter-report.md`
- `detection-engineer-report.md`
- `network-forensics-report.md`
- `host-forensics-report.md`

