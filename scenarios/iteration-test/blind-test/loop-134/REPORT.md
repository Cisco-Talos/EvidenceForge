# Loop 134 Assessment Report

## Summary

Loop 134 fixed the verified core/DMZ Zeek multi-sensor cloning issue. Before the fix, 1,348 of 1,479 matched overlapping flows had identical duration, byte, packet, and history metrics across independent sensors. After regeneration, the hard probe found zero non-locked overlapping TCP flows with identical metrics; the remaining exact matches were DNS/ICMP observations whose packet accounting is intentionally locked.

Automated eval passed at 95.7270 across 80,629 records. Blind reviewers still classified the dataset as synthetic, with scores: Threat Hunter 70, Detection Engineer 78, Network Forensics 72, Host/EDR 74, average 73.5.

## Hard Probe

- Matched overlapping flows: 1,479
- Identical metric flows: 194
- Locked matched flows: 201
- Locked identical metric flows: 194
- Non-locked matched flows: 1,278
- Non-locked identical metric flows: 0
- Duration-different flows: 1,273
- Packet-different flows: 1,197
- IP-byte-different flows: 1,284

## Reviewer Findings

- Network Forensics: the old exact clone issue is fixed for non-locked flows, but the new lossless-duration cap produces 65 SSH cross-sensor duplicates where DMZ duration is exactly core duration plus 0.750000 seconds while bytes remain identical.
- Host/EDR: Linux polkit messages combine incompatible caller programs and actions, such as timedatectl requesting reboot or PackageKit actions and nmcli requesting timedate actions.
- Detection Engineering: CRON/sysstat messages have randomized seconds on cron-originated jobs, and ECAR pipeline telemetry repeatedly captures only head/tail without the left-hand command.
- Threat Hunting: File-SRV svc_mhsync activity around 17:01 lacks a contemporaneous workstation-to-file-server Zeek flow, and some command/artifact naming remains exercise-clean.

## Next Target

Loop 135 should first fix the regression-like SSH cross-sensor `+0.750000s` duration pattern caused by the lossless observation cap. The next concrete source-native targets are polkit action/program binding, CRON minute-granularity, Linux pipeline ECAR coverage, and the File-SRV lateral-use network gap.
