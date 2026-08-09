# Host/EDR — Blind Authenticity Assessment

## Verdict

- **Assessment:** Synthetic
- **Verdict confidence:** 85/100
- **Synthetic-confidence score:** 86/100

## Executive summary

The reviewer found no decisive hard contradiction and described native formats, identity
continuity, lifecycle handling, and cross-source joins as substantially stronger than typical
generated data. The synthetic verdict rested on cross-provider time texture, fleet software and
application semantics, and highly regular background families. The old universal startup-module
tuple was not reproduced as a cross-executable hard defect.

## Evidence supporting synthetic

- Across 593 matched Sysmon Event 1/Security 4688 process creates, Security-minus-Sysmon time ranged
  from about -1.018 to +0.812 seconds. The bounded bidirectional distribution looks like independent
  source jitter. This recurs from the accepted provider-timing family scheduled for Batch 3.
- `Webex.exe` is twice launched with a Slack tenant URL on `WS-OREED-01`, demonstrating independent
  application and destination selection.
- Two identical Nina Kapoor `ssh.exe` launches begin 625 ms apart from one parent/session and
  create long-lived parallel sessions. This is possible but indicates missing demand collision
  control.
- The full Veeam Backup & Replication service appears on ordinary workstations as well as the DC
  and file server, alongside overlapping VPN/SASE and backup products.
- DHCP and some same-executable module groups remain unusually regular, but the reviewer did not
  find the previous exact nine-module template spanning unrelated applications or its exact 2–3 ms
  cadence.

## Evidence supporting real

- Windows XML used credible providers, channels, fields, SIDs, PIDs, tasks, and monotonic record
  identifiers with gaps.
- Process GUID morphology and registry/file cross-source examples were strong.
- Zeek, endpoint, and ASA observations agreed on representative DNS and failed TLS transactions.
- Certificate file SHA-1 values matched X.509 fingerprints, and repeated SNIs reused certificates.

## Scores

| Category | Score |
|---|---:|
| Field and native-format realism | 92 |
| Temporal realism | 69 |
| Cross-source correlation | 96 |
| Behavioral realism | 73 |
| Environmental plausibility | 66 |

## Disposition

Provider timing remains Batch 3 work; software inventory, application semantics, SSH demand, and
background populations remain Batch 4 work. The startup-module gate check passes because the
reviewer's residual same-executable similarity is compatible with profile-coherent dependencies
and the exact rendered recurrence probes are zero.
