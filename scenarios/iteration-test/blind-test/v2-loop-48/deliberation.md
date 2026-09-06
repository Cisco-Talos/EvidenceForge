# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---:|---:|---:|---:|---:|---:|
| Threat Hunter | Real | 76 | 29 | Synthetic | 87 | 68 |
| Detection Engineer | Synthetic | 86 | 68 | Synthetic | 91 | 74 |
| Network Forensics | Inconclusive | 82 | 38 | Synthetic | 86 | 67 |
| Host/EDR Forensics | Synthetic | 84 | 69 | Synthetic | 91 | 75 |

## Key Agreements

The panel agreed that the network fabric, attack-chain pivots, and routine endpoint correlation are
strong. After sharing evidence, all four reviewers nevertheless classified the dataset as Synthetic
because repeated Windows source-native identity and RDP lifecycle defects cannot be explained by
collection delay or the bounded observation window.

## Most Convincing Evidence

1. 151 successful Type 3 logons repeat empty subject, authentication-process, GUID, and LM-package
   fields while naming the receiving server as `WorkstationName` despite a different modeled source.
2. Four Type 10 logons begin with an empty target SID and later emit a concrete SID on the matching
   same-LUID logoff.
3. Four RDP process chains retain resolvable parent PIDs/GUIDs but omit or contradict parent image
   and principal, and keep `userinit.exe` alive for 49 minutes to 2.57 hours.
4. WEB-EXT-01 scanner identities keep stable TTL and packet length while rotating nearly uniformly
   among exactly three TCP window values.

## Improvement Recommendations

- Populate Windows SMB Type 3 subject, workstation, authentication-process, package, and GUID
  fields from canonical session and client truth.
- Make RDP target SID and process ancestry immutable across the login lifecycle, and terminate
  `userinit.exe` within its normal short initialization interval.
- Model scanner TCP fingerprints per source or scanner family rather than per packet.

