# Blind Expert Review Summary

## Panel outcome

Four specialists independently reviewed only the generated data under
`/private/tmp/eforge-realism-review/branch-enterprise/data`. They were not shown the scenario,
ground truth, source code, review package, or one another's reports.

| Reviewer | Verdict | Verdict confidence | Synthetic score |
| --- | --- | ---: | ---: |
| Threat Hunter | Synthetic | 90 | 88 |
| Detection Engineer | Synthetic | 97 | 96 |
| Network Forensics | Synthetic | 93 | 86 |
| Host/EDR Forensics | Synthetic | 98 | 97 |
| **Panel** | **Unanimous synthetic** | **94.5 average** | **91.75 average** |

No deliberation was triggered. The verdicts agree, average confidence exceeds 60, and the score
spread is 11 points, below the established 30-point threshold.

## Validated consensus families

The independent reports converge on these root-cause families. A panel impression enters the final
finding register only where static code trace or direct rendered evidence also supports it.

1. **Process/session ownership and lifecycle:** three reviewers found one `ssh.exe` process owning
   numerous independent, overlapping SSH transports. Detection and host reviewers also identified
   activity under ended Windows sessions, mutable LogonGuid identity, invalid Explorer ancestry,
   and a reversed Linux local-login tree.
2. **IDS semantic attachment:** three reviewers found alerts whose claimed semantics conflict with
   the joined HTTP or transport evidence. The strongest case is a 403 response signature on a
   SYN-only, zero-response flow corroborated by Zeek and ASA.
3. **Timing/lifecycle containment:** reviewers identified RDP endpoint FLOW after authentication,
   fixed OCSP file durations, and file intervals ending just beyond their parent connections.
4. **State and workload texture:** independently sampled IRQ/device ownership, repeated core-service
   starts, forced GPO refreshes, uniform public-client categories, broad DHCP T1 resampling, and
   implausible SSH cadence expose insufficient durable state or session-shaped behavior.
5. **Source-native fidelity:** every reviewed Windows 4648 record uses non-native
   `NetworkAddress`/`NetworkPort` names instead of `IpAddress`/`IpPort`.

## Strong counterevidence

The panel consistently found high-quality construction in several areas:

- Zeek, ASA, NAT, and endpoint tuples and accounting correlate at high rates.
- Explicit-proxy CONNECT, cache/deny, DNS, and origin-side TLS behavior is coherent.
- TLS version, resumption, certificate, X.509, OCSP, file, and PE joins are generally deep and
  protocol-aware.
- Server-side SSH connection, authentication, PAM, logind, and closure ordering is source-native.
- Windows IDs, hashes, process GUIDs, and process create/terminate pairs are usually stable outside
  the session-boundary defects.
- Role placement, addressing, and small source-local collection gaps are broadly plausible.

These strengths support fixing shared semantic ownership and lifecycle contracts before broad field
or vocabulary expansion.

## Historical archive use

The user-supplied archive at
`/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test-expanded/blind-test` was
consulted only after the current reviewers completed their isolated work. Selected historical
reports were used to assess recurrence and sibling risk, not to influence the current verdict:

- `loop-72/REPORT.md`: prior residual timing, accounting, final-window, and lifecycle defects.
- `session-closure-lifecycle-contract/REPORT.md`: prior duplicated failed-logon object identities,
  endpoint-auth ordering, file-envelope tails, and closure-tail defects. The failed-logon identity
  family recurs in the current ten-run matrix.
- `network-contract-milestone-3/REPORT.md`: a previously accepted network-contract milestone,
  useful counterevidence that many tuple/accounting repairs are durable.
- `cryptographic-protocol-payload-contract/REPORT.md`: prior process/file/module ownership, ICMP,
  NAT ordering, NTP, and certificate-texture findings used for sibling checks.
- `identity-lifecycle-contract/final_panel_scorecard.json`: prior accepted identity-lifecycle
  scorecard used as counterevidence; current defects are narrower session/process reuse paths.

Historical observations were not accepted unless the current code or rendered evidence reproduced
them. The archive itself remains outside the tracked review package.

## Individual reports

- [Threat Hunter](blind-threat-hunter.md)
- [Detection Engineer](blind-detection-engineer.md)
- [Network Forensics](blind-network-forensics.md)
- [Host/EDR Forensics](blind-host-edr.md)
