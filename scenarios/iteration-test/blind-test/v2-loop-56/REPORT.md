# Iteration Test Blind Assessment — Loop 56

## Outcome

The exact RDP bootstrap contract now passes its hard probe. All four Type-10 logons name the
session-specific `winlogon.exe` PID, each process exists before its logon, overlapping sessions
use distinct process identities, and every visible RDP winlogon is parented by `smss.exe`.
Automated evaluation passed at 96.1263 across 114,255 records, with every pillar above 93.

## Expert summaries

- **Threat Hunter:** Synthetic, 96 verdict confidence, 86 synthetic-confidence. Found a repeated
  DHCP microsecond fingerprint and Zeek/endpoint ACK disagreement, plus scan packet-size and
  reverse-shell ownership defects.
- **Detection Engineer:** Synthetic, 61 verdict confidence, 54 synthetic-confidence. Found
  repeated Kerberos TGS/logon timing texture and one remotely correlated 4771 without a client
  address, while rating schemas and cross-source joins highly.
- **Network Forensics:** Synthetic, 87 verdict confidence, 74 synthetic-confidence. Found exact
  DNS RTT reuse across 971 multi-sensor transactions and incomplete, success-only TLS lifecycle
  rendering.
- **Host/EDR Forensics:** Synthetic, 91 verdict confidence, 74 synthetic-confidence. Confirmed the
  repaired PID and ordering family, then found that Sysmon still assigns the interactive user as
  the SYSTEM winlogon's `ParentUser` and that RDP `userinit.exe` inherits session-length lifetime.

The required calibration was triggered by the 32-point synthetic-confidence spread. Deliberation
ended unanimously Synthetic at 88, 76, 81, and 82 synthetic-confidence (mean 81.75), while
retaining the dataset's strong schemas, topology, lifecycle integrity, and cross-source pivots as
substantial realism evidence.

## Prioritized improvements

1. **P0 — RDP parent identity and child lifecycle:** derive Sysmon `ParentUser` from the exact
   SYSTEM-owned winlogon and terminate `userinit.exe` shortly after it launches the desktop.
2. **P0 — source-local timing with canonical causality:** remove the DHCP microsecond fingerprint,
   align Zeek DHCP completion with endpoint ACKs, and derive DNS RTT separately per sensor.
3. **P0 — TLS lifecycle coverage:** render failed and partial analyzer outcomes, populate
   capability-appropriate negotiation fields, and avoid success-only SSL evidence.
4. **P1 — stable network-stack profiles:** keep SYN options and packet size coherent through a
   same-host, same-route scan.
5. **P1 — Kerberos transaction timing:** apply observation delay coherently across TGT, TGS,
   service authentication, and logon; retain the remote KDC client tuple on 4771.
6. **P1 — shell pipeline ownership:** materialize observable pipeline children and assign the
   reverse-shell flow to the socket owner, or omit process identity when it is unobserved.
7. **P2 — periodic and public-service texture:** model explicit timer/collection state, repeated
   public clients, response-body-derived redirect MIME, and richer browser concurrency.

## Quantitative comparison

The deterministic evaluator stayed effectively flat from loop 55 (96.1262 to 96.1263) because it
does not yet measure Sysmon `ParentUser`, DHCP timestamp suffix independence, per-sensor DNS RTT,
or TLS analyzer lifecycle completeness. The hard RDP probe demonstrates that the targeted defect
was removed even though adjacent source-native defects became the panel's next strongest signals.
