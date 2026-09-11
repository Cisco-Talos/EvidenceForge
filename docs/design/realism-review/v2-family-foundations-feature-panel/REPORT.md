# V2 Family Foundations Feature-Branch Blind Assessment Panel

## Outcome

All four expert roles classified the dataset as synthetic. The average synthetic-confidence
score is **88.0/100 (confidently synthetic)**. Lower synthetic-confidence scores are better.

| Role | Assessment | Verdict confidence | Synthetic-confidence score |
|---|---:|---:|---:|
| Threat Hunter | Synthetic | 96 | 92 |
| Detection Engineer | Synthetic | 99 | 96 |
| Network Forensics | Synthetic | 78 | 69 |
| Host/EDR Forensics | Synthetic | 98 | 95 |
| **Average** | **Synthetic** | **92.75** | **88.0** |

Deliberation was not triggered: the verdict was unanimous, average verdict confidence was
92.75, and the synthetic-score spread was 27 points, below the 30-point trigger.

## Principal Findings

### Threat Hunter

Strong cross-source attack pivots and role-aware telemetry were undermined by SSH lifecycle
contradictions and unusually synchronized end-of-window closures. Several
`systemd-logind` removals referenced the wrong session ID, and every one of 6,994 ASA
connection builds had an in-window teardown.

### Detection Engineer

The decisive defect was internal Sysmon chronology. Across seven of nine Windows hosts,
105 records had `EventData.UtcTime` more than one second after `System/TimeCreated`, with a
maximum offset of 7,564.947 seconds. Fourteen matched create/terminate pairs reused the
same false `UtcTime` even though their header times differed.

### Network Forensics

The network layer was the strongest part of the dataset, especially Zeek UID integrity,
dual-sensor accounting, DNS cache decay, TLS/X.509 detail, proxy behavior, and ASA byte
accounting. The strongest synthetic tell was ASA ICMP direction: identical DMZ-to-inside
paths alternated between `inbound` and `outbound`, while TCP and UDP used stable direction
semantics. Connection-ID allocation and universal first-answer DNS selection also appeared
overly deterministic.

### Host/EDR Forensics

Process, hash, PID, and attack-chain correlation were strong. However, all four visible RDP
sessions kept transient `userinit.exe` processes alive for 2,823–8,857 seconds, and their
Sysmon parent fields contradicted visible SYSTEM-owned `winlogon.exe` parent records. The
review also confirmed wrong SSH logind session IDs and clustered collection-boundary
closures.

## Prioritized Improvements

1. **P0 — Fix Sysmon canonical timestamps.** Derive both header and payload timestamps from
   the same process-lifecycle truth and add cross-field lifecycle assertions.
2. **P0 — Preserve SSH session identity through closure.** Carry the bundle-owned logind
   session ID through PAM, eCAR, syslog, and session removal.
3. **P1 — Correct RDP process lifecycle and parent rendering.** Give `userinit.exe` a short,
   realistic lifetime and render parent image, command line, and user from the actual
   SYSTEM-owned `winlogon.exe` parent.
4. **P1 — Derive ASA ICMP direction from canonical topology.** Use the same zone-direction
   decision for ICMP, TCP, and UDP instead of activity-family-specific paths.
5. **P2 — Remove collection-boundary fingerprints.** Avoid synchronized lifecycle closure
   and universal in-window ASA teardown when the observation window ends.
6. **P2 — Improve allocation and selection texture.** Allocate ASA connection IDs in device
   chronology and diversify selection among valid multi-answer DNS results.
7. **P3 — Add a small realistic failure tail.** Include plausible NTP traffic and occasional
   failed TLS analyzer outcomes where supported by the environment.

The first four items are highest priority because they are hard source-native or cross-source
contradictions. The remaining items primarily improve distribution texture. Preserve the
existing Zeek lifecycle accounting, proxy/TLS detail, role-specific volume, hashes, and
cross-source attack pivots while making these corrections.

## Method Note

The panel inspected the existing 84-file feature-branch dataset without access to repository
code, scenario provenance, prior assessments, or automated-evaluation output. Three roles ran
in fresh reviewer contexts. Because the environment's agent-thread ceiling blocked a fourth
fresh context, the Host/EDR pass ran sequentially in a still-blind reviewer context after its
first role report had been frozen; it re-inspected the dataset independently and received no
other panel findings. No deliberation or score revision occurred.

No generation, quantitative evaluation, dashboard, code modification, commit, or push was
performed for this panel-only request.
