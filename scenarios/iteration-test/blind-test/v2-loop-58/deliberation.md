# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 74 | 44 | Synthetic | 89 | 80 |
| Detection Engineer | Synthetic | 86 | 70 | Synthetic | 94 | 87 |
| Network Forensics | Synthetic | 97 | 91 | Synthetic | 97 | 91 |
| Host/EDR Forensics | Synthetic | 90 | 82 | Synthetic | 95 | 89 |

The panel's initial mean synthetic-confidence score was **71.75**. After cross-examination,
the mean was **86.75**. The final consensus is **Synthetic**, although the panel continues to
regard much of the dataset as technically sophisticated and production-like.

## Round 1 — Present Findings

### Threat Hunter

The Threat Hunter initially returned **Inconclusive**, with verdict confidence **74** and a
synthetic-confidence score of **44**. Their strongest production-like evidence was the credible
six-hour source volume and source-family mix, non-identical observations from independent Zeek
sensors, and coherent DHCP, TLS, process, authentication, and attack lifecycles. Their strongest
synthetic evidence was repeated exact Linux administrative-command vocabulary, missing initiating
client processes around several consequential SSH/RDP/PsExec pivots, and generic SMB document-name
vocabulary. The specialist observation unique to this review was that the suspicious activity was
operationally pivotable end to end without relying on completeness itself as a synthetic signal;
the Threat Hunter also found the DC-01 Security-log clear and EventRecordID reset convincing.

### Detection Engineer

The Detection Engineer initially returned **Synthetic**, with verdict confidence **86** and a
synthetic-confidence score of **70**. Their strongest evidence was five unambiguous Security
4688/Sysmon Event 1 integrity disagreements for the same processes, seven High-integrity 4688
events that consistently used `TokenElevationType=%%1936` rather than Full-token semantics, and
the all-session RDP `LogonGuid` discontinuity: all 15 Type 10 sessions gave `userinit.exe` and
`explorer.exe` zero GUIDs before later children under the same LogonId adopted the 4624 GUID. Their
unique source-semantic findings included all 110 CRON records having millisecond-quantized RFC
5424 timestamps and 26 non-resumed TLS 1.2 rows with certificate-bearing histories but no
`cert_chain_fuids` despite no reported loss. They nevertheless judged the base Windows schemas,
SID stability, lifecycle ordering, and most Zeek relationships to be unusually strong.

### Network Forensics

The Network Forensics Analyst initially returned **Synthetic**, with verdict confidence **97** and
a synthetic-confidence score of **91**. Their strongest finding was that at least **392 of 522**
conservatively matched successful proxy tunnels opened the proxy-origin TCP connection before the
initiating HTTP `CONNECT`; **115** also detected outbound TLS before the request. Exact SNI and
tunnel-byte matches tied the records to the same transactions. They also found **122 of 586**
non-resumed TLS 1.2 ECDHE sessions whose Zeek `ssl_history` omitted mandatory ServerKeyExchange
marker `K`, including **109** with `missed_bytes=0`, and a systematic absence of failed SSL rows:
all 2,538 SSL records were successful/SF while 180 non-SF `service:"ssl"` connections had no SSL
companion. Unique network findings included cross-sensor application timestamps that did not
preserve the otherwise stable sensor-clock relationships, contradictory `files.analyzers`
provenance for hashes/PE/OCSP, and unstable content identity at identical static download URLs.
They also emphasized that topology, DNS, source ports, firewall lifecycle, certificate reuse, and
connection-state texture were highly realistic.

### Host/EDR Forensics

The Host/EDR Forensics Analyst initially returned **Synthetic**, with verdict confidence **90** and
a synthetic-confidence score of **82**. Their strongest evidence was one WinSxS identity suffix,
`_none_7c91d6e7c9f7f1f5`, reused on seven hosts across servicing-stack versions
`10.0.19041.3636`, `10.0.20348.2322`, and `10.0.22621.3155`; a dataset-wide Windows process-lifetime
floor in which none of 781 matched creations/terminations lasted under one second and only two
lasted under two; and the same session-bootstrap `LogonGuid` discontinuity reported by the
Detection Engineer. They also found three `dsquery.exe` processes lasting roughly 688–982 seconds,
no transient command-line utility among 25 samples ending under three seconds, and repeated Linux
snap and IRQ topology across unrelated roles. Their unique positive observation was that 969 of
970 Sysmon process creations matched Security 4688 across PID, image, command line, parent,
LogonId, and user, with at least 963 also closely matching eCAR; they found no visible dependent
event after actor termination or child before parent.

## Round 2 — Cross-Examination

### Production-like lifecycle evidence versus hard contradictions

The main friction was between the Threat Hunter's production-like end-to-end view and the other
specialists' source-native contradictions. The Threat Hunter's evidence remains valid: the source
mix, role graph, stateful DHCP, sensor skew, event-record reset, and attack pivots are not crude.
However, those strengths do not explain the Network Analyst's exact proxy matches, the missing TLS
1.2 ServerKeyExchange markers, or the Detection Engineer's same-process integrity disagreements.
These are compatible with a sophisticated deterministic generator that has strong broad
contracts but several defective family-level owners. The cross-examination therefore treated the
Threat Hunter's initial absence of a hard contradiction as a specialty blind spot, not evidence
that the contradictory records were mistaken.

### Proxy causality and possible preconnection

A proxy can pool or pre-establish connections, and a product might speculatively connect after
learning a destination. That alternative does not adequately explain the reported set. The
Network Analyst matched SNI plus exact tunnel byte counts, and the outbound TCP start preceded the
Zeek HTTP request in 392 of 522 successful tunnels; in 115 cases outbound TLS detection also
preceded the request. In the concrete `proxy.wellbridge.io` transaction, the outbound TCP start at
`13:42:50.540040` and TLS detection at `13:42:50.649667` precede both the DMZ `CONNECT` timestamp
at `13:42:50.932408` and the core observation at `13:42:50.713502`. A reusable preconnected socket
might explain an earlier TCP start, but it does not naturally explain transaction-specific
outbound TLS tied by exact byte identity before the proxy receives the target-bearing CONNECT.
The panel therefore retained this as the strongest hard contradiction.

### TLS histories, failed handshakes, and capture loss

Packet loss, midstream pickup, or analyzer attachment failure can omit handshake messages. That
explanation is weak for the **109** ECDHE TLS 1.2 sessions with no `K` and `missed_bytes=0`, because
the negotiated `TLS_ECDHE_RSA_*` cipher requires ServerKeyExchange. The panel kept this as a hard
protocol contradiction. By contrast, the absence of `established:false` SSL rows for all 180
non-SF SSL-labeled connections was kept as a strong contract gap rather than an impossibility:
collection policy could suppress failed analyzer records, but the perfect state-conditioned split
is implausible without an explicit profile. The 26 certificate-bearing histories without
`cert_chain_fuids` were likewise retained as a supporting contract gap because asymmetric capture
or extraction failure remains an alternative explanation even when `missed_bytes=0`.

### Windows process identity and token semantics

The five matched Security/Sysmon integrity disagreements survived cross-examination. PID, image,
command line, parent, LogonId, user, and sub-second timestamps identify the same process, so
ordinary join ambiguity is not credible. Security MandatoryLabel and Sysmon IntegrityLevel should
describe a coherent process token. The seven High-integrity 4688 events using
`TokenElevationType=%%1936` were judged somewhat less decisive: High integrity with a default token
can occur under UAC-disabled, built-in-administrator, or nonstandard token-acquisition conditions.
The repeated Medium-parent-to-High-child desktop pattern remains source-native implausibility
without such a modeled path, but it is not universally impossible. The panel ranked the exact
cross-source integrity mismatch above the elevation-type finding.

### RDP `LogonGuid` bootstrap race versus repeated discontinuity

A zero Sysmon `LogonGuid` can result from provider timing or incomplete correlation at session
bootstrap. That makes any single `userinit.exe` or `explorer.exe` example ambiguous. The strength
comes from recurrence: the Detection Engineer found the zero-to-correct transition in all 15 Type
10 sessions and 30 bootstrap process records across five hosts, while the Host/EDR Analyst
independently confirmed at least five sessions on three hosts. Later children adopt the Security
4624 GUID under the same LogonId. The panel retained this as a repeated canonical session/process
identity contract gap, not a hard contradiction.

### Windows process-duration floor and collection boundaries

Collection boundaries can remove starts or terminations, but the Host/EDR finding uses 781
processes with both visible endpoints. Sysmon Event 5 delay or endpoint batching might blur exact
termination times, yet it does not plausibly impose a corpus-wide one-second floor while allowing
bounded utilities such as `whoami.exe`, `wevtutil.exe`, `net.exe`, and `dsquery.exe` to remain alive
for many seconds or, for three directory queries, 688–982 seconds. The panel judged this a strong
distribution fingerprint rather than a causality error.

### Standardized Linux images and cloned hardware

Standard images can explain shared package names, and cloned virtual machines can share broad
device families. They do not fully explain the combined pattern: MicroK8s, LXD, and
`snapd-desktop-integration` refresh activity across application, file, monitoring, mail, proxy,
external-web, laptop, and workstation roles, together with exact IRQ numbers, CPU assignments,
device names, and message strings repeated across unrelated hosts. The Detection and Host/EDR
specialists independently found the same issue. The panel therefore treated it as a strong
environment/distribution fingerprint, while allowing that a documented gold image or uniform
virtual hardware fleet could reduce its weight.

### Findings with credible benign alternatives

The panel did not elevate every reported anomaly. Missing SSH/RDP/PsExec initiating processes may
reflect source-coherent endpoint filtering, although their concentration around consequential
actions warrants a coverage check. Thirty-minute `sysstat` cadence is expected timer behavior,
especially because per-host phase, jitter, and skipped runs were present. Repeated static URLs with
different hashes can reflect CDN rotation, updates, or dynamic delivery, and CRON's timestamp
precision can differ by producer or ingestion path. Generic SMB filenames and repeated shell
commands are synthetic-looking vocabulary but remain weak compared with the exact contradictions.
Retained/disconnected RDP sessions were accepted as operationally plausible rather than treated as
a contradiction.

## Round 3 — Revised Positions

### Threat Hunter — revised to Synthetic

- **Final Verdict:** Synthetic
- **Final Verdict Confidence:** 89
- **Final Synthetic-Confidence Score:** 80
- **Change:** Verdict changed from Inconclusive; verdict confidence increased by 15 points and
  synthetic-confidence increased by 36 points.
- **Influence:** The exact-byte/SNI-matched proxy inversions, mandatory TLS 1.2 ECDHE history
  defect, same-process Windows integrity disagreement, and corpus-wide process-duration floor are
  stronger than the Threat Hunter's original command-pool and initiator-coverage concerns. The
  realistic kill chain and sensor diversity still moderate the score: they establish sophistication,
  not authenticity.

### Detection Engineer — remains Synthetic

- **Final Verdict:** Synthetic
- **Final Verdict Confidence:** 94
- **Final Synthetic-Confidence Score:** 87
- **Change:** Verdict unchanged; verdict confidence increased by 8 points and synthetic-confidence
  increased by 17 points.
- **Influence:** The Network Analyst's repeated proxy causality inversion and impossible ECDHE
  histories independently reinforce the Detection Engineer's Windows contradictions. The
  Host/EDR duration floor and WinSxS template finding add a second endpoint family beyond token and
  LogonGuid semantics. The elevation-type finding is retained with slightly reduced individual
  weight because valid alternate token configurations exist.

### Network Forensics — remains Synthetic

- **Final Verdict:** Synthetic
- **Final Verdict Confidence:** 97
- **Final Synthetic-Confidence Score:** 91
- **Change:** No score change.
- **Influence:** Cross-examination did not produce a credible explanation for the transaction-bound
  proxy ordering or the loss-free ECDHE histories. Endpoint findings from the other reviewers show
  that the problem is not isolated to one Zeek family, but the realistic connection topology and
  sensor clock structure continue to keep the score below absolute certainty.

### Host/EDR Forensics — remains Synthetic

- **Final Verdict:** Synthetic
- **Final Verdict Confidence:** 95
- **Final Synthetic-Confidence Score:** 89
- **Change:** Verdict unchanged; verdict confidence increased by 5 points and synthetic-confidence
  increased by 7 points.
- **Influence:** The Detection Engineer's all-session RDP measurement broadens the independently
  observed `LogonGuid` defect, while the Network Analyst contributes hard contradictions outside
  the endpoint corpus. The WinSxS suffix is still considered strong template evidence, but the
  panel ranks the proxy, TLS, exact integrity, and process-duration findings above it because the
  suffix's precise native derivation merits direct Windows-sample validation.

## Key Agreements

- The dataset has a strong production-like foundation. All reviewers credited source-native
  parsing, credible network topology and role placement, stable identities, realistic sensor-clock
  offsets, lifecycle ordering, DHCP behavior, firewall build/teardown pairing, and detailed
  process/network/file correlations.
- Discoverability, narrative completeness, and high cross-source correlation were not treated as
  synthetic indicators. The consensus rests on concrete source-native contradictions and repeated
  distribution defects.
- The proxy timing family is the highest-confidence failure: transaction-specific proxy-origin
  activity repeatedly occurs before the initiating CONNECT request.
- TLS 1.2 ECDHE histories without `K`, especially the 109 cases with no reported packet loss, are
  incompatible with the negotiated handshake and are not explained by ordinary collection gaps.
- Windows process/session truth is not consistently computed once and rendered everywhere. The
  exact integrity disagreements and repeated RDP `LogonGuid` transitions point to shared identity
  and token-contract defects.
- The Windows process-duration distribution lacks a credible short-lived tail, and Linux snap/IRQ
  baseline activity is insufficiently conditioned on host role, installed software, and hardware.
- Bounded-window semantics explain pre-window objects and end-of-window open connections; the
  panel did not use those as negative evidence.

## Key Disagreements

- **Overall authenticity:** Initially, the Threat Hunter viewed the production-like lifecycle and
  environmental entropy as sufficient for an inconclusive verdict. The other specialists regarded
  their exact contradictions as decisive. This disagreement was resolved when the Threat Hunter
  accepted that sophisticated broad correlation can coexist with family-level generator defects.
- **WinSxS suffix severity:** The Host/EDR Analyst considers the repeated suffix across three
  Windows builds a hard template leak. The rest of the panel accepts it as strong evidence but
  gives it less weight pending validation against native paths for the exact component identities.
- **TokenElevationType severity:** The Detection Engineer views the uniform use of `%%1936` for
  High-integrity processes as source-native implausibility. The panel agrees it is suspicious in
  the observed Medium-parent elevation pattern but does not call every High/default-token pairing
  impossible because alternate UAC/token configurations exist.
- **Missing initiating client processes:** The Threat Hunter sees the concentration around SSH,
  RDP, and PsExec as mildly artificial. Other panelists regard endpoint filtering or observation
  policy as a plausible explanation absent a demonstrated same-source lifecycle contradiction.
- **Weaker distribution clues:** CRON timestamp quantization, changing content at static URLs,
  generic SMB names, repeated shell vocabulary, and broad `sysstat` cadence remain debated because
  producer precision, CDN updates, shared operational practice, and timer configuration provide
  plausible benign explanations.

## Most Convincing Evidence

1. **Proxy child-before-parent causality:** In 392 of 522 exact-byte/SNI-matched successful tunnels,
   proxy-origin TCP begins before the initiating CONNECT; in 115, outbound TLS is also detected
   first. The concrete `proxy.wellbridge.io` transaction remains inverted at both core and DMZ
   observation times.
2. **Impossible TLS 1.2 ECDHE histories:** 122 of 586 non-resumed ECDHE sessions omit mandatory
   ServerKeyExchange marker `K`; 109 report no missing bytes.
3. **Same-process Windows integrity disagreement:** Five Security 4688/Sysmon Event 1 pairs on
   three hosts identify the same process across all join fields but render Medium in Security and
   High in Sysmon.
4. **Corpus-wide Windows process-lifetime floor:** None of 781 visible create/terminate pairs lasts
   under one second, only two last under two, none of 25 transient utilities ends under three
   seconds, and three `dsquery.exe` instances last roughly 688–982 seconds.
5. **Host-independent template leakage:** A WinSxS suffix is reused across three incompatible
   servicing-stack versions, while exact Linux IRQ/device/CPU messages and implausibly broad snap
   inventories recur across unrelated roles. The combined Windows/Linux evidence is stronger than
   either environment clue alone.

## Most Debated Points

- Whether a proxy connection pool could explain early origin TCP starts. The panel accepted that
  pooling can precede CONNECT but rejected it as a complete explanation for transaction-specific
  outbound TLS tied by exact SNI and byte counts before the target-bearing request.
- Whether zero `LogonGuid` on `userinit.exe`/`explorer.exe` could be a real provider race. One case
  could be; the identical zero-to-correct transition across all 15 Type 10 sessions makes a
  deterministic bootstrap contract more likely.
- Whether standardized Linux images or cloned hypervisor hardware could explain shared snap and
  IRQ telemetry. They can explain some overlap, but not the breadth of role-inappropriate software
  plus exact mixed-device mappings without explicit environmental evidence.
- Whether the reused WinSxS suffix is intrinsically impossible across versions. It remains highly
  suggestive, but the panel recommends validating the exact assembly-name construction against
  native samples before using it alone as a release gate.
- Whether process-observation gaps around SSH/RDP/PsExec are defects. The panel retained them as a
  moderate coverage concern because filtering is plausible and no impossible visible ordering was
  demonstrated.

## Improvement Recommendations (Consensus)

1. **Repair proxy causality at the transaction owner.** Anchor destination discovery and every
   transaction-specific origin action to the observed CONNECT request. Enforce the ordering
   `CONNECT request -> origin TCP open -> outbound TLS detection -> CONNECT response`, while
   modeling reusable preconnected pools as explicit preexisting resources that cannot carry a
   transaction-specific handshake before the destination is known. Add high-volume invariant tests
   using exact tunnel identity, not only timestamp spot checks.

2. **Generate protocol histories from negotiated TLS state.** For full TLS 1.2 ECDHE handshakes,
   require ServerKeyExchange `K` unless a modeled directional capture gap removes the packet and is
   reflected coherently in loss/analyzer state. Emit realistic `established:false` SSL records for
   visible aborted handshakes, or avoid assigning `service:"ssl"` when TLS was not observed well
   enough to create a companion record.

3. **Use one canonical process/session token identity across Windows sources.** Derive mandatory
   integrity, Sysmon integrity label, elevation type, LogonId, and `LogonGuid` once per process and
   session. Render the same truth into Security, Sysmon, and eCAR; ensure RDP bootstrap processes
   receive the session GUID before `userinit.exe` and `explorer.exe` are emitted. Add cross-source
   invariants for exact process joins and every Type 10 bootstrap path.

4. **Replace the Windows process-duration floor with executable-class lifetime models.** Give
   bounded local utilities a heavy sub-second tail; reserve longer durations for blocking, remote,
   interactive, or explicitly delayed operations. Test the fleet-level quantiles as well as named
   utilities so a hidden minimum cannot recur through sibling paths.

5. **Condition Linux background telemetry on persistent host inventory.** Build snap refreshes from
   role-appropriate installed-package state and IRQ messages from a stable per-host hardware map.
   Gold-image cohorts may share components, but server roles should not inherit MicroK8s,
   desktop-integration, and identical mixed IRQ/device topology without modeled justification.

6. **Derive complete WinSxS paths from native component identity.** Validate exact folder naming
   against native examples for each supported Windows build and component version, then generate
   the suffix from the full identity rather than reusing a path fragment. Add a cross-build
   uniqueness/validity test after that native rule is confirmed.

7. **Make source-native Zeek analyzer provenance self-consistent.** Populate
   `files.analyzers` from the analyzers actually represented: hash analyzers for emitted digests,
   `PE` for `pe.json` companions, and the appropriate OCSP analyzer for OCSP-derived records.
   Validate every companion record back to its FUID and analyzer set.

8. **Preserve application-event timing across sensor observations.** Start from one canonical
   packet/event anchor, then apply stable sensor-clock offset and direction-appropriate propagation
   delay. Avoid independent per-record jitter that causes HTTP/SSL/file residuals of hundreds of
   milliseconds while DNS preserves sensor offset to microseconds.

9. **Stabilize content identity and make observation gaps coherent.** Reuse one content identity
   for the same static URL within a plausible publication epoch; model explicit deployment/CDN
   boundaries when content changes. For remote-administration client processes and TLS certificate
   extraction, either retain expected companions or express source-coherent observation loss
   across the relevant lifecycle rather than selectively omitting consequential records.

10. **Expand human vocabulary only after the hard contracts are fixed.** Add role-, operator-, and
    host-history-specific Linux commands and SMB filenames, preserving realistic repetition within
    one operator while avoiding identical diagnostic sets across unrelated users and roles. The
    panel considers this lower leverage than proxy, TLS, Windows identity, lifetime, and inventory
    repairs.
