# Deliberation Summary

## Round 1 — Present Findings

### Threat Hunter

The Threat Hunter's initial verdict is **Synthetic**, with **96% verdict confidence** and an
**86/100 synthetic-confidence score**. The strongest evidence is: (1) all 18 complete Linux DHCP
transactions preserve the same final three microsecond digits across separate request, ACK, and
bound records; (2) the endpoint ACK timing repeatedly disagrees by more than a second with the
corresponding Zeek DHCP transaction completion; and (3) one Nmap connect scan varies a same-host,
same-route SYN packet-size property across four values. The specialty-specific observations are
the operationally wrong reverse-shell process owner, serialized one-second browser asset timing,
templated SMB/SYSVOL vocabulary, and fleet-wide `debian-sa1` texture. The Hunter also emphasizes
that topology, attack pivots, source volume, SSH lifecycles, Windows attack ordering, and Security
log clearing are convincing.

### Detection Engineer

The Detection Engineer's initial verdict is **Synthetic**, with **61% verdict confidence** and a
**54/100 synthetic-confidence score**. The strongest evidence is: (1) 145 of 215 tightly matched
Kerberos Type 3 logon/TGS associations put the TGS after the successful 4624; (2) six short-window
sequences put a TGS before a TGT for the same account, address, and KDC port; and (3) one correlated
4771 failure omits the client address even though neighboring evidence identifies a remote
workstation. The specialty-specific contribution is broad schema validation: Windows event
versions, tasks, fields, PIDs, GUIDs, hashes, Zeek UIDs, protocol tuples, Snort joins, and ASA
lifecycle pairs are unusually strong. Because cached or renewed tickets can explain individual
Kerberos examples, this expert treats the timing pattern as generator-like texture rather than a
hard contradiction.

### Network Forensics

The Network Forensics Analyst's initial verdict is **Synthetic**, with **87% verdict confidence**
and a **74/100 synthetic-confidence score**. The strongest evidence is: (1) all 971 matched
multi-sensor DNS transactions copy the exact same RTT despite independent UIDs and differing
sensor timestamps; (2) 176 SSL-classified connections lack SSL companions, including 18 clean,
completed, lossless `SF` connections, while every emitted SSL record says `established:true`; and
(3) all 2,429 SSL records omit ALPN, curve, validation, and alert fields. Unique specialty findings
include one-and-done public HTTP clients, URI-derived-looking MIME types on redirects, and a narrow
TLS negotiation vocabulary. Against those findings, transport states, DNS breadth, sensor-local
UIDs, scan pacing, firewall accounting, byte/loss arithmetic, certificate reuse, and topology are
judged production-like.

### Host/EDR Forensics

The Host/EDR Forensics Analyst's initial verdict is **Synthetic**, with **91% verdict confidence**
and a **74/100 synthetic-confidence score**. The strongest evidence is: (1) four RDP
`userinit.exe` events report the interactive user as `ParentUser` even though each exact parent
GUID resolves to SYSTEM-owned `winlogon.exe`; (2) eCAR reports SYSTEM for those same parents,
creating a direct source-to-source disagreement; and (3) every visible RDP `userinit.exe` survives
31–165 minutes while all nine ordinary instances exit in roughly 3–5 seconds. The specialty-specific
observations are invariant Sysmon-before-4688 delay bounds, isolated missing half-hour cron runs
during otherwise continuous collection, and a narrow `SearchFilterHost.exe` argument pool. This
expert nevertheless finds process identity, GUID lifecycle, hashes, logons, Linux SSH, shell
decomposition, host roles, and user differentiation highly credible.

## Round 2 — Cross-Examination

### Contradictions and points of friction

1. **DHCP looks realistic at the network layer but algorithmic across sources.** The Network
   Analyst considers lease lengths and T/2 renewal jitter plausible. The Threat Hunter does not
   dispute that macro behavior; the challenge is at finer resolution: repeated shared
   microsecond suffixes across separately written endpoint records and Zeek completion times that
   precede endpoint ACKs by more than a second. These positions are compatible. The network
   cadence can be realistic while timestamp materialization is synthetic. The Hunter's evidence
   is stronger on this narrow issue because it is repeated across every complete observed
   transaction and compares both endpoint and network views.

2. **The Nmap scan is behaviorally convincing but packet-profile consistency is disputed.** The
   Network Analyst finds the `/24` five-port burst, state mix, pacing, and responsive-host pattern
   credible. The Threat Hunter finds four different one-SYN IP-byte sizes from one scanner on the
   same route implausible. Again, the claims address different levels: the scan plan can be
   convincing while packet construction varies in a generator-like way. A route, stack, or option
   change could explain isolated variation, but no such distinction is present in the reported
   pattern. The packet-size finding therefore remains meaningful, although less decisive than the
   RDP or DNS contradictions because only one expert tested it.

3. **Kerberos timing is suggestive, not conclusive.** The Detection Engineer sees a dataset-wide
   post-logon TGS majority and six TGS-before-TGT micro-inversions. Other experts describe Windows
   authentication and attack sequences as credible. Cached tickets, renewal, separate service
   connections, and ambiguous event association provide real alternatives; the Detection
   Engineer explicitly acknowledges these. The repeated narrow timing is retained as supporting
   distribution evidence, but it cannot carry the verdict as strongly as exact parent-GUID
   disagreement or copied DNS measurements.

4. **TLS companion gaps may reflect collection policy, but the aggregate pattern needs an
   explanation.** Missing SSL rows for resets or incomplete handshakes can be normal, and optional
   TLS fields can be absent under some Zeek versions or configurations. The stronger network
   challenge is the combination: 18 clean `SF` connections with payload also lack companions,
   every emitted SSL row is successful, and negotiation/alert variation is universally absent.
   An undocumented analyzer or field-removal policy could explain part of this, so the panel treats
   it as a strong contract/schema gap rather than an impossible event ordering.

5. **Fleet scheduling has both a legitimate and a synthetic explanation.** Three experts notice
   the stable `debian-sa1` half-hour grid. Central management can create host-phased schedules, so
   regularity alone is not decisive. The Host Analyst's isolated missing scheduled executions
   during otherwise continuous telemetry makes probabilistic thinning more suspicious, while the
   Threat Hunter's concern about the principal and cadence depends on package configuration not
   established in the reports. The panel retains this as moderate distribution texture, not a
   hard contradiction.

### Blind spots that affect other verdicts

- The Detection Engineer's near-uncertain score did not account for the Host Analyst's exact
  Sysmon parent GUID resolution and eCAR disagreement. That is stronger than a generic “templated
  process tree” claim: two rendered sources disagree about the same visible parent identity.
- The Threat Hunter and Detection Engineer praise network correlations but did not report testing
  sensor-derived DNS RTT independence. Exact equality in all 971 matched transactions materially
  changes the weight assigned to otherwise excellent multi-sensor correlation.
- The Network Analyst's positive DHCP assessment does not invalidate the Hunter's endpoint
  timestamp fingerprint because the former addresses renewal cadence and the latter addresses
  source-native timestamp generation and transaction completion.
- The Host Analyst's positive process-lifecycle assessment remains compatible with the Hunter's
  reverse-shell concern: the broad lifecycle graph can be sound while one shell pipeline omits the
  socket-owning child. Missing child telemetry is a plausible alternative, so this remains a
  contract gap rather than an independently decisive contradiction.

### Strength challenges

- **Complete cross-source matching and bounded source delays:** All experts agree that accurate
  joins, high coverage, stable UIDs, or clean source ordering are not synthetic indicators by
  themselves. They remain affirmative realism evidence. Only concrete contradictions or repeated
  implausible distributions are retained.
- **RDP `ParentUser`:** A field-rendering convention could be proposed as an alternative, but the
  exact parent ProcessGUID identifies a SYSTEM process and eCAR independently reports that parent
  as SYSTEM. Repetition in all four visible RDP bootstraps makes the contradiction difficult to
  dismiss.
- **RDP `userinit.exe` duration:** One hung logon script could be real. Four of four RDP instances
  inheriting session-length lifetimes, contrasted with nine short non-RDP instances, makes a
  lifecycle contract error the stronger explanation.
- **Copied DNS RTT:** Stable sensor clock offsets do not explain identical request/response
  duration measurements across every match, especially when other sensor-local durations differ.
  Canonical RTT reuse is the stronger explanation.
- **Public HTTP uniqueness and narrow TLS vocabulary:** A six-hour quiet-window sample, upstream
  NAT, filtering, or a homogeneous client population can produce constrained traffic. These remain
  supporting texture and should not determine the verdict independently.

## Round 3 — Revised Positions

### Threat Hunter

**Final position: Synthetic; 96% verdict confidence; 88/100 synthetic-confidence.** The verdict is
unchanged. The exact RDP parent-identity contradiction and universal cross-sensor DNS RTT reuse
independently reinforce the Hunter's DHCP evidence. Confidence remains near its ceiling, while the
synthetic-confidence score rises slightly. The panel's strong schema, topology, lifecycle, and
correlation findings prevent a higher score.

### Detection Engineer

**Final position: Synthetic; 84% verdict confidence; 76/100 synthetic-confidence.** This is the
largest revision. The expert's own Kerberos timing remains probabilistic, but the Host Analyst's
GUID-resolved Sysmon/eCAR contradiction and the Network Analyst's all-match DNS RTT duplication
provide concrete, specialty-validated evidence that was absent from the initial assessment. The
verdict does not change, but both confidence and synthetic-confidence increase materially.

### Network Forensics

**Final position: Synthetic; 92% verdict confidence; 81/100 synthetic-confidence.** The network
verdict is unchanged. The Threat Hunter's DHCP timestamp fingerprint resolves the apparent tension
with otherwise plausible lease cadence, while the Host Analyst supplies an independent source-native
contradiction outside the network family. The score rises, but remains below “certain” because
transport, DNS content, certificate, firewall, and cross-sensor topology evidence is strong.

### Host/EDR Forensics

**Final position: Synthetic; 95% verdict confidence; 82/100 synthetic-confidence.** The host
verdict is unchanged. Exact DNS RTT reuse and repeated DHCP timestamp construction provide
independent corroboration that the RDP defect is not an isolated emitter mistake. Confidence and
synthetic-confidence rise, tempered by the otherwise credible process graph, hash stability,
logon lifecycles, Linux SSH evidence, and differentiated endpoint activity.

## Round 4 — Consensus Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 96% | 86/100 | Synthetic | 96% | 88/100 |
| Detection Engineer | Synthetic | 61% | 54/100 | Synthetic | 84% | 76/100 |
| Network Forensics | Synthetic | 87% | 74/100 | Synthetic | 92% | 81/100 |
| Host/EDR Forensics | Synthetic | 91% | 74/100 | Synthetic | 95% | 82/100 |

The final panel verdict is unanimous: **Synthetic**. The mean final synthetic-confidence score is
**81.75/100**. Consensus is based on several independent, repeated, source-native defects rather
than on the dataset being complete, well correlated, narratively clear, or unusually clean.

## Key Agreements

- The dataset is sophisticated and frequently production-like. All four experts credit its field
  formats, host roles, network topology, process and session lifecycles, attack pivots, source
  volumes, and cross-source joins.
- The RDP `ParentUser` mismatch is a concrete source-native contradiction because the visible
  parent GUID and eCAR source principal both identify SYSTEM, while Sysmon identifies the
  interactive user.
- Exact DNS RTT reuse across every matched sensor observation is a strong generator fingerprint;
  independent sensor identities and timestamps should produce at least some measurement variation.
- The DHCP family combines a repeated timestamp-construction fingerprint with cross-source
  transaction-completion disagreement. Plausible lease cadence does not resolve those defects.
- Strong correlation, comprehensive telemetry, and consistently bounded collection delays are not
  synthetic evidence by themselves and should remain realism strengths.

## Key Disagreements

- Kerberos event ordering remains disputed in strength. The Detection Engineer sees repeated
  generator-like timing, while cached tickets and ambiguous event association prevent the panel
  from calling the individual inversions impossible.
- The scan's behavioral shape is accepted as realistic, but its per-probe SYN byte-size variation
  remains suspicious. The panel lacks an independent specialist reproduction of that detail.
- TLS companion omissions and absent negotiation fields are strong realism gaps, but an explicit
  analyzer or collection policy could explain part of the pattern. The reports do not establish
  such a policy.
- Fleet-wide sysstat scheduling is plausibly centrally managed; isolated omissions during otherwise
  continuous collection make it suspicious, but not decisive.
- Reverse-shell process ownership, public-client uniqueness, redirect MIME typing, browser timing,
  SMB vocabulary, and Windows Search arguments remain useful secondary findings rather than panel-wide
  verdict anchors.

## Most Convincing Evidence

1. **RDP parent identity contradiction:** four Sysmon events conflict with their exact visible
   SYSTEM-owned parent GUIDs and with eCAR's rendering of the same parent relationship.
2. **Cross-sensor DNS RTT duplication:** all 971 matched transactions reuse bit-identical derived
   RTT values despite distinct sensor timestamps and UIDs.
3. **DHCP timestamp fingerprint:** all 18 complete endpoint transactions preserve a transaction-level
   microsecond suffix across separate records, coupled with repeated Zeek/endpoint ACK disagreement.
4. **RDP `userinit.exe` lifecycle split:** all four RDP instances last 31–165 minutes while all nine
   ordinary instances terminate in roughly 3–5 seconds.
5. **TLS lifecycle outcome collapse:** SSL companions are absent for 176 SSL-classified flows,
   including 18 clean completed flows, while every emitted SSL record represents success and omits
   common negotiation or failure-state texture.

## Most Debated Points

- Whether clustered Kerberos TGS/TGT/logon timestamps are causal inversions or coincidental matches
  involving cached or renewed tickets.
- Whether the TLS omissions reflect synthetic lifecycle modeling or an undocumented Zeek analyzer,
  field-removal, or collection policy.
- Whether centrally managed sysstat schedules can explain both the half-hour phase grid and isolated
  missing executions without neighboring source loss.
- Whether varying SYN sizes inside one connect scan could arise from a real stack/path distinction
  not visible in the reviewed evidence.
- How much weight to give thin public HTTP recurrence and narrow protocol vocabularies in a bounded
  six-hour collection window.

## Improvement Recommendations (Consensus)

1. **Make observation timing source-local while preserving canonical causality.** Give each DHCP
   endpoint message an independently resolved timestamp, align Zeek DHCP duration with the observed
   ACK lifecycle, and derive DNS RTT from each sensor's own request/response timestamps. Apply delay
   coherently to Kerberos transactions so likely TGT, TGS, service authentication, and logon phases
   do not receive independent jitter that creates repeated micro-inversions.

2. **Correct RDP parent identity and process ownership.** Render Sysmon `ParentUser` from the exact
   canonical parent process identity, keeping `winlogon.exe` as SYSTEM. Give `userinit.exe` a short
   initialization lifecycle independent of the RDP session, leaving long-lived ownership to the
   session, shell, and appropriate desktop processes.

3. **Complete TLS lifecycle rendering.** Emit SSL analyzer rows for classified sessions when
   sufficient protocol evidence exists, including failed and partial handshakes with appropriate
   `established:false`/alert semantics; otherwise avoid classifying the connection as SSL. Populate
   ALPN, curve, validation, and alert fields according to endpoint capability and modeled parser
   visibility rather than leaving them universally absent.

4. **Stabilize host-stack properties within coherent network activities.** Select TCP SYN options
   and resulting header size from a per-host/per-stack profile and keep them stable through a
   same-interface, same-route scan unless an explicit route or stack change explains variation.

5. **Preserve process-level causality for shell pipelines.** Materialize observed `echo`, `base64`,
   and nested shell children when collection depth implies they should be visible, and attribute
   `/dev/tcp` flow ownership to the socket-owning process. If that process is not observed, omit the
   process attribution instead of assigning it to an incorrect ancestor.

6. **Replace probabilistically thinned periodic jobs with explicit schedule/collection semantics.**
   Model cron or systemd timer behavior by distribution and host role. If a deterministic execution
   is absent, couple that absence to a plausible source outage, timer state, package state, or
   explicit collection decision rather than an isolated random skip.

7. **Broaden bounded public-service texture without using completeness as a target.** Add skewed
   repeat-client frequencies, connection reuse, NAT-shared clients, bots/scanners, mobile and legacy
   user-agent tails, and occasional malformed requests. Determine redirect MIME from the actual
   rendered response body and status representation, and vary browser asset concurrency and cache
   behavior where the visible application protocol supports it.

