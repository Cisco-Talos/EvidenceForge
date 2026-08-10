# Loop 49 Blind Expert-Panel Deliberation

## Round 1 — Initial Positions

### Threat Hunter

- **Verdict:** Synthetic
- **Verdict confidence:** 72/100
- **Synthetic-confidence score:** 66/100

The threat hunter judged the corpus to be a strong, production-style synthetic dataset rather
than an obviously fabricated one. The strongest evidence was a duplicate RDP shell bootstrap on
`WS-AJOHNSON-01`: one Type 10 session, one LogonGuid, one LogonId, and one terminal session
produced two nearly simultaneous `userinit.exe -> explorer.exe` chains. The second major signal
was repeated Linux operational texture, especially root-owned one-shot `wget` health checks that
used the same command shape against a broad pool of unrelated SaaS domains. A third concern was
the density and breadth of named-user SSH administration across many host roles during only six
hours.

The threat hunter's specialty-specific observation was that the attack itself remains highly
huntable and temporally coherent. Web exploitation, reverse shell, discovery, credential access,
lateral movement, persistence, collection, proxy-mediated exfiltration, and cleanup can be
reconstructed through multiple source families. Cross-sensor routing, proxy accounting, process
lifecycle, and source-specific imperfections strongly favor authenticity. The synthetic verdict
therefore rested on a localized lifecycle defect plus repeated operational texture, not on an
implausibly neat attack narrative.

### Detection Engineer

- **Verdict:** Synthetic
- **Verdict confidence:** 74/100
- **Synthetic-confidence score:** 66/100

The detection engineer treated the RDP bootstrap issue as the deciding defect and supplied the
strongest corroboration. On `WS-AJOHNSON-01`, a single 4624 Type 10 logon and one `winlogon.exe`
were followed by two separate `userinit.exe` children and two corresponding `explorer.exe`
children under the same Logon ID. The same semantic duplication recurred on `WS-MCHEN-01`, again
with one Type 10 logon but two initialization trees within milliseconds. Because the duplicates
have distinct PIDs and valid local parentage, the engineer interpreted this as duplicate semantic
ownership rather than duplicated collection records.

The secondary evidence was a reused Linux administration template: 65 sudo episodes across
unrelated roles used the same small identity pool and the same successful command/open/close
shape, including interactive PTYs for service-like accounts. The detection engineer nevertheless
found excellent Windows, eCAR, Zeek, firewall, SMTP, IDS, and cross-source contracts outside the
RDP defect. In particular, event identifiers, process dependencies, protocol companions, packet
accounting, sensor-specific loss, ASA lifecycles, and mail queue propagation were all strong.

### Network Forensics Analyst

- **Verdict:** Synthetic
- **Verdict confidence:** 72/100
- **Synthetic-confidence score:** 68/100

The network analyst reached a synthetic verdict without finding a hard protocol contradiction.
The strongest evidence was distributional. All 1,857 matching core/DMZ observations placed the
DMZ timestamp after the core timestamp in a narrow 41.655-66.399 ms band. DHCP renewal intervals
were nearly fixed per client, with only roughly one to three seconds of variation across the full
window. Public HTTP traffic also had a small vocabulary: 64 requests from 60 external IPs used
only seven user agents, eleven URIs, and the GET method.

A further specialty-specific observation was the sharp separation of timing regimes. External
DNS RTTs frequently landed on exact millisecond values, while internal RTTs retained microsecond
texture. Against those signals, the analyst found excellent Zeek parent/child timing, connection
states and histories, TLS certificate/FUID references, firewall build/teardown pairing, proxy
semantics, HTTP transaction depth, dual-sensor scoping, and IDS tuple alignment. The analyst's
case was therefore explicitly cumulative and distributional, not based on malformed network
evidence.

### Host/EDR Forensics Analyst

- **Verdict:** Inconclusive
- **Verdict confidence:** 62/100
- **Synthetic-confidence score:** 56/100

The host analyst found the endpoint evidence unusually coherent and did not identify a hard
lifecycle contradiction during the independent review. The strongest synthetic indicators were
closed behavioral pools: only seven or eight distinct process-access `call_trace` strings per
Windows host across many records; a common palette of generic updater, COM, WMI, and telemetry
processes across unrelated roles; and 1,066 UFW scan records whose advertised TCP windows came
from exactly three values. Common Linux maintenance vocabulary and dense privileged access added
moderate support.

The host analyst's strongest evidence favoring authenticity was the absence of visible process
dependency inversions, the integrity of eCAR create/dependent/terminate relationships, correct
handling of window-boundary lifecycle gaps, stable hashes by executable build, coherent Windows
Security and Sysmon formatting, realistic SSH/PAM/logind ordering, and a causally explained
Security-log reset. The resulting position stayed inconclusive because the generator-like
distribution texture did not, in that independent review, overcome the strength of the endpoint
contracts.

## Round 2 — Cross-Examination

### 1. Is the duplicate RDP bootstrap a decisive contract defect?

The detection engineer challenged the host analyst's statement that no hard lifecycle
contradiction was visible. The challenge was concrete rather than categorical: the engineer
identified two affected workstations, each with one successful Type 10 logon and one
`winlogon.exe`, but two distinct `userinit.exe -> explorer.exe` trees sharing the same session
identity. The threat hunter independently found the `WS-AJOHNSON-01` instance and matched it to
the same LogonGuid, LogonId, and terminal session.

The host analyst's initial statement did not offer a normal Windows mechanism that would explain
the duplicated trees and did not dispute the identifiers or timing. It reported that no such
defect had been found in the host-focused pass. Once the two reports were compared, that absence
of discovery could not outweigh the specific repeated examples. A simple collection duplicate
was also a poor alternative explanation: the processes have distinct PIDs, form valid but
parallel parent-child chains, and are not accompanied by a second 4624 or second transport
session.

The panel therefore distinguished two questions:

1. **Is it a decisive local contract defect?** Yes. Most of the panel accepted that one modeled
   interactive session has acquired two owners for its initial shell lifecycle. The recurrence on
   two hosts makes an incidental shell restart or one-off logging anomaly substantially less
   persuasive.
2. **Does it invalidate the entire dataset?** No. It is localized. The same reports document
   strong process, network, mail, firewall, proxy, and sensor contracts elsewhere. It is decisive
   evidence about synthetic construction, not evidence that the corpus is broadly unusable or
   technically crude.

This distinction mattered to the scoring. The defect moved the categorical authenticity decision
toward Synthetic, but the extensive realism elsewhere kept synthetic-confidence scores in the
likely-synthetic range rather than the confidently-synthetic range.

### 2. Do strong source-native contracts rebut the synthetic verdict?

The host and network findings posed the strongest challenge to the two RDP-focused positions.
Across 25,305 eCAR records and 11,663 Zeek connections, the reports found unique identifiers,
ordered dependencies, coherent lifecycle termination, valid protocol companions, defensible
packet accounting, certificate integrity, and sensor-appropriate visibility. ASA, SMTP, proxy,
IDS, audit-clear, and SSH evidence also retained native semantics rather than appearing as exact
cross-source copies.

The threat hunter and detection engineer did not treat that coherence as suspicious completeness.
Both explicitly credited sensor-local UIDs, timestamp differences, missing bytes, source-specific
byte scopes, and incomplete sibling visibility as realistic collection behavior. The network
analyst likewise argued that contract correctness and synthetic distribution texture can coexist.
The panel's resolution was that source-native realism is strong evidence against a simplistic or
high-confidence synthetic judgment, but it does not explain the duplicated session ownership or
the repeated closed pools. It lowers the magnitude of the synthetic-confidence score; it does not
reverse the balance of evidence.

### 3. Are the distribution findings independent, or one over-read notion of regularity?

The panel challenged each regularity with plausible real-world alternatives:

- Stable DHCP renewal periods are expected from T1 timers, but arbitrary per-client periods with
  uniformly small jitter and no acquisition, NAK, lease-loss, or delayed-renewal texture are more
  regular than the timer explanation alone predicts.
- A stable core-to-DMZ clock relationship is expected, but all 1,857 offsets being positive and
  confined to a roughly 25 ms band resembles bounded latency injection more than independent
  clocks with skew and drift.
- Repeated call traces are normal for repeated Windows code paths, but seven or eight traces reused
  across broad source/target combinations form a conspicuously closed population.
- Stable TTL and packet length per scanner source are realistic fingerprints, but selecting every
  advertised window from the same three-value global pool weakens the campaign-profile
  explanation.
- Cron, `systemd`, updater, and health-check repetition is expected, but common command families,
  generic identities, broad target pools, and shared success-only lifecycles across unrelated host
  roles reduce role specificity.
- A quiet six-hour public HTTP sample can be small, but 60 external addresses converging on only
  seven user agents, eleven URIs, and GET-only behavior is unusually compressed for an
  Internet-facing service.

No single distribution finding was promoted to a hard contradiction. Their force came from
independent manifestations across network timing, DHCP, DNS, HTTP, Windows call traces, Linux
administration, and UFW fingerprints. Because those observations arose in three specialties,
they were less plausibly dismissed as one analyst over-reading a single quiet interval.

### 4. Does the visible attack story look too explicit?

The threat hunter noted highly explicit malicious command lines and unusually complete rendering
of selected attack actions; the host analyst made a related observation about the exhaustive DB
export pipeline. The detection engineer challenged this as weak evidence because native endpoint
telemetry can legitimately expose exact command lines, and the attack remains operationally
detectable without narrative knowledge.

The panel agreed that explicit malicious commands are at most a supporting signal. They are not a
contradiction, and weakening attack evidence merely to make the corpus harder to classify would
reduce hunting utility. The more persuasive issue is whether benign populations and lifecycle
ownership look generated, not whether the malicious activity is understandable.

### 5. What would have changed the network analyst's verdict?

The network analyst had no protocol-level contradiction and therefore depended most on cumulative
texture. A credible explanation for the one-way sensor offsets as stable measured clock skew plus
path delay, explicit DHCP T1/T2 behavior, and a richer public-client population would materially
weaken that verdict. None of the other reports supplied such explanations. Instead, the host and
Linux findings added separate closed-pool behavior, while the RDP evidence supplied a concrete
non-network contract failure. That combination strengthened, rather than displaced, the network
analyst's likely-synthetic position.

## Round 3 — Revised Positions

### Threat Hunter — Revised Position

- **Final verdict:** Synthetic
- **Final verdict confidence:** 77/100
- **Final synthetic-confidence score:** 70/100

The verdict did not change. Confidence rose because the detection engineer found the same RDP
duplication on a second workstation, making a one-off endpoint anomaly less credible. The network
analyst's independent DHCP, sensor-offset, DNS-latency, and public-HTTP findings broadened the
case beyond host activity recipes. The synthetic-confidence score rose only modestly because the
host and network reviews reinforced that the bulk of source-native and cross-source behavior is
technically strong.

### Detection Engineer — Revised Position

- **Final verdict:** Synthetic
- **Final verdict confidence:** 78/100
- **Final synthetic-confidence score:** 70/100

The verdict remained Synthetic. The engineer continued to regard duplicate RDP ownership across
two hosts as decisive for classification. Independent network timing and distribution findings,
plus the host analyst's call-trace and UFW pools, increased confidence that this was part of a
broader generation-texture problem rather than an isolated authoring mistake. Strong network,
mail, firewall, proxy, and eCAR contracts capped the synthetic-confidence score at 70 rather than
supporting a confident-synthetic score.

### Network Forensics Analyst — Revised Position

- **Final verdict:** Synthetic
- **Final verdict confidence:** 75/100
- **Final synthetic-confidence score:** 70/100

The network verdict did not change. The host-side RDP evidence supplied the concrete contract
defect absent from the analyst's own protocol review, while the host analyst's compact trace and
UFW pools independently echoed the network distribution findings. Verdict confidence increased,
but only slightly: the network sources themselves remain highly coherent, and no hard network
protocol contradiction was found.

### Host/EDR Forensics Analyst — Revised Position

- **Final verdict:** Synthetic
- **Final verdict confidence:** 69/100
- **Final synthetic-confidence score:** 64/100

The host analyst revised from Inconclusive to Synthetic. The deciding new evidence was the
detection engineer's two-host RDP comparison, corroborated independently by the threat hunter on
one host. Distinct parallel PIDs under one Logon ID, without a second logon or `winlogon.exe`, are
not rebutted by the broader absence of dependency inversions. The host analyst retained the
lowest final synthetic-confidence score because endpoint formatting, ancestry, SSH lifecycles,
hash stability, audit clearing, and role-shaped volumes remain unusually strong.

Verdict confidence and synthetic-confidence remain intentionally distinct throughout these
revisions. Verdict confidence expresses each expert's confidence that the selected category is
the best of the available verdicts. Synthetic-confidence expresses the estimated strength of the
synthetic-origin inference itself. An expert can therefore be fairly confident that Synthetic is
the best label while assigning only a mid-to-high-60s or 70 synthetic-confidence score because
substantial evidence still resembles real production telemetry.

## Round 4 — Consensus Summary

# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 72/100 | 66/100 | Synthetic | 77/100 | 70/100 |
| Detection Engineer | Synthetic | 74/100 | 66/100 | Synthetic | 78/100 | 70/100 |
| Network Forensics | Synthetic | 72/100 | 68/100 | Synthetic | 75/100 | 70/100 |
| Host/EDR Forensics | Inconclusive | 62/100 | 56/100 | Synthetic | 69/100 | 64/100 |

The final panel consensus is **Synthetic**, specifically **likely synthetic rather than
confidently synthetic**. All four experts select Synthetic after deliberation. Final categorical
verdict confidence ranges from 69 to 78, while final synthetic-confidence ranges from 64 to 70.
Those ranges reflect a corpus with a decisive localized construction defect and broad
distributional tells, but also unusually strong source-native realism.

## Key Agreements

- The duplicate RDP bootstrap is a real and decisive **session-ownership contract defect**. One
  successful Type 10 session should not produce two initial `userinit.exe -> explorer.exe` trees
  under the same session identity without an explicit second logon or restart. Its recurrence on
  two hosts makes duplicate generation ownership the strongest explanation.
- The RDP defect is localized. It does not negate the generally excellent lifecycle handling in
  eCAR, Windows, Zeek, ASA, proxy, SMTP, IDS, SSH, and audit-clear evidence.
- The network evidence is structurally and semantically strong. Parent/child records, UID/FUID
  references, TLS certificates, packet accounting, proxy byte scopes, firewall lifecycles, and
  IDS tuples were all judged convincing.
- Synthetic texture appears across several independent distributions: network clock/latency
  envelopes, DHCP cadence, external DNS precision, public HTTP vocabulary, Windows call traces,
  UFW fingerprints, Linux administrative identities, and generic maintenance/activity families.
- Explicit attack command lines and comprehensive attack reconstruction are weak evidence by
  themselves. The attack remains plausible and useful for hunting.
- No expert supported a high-confidence or near-certain synthetic classification. Strong native
  schemas, host-role differentiation, cross-source agreement, and realistic collection
  imperfections materially constrain the final scores.

## Key Disagreements

The principal initial disagreement was between the host analyst's Inconclusive verdict and the
other three Synthetic verdicts. The host analyst found no lifecycle contradiction and gave more
weight to coherent ancestry, principals, hashes, lifecycle boundaries, SSH ordering, and audit
clearing. The detection engineer's two-host RDP evidence resolved that disagreement because it
was specific, repeated, and not explained by a collection duplicate. The host analyst revised the
verdict but retained lower confidence because most endpoint contracts remained strong.

The panel did not assign identical weight to distributional evidence. The network analyst treated
DHCP cadence, sensor offsets, and public HTTP compression as the primary case; the threat hunter
and detection engineer treated the RDP defect as primary and distribution texture as support.
The host analyst remained most cautious about inferring origin from closed pools because many
individual repetitions have legitimate operational explanations. Consensus was reached on their
cumulative value, not on any single distribution pattern being conclusive.

## Most Convincing Evidence

1. **Duplicate RDP session bootstrap on two workstations.** One Type 10 logon and one
   `winlogon.exe` produce two distinct initialization chains under the same Logon ID. This is the
   strongest evidence because it is a repeated semantic ownership defect, not mere regularity.
2. **Uniformly positive, tightly bounded core-to-DMZ offsets.** All 1,857 matched flows place the
   DMZ observation 41.655-66.399 ms later, consistent with a bounded modeled latency rule.
3. **Mechanically stable DHCP renewals.** Client-specific periods recur with only about one to
   three seconds of variation and without broader client lifecycle texture.
4. **Closed behavioral pools across host sources.** Tiny Windows process-access trace sets,
   exactly three UFW window values, shared generic Windows process families, and common Linux
   command/identity recipes collectively resemble parameterized generation.
5. **Strong source-native realism, favoring real and limiting confidence.** Valid Zeek companions,
   TLS/FUID integrity, proxy and firewall semantics, process lifecycle ordering, SMTP queue
   propagation, sensor-local differences, and coherent attack timing prevent a stronger synthetic
   score.

## Most Debated Points

- Whether two initial shell trees could reflect a normal restart or logging anomaly. Repetition on
  two hosts, distinct PIDs, shared session identifiers, and the absence of a second logon made that
  explanation unpersuasive.
- Whether stable DHCP and sensor timing simply reflect real timers and clock skew. The panel found
  the boundedness and absence of drift or exceptions more informative than regularity alone.
- Whether compact call-trace, UFW, Linux command, and updater pools are realistic repetition or
  generator texture. Each is ambiguous alone; their presence across unrelated source families
  gives them cumulative weight.
- Whether excellent correlation is itself suspicious. The panel rejected that shortcut because
  the dataset includes sensor-local IDs, source-specific byte scopes, loss, latency, and missing
  siblings rather than perfect record cloning.
- Whether explicit attack commands make the story too easy. The panel treated this as a weak
  signal and prioritized lifecycle ownership and benign-population texture instead.

## Improvement Recommendations (Consensus)

1. **Establish one canonical owner for each RDP interactive session.** Generate the 4624 Type 10
   logon, `winlogon.exe`, initial `userinit.exe`, primary `explorer.exe`, terminal-session identity,
   and lifecycle closure from one session contract. Any secondary shell must require an explicit
   restart or second logon event.
2. **Add an RDP cardinality regression check.** Group by target host, Logon ID/LogonGuid, terminal
   session, and `winlogon.exe`; assert one initial `userinit.exe` and one primary shell unless an
   explicitly modeled exception explains additional trees. Cover at least two simultaneous RDP
   sessions and shell-restart cases so the check does not erase legitimate multiplicity.
3. **Replace bounded sensor jitter with clock models.** Give each sensor stable skew, gradual
   drift, path-dependent transit delay, capture buffering, and native timestamp precision. Allow
   occasional sign changes or outliers where independent clocks and routing make them plausible.
4. **Drive DHCP from lease semantics.** Use explicit lease duration and T1/T2 behavior, then add
   boot acquisition, retransmission, delayed/skipped renewal, NAK, lease loss, and recovery. Keep
   deterministic generation while varying behavior by client implementation and state.
5. **Expand public Internet populations.** Add long-tail user agents and URIs, bots and scanners,
   malformed clients, HEAD/POST/OPTIONS, HTTP/1.0, unusual or missing Host headers, query strings,
   failed TLS handshakes, absent SNI, heterogeneous cipher preferences, and multi-request client
   sessions.
6. **Use continuous, resolver-specific DNS latency.** Model cache state, upstream resolver,
   timeout/retry paths, and network conditions without selecting a substantial fraction of
   external RTTs from exact-millisecond pools.
7. **Generate process-access stacks from causal inputs.** Vary call traces by executable build,
   source module, operation, target type, host patch level, and execution path rather than a small
   per-host closed list. Preserve stable stacks when the actual path is the same.
8. **Make external scan fingerprints campaign-coherent.** Bind advertised window, MSS/options,
   packet length, TTL, pacing, and destination strategy to scanner/tool profiles. Avoid drawing
   independent fields from tiny global pools.
9. **Specialize benign activity by role and policy.** Give hosts inventory-specific updater and
   maintenance families, stable application-owned health-check endpoints, narrower administrator
   affinities, bastion-aware access, noninteractive service accounts, host-specific sudo policy,
   longer-lived sessions, and some failed or interrupted administrative episodes.
10. **Preserve the strengths while correcting texture.** Retain canonical network ownership,
    source-local UIDs, connection and process lifecycle integrity, proxy byte-scope differences,
    modeled loss, certificate references, ASA pairing, mail queue propagation, SSH/PAM/logind
    sequencing, audit-clear causality, and the attack's cross-source huntability.
