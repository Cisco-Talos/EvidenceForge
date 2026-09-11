# Deliberation Summary

## Scope and Trigger

This report facilitates a post-review deliberation among four independent blind reviewers: Threat
Hunter, Detection Engineer, Network Forensics Analyst, and Host/EDR Forensics Analyst. It is based
only on their four completed blind reports. No scenario, manifest, review-data directory, generated
source data, repository code, prior-loop report, or git history was consulted.

Deliberation was triggered by verdict disagreement: the Threat Hunter assessed the collection as
**Inconclusive**, while the other three experts assessed it as **Synthetic**. Initial
synthetic-confidence scores were 44, 72, 72, and 72, yielding a 28-point spread and a mean of 65.0.

The panel used the following standard during reconciliation:

- A **hard contradiction** requires source-local or identity-bound evidence that cannot be produced
  by the visible event sequence under ordinary product or collection behavior.
- A **strong contract gap** is highly suggestive but retains a specific alternative explanation,
  such as a cached credential, concurrent shell, opaque product identifier, enrichment policy, or
  selective source loss.
- A **distribution or format indicator** raises synthetic confidence only in proportion to its
  scope, specialist support, and resistance to ordinary deployment explanations.
- Completeness, strong cross-source joins, bounded-window lifecycle gaps, and an easy-to-reconstruct
  activity chain are not synthetic indicators by themselves.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Inconclusive | 82/100 | 44/100 | Synthetic | 86/100 | 70/100 |
| Detection Engineer | Synthetic | 78/100 | 72/100 | Synthetic | 88/100 | 78/100 |
| Network Forensics | Synthetic | 84/100 | 72/100 | Synthetic | 90/100 | 82/100 |
| Host/EDR Forensics | Synthetic | 84/100 | 72/100 | Synthetic | 89/100 | 80/100 |

**Final mean synthetic-confidence score:**
`(70 + 78 + 82 + 80) / 4 = 77.5/100`.

**Final interpretation:** **Likely synthetic**. The final mean falls in the 61-80 band. The panel's
position is not that the collection is crude; rather, several independent source families contain
high-specificity timing or identity defects despite otherwise strong production-like structure.

## Round 1 — Independent Positions

### Threat Hunter

The Threat Hunter initially assessed the collection as **Inconclusive** with 82/100 verdict
confidence and 44/100 synthetic confidence. The strongest realism evidence was operational: 969 of
970 Windows endpoint process creates joined Security 4688, 963 of 970 joined Sysmon Event 1, 1,689
exact process lifecycles had no reversed pair, and every checked Zeek protocol companion joined a
parent connection without preceding its open. The visible activity could be reconstructed through
ordinary pivots without a global attack identifier, and the largest traffic burst was attributable
to a visible `nmap` process rather than unexplained duplication.

The Threat Hunter's principal concerns were systematic loss of actor/PID attribution on 12 of 14
matched Windows RDP client flows, incompatible default curl User-Agent versions from two nearly
simultaneous executions of the same `System32` binary, and sparse Windows process creation relative
to network telemetry. These were treated as collection-policy, enrichment, or filtering-plausible
defects rather than hard contradictions. The Threat Hunter uniquely emphasized hunt pivot quality,
RDP source attribution, and the imbalance between process and network volume.

### Detection Engineer

The Detection Engineer assessed the collection as **Synthetic** with 78/100 verdict confidence and
72/100 synthetic confidence. The main anchor was three KDC-local sequences in which Event 4769
preceded Event 4768 by 7.949-30.950 ms while DC, account, client IP, and ephemeral port matched and
record IDs were adjacent. The reviewer also found 119 of 204 tightly matched machine-authentication
sequences in which a same-DC 4624 preceded the nearest 4769, plus universal zero `LogonGuid` values
across 2,072 Event 4769 records despite 148 non-zero 4624 GUIDs.

The Detection Engineer also found two HTTP response FUIDs without corresponding Zeek file records
and a weak near-fixed four-second process-to-registry delay in eight visible Sysmon pairs. Against
those defects, the report documented excellent schema fidelity; deep 4688/Sysmon/eCAR process joins;
sound token, session, and process lifecycles; strong firewall and IDS contracts; and a convincing
Security-log-clear sequence. This reviewer uniquely supplied rule- and event-semantic scrutiny of
Kerberos ordering and Windows correlation fields.

### Network Forensics Analyst

The Network Forensics Analyst assessed the collection as **Synthetic** with 84/100 verdict confidence
and 72/100 synthetic confidence. The decisive finding was dataset-wide, same-sensor Zeek DNS timing:
3,885 of 3,885 UDP DNS rows occurred after their parent connection start, and 3,863 one-query/
one-response UIDs had one origin packet, one response packet, and `Dd` history. In that packet shape,
the sole origin packet must be the query represented by both `conn.ts` and `dns.ts`, yet every record
inserted a positive pre-query interval and every connection ended after the modeled DNS response.

The reviewer also found all 46 SMTP records, including 17 WAN sessions, within 0.052-0.969 ms of TCP
start; an almost perfectly balanced reuse distribution across a scattered pool of 480 ASA PAT ports;
short, mostly single-request browser tunnels; and three orphaned Zeek FUID references. In contrast,
packet accounting, cross-sensor clock behavior, firewall lifecycles, IDS tuple matches, proxy identity,
TLS/X.509 relations, topology, and DHCP behavior were judged highly realistic. This reviewer uniquely
tested packet-derived timestamp semantics and network allocator/connection-reuse distributions.

### Host/EDR Forensics Analyst

The Host/EDR Forensics Analyst assessed the collection as **Synthetic** with 84/100 verdict confidence
and 72/100 synthetic confidence. The principal finding was a DB-PROD-01 root history sequence in which
four commands were timestamped before the visible SSH connection, authentication, session login, and
bash creation that later commands in the same continuous sequence joined exactly. Eight external
commands in that sequence lacked process evidence, and `file`/`stat` were timestamped while the
foreground `mysqldump` process remained alive.

The reviewer also identified fleet-wide reuse of exact IRQ numbers and hardware/device names across
dissimilar Linux hosts, a narrow 4.723-6.357 second RDP transport-to-authentication band across all 15
visible successful sessions, and three incompatible eCAR FILE object-ID shapes. Strong counterevidence
included exact Windows process and ancestry joins, stable binary hashes, varied process lifetimes,
correct bounded-window lifecycle treatment, coherent SSH sessions, and role-specific application
placement. This reviewer uniquely examined shell-history/session causality and per-host Linux hardware
identity.

## Round 2 — Cross-Examination

### 1. Does the Threat Hunter's clean lifecycle result contradict the specialist hard findings?

No. The Threat Hunter proved that the lifecycle families it checked—Windows processes, sessions,
ordinary Zeek protocol-parent ordering, and the reconstructed hunt path—were coherent. The Detection,
Network, and Host reviewers examined narrower source-native contracts that those checks did not test:
Kerberos AS/TGS order, packet-level DNS timestamp identity, and bash-history attribution to an SSH
shell. A dataset can support a coherent hunt while still containing synthetic defects in independent
families. The specialist findings therefore expose blind spots rather than invalidate the Threat
Hunter's positive evidence.

### 2. Which findings survive as hard contradictions?

**Accepted hard contradiction: Zeek UDP DNS packet timing.** This is the strongest panel finding.
It is same-sensor, same-UID, dataset-wide, and constrained by one origin packet and one response packet.
Clock skew, collector delay, missing pre-window state, and cross-source join ambiguity do not explain
why `conn.ts` and `dns.ts` differ when both must represent the only visible query packet. Nor do they
explain the systematic interval after `dns.ts + rtt` before connection end. The finding remains hard
unless the fields have non-Zeek semantics not disclosed in the records, which would itself be a
source-native schema contract failure.

**Very strong but not mathematically unique: Kerberos 4769-before-4768.** Matching account, client IP,
port, DC, millisecond proximity, and adjacent record IDs make three inversions highly persuasive.
However, Event 4768 and 4769 do not expose a shared ticket transaction identifier in the cited
evidence. A cached prior TGT followed by an unrelated AS exchange with rapid port reuse is improbable
but not logically impossible. The panel therefore preserves this as a near-hard causal defect and a
high-priority family failure, while not relying on it alone as irrefutable proof. The broader 119/204
4624-before-4769 pattern is correctly retained as a contract/timing gap because its join is composite
and non-unique.

**High-confidence sequence contradiction with residual shell ambiguity: DB-PROD-01.** The continuity
from early history entries into three exactly matched later processes makes the pre-authentication
commands highly difficult to reconcile with the visible SSH session. The absent child processes and
foreground-command overlap reinforce the defect. Still, bash history carries no session identifier;
a concurrent or pre-existing root shell and history merge is a theoretical product explanation.
Accordingly, the panel treats this as a high-confidence shell/session causality failure, but slightly
below the DNS finding in proof strength.

### 3. Which findings could be normal collection or product artifacts?

- **RDP FLOW actor/PID loss:** Systematic asymmetry against SSH is a meaningful endpoint contract gap,
  but flow products often vary in process enrichment, timing, and provider coverage. It is not a hard
  lifecycle contradiction.
- **Sparse Windows process telemetry:** Filtering or selective process collection can explain the low
  process-to-network ratio. Without collection metadata, it remains a moderate-to-weak texture signal.
- **Zero Kerberos `LogonGuid`:** Zero GUIDs occur in production and may reflect OS or audit behavior.
  The universal pattern harms correlation and compounds timing ambiguity but is not independently
  proof of synthetic origin.
- **Orphaned Zeek FUIDs:** Selective `files.log` loss or policy can create sparse orphans. The shared
  HTTP examples reported by Detection and Network, plus the additional SMB orphan, establish a real
  relational gap, but its low rate limits verdict weight.
- **Mixed eCAR FILE object-ID shapes:** An opaque identifier contract may legitimately combine
  namespaces. Without a discriminator this is confusing and synthetic-looking, but not invalid on
  the reports alone.
- **Curl User-Agent mismatch:** Per-process configuration, environment, wrapper behavior, or binary
  replacement could produce different versions, although none was visible. The near-simultaneous
  same-path executions make this a focused canonical-identity concern, not a corpus-wide
  contradiction.
- **Short browser tunnels:** Destination behavior, browser policy, proxy inspection, and disabled
  multiplexing can shorten sessions. The population is nevertheless too dominated by short,
  single-request tunnels to dismiss as an isolated deployment choice.
- **Repeated Linux hardware vocabulary:** Golden images can repeat software and some virtual-device
  names, but exact IRQ/device/queue combinations across server and endpoint roles are stronger than
  ordinary image reuse. This remains a high-value fleet-level distribution indicator.

### 4. Do the realism strengths lower the final verdict?

Yes, but they do not reverse it. All four experts independently found strong process identity,
lifecycle ordering, topology, role differentiation, source parsing, bounded-window behavior, and
cross-source pivotability. These strengths prevent a **Confidently Synthetic** panel mean and explain
why three initial synthetic scores stopped at 72. They cannot neutralize a dataset-wide same-source
packet contradiction plus independent authentication, shell-session, hardware-inventory, SMTP,
allocator, and timing-family indicators.

## Round 3 — Revised Positions

### Threat Hunter — revised to Synthetic, 86/100 verdict confidence, 70/100 synthetic confidence

The Threat Hunter's hunt-level evidence remains valid, but the initial statement that no verified
hard contradiction existed cannot survive the Network specialist's one-packet DNS proof. The
Kerberos and DB shell findings add independent host/authentication evidence outside the original
check set. The score rises from 44 to 70; it remains the panel's lowest because RDP attribution,
curl identity, and sparse process volume still have plausible collection explanations and because
the hunt contracts themselves are unusually strong.

### Detection Engineer — remains Synthetic, 88/100 verdict confidence, 78/100 synthetic confidence

Cross-examination slightly tempers the claim that each 4769-before-4768 pair is logically unique,
because a cached TGT cannot be excluded from the reported fields. That moderation is outweighed by
the independent, dataset-wide DNS contradiction and the DB shell chronology. The score rises from 72
to 78, while the verdict confidence rises because the conclusion no longer depends mainly on one
Windows event family.

### Network Forensics Analyst — remains Synthetic, 90/100 verdict confidence, 82/100 synthetic confidence

The network verdict is reinforced by two independent specialist families: Kerberos source-local
ordering and shell/session chronology. The DNS finding remains the strongest evidence because it is
dataset-wide and identity-bound. The score rises from 72 to 82; the high realism of firewall, TLS,
proxy identity, cross-sensor behavior, and packet accounting prevents a still higher score.

### Host/EDR Forensics Analyst — remains Synthetic, 89/100 verdict confidence, 80/100 synthetic confidence

The host verdict is reinforced by the DNS contradiction and Kerberos timing evidence. The panel's
acknowledgment that concurrent shell/history merging is theoretically possible slightly limits the
weight of DB-PROD-01 in isolation, but the fleet-wide hardware reuse and independent source-family
defects preserve the Synthetic assessment. The score rises from 72 to 80.

## Key Agreements

- The collection is technically sophisticated and often production-like; a Synthetic verdict is not
  a judgment that records are broadly malformed or that correlations are unusable.
- The Zeek UDP DNS timestamp contract is the strongest finding because it is same-sensor,
  identity-bound, packet-constrained, and dataset-wide.
- The DB-PROD-01 command/session chronology and KDC timing patterns warrant family-level correction
  even though each retains a narrower alternative explanation than the DNS contradiction.
- Exact process, ancestry, session, Zeek UID, firewall, IDS, proxy, certificate, and topology joins
  are major realism strengths and should remain regression-protected.
- Bounded-window starts/stops and incomplete cross-source observation were handled correctly and are
  not synthetic indicators by themselves.
- Repeated fleet or population texture matters most when it is hardware-specific, timing-constrained,
  or allocator-shaped—not merely because values repeat.

## Key Disagreements

### Whether the collection is authentic overall

This disagreement is resolved after cross-specialty review. The Threat Hunter's initial
Inconclusive verdict reflected strong hunt coherence and the absence of contradictions in the
families examined. Once the same-sensor DNS contradiction and independent Kerberos/shell findings are
considered, all four final positions are Synthetic.

### Whether Kerberos inversions are absolutely impossible

The Detection Engineer treats the three same-port 4769-before-4768 pairs as hard contradictions.
The facilitated panel accepts their very high evidentiary weight but retains a narrow cached-TGT/
unrelated-exchange alternative because the cited fields do not provide one shared ticket transaction
identifier. There is consensus on fixing the family and on its strong synthetic weight, but not on
calling every pair independently impossible.

### Whether DB-PROD-01 is uniquely tied to one shell

The Host specialist treats the continuous history plus exact later process joins as a hard
contradiction. The alternative is a concurrent or pre-existing root shell whose history was merged,
but the missing external child processes and foreground overlap make that explanation weak. The
panel agrees it is a high-confidence causality defect while preserving the residual attribution
ambiguity.

### How much to weight collection-plausible gaps

RDP process attribution, sparse Windows process volume, zero Kerberos GUIDs, orphaned FUIDs, and
mixed eCAR IDs could each occur in real products or collection pipelines. The panel agrees these are
worth correcting but assigns them less verdict weight than source-local timing contradictions and
fleet-wide generated-looking distributions.

## Most Convincing Evidence

1. **Zeek UDP DNS packet-timestamp contradiction:** 3,885/3,885 UDP DNS UIDs show a positive
   `dns.ts - conn.ts`; 3,863 one-query/one-response packet shapes make the query packet identity
   unambiguous, and the modeled response also precedes connection end.
2. **DB-PROD-01 shell/session chronology:** early root history commands precede the visible transport,
   authentication, session, and shell whose later command sequence matches exact eCAR processes;
   eight external commands are missing from the process stream.
3. **Kerberos source-local ordering:** three tightly bound 4769-before-4768 sequences and the broader
   119/204 machine-logon-before-4769 pattern indicate that independent timestamping can invert the
   intended authentication chain.
4. **Linux hardware inventory reuse:** exact IRQ numbers and device/queue names repeat across up to
   10 of 11 Linux hosts with dissimilar roles, exceeding ordinary shared-message or golden-image
   similarity.
5. **SMTP and allocator population semantics:** sub-millisecond SMTP application timestamps after
   TCP start, including WAN sessions, and nearly balanced reuse from a scattered PAT port pool form
   independent network-family fingerprints.

The strongest evidence for authenticity remains the near-exact but non-universal process joins,
correct lifecycle ordering in the large process/session populations, realistic firewall and IDS
contracts, independent sensor-clock relationships, coherent proxy/TLS identity, and role-aware host
activity. These strengths materially constrain, but do not overturn, the final synthetic confidence.

## Most Debated Points

- Whether adjacent Kerberos events with the same composite tuple prove one AS-to-TGS exchange or
  could represent cached-ticket activity plus rapid port reuse.
- Whether the DB root history is one shell's authoritative timeline or a merge from a concurrent,
  unobserved shell.
- Whether systematic RDP actor loss is a generation contract defect or plausible endpoint
  enrichment policy.
- Whether all-zero Event 4769 GUIDs and mixed eCAR FILE IDs are synthetic signatures or legitimate
  product-specific conventions.
- How much browser tunnel persistence and Windows process volume should vary under an unknown proxy
  and endpoint collection policy.

## Improvement Recommendations (Consensus)

The priorities below are family-level and ordered by expected reduction in synthetic confidence,
not merely by the isolated severity labels in the original reports.

| Priority | Family-level improvement | Why it ranks here | Owning contract and actionable correction |
|---|---|---|---|
| P0 | Restore packet-derived Zeek DNS timing | Dataset-wide accepted hard contradiction; highest specialist specificity and score leverage | Make the canonical DNS transaction and parent UDP connection share the actual query/response packet anchors. For one-query/one-response flows, require `dns.ts == conn.ts` and `dns.ts + rtt == conn.ts + duration`; cover retransmissions and all sensor views without independently jittering sibling fields. |
| P0 | Unify SSH session, shell, command, history, and process timing | High-confidence visible causality failure plus missing child-process evidence in one coherent command family | Use one session/action timeline for transport, authentication, PAM/logind, shell readiness, command start, process lifecycle, and history emission. External foreground commands must start after shell readiness, have corresponding child processes when collected, and serialize unless explicitly backgrounded. |
| P0 | Enforce Kerberos AS/TGS/logon causal order before source delays | Three near-hard inversions plus a dataset-wide directional signature; high detection impact | Establish ticket and logon dependencies in one canonical authentication bundle, then apply source-native observation delay without permitting 4769-before-dependent-4768 or 4624-before-required-4769. Preserve usable correlation identity where available and test machine, user, service, and DC-to-DC sibling paths. |
| P1 | Correct network application readiness and connection-population models | SMTP timing is physically implausible at family scale; PAT and browser populations look generated | Anchor SMTP evidence after handshake/banner/application readiness, with WAN-sensitive latency. Replace balanced PAT sampling with a stateful allocator that models original-port preservation, collisions, occupancy, and natural singleton/reuse distributions. Increase browser tunnel persistence and request multiplexing while retaining short command-line/failure sessions. |
| P1 | Derive Linux hardware messages from per-host inventory | Fleet-wide hardware-specific repetition is a strong host-family fingerprint | Assign internally stable NIC, block-device, IRQ, CPU/NUMA, and accelerator inventories by host class and role. Render `irqbalance` and kernel messages only from devices actually assigned to that host; allow shared golden-image software without cloning physical topology. |
| P1 | Repair the RDP family as one transport/auth/process contract | Two specialists found distinct RDP weaknesses: missing source process attribution and narrow authentication latency | Preserve source actor/PID/principal on outbound client flows whenever the process is visible, including non-Windows clients. Condition transport-to-auth latency on path, host load, authentication package, DC selection, reconnect state, and outliers while maintaining transport-before-auth order. |
| P2 | Make cross-source object references observation-coherent | HTTP/SMB FUID orphans and mixed FILE identities weaken otherwise excellent correlation | Make protocol metadata and corresponding file-row retention one coherent observation decision, including mid-window and boundary cases. Standardize the eCAR FILE object-ID namespace or add an explicit source/type discriminator while keeping identity stable on reuse. |
| P2 | Canonicalize application identity across process and protocol evidence | Near-simultaneous same-path curl executions exposed conflicting default versions | Derive User-Agent/version from one canonical executable/application identity and reuse it in process, HTTP, and proxy evidence. Model command-line, environment, or configuration overrides explicitly when divergence is intended. |
| P3 | Add source metadata or benign texture where filtering is intentional | Sparse Windows process coverage and zero Kerberos GUIDs are collection-plausible but analytically ambiguous | Either add proportionate benign process churn and usable Kerberos correlation identity, or expose a consistent collection/product policy that explains filtered process events and unavailable GUIDs. Do not manufacture perfect completeness. |
| P3 | Broaden small repeated timing distributions | Narrow RDP and Sysmon registry offsets can reveal shared fixed-delay rules | Use action- and source-aware latency distributions with per-host variation and occasional outliers, while retaining causal ordering. Treat the eight-record registry sample as a regression target only after the higher-confidence families above. |

## Final Consensus

The panel reaches a unanimous final **Synthetic** assessment with a mean synthetic-confidence score
of **77.5/100 (Likely synthetic)**. The conclusion rests primarily on one dataset-wide hard network
contradiction and independent, high-specificity authentication and host-session defects—not on
narrative neatness, complete correlation, or bounded-window gaps. At the same time, the collection's
schema fidelity, identity continuity, lifecycle handling, topology, sensor relationships, and
analyst pivotability are strong enough that focused family-level corrections should materially lower
future synthetic-confidence scores without sacrificing the realism already achieved.
