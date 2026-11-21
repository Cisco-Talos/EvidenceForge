# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 82 | 43 | Synthetic | 82 | 70 |
| Detection Engineer | Real | 64 | 24 | Synthetic | 84 | 73 |
| Network Forensics | Synthetic | 86 | 74 | Synthetic | 86 | 74 |
| Host/EDR Forensics | Real | 62 | 30 | Synthetic | 79 | 68 |

The arithmetic mean of the four actual revised synthetic-confidence scores is **(70 + 73 + 74 + 68) / 4 = 71.25/100**. This is an aggregation of the submitted scores, not a fifth review or a separately elicited panel probability. This summary records the four original reports and four actual deliberation responses; it adds no facilitator findings or rechecks.

Initially, the Threat Hunter emphasized usable administrative and attack-related pivots, coherent credential boundaries, and one unresolved SCP ownership concern. Detection Engineering emphasized event-specific Windows schemas, file-handle and process/session integrity, and realistic TLS visibility, with only weak concern about repeated Linux hardware messages. Host/EDR Forensics emphasized Windows process/logon joins, Linux privilege and SSH phases, and native Mac fork/exec identities, with weak concern about recurring diagnostic vocabulary. Network Forensics emphasized a localized HTTP/1.1 response-body order contradiction against otherwise convincing transport, DNS, TLS, proxy, and byte-budget evidence.

The Network reviewer's HTTP finding changed all three other reviewers' verdicts after their own reported data rechecks. The Threat Hunter's verdict confidence stayed at 82 while synthetic-confidence rose from 43 to 70; Detection Engineering's confidence rose from 64 to 84 and synthetic-confidence from 24 to 73; Host/EDR's confidence rose from 62 to 79 and synthetic-confidence from 30 to 68. Network Forensics retained its verdict and both scores.

## Key Agreements

- All four actual final responses assess the collection as Synthetic. Each identifies the same localized HTTP response-body reversal as the decisive evidence, rather than suspicious narrative structure, source completeness, or a vote among reviewers.
- The HTTP transaction-to-file links matter: `resp_fuids` associates each response body with its transaction, within the same sensor UID and TCP tuple. Each reviewer reports confirming the reversal in this study's data. Pipelining can explain closely spaced requests but does not explain the reported response-body order under ordinary HTTP/1.1 and Zeek first-seen semantics.
- Core and DMZ corroborate one physical conversation. The smaller 1.987 ms hero-image/favicon overlap belongs to that same conversation and receives little additional weight. These observations must not be inflated into independent broad failures.
- The positive endpoint and network findings remain valid within their tested scope. Windows native wrappers, process/session identities, Mac fork/exec distinctions, SSH transport-before-auth ordering, TLS visibility, proxy separation, and transport byte budgets were judged credible. They limit the extent of the negative conclusion rather than repairing the specific HTTP relationship.
- SCP process ownership remains a qualified concern. Direct attribution to `/usr/bin/scp` without a visible SSH helper, and receiver file attribution to the privileged sshd identity, warrant clarifying the collection contract. None of the reviewers promotes those records to a demonstrated native impossibility.
- Repeated daemon text, diagnostic commands, and concentrated SSH authentication delays carry weak or minimal weight. Shared equipment, software, procedures, authentication infrastructure, and collection behavior remain plausible alternatives. Scheduled sysstat regularity has an ordinary cron explanation.

## Key Disagreements

The original verdict split was substantive: Network Forensics gave the source-native HTTP contradiction more weight, while Detection Engineering and Host/EDR initially favored Real based on the contracts they tested; the Threat Hunter remained Inconclusive. Their actual revised responses resolve the binary verdict split, but do not establish certainty or eliminate competing provenance explanations.

The final synthetic-confidence scores still range from 68 to 74. Host/EDR explicitly retains substantial weight for convincing endpoint evidence and possible transformed real captures. Network Forensics retains 74 because the other reports supply neither a counterexample to response serialization nor an explicit alternate timestamp contract, while acknowledging the defect's narrow scope. Threat Hunting and Detection Engineering likewise retain export, sanitization, or collection defects as possible explanations for production-origin data. The responses do not support inventing sharper differences between these final positions.

The unresolved issue is whether the invalid apparent native timing indicates generated activity or transformed real activity. Independently perturbed file timestamps, faulty export/postprocessing, anomalous packet timestamps, or a custom timestamp meaning remain possible. No reviewer found an established transformation contract in the supplied material; none claims logs alone prove provenance. Packet capture or collection/transformation details were identified as ways to distinguish these alternatives, not as evidence already available.

SCP interpretation also remains conditional: actual socket/file ownership would make missing helper/subsystem identities consequential; intentional ancestor attribution or filtering could explain the normalized records. A title change from `sshd: root [priv]` to `sshd: root@notty` does not itself require an exec record.

## Most Convincing Evidence

Ranked by the weight reflected in the submitted responses:

1. **HTTP/1.1 response-body reversal — decisive synthetic indicator under apparent native semantics.** For `10.10.1.34:51815 -> 10.10.3.10:80`, core UID `CVZ14Uhc67AVJrYgbO` links transaction-1 HTML to a first-seen time of `1793627680.712795` and transaction-2 CSS to `1793627680.631737`. The second body starts 81.058 ms earlier and finishes before the first begins. DMZ UID `CUndz3AFi0yhIEnnis` shows the same relationship with a 73.716 ms reversal. Explicit HTTP version `1.1`, same-connection file links, responder direction, and zero recorded gaps make parallel connections, HTTP/2, and a fixed inter-sensor clock offset insufficient explanations. All four responses accept this finding, with the transformation caveats above.
2. **Credible visible process and session identities — strong evidence of realism, not proof of real origin.** Host/EDR reported matching Security creation images for all 927 visible Sysmon creates; its and the other endpoint-oriented checks found no tested visible process-lifecycle inversion. These successes survive deliberation. Detection Engineering explicitly distinguishes its passing connection-boundary checks from the previously untested sibling-response ordering constraint.
3. **Source-native and operational distinctions — substantial positive counterweight.** Detection Engineering and Host/EDR highlighted Event 1102's distinct provider/UserData wrapper, native Mac successive exec identities, and coherent privilege/session stages. Threat Hunting contributed usable credential and administrative pivots; Network Forensics contributed convincing TLS/proxy/accounting relationships. These findings support the panel's restrained rather than near-certain synthetic scores.
4. **SCP ownership — secondary, contract-dependent concern.** DB-PROD-01 attributes TCP/22 directly to `/usr/bin/scp` PID 1418155; APP-INT-01 attributes the received file to sshd PID 3431531. All four responses retain a normalization/implementation alternative. The source and receiver observations are related aspects of one transfer, not two independent major defects.

## Most Debated Points

- **Passing broad checks versus failing a narrow relationship:** Valid endpoint process graphs and protocol rows inside connection intervals can coexist with invalid response-body order. The new finding exposed a blind spot in initial review scope rather than disproving the successful checks.
- **Pipelining and timing semantics:** One-microsecond request spacing could reflect pipelining or cached asset knowledge and is not independently decisive. The transaction-linked responder-body reversal is the issue. Sorting lines or applying a constant sensor-clock correction would not change it; undocumented per-object timestamp transformation could change its provenance interpretation.
- **Corroboration versus independence:** Two sensor views strengthen confidence in the observed relationship, but remain views of one activity. The tiny later overlap adds little independent weight.
- **Normalized ownership versus native ownership:** Conventional OpenSSH behavior motivates the SCP question, but unspecified attribution, filtering, and implementation prevent an unconditional missing-process conclusion.
- **Texture versus contradiction:** Repeated hardware messages, administrative vocabulary, SSH delay bands, and scheduled activity were challenged with ordinary operational explanations. The actual revised positions do not elevate these to decisive defects or justify arbitrary noise.

## Improvement Recommendations (Consensus)

1. **Build an ordered HTTP/1.1 response-body timeline per connection before deriving file observations.** Ensure a later responder body starts after the preceding body completes. The cited HTML/CSS reversal and same-conversation hero-image/favicon overlap are the concrete targets identified by the reviewers.
2. **Preserve those constraints through sensor observation adjustments.** Derive each file's first/last-seen interval from its position in the valid stream, then apply offsets or timing variation without reversing sibling bodies. Validate `trans_depth -> resp_fuids -> files.ts/duration`, including the previous body's end versus the next body's start; connection containment alone is insufficient.
3. **Clarify collection contracts where semantics differ from native expectations.** If file timestamps intentionally represent ingest/publication time or were transformed, document that meaning. Establish whether eCAR FLOW/FILE identity is the actual actor or an initiating ancestor. If native ownership is intended, represent the actual SSH transport helper and receiver subsystem identities; if ancestor attribution is intended, document the transformation. Do not add processes merely to satisfy an unverified assumption.
4. **Preserve the relationships that withstood review.** Retain stable endpoint identity and lifecycle joins, native Windows/Mac distinctions, ordered SSH phases, authentication boundaries, proxy visibility, TLS distinctions, and byte budgets while correcting HTTP timing. The responses do not support manufacturing missing companions, deliberate correlation errors, or arbitrary extra noise.

Hardware-message suitability, diagnostic vocabulary, and SSH latency distributions remain lower-priority, conditional investigations. The panel does not establish them as mandatory corrections or substitutes for the HTTP timing repair.
