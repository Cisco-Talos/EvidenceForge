# Deliberation Summary

## Scope and method

This is a facilitator synthesis of the four independent reports in this directory, guided by the supplied expert-deliberation reference. No scenario, evaluation, repository, prior-assessment context, or additional data was consulted. It is not a fifth authenticity review. There was no live cross-examination or opportunity for expert replies, so no revised votes, revised confidences, or newly agreed recommendations are attributed to the experts. All original positions and numerical scores are retained.

## Panel composition and retained positions

| Expert | Original verdict | Verdict confidence | Synthetic-confidence | Retained verdict | Retained verdict confidence | Retained synthetic-confidence |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Inconclusive | 80 | 30 | Inconclusive | 80 | 30 |
| Detection Engineer | Inconclusive | 80 | 30 | Inconclusive | 80 | 30 |
| Network Forensics | Real | 63 | 24 | Real | 63 | 24 |
| Host/EDR Forensics | Inconclusive | 80 | 25 | Inconclusive | 80 | 25 |

The original arithmetic mean synthetic-confidence is **27.25/100**, calculated as `(30 + 30 + 24 + 25) / 4`. It is a descriptive average of the submitted scores, not a calibrated provenance probability, consensus verdict, or replacement for the individual conclusions.

Original category scores are also retained below; all are on the reports' 10-point scales.

| Expert | Field formats | Temporal patterns | Cross-source correlation | Behavioral realism | Environmental consistency |
|---|---:|---:|---:|---:|---:|
| Threat Hunter | 8 | 8 | 9 | 8 | 8 |
| Detection Engineer | 9 | 8 | 9 | 8 | 8 |
| Network Forensics | 9 | 8 | 9 | 8 | 8 |
| Host/EDR Forensics | 8 | 9 | 9 | 8 | 8 |

## Round 1 — Independent findings

**Threat Hunter:** The strongest findings are the exact Mac SSH transport/session tuple and the native ES-to-eCAR exec transition. The former preserves `10.10.1.41:63450 → 10.10.1.42:22`, PID 51725, a roughly 590.5-second successful transport, and transport-before-target-login ordering. The latter preserves PID, parent, audit identity, and exec pidversion transition while permitting collection latency. Fleet sysstat repetition and a small shared Mac inventory vocabulary remain weak texture questions with ordinary operational explanations.

**Detection Engineer:** Windows PID 5180, parent 4356, SYSTEM ownership, and lifecycle identity agree across Security, Sysmon, and eCAR despite correct source-specific representations and subsecond observation offsets. Proxy CONNECT control bytes plus tunnel bytes agree with transport payload totals. Bounded parsing and network checks found no demonstrated schema, identity, or byte-accounting contradiction. Unverified ES version details were explicitly not called defects.

**Network Forensics:** The database transport/TLS/files/X.509 pivot preserves UID `C86skU4nKOD3QEHD46`, certificate references, hashes, byte budget, and sequence. A separate exact proxy pivot preserves source port 38139 and accounts for control and tunnel bytes. Distinct sensor protocol mixes, DNS outcomes, TCP states, and TLS 1.3 certificate visibility are production-compatible. Nineteen database TLS observations using two TLS 1.2 ciphers are a weak, environment-dependent concern.

**Host/EDR Forensics:** The Windows process pivot independently supports the Detection Engineer's interpretation, while the Linux SSH tuple `10.10.1.35:61284 → 10.10.3.10:22` preserves transport-before-authentication and session 213. Across four sampled hosts, 372 paired eCAR process identities have no reversed lifetimes. Repeated Mac Unified Log trace and format metadata is the sole retained weak hint; its native uniqueness semantics were not established.

## Round 2 — Cross-examination of the submitted evidence

### Key agreements

All four reports describe substantially production-like observed evidence and establish no important hard contradiction, required-contract gap, or source-native formatting defect. The exact joins support identity, timing, and accounting coherence. Such coherence does not authenticate origin, and successful correlation itself is not suspicious.

The endpoint reports agree that source-specific identifiers need not be equal: Security hexadecimal PIDs can match decimal Sysmon/eCAR PIDs; a normalized object UUID need not equal a Sysmon ProcessGuid; sensor-local Zeek UIDs can differ across observations. They also distinguish fork from exec and native notifications from policy decisions.

The network and detection reports agree that CONNECT message bodies and encrypted tunnel payloads have different semantics. Zero HTTP body length is compatible with nonzero TCP payload. Their proxy examples differ in join strength: the Detection Engineer's access line lacks client source port and is contextual corroboration; the Network Forensics example includes the exact port and supports a stronger independent join. Neither should be promoted beyond its reported identity precision.

### Real versus Inconclusive

The Network Forensics Real verdict and the three Inconclusive verdicts do not reflect a demonstrated factual contradiction. The network specialist gives modest positive authenticity weight to coherent protocol and observation behavior, with verdict confidence 63. The others hold that a capable simulator can also produce the checked coherence and retain unresolved provenance. The review is bounded, and packet capture, exporter provenance, or collection-policy evidence was not established. This limits inference rather than adding synthetic penalties. No majority provenance conclusion is manufactured from the three Inconclusive votes.

### Shared Mac metadata

The Host/EDR report identifies two loginwindow rows and two SSH rows among five Unified Log records with repeated traceID, senderProgramCounter, and format strings across two hosts. Host-specific PIDs, boot UUIDs, threads, and timestamps differ. A trace identifier or program-counter value cannot be assumed globally unique, and identical binaries and format locations can legitimately produce shared presentation metadata. The other reports do not establish contrary native semantics. The supported target is validation against the declared macOS release/exporter, with any correction conditional on that validation. Randomizing these fields simply to erase repetition is unsupported.

### Routine commands and workload homogeneity

The Threat Hunter's 36 sysstat shell/child pairs on each of ten Linux hosts and near-ten-minute spacing are consistent with an aligned six-hour cron slice. The Host/EDR report expressly gives the same maintenance repetition no defect weight. The remaining question is package/scheduler applicability to each host, not a requirement for randomized counts, missing runs, or arbitrary jitter.

Repeated Mac `id`, `sw_vers`, `ps aux`, and PDF inventory commands have a common user and visible inventory-task explanation. The reports do not demonstrate impossible ownership or behavior. Checking command ownership and management-task scope is supportable; adding noise or expanding command pools merely to change repetition is not.

Likewise, the database cipher concentration could reflect a small common service/agent population. Nineteen observations do not justify imposing a modern global TLS distribution. Applicability should be checked before any change.

## Most convincing reported observations

1. **Exact Windows lifecycle identity across native and normalized sources:** corroborated by Detection Engineer and Host/EDR, with consistent PID, parent, user, image, and source-local durable identity. These reports overlap on the same process and are not independent dataset-wide replications.
2. **SSH transport-before-authentication and durable session relationships:** independently checked on different Mac and Linux tuples by Threat Hunter and Host/EDR. Neither requires source timestamps to be identical.
3. **Protocol-to-transport accounting:** explicit CONNECT control/tunnel sums and the database certificate-file byte budget fit their corresponding transport records, with valid temporal order.
4. **Platform and observation distinctions:** fork/exec identity, source-specific Windows fields, sensor-specific network mixes, failed connection outcomes, and TLS 1.3 certificate absence avoid particular semantic contradictions.

These observations support internal plausibility. They are stronger than the reported weak suspicions, but do not prove production provenance.

## Round 3 — Revisions

No expert revisions were requested or obtained in this synthesis. Every verdict, confidence, synthetic-confidence score, and category score remains as originally submitted. The cross-examination above qualifies evidentiary strength without simulating expert re-votes.

## Round 4 — Supported recommendations and limits

No unconditional corrective defect is established. The strongest supported investigation targets are:

- Validate the repeated Mac Unified Log presentation metadata against raw exports from the declared macOS release/exporter. Preserve legitimate common-build repetition and change only fields whose verified semantics require it.
- Check the fleet sysstat package/scheduler footprint and Mac inventory command ownership against the systems and management task actually represented. Preserve genuine periodicity and shared administrative behavior.
- Check the small database TLS population against the actual agents/services before changing cipher diversity.

Across reports, the clearest preservation recommendation is to retain canonical process/session identity, transport-before-authentication, source-native identifiers and delays, and protocol byte accounting. No repair to these checked contracts is indicated.

Declared sensor, filter, decryption, and exporter scope could resolve interpretive uncertainty in a future assessment. A longer window could support broader workload conclusions. These are assessment aids, not missing-coverage defects. No new penalty is assigned for volume, thin coverage, out-of-window lifecycle records, absent optional sources, completeness, narrative shape, or successful joins.
