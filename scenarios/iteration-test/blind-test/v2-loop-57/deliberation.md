# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 78 | 44 | Synthetic | 86 | 74 |
| Detection Engineer | Synthetic | 78 | 65 | Synthetic | 90 | 80 |
| Network Forensics | Synthetic | 94 | 83 | Synthetic | 96 | 87 |
| Host/EDR Forensics | Synthetic | 94 | 84 | Synthetic | 96 | 88 |

The revised positions are a facilitated synthesis of the four submitted reports, not new examinations of the underlying data. The Threat Hunter changes from Inconclusive to Synthetic because the two specialist reports introduce repeated, quantified defects outside that expert's primary review: packet-derived Zeek contradictions and a logon-type-wide `userinit.exe` lifecycle fingerprint. The Detection Engineer's position strengthens for the same reason, while still treating the all-zero process exit status and fractional-phase retry timing as distribution evidence rather than impossibilities. The Network and Host/EDR analysts retain their verdicts and increase slightly in confidence because their independent findings reinforce one another across unrelated source families. The final panel average synthetic-confidence is **82.25**, placing the deliberated assessment in the confidently synthetic range, although the panel continues to regard much of the dataset as highly production-like.

## Key Agreements

- All four experts agreed that the dataset is unusually strong at basic source fidelity. The XML and JSON parse cleanly; Windows Security, Sysmon, Zeek, eCAR, proxy, firewall, IDS, and syslog records generally use source-appropriate fields, values, and timestamp precision.

- All four agreed that broad cross-source correlation is a major realism strength rather than a synthetic indicator by itself. Process IDs and GUIDs, logon IDs, network tuples, Zeek UIDs and FUIDs, proxy tunnel identifiers, file identities, and actor lifetimes usually join without impossible ordering.

- Most or all experts highlighted credible environmental texture: role-weighted host activity, heterogeneous source volumes, substantial benign background noise, protocol diversity, capture-window truncation, and sensor-specific observations. The attack and administration paths are technically workable and embedded in a believable signal-to-noise ratio.

- The panel agreed that exact reuse of some composite shell commands is a low-weight concern only. Shared runbooks, aliases, or common administrative practice are plausible alternatives, and the overall command vocabulary remains diverse.

- The panel also agreed that several timing regularities are suspicious but not independently dispositive: tightly clustered public-key SSH authentication delays, one-sided Snort-to-Zeek offsets, rigid `debian-sa1` schedules, and repeated DNS queries inside a prior TTL can each arise from real infrastructure behavior.

- After cross-examination, the panel agreed that the strongest synthetic case does not depend on the suspicious storyline, its completeness, or unusually good correlation. It rests on repeated source-semantic contradictions and family-wide lifecycle or distribution fingerprints.

## Key Disagreements

- **Whether the dataset contains hard contradictions.** The Threat Hunter and Detection Engineer reported no hard contradiction, while the Network Forensics analyst identified repeated packet-derived impossibilities. The network evidence is stronger within its specialty because it states explicit invariants and scope: a UDP DNS connection with one originator packet, one responder packet, and `history="Dd"` cannot end seconds after the only response; likewise, several file gaps and cross-sensor HTTP body-length differences are not accompanied by parent-stream loss, overflow, timeout, or differing packet accounting. An undocumented analyzer behavior remains a theoretical alternative for the file cases, but the reports provide no positive evidence for it. The panel therefore accepts the DNS duration issue as the clearest hard contradiction and the HTTP/file accounting issue as a second, very strong contradiction.

- **DNS realism versus DNS synthetic texture.** The Threat Hunter found 108 of 1,277 successful-A repeat intervals occurring before prior TTL expiry, especially in DC-to-DC traffic. The Network analyst, however, found exact TTL countdown behavior in recursive answers and called cache behavior notably coherent. These observations are compatible rather than mutually exclusive: recursive resolver cache aging can be correct while individual clients or applications re-query before expiry. Because direct resolver use, isolated caches, cache flushes, and service behavior remain plausible, the panel does not elevate the Threat Hunter's within-TTL repeats to a major finding. The packet-count/duration mismatch is a separate DNS issue and is much stronger.

- **Whether endpoint lifecycle quality is uniformly strong.** The Detection Engineer found keyed process and session lifecycles sound and no material lifecycle defect. The Host/EDR analyst found that all 18 RDP Type 10 `userinit.exe` instances live for 508–9,263 seconds while all five local Type 2 instances exit within 3–5 seconds. These claims can coexist because the Detection Engineer verified identity and ordering, whereas the Host/EDR analyst tested behavioral semantics by process family and logon type. Correct identifiers do not make an implausible lifecycle realistic. The perfect 18-of-18 split, repeated across five targets and three endpoint renderings, gives the Host/EDR evidence greater weight.

- **How strongly to score the isolated RDP close mismatch.** The Host/EDR analyst treated the 1,298-second gap between a clean TCP close and Security 4779 for the same RDP tuple as a contract gap, especially because 16 of 17 comparable sessions align within about 0.83 seconds. The panel accepts it as anomalous but not independently impossible: delayed session-state recognition, an unobserved alternate transport, or Windows retaining a disconnected session could potentially separate transport close from the endpoint event. The report's search for a continuation makes those explanations less persuasive, but the finding remains below the repeated `userinit.exe` defect in weight.

- **Whether missing companion events imply generation gaps.** The Threat Hunter's absent Event 4722 in the `svc_dirsync` enablement sequence and close-only SCP receiver syslog are concrete and occur amid otherwise retained neighboring events. The counterargument is selective collection or source-local loss, particularly because each affects one lifecycle. The panel retains both as contract gaps worth fixing, but neither is strong enough alone to establish synthesis. Their value is cumulative and is strengthened by the presence of independent family-level defects elsewhere.

- **Strength of distribution-only evidence.** The Detection Engineer considers sub-millisecond fractional-phase preservation across failed-logon retries and 840 of 840 successful process exits strong generator signatures. The main alternative explanations are a common retry scheduler or a collection/export convention that normalizes exit status. Neither report supplies evidence for those mechanisms, and the retry pattern spans four workstations while the exit default spans ten hosts and 62 images. The panel therefore treats both as substantial, repeated evidence, but below packet-level contradictions and the `userinit.exe` lifecycle split.

## Most Convincing Evidence

1. **UDP DNS connection durations contradict the packet and DNS timestamps.** In 36 of 2,851 eligible core records and six of 41 DB records, one-request/one-response `Dd` exchanges retain unexplained tails exceeding 100 ms, usually more than 500 ms and often more than one second. The reproduced cross-sensor example leaves roughly 4.88 seconds after the only possible final packet. This is the panel's strongest indicator because packet counts, history, RTT, and duration jointly constrain what could have occurred.

2. **RDP `userinit.exe` has a perfect, semantically implausible lifecycle split.** Every one of 18 Type 10 instances persists for most of its RDP session, while all five Type 2 instances exits normally within seconds. The effect spans five Windows targets and agrees across Security, Sysmon, and eCAR. The repetition by logon type points to a shared lifecycle rule rather than occasional slow scripts or collection loss.

3. **Sensor-local HTTP/file loss is internally inconsistent.** Five file records claim missing bytes although their TCP parents report no missed bytes, normal closure, and no analyzer overflow or timeout. Four mirrored transactions then report different HTTP response body lengths despite identical parent byte counts, packet counts, and zero missed bytes. The dataset contains a correctly correlated 32,768-byte sensor-loss example elsewhere, making these exceptions more conspicuous.

4. **Failed-logon retries preserve a synthetic-looking fractional phase.** Eighteen of 20 events in multi-attempt clusters across four workstations use near-integer-second gaps while retaining the burst's fractional second to sub-millisecond precision. Approximate human periodicity is plausible; phase preservation across independent LSASS completions is much harder to explain naturally.

5. **All 840 Windows process exits use `Status=0x0`.** The population spans ten hosts, 62 image names, and diverse process classes. Zero should remain the majority, but the complete absence of cancellations, forced terminations, application failures, or exceptions resembles a universal default and removes an expected production long tail.

The strongest counterevidence remains the dataset's broad source-native fidelity: independently allocated sensor UIDs, drifting sensor offsets, mostly coherent packet-loss examples, source-appropriate Windows event contracts, stable per-build hashes, valid process/session ownership, realistic proxy accounting, and role-consistent background activity. These qualities explain why the final scores remain below certainty despite the synthetic consensus.

## Most Debated Points

- **RDP transport close versus session disconnect:** the 21.6-minute outlier is sharply inconsistent with the other RDP sessions, but a Windows session can outlive a transport path. Without raw transport or system-state evidence beyond the reports, the panel does not call the delay impossible.

- **Within-TTL DNS repeats:** the Threat Hunter sees excessive client re-querying, while the Network analyst sees correct recursive TTL aging. The panel regards this as a boundary case whose significance depends on whether the querying applications share the OS cache, bypass it, or maintain process-local caches.

- **Exact DNS RTT reuse across sensors:** all 951 mirrored transactions share RTT to six decimals despite independent UIDs, timestamps, and perturbed durations. This looks like copied canonical data, but identical observations of the same request and response packets could produce very close values. It remains strong distribution texture, not a hard contradiction.

- **Sysmon PE metadata placeholders:** complete `-` metadata for all observed `winlogon.exe` and `userinit.exe` instances, plus several third-party families, resembles a finite enrichment catalog. A collector or parser configuration could also omit version resources selectively, so the panel treats the family-wide pattern as supporting rather than decisive evidence.

- **The account-enable and SCP opening gaps:** adjacent retained records make both omissions suspicious, but isolated collection loss remains a viable explanation. Their importance is primarily diagnostic: lifecycle observation should be coherent when the surrounding source profile appears intact.

- **Regular but operationally plausible background:** repeated admin pipelines, six-second public-key authentication delays, uniform half-hourly `debian-sa1`, and bounded positive IDS delay could each reflect shared organizational configuration. The panel declined to convert these weak signals into hard findings without an accompanying contradiction.

## Improvement Recommendations (Consensus)

1. **Derive all packet-level timing and accounting from one sensor-local observation model.** For UDP DNS, compute `conn.duration` from the actual request and response packet timestamps; a one-request/one-response exchange must end at its response unless another counted packet changes the history. For HTTP/file analysis, make `conn.missed_bytes`, packet counts, HTTP body length, file seen/total/missing bytes, analyzer overflow/timeout, and hash availability consequences of the same loss decision.

2. **Correct interactive Windows process ownership.** Treat `userinit.exe` as a short-lived initializer for both Type 2 and Type 10 logons, terminating it shortly after Explorer and logon scripts start with realistic variance. Add a family-level cross-source invariant covering Security 4688/4689, Sysmon 1/5, and eCAR, so the process is never tied to the full RDP session lifetime.

3. **Unify RDP transport and endpoint session transitions.** Use one authoritative lifecycle for the exact source tuple, transport close, eCAR session state, and Windows 4779. If a session remains attached after a TCP close, emit the concrete alternate transport, reconnection, or disconnected-session state that explains it; otherwise keep the disconnect close to an orderly `SF` termination. Apply host capability rules so concurrent RDP sessions on client Windows require an explicit multi-session profile.

4. **Generate authentication retries from independent attempt times.** Sample human think time, UI submission latency, authentication processing, and scheduler noise for every retry rather than adding whole-second offsets to a shared timestamp. Verify that retry bursts do not preserve a common fractional-second phase across hosts or attempts.

5. **Add source-correlated process outcome diversity.** Keep `0x0` dominant, but introduce executable- and cause-aware nonzero exits for cancellation, forced termination, application failure, and exceptions. When another endpoint source exposes termination reason, derive both renderings from the same canonical outcome.

6. **Make source-observation decisions lifecycle-coherent.** Account enablement should produce the expected 4722 alongside UAC-changing 4738 semantics when that event is within the retained Security collection profile. SSH/SCP receiver evidence should retain or drop connection, acceptance, PAM open, session activity, and close as a coherent source-local lifecycle, or expose a collection-loss mechanism that explains partial retention.

7. **Complete image metadata from the same build-aware identity used for hashes.** Populate Sysmon Event 1 version-resource fields for standard Microsoft session binaries and common signed third-party services. Any fallback to `-` should arise from an explicit extraction condition and should not affect every instance of an otherwise ordinary image family.

8. **Preserve organization-level repetition only when it has an observable cause.** Associate repeated shell commands with shared runbooks or scripts, vary public-key SSH latency by authentication path and environmental condition, keep scanner packet construction stable within one tool invocation, and model IDS/network-sensor clocks with per-sensor offset and drift. Retain the existing recursive TTL behavior, proxy tunnel accounting, TLS/certificate realism, sensor-specific UIDs and drift, role-weighted traffic, and detailed Windows event contracts.
