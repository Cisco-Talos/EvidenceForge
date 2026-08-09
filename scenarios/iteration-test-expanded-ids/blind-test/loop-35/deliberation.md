# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 68 | 64 | Synthetic | 75 | 68 |
| Detection Engineer | Synthetic | 78 | 64 | Synthetic | 82 | 69 |
| Network Forensics | Real | 72 | 28 | Real | 55 | 44 |
| Host/EDR Forensics | Synthetic | 76 | 66 | Synthetic | 82 | 71 |

## Key Agreements

The panel agreed that the collection is technically sophisticated and highly usable for investigation. All four experts found strong cross-source correlation, credible lifecycle ordering, and meaningful host- and network-role differentiation. Particularly convincing realistic features included:

- Security 4688, Sysmon Event 1, and eCAR process identities align with very few omissions and no sampled impossible parent/lifecycle relationships.
- Zeek protocol records resolve cleanly to connection UIDs, while independent sensor UIDs and observation delays preserve distinct sensor perspectives.
- NAT, proxy, firewall, endpoint-flow, and byte-count perspectives remain consistent without being artificially identical.
- SSH authentication, PAM/session establishment, endpoint login, and transport evidence form credible ordered lifecycles.
- The main intrusion chain—from web compromise through remote access, lateral movement, staging, and proxy-mediated exfiltration—is technically plausible and unusually pivotable.

Most experts nevertheless judged the collection synthetic. Their shared concern was not simplistic activity but deterministic implementation fingerprints: invariant schema defects, selective lifecycle behavior at the collection boundary, repeated fleet-wide background vocabularies, and missing causal companions in otherwise dense telemetry.

After cross-examination, the Threat Hunter’s position strengthened because the Detection Engineer and Host Analyst supplied broad, measurable defects that alternative explanations such as isolated collection loss cannot easily explain. The Detection Engineer likewise increased confidence after distinguishing the Host Analyst’s post-cutoff finding from ordinary bounded-window lifecycle asymmetry. The Host Analyst was reinforced by the Detection Engineer’s independent source-schema findings and the Threat Hunter’s observations of fleet-pooled Linux behavior.

The Network Analyst retained a Real verdict but reduced confidence substantially. The network evidence itself remained strongly production-like, yet the analyst accepted that source-native defects outside the network layer materially weaken a collection-wide Real assessment.

## Key Disagreements

The central disagreement was whether strong network realism outweighs deterministic defects in other source families.

The Network Analyst found no hard network contradiction and emphasized credible Zeek states, sensor placement, NAT views, proxy legs, protocol diversity, and byte accounting. The other experts agreed those observations were valid but argued that realism in one layer cannot explain invariant provider-format defects or selective lifecycle rendering elsewhere. The panel therefore reached a three-to-one Synthetic majority rather than unanimity.

A specific friction point concerned Snort fidelity. The Network Analyst rated the network formats as source-appropriate because every alert correlated correctly with an appropriate Zeek flow and appeared across varied connection outcomes. The Detection Engineer identified a narrower defect: all 227 alerts render rule `classtype` slugs where native fast-alert output normally uses configured human-readable classification descriptions. The panel judged these findings compatible rather than mutually exclusive—the correlations are realistic, but the formatter is noncanonical. The Detection Engineer’s exhaustive 227/227 observation carried greater weight on source-format authenticity.

The post-18:00 process terminations also generated disagreement. The Detection Engineer initially treated process and session closures crossing the bounded window as potentially legitimate. The Host Analyst’s stronger claim was not merely that some lifecycles ended late, but that every post-cutoff record belonged to termination families across eCAR, Security 4689, and Sysmon Event 5, while ordinary activity disappeared. The panel judged the selective termination-only tail harder to explain as a normal export boundary, though the Network Analyst noted that lifecycle-aware export behavior remains a possible alternative.

The Threat Hunter’s missing PsExec initiator, WMI trigger, and `DeviceSyncSvc.exe` delivery evidence remained less decisive. Dense telemetry makes the omissions conspicuous, but preexisting files, unobserved triggering mechanisms, or source-specific collection gaps remain viable explanations. These gaps supported the majority verdict without independently proving synthesis.

## Most Convincing Evidence

1. **Invariant source-native schema defects across complete event families.** All 227 Snort alerts use identifier-style classifications, all 1,049 Security 4624 v2 events share the same manifest-order mismatch, and all seven Sysmon Event 8 v2 records omit `SourceUser` and `TargetUser`. Their categorical repetition is more consistent with deterministic rendering than sporadic collector damage.

2. **Termination-only leakage beyond the apparent collection boundary.** Normal activity ends near 18:00, yet lifecycle closures continue through 18:49 across six hosts and three correlated source families. The fact that every post-cutoff record is a termination is more revealing than the mere presence of late closures.

3. **Missing causal companions in otherwise dense endpoint coverage.** The target-side PsExec sequence lacks a visible workstation initiator; repeated WMI-spawned administrative actions lack a visible trigger; and `DeviceSyncSvc.exe` is registered and executed without a visible delivery or creation path.

4. **Fleet-wide reusable Linux background texture.** Uncommon resolver, IRQ, NUMA, snap, cron, and administrative-command families recur across unrelated roles with constrained distributions. Exact periodic cron sequences also contain isolated cross-source omissions without visible host outages.

5. **Countervailing evidence: source-perspective and quantitative network coherence.** Independent sensor UIDs, plausible state/history combinations, NAT transformations, proxy client/origin separation, endpoint direction, and payload-versus-wire-byte accounting strongly resemble genuine production telemetry. This evidence prevented unanimous consensus and kept final synthetic-confidence scores moderate rather than overwhelming.

## Most Debated Points

- **Could the post-cutoff tail be intentional lifecycle completion?** Yes, but an exporter designed to complete lifecycles would need to explain why it includes only termination records and no ordinary activity during the same extended period.
- **Could missing PsExec, WMI, or service-binary artifacts be collection gaps?** Individually, yes. Their force comes from occurring in a collection that otherwise provides dense, closely correlated process and network visibility.
- **Does perfect correlation itself indicate synthesis?** The panel rejected that inference. The correlations preserve source-specific latency, NAT, UID, and byte-accounting differences and therefore count as realism strengths.
- **Are repeated Linux messages evidence of central administration?** Fleet-standard packages, cron configuration, and operator playbooks explain some repetition. The concern is the combined breadth, frequency, role independence, and recurrence of comparatively unusual message families.
- **Are stable DHCP renewals synthetic?** Client-specific T1 values could explain stable schedules, but hour-after-hour intervals varying by only about one to two seconds remain unusually tidy. The panel retained this as supporting evidence only.
- **Does absent NTP establish a generation gap?** No. Time synchronization may be outside sensor visibility or use another mechanism. It remains an environmental-plausibility concern, not a contradiction.
- **Does noncanonical Snort classification formatting outweigh correct alert-to-flow correlation?** The majority concluded that these evaluate different properties: the correlations are excellent, while the emitted fast-alert representation is still systematically non-native.

## Improvement Recommendations (Consensus)

- Render each source family from version-specific native schemas. Resolve Snort `classtype` identifiers through an authentic classification configuration, serialize Security 4624 v2 fields in provider-manifest order, and include `SourceUser` and `TargetUser` in Sysmon Event 8 v2. Add strict ordered-field and version-aware fixture tests.
- Enforce one observation-window contract after lifecycle planning. Do not emit Security 4689, Sysmon Event 5, or eCAR termination records beyond the configured cutoff while suppressing all other activity; leave such processes visibly open at window end or extend every relevant source consistently.
- Complete attack-action contracts at the canonical activity layer. Model the source-side PsExec process and its relationship to SMB transport, attach WMI-spawned commands to a visible remote or local trigger, and provide either a delivery/create event or explicit preexisting-file evidence for `DeviceSyncSvc.exe`.
- Broaden Linux background behavior by host role, installed software, version, verbosity, and operator practice. Reduce fleet-wide reuse of unusual resolver, irqbalance, NUMA, snap, cron, and exact administrative-command templates.
- Make periodic activity less fingerprintable while preserving causality. Give DHCP renewals explicit visible T1 semantics or greater scheduler/negotiation variation, and ensure skipped cron executions correspond to downtime, service interruption, overload, or a coherent observation gap.
- Expand public-edge and diagnostic texture. Use a broader, skewed scanner population with different port preferences and persistence patterns, and tie ICMP sizes more closely to identifiable operating-system or tool behavior.
- If broad infrastructure visibility is intended, add low-volume, host-stable NTP behavior with realistic polling intervals and source-specific observation gaps.
- Preserve the collection’s strongest existing qualities: independent sensor observations, endpoint versus firewall NAT perspectives, proxy client/origin separation, lifecycle-safe process identities, protocol timing, and quantitative byte accounting.
