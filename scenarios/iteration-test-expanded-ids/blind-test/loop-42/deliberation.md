# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 74 | 43 | Synthetic | 88 | 82 |
| Detection Engineer | Inconclusive | 82 | 43 | Synthetic | 91 | 84 |
| Network Forensics | Synthetic | 94 | 88 | Synthetic | 96 | 91 |
| Host/EDR Forensics | Synthetic | 94 | 87 | Synthetic | 96 | 91 |

## Key Agreements

The panel agreed that the collection is technically sophisticated at the individual-event level. Windows Security, Sysmon, and eCAR process lifecycles correlate well; visible process and session ordering is coherent; SSH/PAM phases are credible; Zeek UIDs and protocol tuples generally resolve correctly; certificates, host roles, scanning, DHCP, authentication, and ordinary user activity provide convincing production-like texture. Complete cross-source correlation was not treated as synthetic by itself.

After cross-examination, all four experts also agreed that strong local construction does not overcome the global defects reported by the specialists. The network analyst's proxy CONNECT finding is a dataset-wide source-semantic contradiction rather than merely "too perfect" correlation: the same Zeek UID records the CONNECT request while its TCP byte counters omit the separately visible control exchange and match only tunnel payload, with ASA totals providing an independent check. The host analyst's Linux session-ID finding is likewise stronger than ordinary regularity because nine hosts exhibit one of two near-linear wall-clock allocation rates while showing far fewer actual session creations. The repeated IRQ/device map, bounded TLS delays, recursive-DNS quantization, and repeated source-native schema defects independently reinforce a generated-data explanation.

The Threat Hunter revised from Inconclusive to Synthetic because the network byte contradiction and host-wide counter fingerprints supply stronger evidence than the remote-execution gaps alone. The Detection Engineer made the same revision: its original checks established excellent local schema and lifecycle fidelity, but did not test the byte-ownership contract or cross-host session-counter allocation exposed by the other specialists. Network and Host/EDR retained Synthetic verdicts and raised confidence modestly because their independent network-wide and host-wide findings corroborate one another without depending on the same source family.

## Key Disagreements

The principal initial disagreement was whether high field fidelity, coherent lifecycle ordering, and plausible operational behavior justified an Inconclusive verdict despite isolated defects. The Threat Hunter and Detection Engineer emphasized those strengths and treated their own findings—missing remote-execution prerequisites, one incomplete SSH initiator, Event 1102 fields, and ICMP JSON encoding—as gaps that could occur in otherwise real collection. The Network and Host/EDR analysts instead found high-volume patterns that are difficult to attribute to collection loss. The panel resolved this as a difference in analytic scope, not a factual conflict: local records can be realistic while dataset-wide accounting, allocation, and timing rules remain synthetic.

The Detection Engineer's statement that Zeek protocol records resolve correctly to matching connection UIDs initially appeared to conflict with the Network analyst's proxy finding. Cross-examination showed that the Detection Engineer validated UID existence, tuple agreement, and ordering, whereas the Network analyst tested byte ownership within those matched records. Both claims can therefore be true, and the quantified source-semantic contradiction carries greater authenticity weight.

Some points remain less decisive. Missing WMI/RPC or WinRM transport and an actorless SSH source flow could result from endpoint or network observation loss, although their repetition at attack-critical boundaries makes that explanation less persuasive. Exact IRQ reuse could partly reflect cloned virtual-machine hardware, but identical IRQ numbers and mixed VMware, virtio, NVMe, and Mellanox devices across servers and workstation-class systems exceed what a shared image alone readily explains. Absent NTP can follow filtering or an unusual time architecture, and redundant eCAR aliases are compatible with an enrichment layer; neither materially drove the final consensus.

## Most Convincing Evidence

1. **Proxy CONNECT byte-accounting contradiction.** Hundreds of matched sessions have Zeek counters equal to tunnel bytes rather than CONNECT-control-plus-tunnel bytes even though Zeek logs the CONNECT exchange on the same UID; the ASA aggregate supports the missing-byte interpretation. A capture gap does not plausibly remove the same semantic byte component across both sensors while retaining the HTTP transaction.
2. **Clock-derived Linux session identifiers.** Across nine hosts, session IDs advance at near-perfect rates of roughly 0.15 or 0.1333 IDs per second despite only 13–62 visible new sessions per host. Invoking thousands of hidden sessions would require an internally implausible collection profile and would not readily explain the shared rate families.
3. **Identical cross-host IRQ/device topology.** Unrelated host roles reuse exact IRQ assignments for storage, network, input, and Mellanox devices, including unlikely mixed hardware on workstation-class systems. Cloning can explain common device names, but is a weak explanation for exact kernel allocation identity across the estate.
4. **Bounded network timing distributions.** TLS handshake offsets are nearly flat and terminate at the same approximately 650 ms ceiling across sensors and path types; 1,714 of 1,715 mirrored flows also use an almost universally positive 42–66 ms observation band. Stable clock skew or ordinary path latency could explain a center, not these shared hard bounds and nearly universal directionality.
5. **Repeated source-native and remote-execution contract gaps.** Event 1102 lacks required subject fields, ICMP JSON carries an ASCII unset marker, and multiple WMI-attributed target executions lack viable contemporaneous RPC/WinRM transport and source callers. Each issue admits a narrower alternative explanation than the first four findings, but together they reinforce the conclusion.

## Most Debated Points

The proxy-byte issue received the strongest challenge: control bytes might conceivably be metadata outside the measured tunnel stream. That explanation was rejected because the CONNECT HTTP row belongs to the same Zeek UID and ASA accounting independently reflects the larger aggregate; the repeated exact equality between Zeek and tunnel-only counters is too systematic for incidental capture loss.

The Linux session counters prompted debate over bounded-window incompleteness. The panel did not penalize missing pre-window initiators, but the issue is not a missing initiator: it is a cross-host mathematical relationship between new IDs and wall-clock time. The volume of hypothetical unobserved sessions needed to preserve normal counter semantics conflicts with the otherwise rich PAM, logind, SSH, and eCAR coverage.

The WMI and source-side SSH omissions remain boundary cases. Dense adjacent telemetry and recurrence make them suspicious, yet selective source loss or collection policy remains possible, so they were retained as supporting contract gaps rather than promoted to hard contradictions. Likewise, NTP absence and eCAR alias duplication remained weak signals because filtering, centralized time design, or compatibility schemas provide credible alternatives.

## Improvement Recommendations (Consensus)

- Establish one canonical proxy-transaction byte contract. Zeek connection payload counters should include the CONNECT request/response plus tunneled payload when the HTTP CONNECT row shares that TCP UID; proxy and firewall renderers should derive their documented source-native scopes from the same transaction totals.
- Allocate Linux logind session IDs from persistent per-host counters only when modeled sessions are created. Remove timestamp-derived formulas and keep PAM, logind, SSH, and endpoint session lifecycle records tied to the same allocation event.
- Give every host a durable hardware and daemon-state profile. Derive IRQ/device messages from role-appropriate per-host inventories, identify `fwupd` remotes, evolve metadata ages coherently, and broaden ambient daemon vocabularies through persistent host-specific entities rather than independent message sampling.
- Replace bounded timing draws with path-, endpoint-, and sensor-conditioned distributions. TLS handshakes should have realistic concentration and sparse long tails; DNS RTTs should retain capture-native precision; sensor clock offset, transit, and capture jitter should be modeled separately without one universal positive band.
- Complete remote-execution action contracts. WMI execution should include a source caller and contemporaneous TCP/135 plus dynamic RPC or WinRM transport, and SSH pivots should retain a source client process when that host's endpoint coverage is otherwise present; any observation loss should apply coherently to source-local lifecycle groups.
- Correct source-native schemas: populate Security Event 1102 subject fields, omit unset Zeek JSON `history` rather than writing `"-"`, document or normalize eCAR property aliases, and diversify Sysmon Event 11 filenames according to the creating process and native filename conventions.
