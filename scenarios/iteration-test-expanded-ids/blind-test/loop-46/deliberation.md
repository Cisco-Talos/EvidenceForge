# Deliberation Summary

## Round 1 — Independent Positions

| Expert | Initial Verdict | Verdict Confidence | Synthetic-Confidence | Strongest Evidence |
|---|---:|---:|---:|---|
| Threat Hunter | Synthetic | 76 | 66 | Six generic identities account for all 64 interactive Linux sudo commands across nine hosts; 22 commands are attributed to `backup` or `svc_app` on a TTY; 29 commands run from another identity's home directory. |
| Detection Engineer | Real | 78 | 24 | Windows/Sysmon schemas and process identities are precise; lifecycle checks found no impossible visible ordering; Zeek protocol rows resolve to coherent connection tuples. The only scored concern was 74 Windows OpenSSH launches collapsing to 14 exact patterns. |
| Network Forensics | Synthetic | 78 | 66 | Forty-seven established, non-resumed TLS rows contain 70 certificate FUID references absent from the corresponding sensor's x509 stream; 13 of 15 rapid ICMP bursts vary payload size within a single apparent invocation. |
| Host/EDR Forensics | Synthetic | 82 | 70 | Every Linux host has exactly eight D-Bus records; 904 UFW blocks on the public web host reuse nine source IPs and near-evenly rotate exactly three TCP windows; rigid sysstat grids contain isolated unexplained holes. |

The panel began with broad agreement that the collection is mechanically strong. All four experts credited the Windows event schemas, process identities, visible lifecycle ordering, network tuple relationships, and source-native log-clear behavior. The dispute was whether those strengths outweighed dataset-wide population texture and an explicit network referential-integrity failure.

## Round 2 — Cross-Examination

### Precise mechanics versus population realism

The Detection Engineer's strongest evidence establishes that records are ingestible and that sampled identities, tuples, and visible lifecycles are coherent. It does not rebut the other experts' distribution findings. Exact per-host daemon quotas, roaming service-style sudo identities, narrow UFW fingerprints, and within-burst ICMP payload randomization can coexist with perfect XML schemas and process correlations. The panel therefore treated the detection checks as strong evidence of implementation quality, but not as sufficient evidence that the population came from production.

### Zeek protocol coherence versus dangling x509 identities

The Detection Engineer confirmed that DNS, HTTP, SSL, SMTP, and file records join to connection UIDs with compatible tuples and times. The Network Analyst found a narrower contract the detection review did not test: 47 established, non-resumed SSL rows explicitly name 70 certificate FUIDs absent from the same zone's x509 stream. These observations are not contradictory. Connection linkage can be correct while certificate-object linkage is broken.

The bounded-window caveat does not explain this finding. An SSL row observed in the window is not merely referring to an arbitrary process that may have begun before capture; it explicitly records certificate file identities for that observed handshake. If the source-local x509 objects are intentionally uncollected, the retained references should be omitted coherently. The panel judged this a material `contract_gap`, though not proof by itself that the entire corpus is synthetic.

### Central administration versus interchangeable Linux identities

A shared administrative team and centrally managed command vocabulary could explain some repeated sudo commands. They do not adequately explain why `backup` and `svc_app` repeatedly appear as interactive TTY users, or why 29 of 64 commands execute under another sampled identity's home directory across workstations, mail, application, database, proxy, and public-web roles. The threat-hunting evidence is fleet-wide and measured, so it carries more weight than a single odd shell line. The panel retained the possibility of shared jump-host practices, but no visible evidence in the reports ties these sessions to such a workflow.

### Scheduled jobs versus fixed quotas and unexplained gaps

Exact cron cadence is not inherently synthetic. A centrally deployed sysstat job can legitimately run on a rigid grid, and timer-driven DHCP renewals can be smooth. The stronger host finding is the conjunction: perfectly staggered fleet grids, isolated missing executions despite continued host logging, exactly eight D-Bus records on all nine Linux hosts despite sharply different volumes, and additional repeated quotas such as five anacron records. No single quota was treated as decisive; their cross-family recurrence materially strengthens the generator-template interpretation.

### Stable scanner fingerprints versus pooled UFW parameters

Persistent external scanners can reuse a source IP, packet length, and TTL. The implausible part is that each of several otherwise-stable sources rotates among the same three TCP window values in approximately balanced proportions over hundreds of blocks. The panel found no ordinary network explanation for that repeated three-bin behavior. It is stronger than the merely short source-IP tail and is independent of the Linux sudo issue.

### ICMP burst sizing and bounded samples

Fifteen bursts is a bounded sample, and deliberately varied payloads can occur in diagnostics or path-MTU testing. The concern survives because 13 of 15 same-tuple rapid bursts vary payload size, including large changes over tens of milliseconds. The panel reduced the weight slightly for sample size, but still considered it a strong distribution signal because ordinary ping invocations generally hold size constant within a burst.

### Narrative visibility

The attack chain is readily reconstructable, but no expert penalized it merely for being visible. The Threat Hunter and Host Analyst cited concrete baseline distributions, while the Network Analyst cited source-contract and sequence texture. Strong cross-source attack correlation was retained as positive evidence rather than relabeled as suspicious completeness.

## Round 3 — Revised Positions

### Threat Hunter

**Final Assessment:** Synthetic  
**Final Verdict Confidence:** 83  
**Final Synthetic-Confidence Score:** 72

The hunter increases confidence because the independent host findings show additional fleet-wide templating beyond sudo, and the network review adds a concrete reference-contract failure. The detection review prevents a higher score: process, session, and attack-chain mechanics are unusually sound.

### Detection Engineer

**Final Assessment:** Synthetic  
**Final Verdict Confidence:** 67  
**Final Synthetic-Confidence Score:** 61

The engineer revises from Real after distinguishing connection-UID coherence from the untested SSL-to-x509 contract and weighing multiple independent fleet-level distributions. Confidence remains lower than the other roles because the schemas, lifecycle ordering, collection gaps, and cross-source identifiers all remain strongly production-like, and several distribution findings could individually have operational explanations.

### Network Forensics Analyst

**Final Assessment:** Synthetic  
**Final Verdict Confidence:** 84  
**Final Synthetic-Confidence Score:** 71

The analyst modestly increases confidence because host and identity textures independently support the network verdict. The ICMP finding is kept below decisive weight due to the 15-burst sample, while the explicit dangling certificate references remain the strongest network-specific evidence.

### Host/EDR Forensics Analyst

**Final Assessment:** Synthetic  
**Final Verdict Confidence:** 87  
**Final Synthetic-Confidence Score:** 75

The analyst increases confidence because the sudo identity distribution and ICMP session texture show similar pool-driven behavior in independent families. The score remains below the highest band because Windows host telemetry, Linux shell narratives, and visible lifecycle relationships are coherent.

## Round 4 — Consensus

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---:|---:|---:|---:|---:|---:|
| Threat Hunter | Synthetic | 76 | 66 | Synthetic | 83 | 72 |
| Detection Engineer | Real | 78 | 24 | Synthetic | 67 | 61 |
| Network Forensics | Synthetic | 78 | 66 | Synthetic | 84 | 71 |
| Host/EDR Forensics | Synthetic | 82 | 70 | Synthetic | 87 | 75 |

**Consensus Verdict:** Synthetic  
**Consensus Verdict Confidence:** 80  
**Consensus Synthetic-Confidence Score:** 70

The final synthetic-confidence score is the rounded mean of the four revised role scores. Consensus confidence reflects unanimous final direction but preserves the Detection Engineer's material reservation that the corpus is mechanically stronger than the population-level defects suggest.

## Key Agreements

- Windows Security, Sysmon, and eCAR process/session evidence is source-appropriate and temporally coherent within the visible window.
- Zeek connection tuples and most protocol timing relationships are strong, and the core-versus-DMZ traffic mix is environmentally plausible.
- The log-clear EventRecordID reset and the multi-source attack chain are credible source-native details.
- The decisive synthetic case comes from several independent, measurable population or contract defects, not from attack visibility or mere cross-source completeness.
- Timer regularity, absent pre-window lifecycle starts, and optional collection gaps must be treated cautiously; none was used alone to decide the verdict.

## Key Disagreements

- The initial disagreement centered on whether excellent schemas and identity coherence should dominate authenticity. The final panel concluded they establish technical quality but do not neutralize broad distribution fingerprints.
- The Detection Engineer gave little weight to repeated OpenSSH commands and DC DNS concentration because both have ordinary enterprise explanations. The panel retained those only as low-priority signals.
- Network ICMP evidence was debated because only 15 bursts were identified. It remains actionable, but below the explicit SSL/x509 contract gap and the larger Linux/UFW populations.
- Rigid cron and DHCP timing can be legitimate. The panel objected primarily to unexplained missing ticks and repeated quota-like behavior, not to periodic scheduling itself.

## Most Convincing Evidence

1. **Linux interactive identity and working-directory texture:** all 64 sudo commands across nine hosts use six generic identities; 22 TTY commands use `backup` or `svc_app`, and 29 commands run from another identity's home directory.
2. **Zeek SSL/x509 referential-integrity gap:** 47 established non-resumed TLS rows retain 70 certificate FUIDs whose source-local x509 objects are absent.
3. **Public-web UFW fingerprint pooling:** 904 blocks reuse nine sources, with dominant stable sources repeatedly and near-evenly rotating the same three TCP windows.
4. **Fleet-wide fixed daemon quotas:** every Linux host emits exactly eight D-Bus records despite large role and volume differences, reinforced by repeated anacron quotas and rigid sysstat schedules with unexplained holes.
5. **Within-burst ICMP randomization:** 13 of 15 rapid same-tuple echo bursts change payload size, behavior more consistent with per-event draws than a normal ping invocation.

## Most Debated Points

- Whether missing x509 records are ordinary source-local collection loss. The panel decided explicit retained FUID references make this a lifecycle-group contract issue rather than an unscored absence.
- Whether central Linux administration explains the sudo pool. Shared administration is plausible, but interactive service accounts and widespread cross-home working directories remain unmotivated.
- Whether ICMP and scheduled-task patterns are large enough to generalize. Both were weighted conservatively; their importance comes from recurrence and agreement with independent pool/quota findings.
- Whether precise Windows and Zeek mechanics support a Real verdict. They substantially lower synthetic confidence, but do not directly address the decisive population evidence.

## Improvement Recommendations (Consensus)

1. **Repair TLS observation-group integrity.** Make SSL and x509 observation decisions atomic per sensor and handshake. If an SSL row retains `cert_chain_fuids`, retain every referenced x509 object in that zone; if certificate objects are dropped, omit the references coherently.
2. **Make Linux interactive identity session-owned and role-specific.** Reserve TTY sudo for plausible human administrators, keep service accounts non-interactive by default, and derive `PWD` from the authenticated session and command intent. Cross-account home directories should require a visible reason.
3. **Give Internet scanners persistent, source-specific fingerprints.** Expand the source population and bind TCP window, length, TTL, port preferences, and pacing to a scanner profile instead of redrawing a shared small pool per packet.
4. **Generate ICMP as invocation bundles.** Hold payload size, identifier, interval, and sequence behavior stable within one ping session; vary them between sessions or for explicitly modeled diagnostic modes.
5. **Replace fixed Linux background quotas with causal rates.** Derive D-Bus, anacron, and related counts from host role, uptime, active sessions, daemon state, and collection behavior. Tie skipped cron ticks to observable delay, outage, load, or collection loss.
6. **Diversify remote-administration texture after the higher-impact fixes.** Preserve legitimate recurring SSH destinations, but vary persistent versus fresh sessions, options, aliases, jump-host use, and command/session duration. Treat repeated DC DNS lookups and DHCP smoothness as lower-priority tuning, not contradictions.

## Prioritized Improvement Families

| Priority | Improvement family | Why it ranks here |
|---:|---|---|
| 1 | TLS lifecycle-group observation / SSL-to-x509 referential integrity | A concrete, source-native contract failure with 47 affected handshakes and 70 explicit dangling identities. |
| 2 | Linux sudo identity, session, and working-directory ownership | Broad fleet impact and a direct behavioral realism defect across 64 interactive commands. |
| 3 | Internet scanner fingerprint persistence and UFW source diversity | Very high-volume, externally visible pooled texture on the public web host. |
| 4 | ICMP invocation/session modeling | Repeated within-burst randomization; bounded sample lowers it below the larger families. |
| 5 | Linux daemon/background scheduling and quota modeling | Fleet-wide fingerprints, but some periodicity and centrally managed schedules are operationally plausible. |
| 6 | Windows SSH and resolver distribution texture | Measurable repetition with plausible enterprise explanations and no accompanying contract contradiction. |
