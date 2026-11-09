# Loop 15 Expert Panel Deliberation

**Scope:** This deliberation uses only the four saved Loop 15 expert reports. It does not independently inspect the underlying records. Round 3 records facilitator-modeled revisions based on the reports' cross-examination; it is not a claim that the original experts submitted follow-up statements.

## Round 1 — Present Findings

### Threat Hunter

- **Initial verdict:** Inconclusive
- **Verdict confidence:** 65
- **Synthetic-confidence score:** 37
- **Strongest evidence:** Two SSH sessions have matching source ports, tuples, and plausible timing across shell history, eCAR, Zeek, Unified Log, and Endpoint Security. The endpoint process/session lifecycle is compatible with the eCAR logout. The repeated root-shell creation and later deletion of the same LaunchDaemon plist on both Macs is unusual, but the report does not establish its contents, registration, or activation.
- **Distinct observation:** The MeetingAssist Unified Log entry says policy would not allow the app; it does not demonstrate execution or effects.

### Detection Engineer

- **Initial verdict:** Inconclusive
- **Verdict confidence:** 65
- **Synthetic-confidence score:** 43
- **Strongest evidence:** The two SSH tuples and source ports align across eCAR, Zeek, and Unified Log. The inspected Windows XML and Zeek JSON parse and contain plausible source-specific fields; no demonstrated schema, field-value, UID, or tuple defect was found. Four failed local logins on one Mac have close spacing, but could be user retries.
- **Distinct observation:** The Unified Log file contains only three records, so its failure to show the eCAR login attempts does not establish a collection gap.

### Network Forensics Analyst

- **Initial verdict:** Inconclusive
- **Verdict confidence:** 65
- **Synthetic-confidence score:** 30
- **Strongest evidence:** DNS, proxy CONNECT, and TLS records provide a coherent egress pivot; DNS/HTTP/SSL UIDs and tuples resolve to connection records. Connection states, hourly counts, DNS responses, TLS versions, and sensor-specific service mixes vary plausibly.
- **Distinct observation:** Repeated HTTP user agents and core DNS/Kerberos concentration are weak distribution signals, with plausible explanations in a limited client fleet, sensor overlap, and directory infrastructure.

### Host/EDR Forensics Analyst

- **Initial verdict:** Synthetic
- **Verdict confidence:** 76
- **Synthetic-confidence score:** 68
- **Strongest evidence:** Generic inspection commands recur across Linux histories for unrelated users and hosts, while the same user's two Mac histories repeat a small discovery-command set. The Mac Endpoint Security reports also reuse directory inode values and exact directory timestamps dated a year before the observed events.
- **Distinct observation:** Despite these texture concerns, the report found plausible Linux session lifecycles, a correlated dump/compression/SCP chain, matching Windows Security/Sysmon process fields, and coherent Mac process transitions, with no clear impossible ordering or source-native contradiction.

## Round 2 — Cross-Examination

### Contradictions and friction

The central disagreement is about how much weight to give recurring baseline texture. Host/EDR treats repeated generic commands across distinct hosts and users, plus repeated Mac filesystem metadata, as sufficient for a **Synthetic** verdict. The other three reports either did not identify those signals or regard the unusual activity they did identify as weak and ambiguous. The evidence is not directly contradictory: a dataset can have coherent individual event chains and still have overly repeated baseline behavior. The reports differ in the breadth and diagnostic weight they assign to that pattern.

The strongest common counterweight is cross-source coherence. All four reports describe SSH evidence as internally aligned, and the host and detection reports also identify plausible endpoint/process relationships. This supports consistency and usability, but—as the detection and network reports explicitly caution—consistency alone does not prove real-world origin.

### Blind spots

- The threat-hunter and detection reports focus heavily on the SSH pivots and do not discuss the broad recurrence of Linux inspection commands or the exact Mac directory metadata highlighted by Host/EDR. If those patterns are pervasive across the bundle as Host/EDR reports, they could raise the other experts' synthetic-confidence scores without invalidating the SSH evidence.
- Host/EDR's synthetic verdict depends on broad distribution and metadata signals, while its own report calls the metadata a weak signal and acknowledges that command recurrence could reflect routine health checks. Coordinated operational practices or a cloned/normalized filesystem image remain possible explanations in the reports; neither explanation is established.
- The threat hunter's repeated plist lifecycle and the detection engineer's failed-login spacing add separate weak signals. The reports provide plausible alternatives—coordinated administration and user retries—and no demonstrated contradiction. The small Unified Log sample further limits the failed-login coverage inference.
- The network report's repeated user agents and DNS/Kerberos concentration could be consistent with Host/EDR's narrow baseline patterns, but it does not tie those network patterns to the same generator mechanism. Sensor overlap, fleet size, and infrastructure roles remain viable alternatives described in the reports.

### Strength challenges

- **Repeated generic commands:** Their recurrence across unrelated accounts and hosts is suggestive of a narrow command pool. However, the reports also identify maintenance-oriented tasks and varied background infrastructure activity. The recurrence raises suspicion but does not by itself show impossible or implausible activity.
- **Repeated Mac metadata:** Reused inode values and directory timestamps from 2025 for events in 2026 can suggest cloned or normalized image metadata. Host/EDR explicitly does not claim an impossible state; the supplied reports do not establish whether the same metadata would be expected from the modeled images.
- **Repeated plist lifecycle:** Similar create/delete times on both Macs are unusual. Without contents, registration, activation, or service-management records, it is not possible to distinguish coordinated administration from templated generation.
- **SSH correlation:** Exact tuples, ports, and compatible lifecycle evidence across several sources are strong evidence of internal consistency. They are not proof of authenticity, and none of the reports treats them as such.
- **Failed-login rhythm and user-agent reuse:** Both are weak distribution indicators with credible benign or collection explanations in the reports.

## Round 3 — Revised Positions

These revisions are facilitator-modeled judgments after considering the other reports. Scores remain on the same scales as the submitted reports.

| Expert | Revised verdict | Revised verdict confidence | Revised synthetic-confidence | What influenced the revision |
|--------|----------------|----------------------------|------------------------------|-----------------------------|
| Threat Hunter | Inconclusive | 65 | 40 | Host/EDR's cross-host command recurrence and repeated filesystem metadata add texture concerns outside the threat hunter's narrow Mac review. The report's own plist concern remains weak, and the SSH pivots remain coherent. |
| Detection Engineer | Inconclusive | 65 | 45 | Host/EDR's broader routine-activity patterns modestly increase concern. The small Unified Log sample still cannot establish a companion-record gap, and no schema or field contradiction is demonstrated. |
| Network Forensics | Inconclusive | 65 | 34 | The host-side texture signals modestly increase the possibility of a modeled baseline, but do not explain or contradict the plausible traffic mix and intact Zeek pivots. |
| Host/EDR Forensics | Synthetic | 72 | 64 | The other reports' coherent SSH and source-native correlations reinforce that the bundle is operationally consistent, lowering confidence that texture alone settles origin. The repeated baseline patterns and metadata remain the strongest cross-host signals in the reports, so the verdict stays Synthetic. |

No expert changes the verdict category. The three initially Inconclusive reports move their synthetic-confidence scores upward modestly after hearing the broader host-side concerns. Host/EDR retains its Synthetic verdict but lowers its confidence and synthetic-confidence score because the other reports describe coherent, independently corroborated activity and because its strongest concerns remain non-conclusive.

## Round 4 — Consensus Summary

# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 65 | 37 | Inconclusive | 65 | 40 |
| Detection Engineer | Inconclusive | 65 | 43 | Inconclusive | 65 | 45 |
| Network Forensics | Inconclusive | 65 | 30 | Inconclusive | 65 | 34 |
| Host/EDR Forensics | Synthetic | 76 | 68 | Synthetic | 72 | 64 |

## Key Agreements

- The two SSH sessions are internally coherent across endpoint, network, and authentication evidence, including matching tuples/source ports and compatible timing.
- The reviewed records show no demonstrated impossible ordering, source-native schema defect, or clear field/tuple/UID contradiction.
- Cross-source correlation supports investigation pivots and internal consistency, but does not establish authenticity by itself.
- Several concerns are weak or ambiguous: repeated plist activity, failed-login spacing, user-agent reuse, DNS/Kerberos concentration, and filesystem metadata can each have plausible explanations not resolved by the reports.
- The denied MeetingAssist policy event does not establish successful execution or downstream effects.

## Key Disagreements

- Host/EDR assesses the bundle as Synthetic, emphasizing repeated generic commands across Linux hosts/users, repeated discovery commands on both Macs, and uniform Mac directory metadata.
- Threat Hunter, Detection Engineer, and Network Forensics remain Inconclusive. Their reports emphasize coherent cross-source behavior and caution that the identified anomalies do not demonstrate a defect or synthetic origin.
- The panel cannot determine from these reports whether the repeated commands and metadata reflect a narrow synthetic baseline, standardized administration, or cloned/normalized host images. The disagreement is therefore about evidentiary weight and coverage, not a direct conflict in event facts.

## Most Convincing Evidence

1. **Cross-source SSH lifecycle alignment (supports internal consistency):** Matching source ports and tuples across eCAR, Zeek, Unified Log, shell histories, and endpoint/session records provide the strongest corroboration described by multiple experts. It shows coherent event construction, though not provenance.
2. **Repeated generic host command patterns (supports synthetic concern):** Host/EDR reports the same small inspection-command set across several unrelated Linux histories and both Mac histories. The breadth of recurrence is the clearest distribution-texture concern, while still compatible with standardized maintenance.
3. **Repeated Mac filesystem metadata (supports synthetic concern):** Reused inode values and exact 2025 directory timestamps in both Mac exports, against 2026 event times, are notable. The report offers cloned or normalized images as a possible explanation and does not establish an impossible state.
4. **DNS-to-proxy-to-TLS and Zeek UID/tuple integrity (supports internal consistency):** The network report describes a coherent egress example and intact references across protocol and connection records, with plausible sensor-specific traffic mixes.
5. **Repeated LaunchDaemon plist lifecycle and failed-login cadence (weak synthetic signals):** Similar file create/delete timing on both Macs and a short burst of failed logins deserve contextual review, but the reports identify plausible operational explanations and no confirming artifact.

## Most Debated Points

- Whether repeated generic commands indicate an overly narrow baseline or ordinary standardized administration.
- Whether the exact Mac directory metadata reflects templated output or a consistent modeled filesystem image.
- Whether the repeated LaunchDaemon plist activity represents coordinated deployment/cleanup or a repeated synthetic workflow; file operations alone do not establish registration or activation.
- How much weight to assign eCAR-only failed-login attempts when the Unified Log sample contains just three records.
- Whether repeated user-agent strings and concentrated DNS/Kerberos traffic are meaningful distribution signals given the reported sensor overlap and infrastructure roles.

## Improvement Recommendations (Consensus)

These are conditional recommendations for a synthetic dataset, as framed by the expert reports:

- Broaden routine shell-history variation by role and host. Reduce recurrence of the same generic inspection commands across unrelated accounts, while retaining operationally plausible health checks.
- Give Mac filesystem metadata realistic host- and path-specific variation, or make the modeled filesystem-image relationship consistent enough that reused metadata has an explainable basis.
- If the repeated LaunchDaemon lifecycle represents deployment or cleanup, include source-visible context for the responsible command or service-management operation. Keep file creation distinct from registration, activation, or unload evidence.
- Vary repeated failed-login timing when the intended behavior is user retry, and include source-native companion records only where the modeled collection profile would capture them.
- Preserve the coherent SSH tuple, source-port, authentication, connection-state, and session-close relationships, along with the DNS/proxy/TLS pivots and sensor-specific Zeek UID/tuple integrity.
- Keep repeated user-agent patterns tied to plausible client populations and observation points, and retain the distinct service mix reported for core, DMZ, and database sensors.
