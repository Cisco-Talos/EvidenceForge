# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Real | 68 | 36 | Inconclusive | 72 | 45 |
| Detection Engineer | Real | 82 | 24 | Real | 76 | 34 |
| Network Forensics | Synthetic | 76 | 66 | Inconclusive | 72 | 58 |
| Host/EDR Forensics | Synthetic | 78 | 67 | Synthetic | 80 | 64 |

The initial panel average synthetic-confidence score was **48.25**. After cross-examination, the revised average is **50.25**. This small movement toward uncertainty is not a new independent judgment by the facilitator; it reflects the panel giving more weight to findings from adjacent specialties while retaining different thresholds for whether strong distribution artifacts outweigh technically correct source-native evidence.

## Round 1 — Initial Positions

### Threat Hunter

The Threat Hunter initially assessed the dataset as **Real**, with **68% verdict confidence** and a **36 synthetic-confidence score**. The strongest evidence was the coherent end-to-end intrusion: initial web compromise, Apache-owned reverse-shell execution, correlated egress, discovery, SSH lateral movement, staging, browser file access, proxy upload, and independently plausible byte accounting. The reviewer also emphasized role-shaped source volumes, mixed connection outcomes, normal collection gaps, and believable contention from benign activity. Their strongest synthetic indicators were approximately 120 successful SSH authentications concentrated in a few administrators, broad direct and direct-root SSH access to the public-facing web host, and a narrow command vocabulary reused across unlike Linux systems. The Threat Hunter uniquely evaluated the full operational hunt path and found no impossible visible ordering.

### Detection Engineer

The Detection Engineer initially assessed the dataset as **Real**, with **82% verdict confidence** and a **24 synthetic-confidence score**. Their strongest evidence was accurate source-native Windows Security and Sysmon metadata, near-complete but non-identical Security 4688/Sysmon Event 1/eCAR process correlation, and exhaustive Zeek UID/tuple/protocol-interval integrity without causal inversion. The principal concern was a fleet-wide collection-profile asymmetry: all 695 Sysmon Event 3 records were `Initiated=true` despite 4,866 inbound Security 5156 records on the same Windows estate. They also noted categorical field populations—uniform WFP remote identities, successful process exits, and empty source-port service names—and broad use of zero Sysmon `LogonGuid`, but treated these as weaker or plausibly filter-driven. This reviewer uniquely established parser/schema fidelity and exhaustive protocol-reference integrity.

### Network Forensics Analyst

The Network Forensics Analyst initially assessed the dataset as **Synthetic**, with **76% verdict confidence** and a **66 synthetic-confidence score**. Their strongest indicators were that eight persistent, service-specialized external sources produced 1,043 of 1,225 external DMZ `S0` records; DHCP renewal intervals stayed within roughly one to two seconds of a host-specific cadence over repeated cycles; and five major service labels accounted for 91.4% of core connections while NTP and most ambient discovery traffic were absent. Against that verdict, the analyst found convincing Zeek state/history semantics, rich DNS and TLS behavior, coherent explicit-proxy legs, credible ASA/NAT lifecycles, and sensor-specific IDS timing. This reviewer uniquely quantified perimeter-source concentration, DHCP periodicity, and the short internal protocol tail.

### Host/EDR Forensics Analyst

The Host/EDR analyst initially assessed the dataset as **Synthetic**, with **78% verdict confidence** and a **67 synthetic-confidence score**. Their strongest indicators were five unrelated Windows network-logon pairs with an exact 1 ms lifetime, more than 100 accepted SSH sessions concentrated in a small persona/host matrix, and invariant Defender Sysmon Event 10 call traces within each host despite arbitrary-looking cross-host offsets. They also identified a concrete SCP receiver lifecycle gap on `APP-INT-01`, where two sibling privileged `sshd` processes split syslog/session and file ownership and only one visibly terminated, plus heavily quantized module-load bursts. Against these concerns, the reviewer found excellent 4688/Sysmon/eCAR process correlation, generally sound session state, source-native SSH sequences, and a particularly credible Windows Security-log-clear sequence. This reviewer uniquely surfaced the 1 ms lifecycle floor, call-trace templating, module timing quantization, and SCP receiver ownership split.

## Round 2 — Cross-Examination

### Friction 1: Correct contracts versus modeled population texture

The strongest disagreement is not factual. All four reviewers agreed that the inspected records are generally parseable, source-appropriate, cross-source coherent, and free of broad impossible ordering. The Detection Engineer and Threat Hunter treated that as dominant evidence for a production-like collection. The Network and Host reviewers treated population-level regularity as dominant evidence of generation.

Cross-examination narrows the dispute: technical consistency does not rebut the quantified SSH concentration, scanner persistence, DHCP cadence, 1 ms logon floor, or template timing; conversely, those patterns do not invalidate the unusually strong tuple, PID, UID, NAT, certificate, and lifecycle contracts. The evidence supports a dataset that is technically convincing at the individual-event and correlated-activity level but less convincing in several background-population distributions. The panel therefore moved toward the middle without reaching a common verdict.

### Friction 2: SSH as realistic operations or reusable persona matrix

The Threat Hunter and Host analyst independently found essentially the same SSH issue from different evidence. The Threat Hunter counted roughly 120 successful authentications and observed a few named users repeatedly traversing web, app, database, mail, and proxy hosts. The Host analyst counted 46 public-key sessions for `marcus.chen`, 43 for `aisha.johnson`, and 16 for `lina.nguyen`, along with matching repeated eCAR process titles. This corroboration makes the issue stronger than an isolated impression.

The alternative explanation is an operations-heavy environment or automation represented through SSH. That explanation weakens because the records look interactive, reuse a small command pool, span unrelated sensitive roles, and include broad direct access to an Internet-facing host rather than a bastion- or task-oriented pattern. At the same time, the SSH transport/auth/PAM/logind ordering itself is convincing. The panel therefore agreed that SSH is a distribution and environment-design weakness, not a broken SSH contract.

### Friction 3: Missing inbound Sysmon Event 3 as filter or generator omission

The Detection Engineer's all-`Initiated=true` finding is concrete and dataset-wide, but its meaning remains disputed. A deliberate outbound-only Sysmon configuration is a credible production explanation, particularly because Security 5156 still records inbound traffic. However, no visible collection-profile artifact explains the policy, and the asymmetry spans server roles where inbound Event 3 observations would ordinarily be expected under a broad network-connect configuration.

The Host reviewer did not identify malformed Event 3 semantics, and the Threat Hunter considered incomplete endpoint FLOW attribution normal. Thus, the panel did not elevate this to a contradiction. The specialist evidence nevertheless changes the broader interpretation: without explicit collection-profile support, the all-or-nothing directionality is a meaningful curated-coverage signal.

### Friction 4: Sparse network long tail versus a quiet, filtered six-hour window

The Network analyst's 91.4% concentration in five service labels, complete absence of UDP/123, and near-absence of mDNS/LLMNR could reflect a small, tightly managed network, centralized time synchronization outside the observed path, or sensor filtering. The bounded six-hour window also limits the expected long tail. Those alternatives are plausible individually.

The concern becomes stronger in combination with broad core visibility across DHCP, DNS, Kerberos, LDAP, SMB, proxy, ICMP, SSH, and RDP. The same sensor looks comprehensive for modeled enterprise families but empty for common low-volume infrastructure and discovery families. The panel accepted this as a moderate environment/collection-plausibility signal, while stopping short of calling any one absent protocol a contradiction.

### Friction 5: SCP receiver process split and OpenSSH privilege separation

The Host reviewer found the most concrete single lifecycle concern: two sibling `sshd: root [priv]` processes for one SCP tuple, with syslog/session ownership on PID 980771, file ownership on PID 980770 after a title change, and visible termination only for PID 980771. OpenSSH privilege separation can legitimately create multiple related processes and change process titles, so process multiplicity alone is not synthetic evidence.

The stronger issue is the modeled ownership split: both children begin as direct listener children, the authentication/session records select one, the received file selects the other, and the lifecycle does not visibly resolve the file-owning process. Because this is one high-value occurrence rather than a dataset-wide pattern, the panel treated it as a concrete contract gap with high diagnostic value but less overall score leverage than the recurring SSH and network-population textures.

### Friction 6: Strong unique host timing findings

The exact 1 ms network-logon pairs, fixed per-host Defender call traces, and 0–3 ms module-load quantization were unique to the Host reviewer. Alternative explanations exist: very short Type 3 sessions, common Defender code paths on a stable build, and fast initial module loading. The repeated shapes weaken those alternatives. Five unrelated session types sharing an exact floor suggests a minimum-duration rule; per-host rather than build/code-path call-trace identity is hard to explain semantically; and hundreds of tightly quantized ordered module records look more like renderer timing than collector scheduling.

The other reviewers did not contradict these measurements; they largely sampled different levels of the data. The panel therefore retained them as strong specialist findings, while distinguishing the repeated 1 ms floor from the lower-confidence interpretation of module and call-trace distributions.

## Round 3 — Revised Positions

### Threat Hunter — revised to Inconclusive, 72% verdict confidence, 45 synthetic-confidence

The Threat Hunter's operational assessment remains: the intrusion and its pivots are credible, source volumes are role-shaped, and no impossible visible ordering was found. The verdict moves from Real to Inconclusive because the Host reviewer independently confirmed the SSH concentration and added repeated 1 ms session floors, call-trace templating, and module timing artifacts that are not explained by the realistic hunt path. The concrete SCP ownership split also weakens the assumption that all lifecycle joins are production-like. Increased verdict confidence reflects a better-supported mixed assessment, not greater confidence that the data is synthetic.

### Detection Engineer — remains Real, 76% verdict confidence, 34 synthetic-confidence

The Detection Engineer retains a Real verdict because source-native schemas, event metadata, process joins, Zeek UID contracts, protocol timing, and the log-clear sequence remain exceptionally strong. Synthetic-confidence rises because the Host review shows that validity checks can pass while source-native populations still carry generator-like duration and timing floors, and the Network review adds independent dataset-wide distribution evidence. Verdict confidence falls because the outbound-only Sysmon profile is no longer an isolated concern; it fits a broader pattern of cleanly bounded populations. The reviewer still does not regard any of these as a broad hard contradiction.

### Network Forensics — revised to Inconclusive, 72% verdict confidence, 58 synthetic-confidence

The Network analyst retains the scanner concentration, DHCP regularity, and short protocol tail as material synthetic indicators. The verdict softens to Inconclusive after giving greater weight to the Detection Engineer's exhaustive UID/tuple/interval checks and the Threat Hunter's end-to-end validation of NAT, proxy, transport, authentication, process, and byte-accounting relationships. The individual network records and multi-vantage relationships are too strong for a confident synthetic verdict based only on population texture. Synthetic-confidence remains above the midpoint because the scanner and DHCP measurements are repeated, quantified, and specialty-specific.

### Host/EDR Forensics — remains Synthetic, 80% verdict confidence, 64 synthetic-confidence

The Host reviewer retains a Synthetic verdict. Cross-examination reinforces the SSH finding through independent Threat Hunter corroboration, while the exact 1 ms floor, call-trace templates, quantized module bursts, and SCP ownership split remain unrebutted concrete host observations. Synthetic-confidence falls slightly because the Detection Engineer's broad schema and lifecycle checks establish that these defects sit inside an otherwise strong source-native implementation, and because plausible production explanations exist for parts of the Event 10 and module-load evidence. Verdict confidence rises because the remaining conclusion is more narrowly grounded in repeated host-population artifacts rather than any claim that the entire dataset is technically invalid.

## Key Agreements

- All four reviewers agreed that the dataset is technically strong at the record and correlation layers. Windows/Sysmon schemas, Zeek UID and tuple contracts, TLS certificates, proxy legs, ASA/NAT records, process identities, and the main attack sequence are generally source-native and causally coherent.
- No reviewer found a broad impossible ordering in the visible six-hour window. Missing pre-window initiators or post-window terminations were not treated as synthetic by themselves.
- The panel agreed that SSH administration is the highest-leverage shared weakness: too many interactive-looking sessions are concentrated in a few users and spread across too many unrelated Linux roles, including the public-facing web host.
- The panel agreed that the remaining strongest concerns are population/distribution or lifecycle-template issues, not basic parser, schema, or identifier failures.
- The panel agreed that collection-filter explanations can plausibly account for missing inbound Sysmon Event 3 and parts of the sparse protocol tail, but those explanations should be explicit and internally reflected if they are intended.
- The panel agreed that the one SCP receiver process split deserves a focused lifecycle correction even though it is not broad enough to determine the overall verdict.

## Key Disagreements

- The panel did not agree on whether source-native correctness and causal integrity outweigh recurring distribution artifacts. Detection continued to say yes; Host continued to say no; Threat Hunter and Network converged on Inconclusive from opposite directions.
- The panel did not agree on how much evidentiary weight to give absent inbound Sysmon Event 3. Detection views the 695/695 outbound population as curated-looking but plausibly filtered; the other findings make it more suspicious, but no reviewer established a contradiction.
- The panel did not agree that missing NTP or ambient discovery is independently meaningful. Network considers the combined protocol distribution implausibly short for the apparent sensor breadth; others accept that filtering or a quiet managed environment could explain it.
- The fixed Defender call traces and quantized module bursts remained specialist-supported rather than independently reproduced by another reviewer. They are credible synthetic indicators, but their exact weight remains disputed because production collectors can also yield repeated code-path and startup patterns.
- The final verdict remains split: one Real, two Inconclusive, and one Synthetic. The panel's revised average synthetic-confidence of 50.25 accurately represents this boundary rather than supporting a forced consensus label.

## Most Convincing Evidence

1. **Dataset-wide SSH persona/host repetition — synthetic indicator.** Two specialties independently measured more than 100 accepted sessions concentrated in `marcus.chen`, `aisha.johnson`, and `lina.nguyen`, with repeated interactive-looking process titles and commands across web, mail, proxy, app, and database roles. Its recurrence, cross-source visibility, sensitive-host breadth, and independent corroboration make it the strongest improvement target.
2. **Source-native and cross-source contract integrity — real indicator.** The Detection Engineer exhaustively found no orphan or tuple-conflicting Zeek DNS/HTTP/SSL UIDs, while the Threat Hunter validated a multi-stage intrusion across web, eCAR, Security/Sysmon, Zeek, proxy, ASA, and syslog without visible causal inversion. This is the strongest evidence against a confidently synthetic verdict.
3. **Persistent service-specialized perimeter scanners and short internal protocol tail — synthetic indicator.** Eight sources account for 1,043 of 1,225 external `S0` records over most of the window, while five service labels make up 91.4% of core connections. The quantified, dataset-wide pattern is difficult to dismiss as a single quiet-period anomaly.
4. **Repeated exact 1 ms Windows network-logon lifetimes — synthetic indicator.** Five unrelated LDAP/SMB, machine, anonymous, and user sessions on two hosts share the same exact minimum lifetime. A single 1 ms session is plausible; repeated cross-family use strongly suggests a shared duration floor.
5. **Concrete SCP receiver ownership split — synthetic indicator.** One transfer divides authentication/session and received-file ownership across two sibling privileged `sshd` processes and leaves the file-owning process without visible termination. OpenSSH process multiplicity is real, but this particular hierarchy and ownership split are not convincingly source-native.

## Most Debated Points

- Whether an explicit outbound-only Sysmon configuration sufficiently explains all 695 Event 3 records being `Initiated=true` despite thousands of inbound Security 5156 observations.
- Whether the absence of NTP and almost all ambient discovery traffic reflects a curated generator population or a legitimate sensor/filtering boundary during a six-hour slice.
- Whether one fixed Defender Event 10 call trace per host can arise from stable code paths and patch levels, or whether the per-host arbitrary offset pattern is parameterized.
- How heavily to weight extremely strong cross-source matching: the panel treated correctness as positive evidence, not as a synthetic indicator merely because the matches are complete.
- Whether the SCP receiver process structure is an OpenSSH privilege-separation variant or an action-bundle ownership defect. The panel agreed that process multiplicity is plausible but found the split ownership and incomplete visible lifecycle difficult to explain.

## Improvement Recommendations (Consensus)

1. **Diversify and constrain the SSH administration model.** Assign administrators role-appropriate destination sets; make routine administration bastion- or management-subnet-mediated; reduce direct-root and direct public-web-host access; and mix persistent/multiplexed sessions, sudo by named users, noninteractive automation, and days or windows without access. Bind command vocabulary, authentication method, session duration, and cadence to user specialty and destination role rather than drawing many interactive-looking sessions from one shared matrix.
2. **Broaden and churn perimeter background identities.** Replace the small all-window scanner roster with a larger population containing many one-off and short-lived sources, overlapping rather than perfectly specialized service interests, independently varying hourly envelopes, and stable per-source persona only for the period that source exists. Preserve current Zeek/ASA/IDS tuple and timing contracts while changing population generation.
3. **Remove deterministic lifecycle and timer floors.** Replace the exact 1 ms Windows Type 3 logon minimum with service- and outcome-dependent duration distributions covering LDAP, SMB machine-account, anonymous, and user sessions. Give DHCP renewals wider stateful jitter, delayed or missed renewals, occasional lease changes, and less invariant host-specific recurrence while preserving valid REQUEST/ACK ordering.
4. **Make receiver-side OpenSSH ownership coherent.** Model listener, privileged monitor, session child, and noninteractive SCP process as an explicit hierarchy. Attach the accepted tuple, syslog PID, process-title transitions, received-file writer, and termination to the correct process identities, then verify both SCP and ordinary interactive SSH sibling paths.
5. **Make host telemetry templates build- and code-path-aware.** Derive Sysmon Event 10 call traces from OS/build/module version and access path rather than a unique per-host template. Add process/image-specific module sets and source-observation jitter so module loads retain realistic dependency order without hundreds of 0–3 ms quantized bursts.
6. **Align collection coverage with an explicit profile.** Either emit a small source-native population of inbound Sysmon Event 3 records on server roles corresponding to already-visible inbound 5156 flows, or represent and document a deliberate outbound-only filter. Apply the same principle to the network sensor: add a low-volume role-appropriate NTP/discovery/application tail, or encode plausible suppression/routing that explains why broad core visibility excludes those families.
7. **Add safe long-tail field behavior only where source semantics support it.** Preserve the strong schemas and contracts while allowing genuinely abnormal process exits, session-backed non-zero `LogonGuid` values, and other rare field states. Do not introduce variation merely for randomness; tie it to an owned process, session, security policy, or collection condition.

The ranked top improvement is the SSH administration family because it is dataset-wide, independently corroborated by two specialties, visible across syslog/eCAR/Zeek, and tied to both behavioral frequency and host-role plausibility. It offers greater expected synthetic-confidence reduction than repairing any single isolated row while retaining the dataset's strongest correlation behavior.
