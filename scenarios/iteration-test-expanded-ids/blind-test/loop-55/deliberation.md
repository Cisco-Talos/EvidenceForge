# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 76 | 48 | Inconclusive | 80 | 60 |
| Detection Engineer | Synthetic | 87 | 68 | Synthetic | 91 | 76 |
| Network Forensics | Real | 74 | 32 | Inconclusive | 70 | 49 |
| Host/EDR Forensics | Synthetic | 84 | 74 | Synthetic | 88 | 78 |

The initial average synthetic-confidence score was **55.5**. After cross-examination, the revised average was **65.75**. The panel's final collective assessment is **likely synthetic**, but not because the corpus is broadly malformed or causally incoherent. Two reviewers retained a non-Synthetic verdict because most of the dataset remains production-like; the consensus moved toward synthetic because a small number of concrete, reproducible fingerprints are difficult to explain as ordinary collection behavior.

## Round 1 — Initial Positions

### Threat Hunter

The Threat Hunter began **Inconclusive** at 76% verdict confidence and a synthetic-confidence score of 48. Their strongest evidence for authenticity was the technically coherent end-to-end attack lifecycle: LSASS access, PsExec transport and service creation, persistence, file staging, proxy upload, database staging, and cleanup were correctly ordered and pivotable across sources. They also emphasized credible scale, mixed connection outcomes, imperfect file extraction, and a jittered DNS tunnel rather than a mechanically fixed loop.

Their strongest synthetic concerns were environmental: two overlapping RDP sessions for the same user/client/target created separate target-side interactive process trees only 34.2 seconds apart; 136 successful SSH authentications were concentrated in three people; and a generic root-owned health-check script repeatedly contacted semantically unrelated advertising, analytics, widget, and package-registry destinations from two dissimilar server roles. The role-incompatible health-check target pool was their most distinctive observation.

### Detection Engineer

The Detection Engineer began **Synthetic** at 87% verdict confidence and a synthetic-confidence score of 68. Their decisive evidence was a repeated DHCP syslog timestamp fingerprint: all 34 complete REQUEST/ACK/bound triplets across three hosts preserved the same final three microsecond digits within each triplet. The suffix changed between transactions but remained frozen across the three independently logged lifecycle messages, which strongly suggests integral-millisecond arithmetic from one shared anchor.

Their evidence for authenticity was extensive: correct Windows and Sysmon event versions and field forms, sensor-local Zeek UID integrity, protocol children inside visible connection intervals, coherent eCAR lifecycles, varied Security-to-Sysmon and Sysmon-to-eCAR timing, and diverse process command lines. The DHCP residue fingerprint was the only decisive synthetic indicator they reported, which made it unusually specific rather than cumulative.

### Network Forensics Analyst

The Network analyst began **Real** at 74% verdict confidence and a synthetic-confidence score of 32. Their strongest authenticity evidence was independent multi-sensor behavior: the two Zeek sensors used different UIDs for matching flows, exhibited a drifting 26.9–66.3 ms offset, and disagreed plausibly on packet counts and histories because of sensor-specific loss. They also found realistic state/history diversity, nonzero `missed_bytes`, valid connection-child timing, broad DNS outcomes, coherent suspicious TXT traffic, plausible TLS chain visibility, and IDS timing consistent with sensor skew.

Their principal synthetic concern was the complete absence of UDP/123 in 11,472 flows despite broad visibility into DHCP, DNS, Kerberos, and at least 18 internal addresses. They also found external scanner sources unusually partitioned into narrow port palettes, with weaker concerns about uniformly established parsed TLS sessions and heavy DNS concentration on the domain controller hostname. The missing NTP population and dual-sensor realism were observations unique to their specialty.

### Host/EDR Forensics Analyst

The Host/EDR analyst began **Synthetic** at 84% verdict confidence and a synthetic-confidence score of 74. Their strongest finding was a source-visible hard contradiction: `runas.exe` PID 8812 had the complete command line `runas.exe`, then produced successful explicit-credential Event 4648 evidence and remained alive for 2,605.686 seconds. A bare invocation has neither `/user:` nor a target program, should show usage and exit quickly, and cannot perform the represented credentialed launch.

They also found that all six Office-specific registry records were owned by an incompatible Office executable, including Word writing PowerPoint and Excel state and Outlook writing Word and Excel state. Fourteen Defender exclusion writes on three hosts formed a further repeated template: numbered generic vendor-cache paths were directly attributed to Defender processes rather than a credible policy, installer, PowerShell, or administrator producer. Their positive evidence included 893 perfectly aligned process paths across Security, Sysmon, and eCAR; valid visible lifecycles; credible EventRecordID reset semantics; and differentiated Linux host roles.

## Round 2 — Cross-Examination

### Hard endpoint contradiction versus broad operational coherence

The central friction was whether one source-visible process contradiction should outweigh tens of thousands of coherent records. The Threat Hunter and Network analyst initially weighted the intact attack lifecycle and production-like network texture heavily. The Host analyst's `runas.exe` finding nevertheless survived the strongest alternative explanations. It is not merely a missing pre-window argument, truncated command-line field, or logging gap: the process creation is visible in-window, Sysmon presents `runas.exe` as the complete command line, Security then attributes successful explicit-credential use to that same PID, and eCAR gives the bare invocation a 43-minute lifetime. The panel judged this the strongest individual synthetic observation.

This evidence does not invalidate the Threat Hunter's finding that the broader attack chain is operationally coherent. Both can be true: the correlation framework can be highly realistic while one action-family contract creates impossible executable semantics. The disagreement narrowed from whether the corpus contains a hard defect to how much one defect should control the global verdict.

### DHCP residue fingerprint versus legitimate lifecycle anchoring

The Detection Engineer's DHCP finding was challenged as a possible consequence of one host clock, one daemon, or a tightly related transaction. Those explanations account for close timing but not for preserving an arbitrary nonzero final-three-digit suffix across three separate log calls in **34 of 34** triplets on three hosts while changing the suffix between transactions. The causal ordering and renewal cadence remain credible; the defect is specifically the low-order timestamp distribution. The panel accepted it as a strong dataset-level generator fingerprint rather than an impossible causal ordering.

This finding materially influenced the Threat Hunter and Network analyst because it is repeated, source-native, and independent of narrative design. It also reinforced the Host analyst's concern that some otherwise coherent event families are assembled through reusable templates.

### Office and Defender registry ownership versus benign telemetry ambiguity

The panel distinguished the six Office mismatches from the fourteen Defender records. The Office result is systematic and semantically testable: all six application-specific paths disagree with their producing executable, so ordinary timing or collection loss is not a persuasive alternative. It was accepted as a high-strength contract gap.

The Defender exclusion writes are less absolute. Defender components can participate in preference handling, and centralized policy could create repeated state. However, direct attribution to `MsMpEng.exe` or `MpCmdRun.exe`, generic numbered `Vendor\Cache\<n>` paths, repeated mutations, and occurrence across unrelated host roles collectively look pool-driven. The panel retained this as a meaningful distribution and actor-ownership concern, below the Office mismatch in strength.

### Environmental weaknesses versus collection-profile explanations

The Network analyst's zero-NTP finding prompted the most unresolved discussion. A broad six-hour enterprise capture would normally contain some NTP, especially with DHCP, DNS, and Kerberos visible, but a collection policy, longer polling intervals, host-local time service, or upstream filtering could explain the absence. Because the dataset contains no explicit collection profile establishing that exclusion, the finding remains a concrete environment plausibility gap, not a hard contradiction.

The same caution applied to scanner port palettes, duplicate RDP sessions, concentrated SSH administration, uniform Sysmon families, and repeated DLL palettes. Each can occur in a real environment. Their evidentiary strength comes from repetition, clean partitioning, role mismatch, or simultaneous appearance with stronger defects—not from mere completeness, tidiness, or a compact attack narrative.

### Positive evidence that resisted synthetic over-interpretation

All four experts agreed that complete cross-source matching by itself is not a synthetic indicator. More importantly, the corpus includes details that actively support authenticity: independent Zeek sensor clocks and UIDs, asymmetric packet-loss observations, varied source-native timestamp delays, correct EventRecordID behavior after log clearing, imperfect file observation, connection-state diversity, and no visible same-identity lifecycle inversion in the principal chain. The panel treated these as genuine realism strengths, not as reasons to dismiss the specific contradictions.

## Round 3 — Revised Positions

### Threat Hunter — revised but still Inconclusive

The Threat Hunter retained an **Inconclusive** verdict, increased verdict confidence from 76 to 80, and raised synthetic confidence from 48 to 60. The `runas.exe` contradiction, the 34/34 DHCP residue pattern, and the systematic Office actor mismatch moved the assessment toward synthetic because they are concrete log-visible defects outside narrative-design concerns. They did not adopt a fully Synthetic verdict because the attack lifecycle, pivot feasibility, signal-to-noise ratio, and cross-source causal ordering remain unusually convincing.

### Detection Engineer — reinforced Synthetic

The Detection Engineer retained **Synthetic**, raised verdict confidence from 87 to 91, and raised synthetic confidence from 68 to 76. The Host analyst's `runas.exe` evidence supplied a hard semantic contradiction independent of the DHCP timing distribution, while the six Office mismatches supplied a second repeated family-level defect. Those findings reduced the possibility that the DHCP pattern was an isolated source-specific artifact.

### Network Forensics Analyst — revised from Real to Inconclusive

The Network analyst revised **Real** to **Inconclusive**, lowered verdict confidence from 74 to 70, and raised synthetic confidence from 32 to 49. Their network-only assessment remained mostly production-like, especially because of dual-sensor drift, packet-loss texture, and valid protocol timing. The cross-examination changed the whole-corpus verdict because the endpoint hard contradiction and DHCP timestamp fingerprint are reproducible source-native evidence, although outside the core of the analyst's initial specialty review.

### Host/EDR Forensics Analyst — reinforced Synthetic

The Host/EDR analyst retained **Synthetic**, raised verdict confidence from 84 to 88, and raised synthetic confidence from 74 to 78. The DHCP timestamp pattern added an independent generator-like fingerprint from another source family, and the role/distribution concerns showed that the endpoint actor mismatches were not the only repeated abstraction leaks. The analyst did not move higher because the visible process lifecycles, cross-source identities, Linux role texture, and channel sequencing remain strong.

## Key Agreements

- The principal attack chain contains no demonstrated impossible visible ordering. Transport, authentication, process, file, persistence, staging, exfiltration, and cleanup evidence are broadly coherent and huntable.
- Windows, Sysmon, eCAR, Zeek, firewall, proxy, and IDS data are generally parseable and source-appropriate. Identifier and lifecycle correlation are material strengths.
- The commandless, long-lived `runas.exe` that produces explicit-credential evidence is the strongest hard contradiction and requires correction regardless of the global verdict.
- The repeated low-order DHCP syslog residue is a genuine dataset-wide timing fingerprint, not merely a tightly timed transaction.
- Office registry effects must be owned by the application whose state they represent. Six mismatches out of six are systematic rather than incidental.
- Environmental and distribution findings should be treated by strength: role-incompatible health checks, human-session overproduction, narrow scanner cohorts, and missing NTP merit improvement, while uniform Sysmon coverage or common DLL palettes are weak alone.
- Existing causal ordering, lifecycle termination, independent sensor behavior, imperfect observation, and cross-source identity contracts should be preserved while fixes are made.

## Key Disagreements

- **Global verdict weight.** Detection and Host judged the hard contradiction plus repeated fingerprints sufficient for a Synthetic verdict. Threat Hunting and Network retained Inconclusive because the defects are sparse relative to a broadly realistic and technically coherent corpus.
- **NTP absence.** Network considered zero UDP/123 the clearest network environment gap. Other reviewers could not rule out a collection-profile or polling explanation, so the panel did not elevate it to a contradiction.
- **RDP and SSH volume.** Threat Hunting considered duplicate overlapping RDP trees and concentrated SSH sessions meaningful environmental tells. The others accepted them as plausible findings but not decisive without explicit session-policy and operational-event context.
- **Scanner cohort regularity.** Network found clean port-family partitioning generator-like. The panel agreed it is patterned but noted that specialized Internet scanners can have narrow target sets, keeping it below the source-native endpoint and DHCP findings.
- **Uniform collection shape.** Host's common Sysmon family and module palettes were retained as weak support only; centralized policy and filtering provide credible real-world alternatives.

## Most Convincing Evidence

1. **Commandless `runas.exe` performs explicit credential use and survives 43 minutes — synthetic.** The same visible PID has a complete bare command line, produces Event 4648 behavior requiring operands, and receives a long interactive-style lifetime. This is a direct executable-semantics contradiction across Sysmon, Security, and eCAR.
2. **All 34 DHCP renewal triplets preserve one arbitrary microsecond residue — synthetic.** The pattern spans 102 messages and three hosts. Independent logging calls should not preserve the same final three digits in every triplet while selecting new residues between transactions.
3. **All six Office-specific registry effects have the wrong application actor — synthetic.** The systematic Word/Excel/PowerPoint/Outlook disagreement reveals a reusable process-to-effect ownership gap rather than a single anomalous record.
4. **Independent sensor identities, drifting clocks, and loss texture — real.** Matching transit traffic receives sensor-local UIDs, a changing inter-sensor offset, and differing packet histories/accounting. This is strong positive evidence that network observations are not simple cloned rows.
5. **End-to-end causal and lifecycle coherence — real.** The LSASS, PsExec, service, scheduled-task, file staging, proxy upload, database staging, and cleanup branches preserve transport-before-auth and actor/file/session ownership without a visible same-identity inversion.

## Most Debated Points

- Whether a small number of decisive source-native contradictions should control the verdict over a corpus whose overwhelming majority is coherent.
- Whether zero visible NTP in six hours reflects an implausible environment model or an unstated but legitimate collection boundary.
- Whether two overlapping RDP sessions are improper session stacking or a permitted parallel-session configuration.
- Whether concentrated SSH administration represents an operations event or overproduction of fresh interactive sessions.
- Whether narrow scanner port palettes reflect generator cohorts or genuine specialized scanner behavior.
- How much weight to assign uniform Sysmon event-family coverage and repeated startup DLL palettes under plausible centralized collection policy.

## Improvement Recommendations (Consensus)

1. **Make executable semantics authoritative for explicit-credential actions.** A successful `runas.exe` action must carry a valid `/user:` operand and target command; the Security 4648 subject, target, caller PID, and process path must derive from that same action. A bare invocation must terminate within seconds and must not create successful explicit-credential evidence. Add a regression test covering both successful and usage-error outcomes across Sysmon, Security, and eCAR.
2. **Bind registry effects to the process family that owns the state.** Select Office MRU and reading-location paths from the active executable: Word only writes Word state, Excel only Excel state, PowerPoint only PowerPoint state, and Outlook only Outlook state. Add cross-product tests over application executable, registry path, principal, PID, and ProcessGuid rather than testing only field format.
3. **Give DHCP lifecycle messages independent source-native observations.** Preserve REQUEST-before-ACK-before-bound ordering, but apply separate full-microsecond clock observations or jitter to each emitted syslog record. Add a dataset probe that groups renewal triplets and rejects systematic low-order residue preservation; extend the audit to SSH, sudo/PAM, and systemd multi-message lifecycles.
4. **Use credible producers and workload-bound paths for Defender changes.** Attribute exclusions to policy application, a correctly formed PowerShell `Add-MpPreference` action, or a known installer when appropriate. Reduce their frequency and bind exclusion paths to installed products and host roles rather than numbered generic cache entries.
5. **Make remote interactive activity session-aware.** For repeated same-user/client/target RDP activity, reconnect, reuse, or replace an existing session unless explicit target policy permits parallel sessions; only then create a second target-side shell tree. Reduce fresh human SSH sessions by reusing sessions and shifting recurring administration to named automation accounts, bastions, or configuration-management tooling.
6. **Bind health checks to deployed service and host role.** Give each health-check job a stable, purpose-specific target set, cadence, expected protocol, and owner. Do not draw advertising, analytics, package-registry, and widget destinations from one generic pool for unrelated application and mail servers.
7. **Model network environment choices explicitly.** Add sparse, host-specific NTP polling with occasional unanswered flows, or define a collection profile that consistently filters UDP/123. Broaden scanner cohorts with overlapping port choices, source rotation, incomplete passes, revisits, and occasional application-handshake outcomes; retain the existing mix of unanswered, reset, rejected, and successful flows.
8. **Preserve the corpus's strongest contracts.** Do not weaken transport-before-auth ordering, process/file/session identity, lifecycle closure, bounded-window handling, independent sensor UIDs and clocks, packet-loss texture, EventRecordID reset behavior, or imperfect file observation while addressing the defects above.
