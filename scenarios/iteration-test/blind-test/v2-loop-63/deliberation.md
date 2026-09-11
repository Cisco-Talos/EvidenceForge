# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Real | 74 | 29 | Synthetic | 78 | 64 |
| Detection Engineer | Synthetic | 84 | 71 | Synthetic | 90 | 82 |
| Network Forensics | Synthetic | 74 | 66 | Synthetic | 84 | 78 |
| Host/EDR Forensics | Synthetic | 95 | 92 | Synthetic | 96 | 93 |

Initial average synthetic-confidence: **64.5**  
Final average synthetic-confidence: **79.25**

The panel’s final consensus is **Synthetic**, with residual disagreement about degree rather than verdict. The Threat Hunter continues to give substantial weight to the production-like network, environmental, and lifecycle evidence, while the Host/EDR specialist considers the repeated binary-identity contradictions close to dispositive.

## Round 1 — Initial Positions

### Threat Hunter

The Threat Hunter initially assessed the dataset as **Real**, with verdict confidence **74** and synthetic-confidence **29**. The strongest production-like evidence was the role-scaled source volume, coherent end-to-end attack and exfiltration activity, and absence of impossible lifecycle ordering across process, authentication, transport, and file evidence. Independent sensor offsets, packet loss, varied terminal states, and compatible proxy/Zeek/ASA byte accounting further supported authenticity.

The principal adverse finding was four close-only SSH syslog lifecycles whose corresponding `sshd` processes visibly started inside the collection window. The Threat Hunter also identified unusually regular Sysmon Event 10 ProcessAccess bursts, but regarded both issues as limited compared with the corpus’s extensive realistic evidence.

### Detection Engineer

The Detection Engineer initially assessed the dataset as **Synthetic**, with verdict confidence **84** and synthetic-confidence **71**. The strongest evidence was the Event 4648 cross-host IP leak on WS-MCHEN-01, where a local `runas.exe` process was paired with LT-MRIVERA-02’s IP address; missing child processes after successful `runas /netonly` and PSEXESVC wrapper execution; and contradictory Zeek analyzer metadata.

The reviewer also identified remote Linux `smbclient` process identity appearing in host-scoped Windows eCAR FILE fields and repeated Linux `snapd`/`irqbalance` vocabulary. These defects existed inside otherwise strong source-native schemas, process correlation, DHCP behavior, and firewall lifecycles.

### Network Forensics

The Network Forensics reviewer initially assessed the dataset as **Synthetic**, with verdict confidence **74** and synthetic-confidence **66**. The strongest synthetic indicators were the same Zeek analyzer-bookkeeping defects found independently by the Detection Engineer: 87 SMB file records populated with hashes while declaring only `MIME`, and all three PE records lacking `PE` in their associated analyzer sets.

The reviewer additionally found implausibly large SYSVOL/NETLOGON scripts and configuration files, templated SMB names extending into future years, extension-derived MIME types on redirects, and six unresolved file references. Counterevidence included highly credible TCP state semantics, DNS diversity, DNS-to-TLS consistency, certificate behavior, proxy timing, sensor-local UID integrity, and non-periodic scanning and TXT-query activity.

### Host/EDR Forensics

The Host/EDR specialist initially assessed the dataset as **Synthetic**, with verdict confidence **95** and synthetic-confidence **92**. The strongest evidence was dataset-wide binary content-identity inconsistency: identical third-party releases had different complete hash sets, including IMPHASH, across users and hosts, while `winlogon.exe` and `userinit.exe` had identical hashes across multiple apparent Windows builds.

The reviewer also found doubled local-path separators leaking into Exchange command lines across Security, Sysmon, and eCAR; excessive overlapping Exchange service instances; uniformly simplified `TiWorker.exe` parentage; and fleet-wide reuse of Linux software and hardware vocabulary. Strong process, session, and source-delay correlation was acknowledged but interpreted as evidence that incorrect canonical values were being propagated consistently.

## Round 2 — Cross-Examination

### Binary identity versus otherwise strong endpoint correlation

The Host/EDR findings materially changed the discussion. Per-host binary variation can be legitimate when vendors rebuild without changing display versions, but that explanation is weak here because the pattern spans Slack, Zoom, Teams, OneDrive, and related DLLs and changes MD5, SHA1, SHA256, and IMPHASH together. The inverse pattern—identical `winlogon.exe` and `userinit.exe` hashes across distinct Windows builds while neighboring system binaries vary correctly—further reduces the likelihood of an operational explanation.

The panel therefore treated binary identity as the strongest synthetic evidence. Excellent Security/Sysmon/eCAR agreement does not neutralize it; instead, it demonstrates that a shared canonical identity defect propagated consistently into multiple sources.

### Event 4648 cross-host IP leak

The Detection Engineer’s Event 4648 finding is a concrete ownership contradiction: a process local to WS-MCHEN-01 is associated with the stable address of another workstation, while other 4648 records on WS-MCHEN-01 use the correct local address. The panel accepted this as a hard contradiction rather than an ambiguous remote-execution representation.

Its scope remains one observed event, so it carries less dataset-wide weight than the binary-identity family. Nevertheless, it is highly diagnostic because it exposes cross-host state leakage inside an otherwise disciplined identity model.

### Zeek analyzer bookkeeping

The Detection and Network reviewers independently found the same two inconsistencies: hash-bearing SMB file records omit the corresponding hash analyzers, and PE records exist without `PE` in the parent file’s analyzer list. Agreement between the detection and network specialties significantly strengthens the finding.

The panel rejected ordinary collection loss as an explanation because the contradiction exists within the same modeled file-analysis result: populated hashes and emitted PE metadata prove that those analyses occurred. This is a repeated source-native bookkeeping defect, not merely missing companion telemetry.

### Close-only SSH observations

The Threat Hunter’s four close-only SSH lifecycles remain valid because each corresponding `sshd` process visibly starts inside the window; pre-window state cannot explain them. However, selective UDP syslog loss, forwarding gaps, or collector outages could produce close-only observations in a real environment.

The repeated shape across four unrelated hosts, alongside complete eCAR activity, makes independent event-level loss more suspicious than a single orphan close. The panel therefore retained this as a moderate contract gap, not a hard contradiction. It should increase synthetic confidence, but much less than the binary, Event 4648, or analyzer findings.

### Realistic network and lifecycle evidence

All reviewers acknowledged substantial production-like evidence:

- No same-identifier process, session, authentication, or transport inversion was found.
- TCP states, histories, ports, packet counts, bytes, and durations are internally credible.
- DNS behavior, TLS negotiation, certificates, proxy sequencing, and multi-sensor observations are heterogeneous and coherent.
- Security, Sysmon, and eCAR agree at high rates while retaining source-specific timestamp differences and occasional loss.
- ASA connection and translation lifecycles balance naturally at the collection boundary.
- Host roles materially affect traffic, process, command, and source-family distributions.
- Attack, lateral-movement, persistence, collection, and exfiltration evidence supports operational pivots without impossible ordering.

The panel agreed that these are genuine realism strengths and should constrain the final scores below certainty. Complete correlation by itself was not treated as synthetic evidence. The decisive issue is that several shared canonical values and source-native declarations are concretely wrong despite the surrounding lifecycle quality.

## Round 3 — Revised Positions

### Threat Hunter

**Final verdict:** Synthetic  
**Final verdict confidence:** 78  
**Final synthetic-confidence:** 64

The Threat Hunter changed verdict after considering the endpoint binary-identity contradictions, the Event 4648 ownership leak, and the independently corroborated Zeek analyzer defects. The score remains the panel’s lowest because the network, lifecycle, role, volume, and end-to-end pivot evidence is unusually credible, and the SSH observation gaps retain plausible collection-loss explanations.

### Detection Engineer

**Final verdict:** Synthetic  
**Final verdict confidence:** 90  
**Final synthetic-confidence:** 82

The Detection Engineer increased both confidence and synthetic-confidence. The Host/EDR binary findings provided a broader canonical-identity defect than the reviewer’s initially isolated Event 4648 contradiction, while the Network reviewer independently confirmed the Zeek analyzer findings.

### Network Forensics

**Final verdict:** Synthetic  
**Final verdict confidence:** 84  
**Final synthetic-confidence:** 78

The Network reviewer increased confidence after the detection review independently reproduced the analyzer-bookkeeping defects and the host review demonstrated recurring cross-host content-identity problems. The score remains below the Host/EDR result because transport, DNS, TLS, proxy, certificate, and multi-sensor behavior are otherwise strongly production-plausible.

### Host/EDR Forensics

**Final verdict:** Synthetic  
**Final verdict confidence:** 96  
**Final synthetic-confidence:** 93

The Host/EDR specialist retained the verdict and made only a small upward revision. Independent evidence from Event 4648 and Zeek showed that canonical ownership and bookkeeping defects extend beyond binary identity. The score does not approach 100 because the dataset preserves extensive realistic lifecycle ordering, role-aware behavior, and source-specific timing.

## Key Agreements

- The binary hash and PE-metadata behavior is the strongest synthetic indicator because it is repeated, cross-host, cross-product, and internally contradictory.
- The Event 4648 address on WS-MCHEN-01 is a genuine cross-host ownership leak, although currently isolated.
- Zeek analyzer declarations contradict the analyses demonstrably performed; detection and network reviewers independently reached the same conclusion.
- The four close-only SSH syslog observations are real contract gaps, but selective logging loss remains a plausible alternative explanation.
- Network transport, DNS, TLS, proxy, firewall, process, authentication, and collection-boundary lifecycles are unusually realistic.
- High cross-source completeness is not itself evidence of synthesis. The concern arises only where consistently propagated values are impossible or source-native metadata contradicts itself.
- Linux `snapd` and `irqbalance` distributions are insufficiently conditioned on host inventory, role, hardware, and logging policy.

## Key Disagreements

The remaining disagreement concerns evidentiary weight. The Threat Hunter assigns greater weight to corpus-wide realism and treats several defects as bounded exceptions within a credible collection. The Host/EDR specialist assigns greater weight to the binary-identity family because it reveals how shared facts were constructed, not merely how individual records were formatted.

The panel also differs on whether the SSH close-only pattern is more consistent with modeled observation loss or a lifecycle-grouping defect. No consensus was forced beyond classifying it as actionable but secondary.

Strict timestamp ordering in Zeek, narrow RDP authentication delays, ProcessAccess micro-cadence, and a few unresolved FUIDs remained weak or ambiguous indicators. They did not materially drive the final consensus.

## Most Convincing Evidence

1. **Synthetic — Binary content-identity contradictions.** Identical third-party release metadata produces host-specific full hash and IMPHASH sets, while build-specific Windows binaries remain identical across different builds. The paired forward and inverse contradictions make benign explanations unlikely.

2. **Synthetic — Event 4648 cross-host address leakage.** A local WS-MCHEN-01 process carries LT-MRIVERA-02’s stable IP, demonstrating incorrect host ownership in a source-native security event.

3. **Synthetic — Zeek analyzer bookkeeping.** Eighty-seven hash-bearing SMB records omit hash analyzers, and every emitted PE record lacks `PE` in its parent analyzer set. Independent specialist agreement and same-record contradictions make this strong evidence.

4. **Real — Network and protocol lifecycle quality.** TCP states, DNS behavior, TLS/certificate relationships, proxy sequencing, independent sensor observations, packet loss, byte accounting, and collection-boundary behavior are mutually credible.

5. **Real — Endpoint and authentication ordering.** Security, Sysmon, eCAR, SSH, RDP, and process lifecycles show high correlation without visible same-identifier inversions, while retaining realistic source-specific delays.

## Most Debated Points

- Whether vendor rebuilds could explain the third-party hash differences. The breadth across products and simultaneous IMPHASH divergence ultimately made this explanation unpersuasive.
- Whether the isolated Event 4648 leak should dominate the verdict. The panel treated it as highly diagnostic but limited in scope.
- Whether close-only SSH records reflect realistic syslog loss. This remains possible, but the repeated cross-host pattern suggests lifecycle observations are being dropped independently.
- Whether excellent correlation is “too perfect.” The panel rejected completeness as an indicator by itself and relied only on concrete contradictions.
- Whether SMB sizes, naming vocabulary, redirect MIME types, strict Zeek sorting, and narrow timing ranges are decisive. These were retained as supporting texture rather than verdict-determining evidence.

## Improvement Recommendations (Consensus)

1. **Repair canonical binary content identity.** Key third-party artifacts by vendor, product, release, architecture, and actual binary build rather than host, username, or installation path. Key Windows system binaries by modeled OS build. Generate hashes and PE metadata atomically, and validate that identical artifact identities share all hashes while build-distinct artifacts do not collapse onto one identity.

2. **Enforce host ownership for Event 4648 and related authentication evidence.** Derive local process and address fields from the same canonical host context. Add an invariant rejecting an address owned by another modeled endpoint unless the field explicitly represents a remote origin.

3. **Derive Zeek analyzer declarations from completed analysis.** A populated MD5, SHA1, or SHA256 field must imply its corresponding analyzer, and an emitted PE record must imply `PE`. Apply this contract across SMB, HTTP, SMTP, TLS, and future file-producing paths.

4. **Preserve native process semantics through canonical construction.** Remove doubled separators from drive-letter command lines while retaining genuine UNC paths. Materialize executable children after successful `runas /netonly` and `cmd.exe /c` wrappers when the command invokes an external program.

5. **Model service lifecycle and parentage explicitly.** Enforce realistic Exchange service cardinality and bounded recycle overlap. Route `TiWorker.exe` through a modeled TrustedInstaller process layer, with any missing observations controlled by the collection profile.

6. **Apply observation loss coherently to SSH lifecycle groups.** Keep authentication, PAM open, shell activity, and close observations under a shared source-local loss decision. If partial loss is intended, model a collector outage or adjacent message-loss interval rather than repeatedly retaining only the terminal close.

7. **Condition Linux activity on durable host inventories.** Bind Snap packages to installed software and role; bind `irqbalance` messages to a stable per-host hardware profile and source-specific verbosity. Avoid sharing desktop, container, storage, and network-device vocabularies across unrelated hosts without explicit deployment.

8. **Strengthen SMB content and attribution models.** Separate remote client identity from the Windows server’s local process in eCAR. Condition file sizes and names on share purpose, extension, and operational role so SYSVOL scripts, INI files, and policy XML do not inherit office-document size or naming distributions.

9. **Polish secondary distribution and collection behavior.** Broaden ProcessAccess and RDP timing distributions, model redirects independently of requested file extensions, ensure file references follow explicit observation policy, and preserve native Zeek write order when raw-log fidelity is intended.
