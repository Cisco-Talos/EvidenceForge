# Expert Panel Deliberation

## Round 1 — Present Findings

### Threat Hunter

- **Initial verdict:** Synthetic
- **Verdict confidence:** 93
- **Synthetic-confidence score:** 86
- **Strongest evidence:**
  - On `WS-AJOHNSON-01`, two processes use RDP Logon ID `0x27015bf` before the corresponding Type 10 login creates that identity. The inversion appears in Windows Security, Sysmon, and eCAR, so it is not explained by one source's clock or formatting.
  - The recorded `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` command lacks `-Pn`, yet the network data contains the exact 254-address by five-port product even though preceding discovery found only a small responsive population.
  - The PsExec Type 3 login on `DC-01` precedes the only visible related SMB/RPC transports by more than eight seconds, and its stated source port appears in no network view.
- **Specialty-specific observations:** The hunter uniquely connected the full attack lifecycle across endpoint, authentication, network, file, proxy, and storage sources. They also noticed a fleet-wide hard ceiling of three occurrences per exact Bash command and treated concentrated UFW scanner traffic as a weaker supporting signal.

### Detection Engineer

- **Initial verdict:** Synthetic
- **Verdict confidence:** 76
- **Synthetic-confidence score:** 67
- **Strongest evidence:**
  - In 659 of 911 Sysmon Event ID 1 records, all five PE resource fields are `-`, including every observed instance of several standard signed Microsoft binaries, despite hashes being present and neighboring binaries having populated metadata.
  - High-volume Windows process families repeatedly draw from only two to four exact command-line forms across unrelated hosts.
  - A local Linux `pam_unix` console failure for `aisha.johnson` is coupled within milliseconds to an endpoint-less DC Kerberos 4771 without a visible port-88 flow, mixing authentication contracts.
- **Specialty-specific observations:** The engineer uniquely identified that nonzero `LogonGuid` values on network logons never correlate through the 2,034 visible 4769 events, all of which carry a zero GUID. They also highlighted authentic Sysmon `ProcessGuid` time encoding and source-native Windows schema fidelity.

### Network Forensics Analyst

- **Initial verdict:** Real
- **Verdict confidence:** 64
- **Synthetic-confidence score:** 36
- **Strongest evidence:**
  - DNS cache-TTL decay, suffix-search NXDOMAINs, query-type variety, and resolver behavior look organic and internally consistent.
  - TLS versions, ciphers, certificate chains, SAN/SNI relationships, validity windows, and session-dependent omissions are source-native and coherent.
  - Separate Zeek sensors, ASA, and Snort agree on physical activity while retaining distinct UIDs, clock offsets, packet observations, and source-specific timing.
- **Synthetic concerns:** Approximately 11% of same-client proxy HTTP gaps cluster near 600 ms; all Zeek files are perfectly sorted by `ts`, including long-lived connections; and five HTTP FUID references are absent from local `files.json`.
- **Specialty-specific observations:** The analyst uniquely quantified the 600 ms proxy cadence and showed that the sensor overlap behaves like separate observation points rather than duplicated logs.

### Host/EDR Forensics Analyst

- **Initial verdict:** Synthetic
- **Verdict confidence:** 84
- **Synthetic-confidence score:** 71
- **Strongest evidence:**
  - The same dataset-wide Sysmon PE metadata gap identified by the detection engineer is deterministic by image family and affects hundreds of normal Microsoft processes.
  - Eight Linux server-role hosts reuse nearly the same mixed irqbalance device vocabulary, while seven unrelated servers repeatedly advertise the same improbable snap inventory, including MicroK8s and desktop integration.
  - The 821 UFW blocks on `WEB-EXT-01` use only 12 source IPs and three nearly balanced TCP-window values; individual sources rotate among those windows while keeping invariant TTL and packet length.
- **Specialty-specific observations:** The analyst uniquely found rotating low producer PIDs across repeated 4800/4801 lock/unlock transitions within the same LUID/session, and unusually dense Type 5 service-login activity normalized into repeated session objects around the three reserved built-in LUIDs.

## Round 2 — Cross-Examination

### 1. Is the Nmap trace realistic or contradictory?

The network analyst initially called the scan mechanically realistic because discovery precedes scanning, most probes receive no response, and live systems exhibit differentiated service outcomes. The threat hunter's objection addresses a different layer: whether the **recorded command could have produced that traffic**. Without `-Pn`, default host discovery should prevent a complete five-port connect scan against hundreds of hosts that did not answer discovery. The exact 254-by-five matrix is therefore not rescued by realistic per-flow states.

The threat hunter has the stronger evidence because it links process telemetry to packet output and identifies a command/behavior contradiction. Conceivable alternatives—an unrecorded wrapper, modified Nmap behavior, truncated command-line collection, or discovery responses missing from every network view—require additional facts not present in the reports. The network analyst's findings still establish that the generated scan packets are individually plausible; they do not establish that the visible command explains their scope.

### 2. Does good RDP transport ordering refute the RDP lifecycle defect?

No. The host analyst verified that visible Type 10 logins have matching TCP/3389 transport several seconds earlier. The threat hunter found a later-stage inversion: PowerShell and `whoami.exe` already carry the future RDP Logon ID before the login, `userinit.exe`, and Explorer appear. These findings are compatible: the transport can precede authentication correctly while session-bound user activity begins too early.

The threat hunter's exact same-host, same-LUID evidence across Security, Sysmon, and eCAR is stronger than the host analyst's broader transport-before-login check. A delayed 4624 write is an alternative explanation in principle, but the inversion also exists in eCAR timing, and the early PowerShell parentage does not fit the later interactive tree. This became the most consequential blind spot in the initial host and detection assessments.

### 3. How strong is the Sysmon PE metadata finding?

The detection and host analysts independently reached the same count—659 of 911 process creates with all five PE resource fields blank—and named the same affected image families. That agreement, scope, and deterministic image-family pattern make this stronger than an isolated extraction failure.

Alternative explanations include Sysmon access failures, stripped resources, mixed collection settings, or deliberate field redaction. None comfortably explains why hashes remain available, why standard inbox binaries are consistently affected across hosts, and why adjacent executable families are enriched normally. The panel therefore treats this as a high-volume source-native defect, though not a logical impossibility on the level of the RDP inversion.

### 4. Are the Linux inventory and UFW patterns merely a golden image plus persistent scanners?

A common virtual-machine template could explain some shared hardware names and package inventory. Persistent Internet scanners could also explain stable source-specific TTL and packet length. The host analyst's stronger point is the conjunction: unrelated server roles share a mixed device vocabulary and the same role-incongruent snap set, while each scanner independently cycles through a nearly balanced global pool of only three TCP-window values.

The threat hunter agreed that scanner concentration alone is weak. The panel did not treat either Linux uniformity or UFW concentration as decisive in isolation. Most members nevertheless regarded the repeated cross-role inventories and per-source TCP-window rotation as credible supporting evidence of shared enumerables rather than lived host state.

### 5. Could collection or export behavior explain the remaining network concerns?

Yes, for some of them. Perfect Zeek `ts` ordering can result from a normalized study export, and five dangling FUIDs can result from filtering or loss. Those points remain weak unless the corpus claims to preserve untouched native write order and complete same-sensor file logging.

The 600 ms proxy cadence is harder to dismiss because it repeats across clients and appears at both sensors with the expected clock relationship. A browser or application scheduler could produce periodic fan-out, so it is a distribution fingerprint rather than a contradiction. The panel retained it as a medium-strength improvement target, below the RDP, Nmap, and PE metadata findings.

### 6. Do isolated authentication and Windows-session anomalies carry enough weight?

The local `pam_unix`/KDC pairing could be two coincident attempts or a collection gap, and the PsExec tuple could reflect a dropped preliminary connection. Similarly, lock/unlock producer PIDs and dense built-in Type 5 logins may depend on source semantics that warrant comparison with native captures. These are not as conclusive as the two hard contradictions.

They remain useful contract tests because each names the missing or inconsistent identity that should join related records. The panel treated the PsExec tuple as the strongest of this group, the local-login/KDC pairing and unusable Logon GUIDs as supporting contract gaps, and Type 5 volume as distribution evidence needing native calibration.

### 7. Can extensive production-like detail coexist with a synthetic verdict?

Yes. All four experts found substantial realism: coherent protocol children, credible TLS and DNS, separate sensor clocks, correct Windows schemas, strong process and session lifecycles, role-aware traffic, and a convincing multi-host attack chain. Those properties show that the corpus is high fidelity. They do not neutralize narrow causal impossibilities or repeated catalog artifacts. The disagreement is therefore about how much weight to assign a few high-specificity defects relative to a much larger body of realistic evidence, not about whether the realistic evidence exists.

## Round 3 — Revised Positions

### Threat Hunter — Revised

- **Final verdict:** Synthetic
- **Final verdict confidence:** 96
- **Final synthetic-confidence score:** 92
- **Change:** Verdict unchanged; confidence increased by 3 points and synthetic-confidence increased by 6 points.
- **Influence from others:** Independent confirmation of the dataset-wide PE metadata defect by both endpoint-oriented experts, plus the host analyst's cloned Linux inventory and UFW fingerprint findings, reinforced that the two hard contradictions are not isolated imperfections in an otherwise fully organic collection. The network analyst's protocol findings kept the score below certainty by confirming that much of the corpus is genuinely difficult to distinguish from production telemetry.

### Detection Engineer — Revised

- **Final verdict:** Synthetic
- **Final verdict confidence:** 88
- **Final synthetic-confidence score:** 83
- **Change:** Verdict unchanged; confidence increased by 12 points and synthetic-confidence increased by 16 points.
- **Influence from others:** The exact RDP same-LUID inversion and the Nmap command/traffic mismatch supply the hard causal evidence absent from the initial detection report. The network analyst's strong schema and protocol results still temper the assessment, but they no longer support treating the defects as merely incomplete metadata and shallow distributions.

### Network Forensics Analyst — Revised

- **Final verdict:** Inconclusive
- **Final verdict confidence:** 72
- **Final synthetic-confidence score:** 58
- **Change:** Verdict changed from Real to Inconclusive; confidence increased by 8 points and synthetic-confidence increased by 22 points.
- **Influence from others:** The command-aware Nmap analysis changed the interpretation of an otherwise realistic packet trace, while the cross-source RDP session inversion introduced a high-specificity defect outside the initial network-only checks. The analyst did not move to Synthetic because DNS, TLS, flow accounting, sensor separation, firewall lifecycles, and IDS timing remain strongly production-like, and several network concerns still admit ETL or collection explanations.

### Host/EDR Forensics Analyst — Revised

- **Final verdict:** Synthetic
- **Final verdict confidence:** 91
- **Final synthetic-confidence score:** 85
- **Change:** Verdict unchanged; confidence increased by 7 points and synthetic-confidence increased by 14 points.
- **Influence from others:** The threat hunter's RDP finding corrected the initial conclusion that no impossible RDP ordering was visible: transport ordering was sound, but session-owned process activity was not. The Nmap contradiction adds an independent non-endpoint defect, while the network analyst's evidence confirms that the verdict should not be read as a judgment that the corpus lacks broad technical realism.

# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 93 | 86 | Synthetic | 96 | 92 |
| Detection Engineer | Synthetic | 76 | 67 | Synthetic | 88 | 83 |
| Network Forensics | Real | 64 | 36 | Inconclusive | 72 | 58 |
| Host/EDR Forensics | Synthetic | 84 | 71 | Synthetic | 91 | 85 |

## Key Agreements

- The corpus is high fidelity in source-native structure, role placement, protocol semantics, and most lifecycle relationships. The panel specifically agreed that DNS/TLS behavior, multi-sensor differentiation, ASA/Zeek lifecycle agreement, Windows schema fidelity, process correlation, SSH sequences, and the Security-log clear are unusually strong.
- The Sysmon PE metadata pattern is a dataset-wide authenticity weakness. Two experts independently measured the same 659-of-911 scope, and the other panelists accepted that deterministic blanking of standard binary metadata is difficult to explain as ordinary collection loss.
- Correct transport-before-authentication ordering does not guarantee correct session lifecycle ordering. The RDP flow is plausible, but processes cannot legitimately use the new interactive LUID before the session exists.
- The Nmap packet records are individually credible, but the complete host/port product is not credibly explained by the visible command and discovery results.
- Distribution findings should be weighted by scope and alternative explanations. The panel agreed that sorted Zeek files and a handful of dangling FUIDs are weak, while repeated proxy cadence, cloned host inventories, shallow command pools, and UFW value pools are useful supporting evidence.

## Key Disagreements

- The panel did not reach unanimous agreement on the final overall verdict. Three experts remained Synthetic; the network analyst moved from Real to Inconclusive rather than Synthetic because the network subsystem contains extensive protocol-level realism and several network-only concerns admit normalization or collection explanations.
- The Nmap trace remained the sharpest scope disagreement. The network analyst judged its packet mechanics realistic, while the threat hunter showed that the process command lacks the option required to explain scanning every address. The panel resolved the factual tension in favor of the command-aware finding but retained the network analyst's narrower conclusion that the rendered responses and states are realistic.
- The exact weight of the Linux hardware/snap uniformity and UFW fingerprints remained unsettled. A golden image and persistent scanners are plausible alternatives; most panelists still considered the combined cross-role and per-source patterns too regular to ignore.
- The panel did not elevate the local `pam_unix`/4771 pairing, zero 4769 Logon GUIDs, rotating lock/unlock producer PIDs, or dense Type 5 logins to hard contradictions. Each is actionable, but each needs native-capture calibration or could be affected by missing observations.

## Most Convincing Evidence

1. **RDP session-before-use violation — synthetic:** The same non-system Logon ID is used by PowerShell and `whoami.exe` before the Type 10 login creates it, with the inversion independently visible in Security, Sysmon, and eCAR and reinforced by implausible early parentage.
2. **Nmap command/traffic mismatch — synthetic:** A command without `-Pn` produces an exact 254-host by five-port scan despite discovery and service responses showing that most addresses are not live. The exact Cartesian product is more consistent with command-agnostic expansion than actual Nmap execution.
3. **Systematic Sysmon PE metadata blanking — synthetic:** All five PE resource fields are absent in 659 of 911 process creates, deterministically affecting common signed binaries across hosts while hashes and selected neighboring metadata remain available.
4. **Independent sensor and protocol coherence — real:** Zeek sensors use distinct UIDs and plausible clock offsets and capture differences; DNS cache decay, TLS/certificate semantics, ASA flow closure, and Snort timing remain mutually consistent. This is the strongest counterweight to the synthetic indicators.
5. **Cross-host enumerable reuse — synthetic supporting evidence:** Repeated Linux device/package inventories, shallow Windows process command pools, capped Bash-command reuse, and narrow UFW scanner fields collectively suggest shared catalogs, although individual patterns have plausible real-world alternatives.

## Most Debated Points

- Whether realistic Nmap response mechanics can outweigh a visible command that does not explain the complete target matrix.
- Whether delayed audit publication could explain the RDP inversion despite the same ordering appearing in multiple endpoint views and the process tree itself.
- Whether the common Linux hardware and package vocabulary represents a legitimate golden image or an over-broad shared generator pool.
- Whether approximately 600 ms proxy connection spacing reflects browser/application scheduling or a generator timing quantum.
- Which missing correlations are defects versus collection imperfections: PsExec's absent tuple, dangling FUIDs, the endpoint-less 4771, and nonzero logon GUIDs without matching ticket GUIDs.

## Improvement Recommendations (Consensus)

1. **Enforce session creation before dependent activity.** Add a canonical invariant that no process, file, registry, module, or network event may reference a non-system LUID before its successful login. For RDP, regression-test the order `transport -> 4624/eCAR login -> userinit.exe -> explorer.exe -> user activity` across Security, Sysmon, and eCAR, including source-specific delays that cannot invert the canonical lifecycle.
2. **Make scan expansion obey visible tool semantics.** Parse or carry canonical Nmap discovery options into the scan plan. Require `-Pn` for a full address-by-port product; otherwise, perform discovery first and scan only hosts that respond to the command's actual discovery probes. Add an end-to-end assertion that the rendered process command, discovery evidence, and attempted target set describe the same execution.
3. **Populate PE metadata from image- and build-aware identity.** Key `FileVersion`, `Description`, `Product`, `Company`, and `OriginalFileName` to exact image, OS build, and file identity, and keep them consistent with hashes. Model extraction failure as an occasional host/config/file condition, then validate all-five-blank rows for known signed inbox binaries.
4. **Unify remote-administration authentication with its transport.** Allocate one canonical tuple and timing contract for 4648/caller context, Type 3 login, SMB/RPC flows, endpoint FLOW records, Zeek, and service installation. Apply source observation loss to the whole correlated unit or document a precise allowed partial-observation pattern; do not leave the login naming a source port absent from every network view.
5. **Replace fleet-wide enumerable pools with scoped, heavy-tailed state.** Generate Windows command variants by build, role, service/task identity, and installed software; Linux hardware by host or infrastructure cohort; packages/daemons by role; and shell commands by user/session/troubleshooting episode. Permit common commands to repeat well beyond three while keeping long runbook literals clustered to the operators and hosts that plausibly use them.
6. **Give each Internet scanner a persistent network fingerprint.** Bind source IP to stable or slowly evolving TTL, packet length, TCP options, window family, port preferences, and revisit cadence. Expand the singleton/low-frequency source tail and avoid independently resampling every packet from a global three-window pool.
7. **Remove the proxy timing quantum.** Model browser/proxy fan-out through concurrent sockets, connection reuse, cache state, page dependency timing, and wider per-client jitter. Add a distribution test for excessive mass around 600 ms and its simple multiples without suppressing legitimate burstiness.
8. **Calibrate weaker source-native contracts against real captures.** Verify 4800/4801 producer PID behavior, Type 5 login volume and session normalization, Kerberos `LogonGuid` availability, and local PAM/KDC companion behavior before broad fixes. Where collection filtering is intentional, encode it explicitly so dangling FUIDs, sorted Zeek exports, and missing ticket/flow companions are distinguishable from generator omissions.

The panel's informed consensus is that the corpus is **high-fidelity synthetic data**: three experts retain a Synthetic verdict, and the sole initial Real verdict moves to Inconclusive after considering the command-aware Nmap and cross-source RDP evidence. The disagreement that remains concerns degree, not the presence of concrete authenticity defects.
