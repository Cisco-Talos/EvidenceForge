# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Real | 76 | 29 | Synthetic | 91 | 88 |
| Detection Engineer | Synthetic | 97 | 89 | Synthetic | 98 | 94 |
| Network Forensics | Synthetic | 80 | 72 | Synthetic | 94 | 91 |
| Host/EDR Forensics | Synthetic | 84 | 58 | Synthetic | 96 | 92 |

**Consensus Verdict:** Synthetic  
**Consensus Verdict Confidence:** 96/100  
**Consensus Synthetic-Confidence Score:** 91/100

## Round 1 — Present Findings

### Threat Hunter

The Threat Hunter initially assessed the collection as **Real** with verdict confidence 76 and synthetic-confidence 29. The strongest evidence was the source-native DC Security-log clearing lifecycle: `wevtutil cl Security`, Event 1102, and the `EventRecordID` reset all occur in the right order. The Nmap discovery/port scan and the DB-to-application-server SSH/SCP sequence also have convincing process, session, tuple, byte-direction, and file correlations. The role specialist uniquely emphasized that the intrusion remains huntable inside substantial, role-sensitive background traffic rather than appearing as isolated attack rows.

The Threat Hunter nevertheless noted repetitive Linux command vocabulary, homogeneous fleet-wide `debian-sa1 1 1` scheduling, and no UDP/123 traffic in 6,408 core connections.

### Detection Engineer

The Detection Engineer assessed the collection as **Synthetic** with verdict confidence 97 and synthetic-confidence 89. The two strongest findings were multiple post-March-2024 software versions in telemetry dated March 18, 2024, and different SHA-1, MD5, SHA-256, and IMPHASH values for nominally identical versions of Zoom, Teams, Slack, and OneDrive when installed under different usernames. The specialist also found that all 325 successful Type 5 service logons populate `WorkstationName` with the destination host's own short name, a dataset-wide source-field template.

The Detection Engineer uniquely distinguished good ingest/schema mechanics from detection-valid content identity: excellent parsing and correlation do not make path-dependent content hashes plausible.

### Network Forensics

The Network Forensics analyst assessed the collection as **Synthetic** with verdict confidence 80 and synthetic-confidence 72. The strongest findings were the total absence of CNAME/alias names from every A/AAAA answer vector across both sensors, despite thousands of public-service queries, and nearly invariant per-client DHCP renewal periods with different stable fractions of identical lease lengths. Zero NTP, NetBIOS, SSDP, mDNS, and LLMNR traffic in an otherwise broad core view added supporting environmental evidence.

The network specialist uniquely established that the defects coexist with excellent transport accounting, protocol-within-connection timing, dual-sensor variation, TLS/certificate reuse, proxy fan-out, and firewall lifecycle handling.

### Host/EDR Forensics

The Host/EDR analyst assessed the collection as **Synthetic** with verdict confidence 84 and synthetic-confidence 58. The decisive finding was a dead-process ownership contradiction on `WS-AJOHNSON-01`: PID 5232 is created at 12:44:20Z, terminated by Security and Sysmon at 12:44:58Z and by eCAR at 12:44:59Z, then named as the caller in Security 4648 at 12:45:29Z, with no intervening PID reuse. Repeated `ssh.exe user@host` launches on two Windows desktops and generic root/systemd-owned `wget` activity across unrelated Linux roles supplied additional behavioral texture.

The host specialist uniquely separated this one impossible ownership edge from the otherwise strong process, ProcessGuid, termination, session, lock/unlock, and cross-source lifecycle model.

## Round 2 — Cross-Examination

### Can the production-like correlations outweigh the hard contradictions?

No. The Threat Hunter's log-clear reset, scan behavior, SCP transfer, sensor-local UIDs, and right-censored sessions are concrete and persuasive realism evidence. The other three experts agreed that these features rule out a crude generator and deserve preservation. They do not, however, provide an alternative explanation for impossible artifact chronology, systematic content-identity divergence, or a caller process used after termination. The panel reconciled the different standards by treating realistic correlation as evidence about implementation quality, while treating hard contradictions as evidence about origin.

This point changed the Threat Hunter's verdict. Their initial report explicitly stated that no hard contradiction had been found; the Detection and Host reports supplied multiple log-visible contradictions outside the hunter's principal line of inquiry.

### Software chronology

The anonymous Sysmon data confirms that the cited versions are attached to March 18, 2024 Event 1 records, including VS Code `1.89.1`, DBeaver `24.0.5`, Docker `26.1.1`, Zoom `6.0.11.39959`, and other products. The Detection Engineer's release-chronology determination spans several unrelated vendors, so a single backport, stale resource string, or misconfigured endpoint clock does not explain it; the same March date is shared across host and network sources. The panel accepted this as a hard contradiction. The Threat Hunter noted that the release-date conclusion requires product-history knowledge rather than fields carried in the logs, but found the multi-vendor scope persuasive after cross-examination.

### Same-version executable hashes

The panel considered whether architecture, localization, staged rollout, or vendor repackaging could cause same-version binaries to hash differently. Such explanations can account for isolated SHA-256 differences. They do not plausibly account for all recorded digest families, including IMPHASH, changing systematically across username-bearing paths for the same nominal vendor version, with the pattern recurring across Zoom, Teams, Slack, and OneDrive. The data directly confirms three different full hash sets for Zoom `6.0.11.39959` under Aisha, Marcus, and Sophia. Because common-path system binaries remain stable while per-user application paths diverge, the Detection Engineer's generator-derivation interpretation is stronger than the variant-build explanation. The panel ranked this as the strongest authenticity indicator.

### Dead PID in explicit-credential use

The Host analyst's PID 5232 claim was confirmed directly. Security 4689 and Sysmon Event 5 terminate the same PowerShell process around 12:44:58Z, eCAR independently records termination around 12:44:59Z, and Security 4648 names that PID and image at 12:45:29Z. No intervening creation establishes PID reuse. Collection latency cannot readily explain a source event timestamp that places a new credential operation more than 31 seconds after two source-native termination observations, and eCAR reinforces rather than resolves the conflict. The panel therefore retained the `hard_contradiction` classification.

### Type 5 service-logon workstation semantics

The data confirms the Detection Engineer's scope: 325 of 325 Type 5 logons across nine Windows hosts use the local destination's short hostname as `WorkstationName`. The panel agreed that the universal value is template-like and likely source-inaccurate for local service logons. Because Windows authentication packages and collection/rendering paths can vary, the panel treated this as a strong `schema_or_format` defect rather than an independently decisive impossibility.

### Network distribution findings

The Threat Hunter's positive DNS evidence and the Network analyst's negative DNS evidence are compatible. Query-type, failure-code, suffix-search, timing, and TTL diversity can be realistic while answer-section construction remains simplified. The absence of any CNAME/alias names across all A/AAAA answer vectors is stronger than a claim about one sanitized domain and was retained as a dataset-wide `schema_or_format` indicator.

DHCP renewals are valid REQUEST/ACK transactions and may legitimately repeat on server-supplied timers. The synthetic signal comes from every client's almost invariant private cadence, only about one second of cycle disturbance, and materially different stable fractions of identical leases. The panel retained this as strong `distribution_texture`, but below the endpoint contradictions.

The missing NTP and discovery families remain valid supporting evidence, not a standalone verdict driver. Routing, hardening, or sensor policy could suppress them, and the logs do not expose enough collection-policy context to eliminate those alternatives.

### Repetitive behavior texture

The experts independently observed shared Linux administrative commands, shallow SSH client command shapes, and generic process attribution. Common commands and managed cron schedules naturally repeat, so none is decisive alone. Their recurrence across different users, hosts, and roles is still consistent with a pool-driven baseline and corroborates the stronger defects. The panel agreed not to score the intrusion merely because it is coherent or easy to narrate.

## Round 3 — Revised Positions

### Threat Hunter — revised

**Final verdict: Synthetic; verdict confidence 91; synthetic-confidence 88.** The verdict changed because the initial authenticity argument depended partly on finding no hard contradiction. The cross-vendor future-version evidence, repeated same-version hash divergence, and dead-PID credential event directly defeat that premise. The hunter retained substantial credit for the DC log reset, scan, SCP, baseline, and sensor realism, which keeps the final score below the top of the rubric.

### Detection Engineer — reinforced

**Final verdict: Synthetic; verdict confidence 98; synthetic-confidence 94.** The position strengthened because the Host analyst supplied an independent lifecycle contradiction and the Network analyst supplied dataset-wide source-content and scheduling defects. The score remains below 100 because the source schemas, observation gaps, protocol mechanics, and most cross-source timing are highly credible.

### Network Forensics — revised upward

**Final verdict: Synthetic; verdict confidence 94; synthetic-confidence 91.** The network-only case was likely synthetic but allowed collection-policy and resolver-behavior alternatives. Endpoint chronology, content identity, and process-liveness contradictions remove much of that ambiguity. The analyst retained that CNAME absence and DHCP cadence are strong supporting textures, while missing infrastructure protocols remain qualified.

### Host/EDR Forensics — revised upward

**Final verdict: Synthetic; verdict confidence 96; synthetic-confidence 92.** The host analyst's initial moderate score reflected one localized hard contradiction amid excellent lifecycle realism. The Detection Engineer's independent multi-product chronology, hash, and Type 5 findings show broader endpoint-generation defects, while the network findings establish that the issue is not confined to one caller-PID edge.

## Key Agreements

- The dataset is technically sophisticated, parseable, and strongly correlated across host, network, proxy, firewall, and application sources.
- The DC audit-log clear/reset, SSH/SCP lifecycle, dual-sensor observations, TLS certificate reuse, proxy behavior, and firewall right-censoring are convincing production-like details.
- Same-version vendor hashes varying systematically with per-user paths and the dead-PID 4648 are hard contradictions that realistic surrounding evidence cannot explain away.
- Linux command reuse, SSH-launch density, generic `wget` ownership, and infrastructure-protocol gaps are supporting texture, not sufficient verdict evidence by themselves.
- Missing NTP/discovery traffic is plausibly explainable by policy or topology and should carry less weight than directly contradictory fields and lifecycles.

## Key Disagreements

The initial disagreement was primarily evidentiary coverage rather than incompatible interpretation: the Threat Hunter did not find the endpoint version, hash, service-logon, or dead-PID defects and therefore weighted the highly realistic attack and baseline correlations most heavily. Once those specialist findings were presented and checked against the anonymous data, the Threat Hunter changed verdict.

Residual disagreement remains about magnitude, not direction. The panel does not assign equal weight to the Type 5 `WorkstationName` pattern, zero CNAME chains, perfectly stable DHCP cadence, or missing infrastructure protocols because each has conceivable environmental or implementation-specific explanations. The Detection and Host contradictions do not depend on those weaker signals, so the final verdict is unanimous without forcing agreement that every cited anomaly is independently dispositive.

## Most Convincing Evidence

1. **Systematic same-version hash divergence:** Zoom, Teams, Slack, and OneDrive change every content hash, including IMPHASH, across username-bearing installation paths while nominal product versions remain identical.
2. **Cross-vendor software anachronisms:** multiple endpoint builds released after the shared March 18, 2024 evidence date appear in ordinary Sysmon Event 1 metadata.
3. **Dead-process credential ownership:** `WS-AJOHNSON-01` PID 5232 performs a 4648 explicit-credential operation more than 31 seconds after Security, Sysmon, and eCAR agree that it terminated, without PID reuse.
4. **Uniform service-logon field template:** all 325 Type 5 logons across nine hosts set `WorkstationName` to the destination's own short hostname.
5. **Network renderer/scheduler texture:** no CNAME alias names occur in thousands of A/AAAA answer vectors, and DHCP clients renew on near-metronomic, client-specific fractions of their leases.

## Most Debated Points

- Whether the exceptional DC log-clear and cross-source lifecycle realism should favor real origin. The panel concluded that it demonstrates generator sophistication but cannot negate hard contradictions elsewhere.
- Whether same-version vendor binaries can legitimately have different hashes. Isolated variants are possible; the repeated user-path boundary across several vendors and simultaneous IMPHASH divergence made that explanation inadequate.
- Whether Type 5 `WorkstationName=<self>` is impossible or merely source-inaccurate. The panel retained it as a strong schema defect but not an independent hard contradiction.
- Whether recursive DNS caches, capture position, or response logging can explain no visible CNAME chains. The panel retained it as a broad synthetic indicator while avoiding claims about any single sanitized domain.
- Whether absent NTP and discovery traffic is evidence of generation or collection policy. The panel preserved this as qualified dissent and low-to-medium-weight support only.

## Improvement Recommendations (Consensus)

1. Generate executable hashes from canonical binary artifact identity. A product version, architecture, language, and signature variant should map to one stable byte-derived SHA-1, MD5, SHA-256, and IMPHASH set regardless of username, hostname, or installation path.
2. Make software inventories time-aware. Record release/signing dates and reject any selected build that postdates the evidence clock; add a dataset QA check spanning every version-bearing process and module event.
3. Enforce process liveness for every event carrying caller identity. A 4648 or other dependent event must occur before the canonical process termination and before rendered Security 4689, Sysmon Event 5, and eCAR TERMINATE observations, unless explicit PID reuse is modeled with a new process identity.
4. Render Windows logon fields from an Event-ID/logon-type/authentication-package matrix. In particular, correct local Type 5 `WorkstationName`, IP, port, process, and authentication-package semantics and test their fleet-wide distributions.
5. Model DNS answer sections as realistic RR chains. Include cache-dependent terminal-only responses, CNAME hops, per-hop TTLs, and multi-alias cases while preserving packet-consistent answers across sensors.
6. Derive DHCP renewals from coherent T1/T2 and server policy, then add realistic queue jitter, retries, sleep/wake gaps, missed observations, delayed renewals, and occasional reacquisition.
7. Add a low-volume, role- and policy-aware infrastructure tail, including NTP/W32Time and selectively enabled NetBIOS, LLMNR, mDNS, or SSDP; if protocols are suppressed, make that collection or hardening posture visible in the evidence.
8. Increase persona- and role-specific behavior: reduce repeated standalone `ssh.exe user@host` launches, diversify Linux administrative sequences, and attribute Linux egress to stable role-owned services or units instead of generic root/systemd `wget` processes.
9. Preserve the strongest existing realism: EventRecordID reset behavior, independent sensor UIDs/accounting, certificate identity reuse, varied transport states, source observation gaps, transport-before-auth ordering, and cross-source file/session lifecycle consistency.
