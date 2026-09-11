# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 86 | 68 | Synthetic | 90 | 76 |
| Detection Engineer | Inconclusive | 80 | 53 | Synthetic | 86 | 70 |
| Network Forensics | Synthetic | 92 | 82 | Synthetic | 94 | 86 |
| Host/EDR Forensics | Synthetic | 97 | 94 | Synthetic | 97 | 94 |

The Threat Hunter initially judged the dataset synthetic despite finding the environment, source volumes, attack lifecycle, and cross-source pivots highly convincing. Their strongest adverse evidence was successful Samba `opendir` activity against apparent CSV and DOCX files, the LOG-MON-01 Java process receiving ownership of a connection after termination, and repeated remote-service authentication/transport gaps. Their specialty also exposed the missing 4648 companion for one Type 9 session and exact shell-command reuse across unrelated Linux roles.

The Detection Engineer initially remained inconclusive. Their strongest adverse evidence was the same post-termination Java/OCSP transaction, the absence of matching 4776 validation for 69 of 80 successful domain NTLM logons, and narrow Linux background-message diversity. Their uniquely detection-oriented concern was that receiver-side Windows eCAR FILE records carry remote Linux process metadata without an explicit source-host field, which could cause a host-local parser to misattribute the actor.

The Network Forensics Analyst initially judged the data synthetic based primarily on population-level timing and transport texture: exact 0.600-second browser-asset intervals, a broad mode at approximately 1.200 seconds for otherwise unrelated TLS connections, and UDP syslog pseudo-connections with multiple packets but no duration and a new source port for every row. Their unique DNS observation was that none of 663 successful public A-query rows contained a CNAME despite a broad SaaS, CDN, update, and collaboration domain mix.

The Host/EDR Forensics Analyst initially issued the strongest synthetic verdict. Their principal evidence was application metadata dated 2024-03-18 containing software generations they identified as not yet released, especially Zoom Workplace 6.0.11 across five workstations. They also cited a 1.848-millisecond lock/unlock pair, the post-termination Java flow, and repeated fixed-profile Linux daemon noise. Their specialty uniquely connected the software chronology across process creation, module load, version, product, and hash fields rather than treating it as a single-record typo.

After cross-examination, the Threat Hunter retained the Synthetic verdict and raised verdict confidence from 86 to 90 and synthetic-confidence from 68 to 76. The independent network finding that exact HTTP and TLS timing modes recur across unrelated sessions changed the weight of “good coarse timing” in the initial assessment; the Host/EDR software chronology also added a second environment-wide contradiction outside the hunter's original evidence set.

The Detection Engineer changed from Inconclusive to Synthetic, raised verdict confidence from 80 to 86, and raised synthetic-confidence from 53 to 70. The change was driven by accumulation rather than by reclassifying the 4776 deficit: the Network analyst's repeated timing/socket fingerprints, the Host analyst's repeated date-versus-version finding, and the Threat Hunter's source-native Samba operation error added independent source families to the already-confirmed process-lifecycle contradiction. The engineer continued to treat missing 4776 records and ambiguous cross-host eCAR enrichment as contract or collection issues rather than hard impossibilities.

The Network Forensics Analyst retained the Synthetic verdict and raised verdict confidence from 92 to 94 and synthetic-confidence from 82 to 86. The endpoint specialists clarified that the Java/OCSP issue is not contradicted by the network analyst's clean Zeek parent-child ordering: Zeek's HTTP record is correctly inside its TCP connection, but the TCP connection itself starts after the attributed endpoint process terminates. That cross-source ownership failure reinforced the network population-level fingerprints.

The Host/EDR Forensics Analyst retained the Synthetic verdict and kept verdict confidence at 97 and synthetic-confidence at 94. The network timing modes and the independently reproduced Samba operation mismatch reinforced the position, but did not materially change an already near-certain assessment. The analyst acknowledged that software release chronology depends on the timestamps representing literal collection dates rather than an undisclosed time shift; the recurrence across products and hosts still left the initial weighting unchanged.

## Key Agreements

- The panel agreed that the strongest shared hard contradiction is the LOG-MON-01 Java/OCSP lifecycle. The same Java object and PID terminate at `17:47:39.136Z`, receive an eCAR FLOW at `17:47:39.266Z`, and are tied to a Zeek TCP connection that starts at `17:47:39.789773Z` and an HTTP request at `17:47:39.826773Z`. Three experts found it independently, and the cited records directly confirm that this is actor use after a visible terminal event rather than a missing pre-window creation.

- All experts agreed that broad source shape and correlation are unusually strong. Windows and Sysmon schemas, process joins, Zeek UID and certificate relationships, proxy state, firewall/IDS alignment, host roles, source volumes, and most lifecycle ordering are credible. The consensus Synthetic verdict therefore rests on concrete contradictions and repeated distribution texture, not on completeness, easy narratability, or the presence of suspicious activity.

- Three experts independently identified fleet-wide Linux background texture as too narrow or profile-driven. They converged on the repeated `irqbalance`, `snapd`, sysstat, `systemd-resolved`, `anacron`, D-Bus, and polkit families, while agreeing that a centrally managed fleet can legitimately share packages and runbooks. The concern is the combined repetition, fixed or role-scaled counts, high verbosity, and weak host-specific long tail.

- The panel agreed that several adverse findings are independent rather than different views of one defect. Endpoint chronology, process ownership, HTTP/TLS timing, Samba operation semantics, authentication companions, and syslog socket behavior affect distinct source families. Their accumulation materially reduces the chance that one unusual collector or audit policy explains the result.

- The panel also agreed that bounded-window effects and small collection gaps are not synthetic evidence by themselves. Unmatched lifecycle endpoints, six unresolved HTTP FUIDs, and very complete cross-source joins were not treated as decisive without a visible contradiction or repeated implausible distribution.

## Key Disagreements

- **Software release chronology:** Host/EDR treated post-date application versions as decisive and dataset-wide; the other experts did not independently raise the release-history fact. The underlying records do confirm the March 18 timestamps, repeated Zoom/Webex/Postman versions, and cross-host recurrence, but the release-date premise comes from the Host specialist's product knowledge rather than another panel report. The panel gave it high weight because it is concrete and repeated, while retaining the caveat that an undisclosed timestamp shift could explain it.

- **Authentication completeness versus collection policy:** Detection found 69 of 80 domain NTLM successes without a nearby 4776 on either visible DC. Threat Hunting separately found a missing 4648 for one Type 9 session and transport/source-port gaps in two remote-service installations. Detection argued that equivalent paired records and dense DC coverage make the omissions systematic; the alternative is selective per-event collection or a distinct authentication socket. The panel retained these as contract gaps, not hard contradictions, because selective loss and separate transport are possible explanations.

- **Network correctness versus network naturalism:** Threat Hunting and Detection praised Zeek parent-child integrity, TLS/X.509 semantics, sensor offsets, and connection-state variety; Network Forensics found exact 0.600-second HTTP scheduling, a cross-population 1.200-second TLS duration mode, and stateless UDP syslog sockets. These positions are compatible: structural correctness establishes that records correlate, while the repeated fine-grained distributions challenge whether they arose naturally. The network specialist's population counts and examples carry greater weight on temporal texture than isolated realistic sessions.

- **How much weight to give isolated hard defects:** The Host lock/unlock pair and Threat Hunter Samba operations are concrete, but limited in count. The 1.848-millisecond lock/unlock could conceivably reflect automation or a provider quirk, and `opendir` could be defensible only if the named objects were actually directories despite file extensions. The absence of an automation explanation, the normal 13–39 minute comparison pairs, and three repeated `opendir|success` document paths made both stronger than mere oddities, but weaker than the shared process-lifecycle contradiction.

- **CNAME absence and unresolved FUIDs:** Network Forensics viewed zero CNAME-bearing public A responses as implausibly uniform but treated six unresolved HTTP FUIDs as weak. Other experts' positive DNS and HTTP assessments show why neither is self-proving: recursive logging or normalization could flatten aliases, and file-analysis filtering can orphan a small number of references. The panel kept the CNAME pattern as a useful distribution signal and excluded the FUID gap from the strongest evidence.

## Most Convincing Evidence

1. **Post-termination Java/OCSP activity — synthetic, strongest.** Three experts independently identified the same object-ID lifecycle, and direct record comparison shows both endpoint attribution and the independent network start occur after termination. Alternative explanations based on delayed eCAR delivery do not account for the later Zeek connection start; a surviving process would require different actor attribution.

2. **Repeated application-version chronology conflict — synthetic.** The Host specialist identified multiple software generations as later than the March 2024 timestamps, with Zoom 6.0.11 repeated on five workstations and Webex/Postman examples repeated across additional hosts and module records. Recurrence rules out a single typo; only a nonliteral time shift remains a broad alternative explanation.

3. **Exact network timing modes across unrelated traffic — synthetic.** The 0.600-second browser-asset cadence affects 33 of 78 within-UID intervals and is visible across sensors, while 113 DMZ TLS connections cluster within two milliseconds of 1.200 seconds across directions, endpoints, versions, and payload sizes. Browser scheduling or a common timeout can explain individual examples but not the reported cross-population uniformity as well as a shared timing template.

4. **Successful Samba `opendir` on document-like paths — synthetic.** All three cited `opendir` records target `.csv` or `.docx` paths and report success. Unless those unusually named objects are directories, the source-native operation conflicts with their apparent file semantics; the repetition makes accidental corruption less likely.

5. **High-quality cross-source and lifecycle structure — real.** Nearly all process, session, Zeek UID/FUID, TLS/X.509, proxy, firewall, IDS, SSH, and role-placement checks were coherent, with plausible sensor offsets and bounded-window behavior. This evidence is why the panel did not move every score into the high 90s: the dataset is polished and operationally useful even though several independent defects reveal synthesis.

## Most Debated Points

- Whether the application metadata is a literal chronology contradiction or evidence that the corpus was intentionally time-shifted. No record-visible marker establishes a time shift, but the deliberation could not independently verify product release history beyond the Host specialist's report.

- Whether missing 4776 and 4648 events reflect generation gaps or selective audit/collection loss. Dense same-family coverage and correctly paired comparison sessions strengthen the gap finding; real pipelines can nevertheless sample Event IDs unevenly.

- Whether exact timing constants are artifacts of deterministic synthesis or legitimate application behavior. The panel found the browser-asset context, cross-sensor recurrence, broad TLS population, mixed directions, and varied byte volumes more persuasive than a single-client or single-timeout explanation.

- Whether UDP syslog rows should retain source ports and durations in the observed manner. Packet aggregation without duration and a fresh ephemeral port per row look unlike a long-lived sender socket, but sensor timeout behavior and source implementation can vary. The combination of both properties across many senders is more concerning than either alone.

- Whether Linux background homogeneity is a synthetic fingerprint or a centrally managed fleet. Common packages and cron jobs explain overlap; fixed bundle counts, consistently verbose `irqbalance`/`snapd` output, shared templates across dissimilar roles, and limited source-local long tails led the panel to retain it as supporting distribution evidence rather than a hard contradiction.

## Improvement Recommendations (Consensus)

- **Enforce actor lifetime after every timing transformation.** Before rendering, validate that every FLOW, FILE, MODULE, REGISTRY, PROCESS/OPEN, THREAD, DNS dependency, and application transaction carrying a process object occurs between that object's create and terminate times. For OCSP and similar certificate-validation dependencies, either keep the owning process alive through the final network close or assign the activity to the actual surviving process; add a cross-source test that compares endpoint actor lifetime with the sensor-visible connection interval.

- **Make software catalogs date-aware.** Store release start/end dates with application product names, versions, module paths, and hashes; select only versions valid at the collection timestamp. Add validation that rejects process and module metadata outside the permitted release window, with boundary tests for Zoom product-name transitions, calendar-versioned Webex builds, and major-version application releases.

- **Replace shared HTTP/TLS timing constants with causal timing models.** Generate browser page loads as waterfalls with dependency discovery, parallel connections or streams, object-size/RTT-dependent completion, connection reuse, and varied think time. Derive TLS close time from handshake, transfer, reuse, FIN/reset, and idle-timeout behavior, then test distributions across direction, service, payload-size bands, and sensors to prevent a narrow global mode.

- **Model UDP syslog as persistent sender state.** Reuse a source socket per host/process until a realistic restart, reconfiguration, or inactivity boundary; let sensor idle expiry create new UIDs without automatically changing the source port. When a row aggregates multiple datagrams, space them over nonzero time and emit a duration consistent with packet timestamps and byte accounting.

- **Drive Linux background logs from host state and role-specific packages.** Decide per host whether each daemon is installed, active, quiet, verbose, restarting, or absent; emit messages only for actual state transitions and work. Expand the host-specific long tail, reduce fixed bundle counts, and avoid scaling the same small `irqbalance`, `snapd`, sysstat, D-Bus, and resolver vocabulary across unrelated roles.

- **Add source-semantic lifecycle validation.** Resolve filesystem object type before choosing Samba operations, reserving `opendir` for directories and file-open/read operations for documents. Model workstation locking with human-scale dwell time and align Type 7 logon and 4801 provider timing, while allowing subsecond transitions only when an explicit automation or failure event explains them.

- **Make authentication and remote-actor contracts explicit.** For domain NTLM, produce an authoritative 4776 on the validating visible DC unless a coherent observation policy drops that family; emit 4648 consistently for audited explicit-credential Type 9 sessions. Preserve remote-service authentication/transport relationships where source-native semantics require them, and add an explicit source hostname to cross-host eCAR process enrichment so receiver-local parsers cannot mistake a remote Linux PID or image for a local Windows actor.

- **Restore public-DNS structural diversity without sacrificing current correctness.** Represent CNAME chains, variable chain depth, mixed terminal-address counts, and TTL arrays aligned to every returned RR. Preserve the existing strengths in rcode variety, suffix-search failures, internal authoritative answers, transaction timing, and sensor-local identities.
