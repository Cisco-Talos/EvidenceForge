# Mac-series loop48: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop5 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **96.4549**, 136,811 records. Hard acceptance is recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat30 / Detection54 / Network74 / Host38**, mean **49.00** (mixed/inconclusive); lower is more production-like. Prior mean59.25; current rolling5 **51.60**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **64.75**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Root repair and verification

[Family contract](family-contract.md) assigns remote-session missingness/delay to the source-observation tuple owner. Login and transport already shared that key; logoff incorrectly fell back to a separate lifecycle identity. The policy now includes closure, preferring typed SSH/RDP session kind and using OS-aware legacy Type10 semantics. Local/SMB sessions and failed attempts remain separate. Classification `family_level`; no eCAR emitter patch, forced retention, source-count tuning or scenario edit.

115 observation/dispatcher tests plus15 exact SSH/RDP close tests pass; Ruff and behavior checks pass at revision447, digest `d8ad8f7969c91b875ffca3e9ed46fcd298f5ffa253b1e2decec66abd06955b55`. Tests exercise Mac/Linux SSH and Windows RDP with nonzero drop/delay, typed and legacy paths and nonremote exclusions. Full routine suite was reconciled before initial push and is not repeated per uncommitted loop.

[Fresh closure probe](remote-session-close-probe.json) verifies the exact missing Mac02 SSH object39502e16-8050-4eaa-99a0-25f8d5ed2185 now has its matching logout. Visible remote login/logout totals remain66/59; pairing improves52→54 and visible login-without-visible-logout14→12. These are collection-window counts, not12 proven defects. Observation fate changes remove some unmatched closures as well as restore an intended one; they do not force every phase visible.

Only3 eCAR files change (Mac02, MAIL-CLIN, WEB-EXT);114 files, including every native ES and network file, match47 exactly. All hard criteria pass at96.4549,136,811 records/117files. Native forks89/89, execs107/107, expected exits87/87, aggregate births0, mounted exits4/4, authored timing unchanged. ASA/stream/HTTP repairs remain clean. [Mac allocation probe](mac-pidversion-probe.json) explicitly retains the unresolved4 adjacent new-fork reversals and53 new assignments below prior high water on Mac02; the clean host review does not resolve that defect.

## Review validity and score interpretation

The first network attempt unexpectedly received a task-project public search-result snippet despite textual site qualifiers. It stopped unscored and was discarded; its provenance report and [discard record](discarded-review-attempts.json) are preserved. A fresh replacement inspected only neutral data/briefing and primary upstream references, using actual domain filtering/direct URLs for subsequent research. Its accepted report is the raw network assessment. Future prompts require actual domain filters, not only textual site qualifiers. Other reviewers and facilitator retain separate actual-input statements. Generic inherited operating metadata remains an environmental limitation, not an origin indicator.

Initial mean59.25→49.00 is mainly reviewer coverage variance. Native and network files are byte-identical, yet host78→38 because this reviewer did not test the known native allocation invariant. Network74 confirms ICMP state semantics and discovers a scan payload gap but does not independently retest packet/history minima. Detection54 finds a different Windows account-change contradiction. Automated eval improves with session consistency; the blind mean is not a controlled causal estimate of this repair. Known contradictions remain visible in coordinator probes even when a fresh reviewer does not find them.

## Prioritized findings

Coordinator priorities/classifications; original P0–P4 ratings were not provided. Counts of sensor observations are not unique transactions or independent votes.

| Priority | Finding / classification | Reporter / original rating | Scope / leverage | Owner, risk and action |
|---|---|---|---|---|
| P0 | Captured TCP packets versus recorded history / sibling_defect | Network47 carried, not labeled; fresh coordinator48 |13 conservative rows unchanged; high |Capture selection/typed observation admission.49 repair is prepared with shared physical packet minimum and persistent/codec siblings. Medium–high risk; retain physical partitions, real partial loss and stream/content separation. |
| P0 | Native ICMP state / sibling_defect | Network48 independently repeats47, not labeled |All723 observations; high |Zeek protocol-specific native state projection. Upstream returnsOTH outside TCP/UDP. Preserve canonical echo success/failure truth. Low–medium risk; target50. |
| P0 | Native Mac audit allocation chronology / sibling_defect | Host46/47 carried, not labeled; coordinator48 |Mac02 four fork reversals; high |Canonical chronological identity allocator across immutable/proof/source references. High architectural risk; explicitly deferred, not repaired. Do not hide by emitter-local numbering or timestamp changes. |
| P1 | Plain connect-scan client payload / new_family | Network48, not labeled |12 payload-bearing tuples among1,256 scan FLOWs; medium–high |Scan action/network intent contract. Exact Nmap -sT command has no probing/data options, but source payload13–170 bytes. Server-first banner is allowed and cannot explain client payload. Modified binary/ownership alternatives remain qualified. Medium risk; verify all scan modes and keep -sV siblings distinct. |
| P1 | Account-change mask/change-list mismatch / new_family | Detection48, not labeled |One4738:0x15→0x10 clears2 SAM bits, one token; medium |Canonical account-state transition and native delta projection. Derive masks and tokens together, distinguish SAM from LDAP UAC values. Exporter alternative remains. Low–medium risk; queued after broader families. |
| P1 | Browser singleton and4672 membership / carried families | Detection46, not labeled |Mac/Windows roots;271/408 privilege rows; high/medium–high |Application/process owner and auth realism catalog/loader/native projection. Preserve explicit separate profiles and actual token grants. Medium–high/medium risk. |
| P1 | Runtime lower-tail support / sibling_defect | Detection47, Host43/44 carried, not labeled |733 Windows pairs min3.004s plus Linux stages; medium–high |Workload lifecycle/runtime profiles. Distribution evidence; filtering/overhead alternatives retained. Medium risk. |
| P1 | Multipart completion/relay timing / sibling_defect | Threat44 carried, not labeled |One related upload case; qualified medium–high |Action byte availability/client lifetime. Verify file-analysis interval versus actual same-content completion and termination semantics before fixing. Medium–high risk. |
| P2 | Nikto test identities / new_family carried | Threat46, not labeled |315 identifiers on316 requests,40 paths; medium |Scanner test/variant catalog; custom/spoofed scanner remains possible. Low–medium risk after reference verification. |
| P3 | Shell socket ownership and console/storage leads / false_positive_or_unproven | Prior specialists, not labeled |Qualified leads; low–medium |Require native/normalized ownership contracts before generating descendants or changing parents. |
| P4 | Mac command vocabulary,1ms intervals and anacron onset / false_positive_or_unproven | Threat48/Host48 and Detection47, not labeled |Same-user39 commands; isolated scheduling pairs;10 Linux starts in28min; low |Task/scheduling/collection context may explain all. Do not add arbitrary noise or remove valid repetition; common maintenance policy remains plausible. |

## Next action

Complete49's physical captured-packet/history invariant, then native ICMP projection. Retain Mac audit allocation at P0 with explicit unresolved evidence, and pursue browser/privilege/scan/account/runtime owners without scenario changes. This loop closes the selected source-observation defect; it does not claim every missing session endpoint is a generator error or that a lower fresh host score resolves known native issues.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 80; synthetic-confidence score 30. The supplied slice is mostly production-like from a threat-hunting perspective: suspicious Windows activity and Linux database staging support workable pivots through process, authentication, network, and file evidence. I found modest repetition in the two Macs' shell activity, but did not demonstrate an impossible visible lifecycle, account-identity contradiction, or required cross-source companion failure sufficient to establish synthetic origin.

**Detection Engineer:** Inconclusive; verdict confidence 78; synthetic-confidence score 54. Most of this collection would ingest and correlate credibly in a detection stack: the Windows, normalized endpoint, and network records have strong identity and lifecycle consistency. A concrete account-change field inconsistency and a narrow repeated macOS command vocabulary make me cautious, but they do not establish that the full collection is synthetic. My score reflects mixed evidence, rather than the confidence with which I can prove the isolated field discrepancy.

**Network Forensics:** Synthetic; verdict confidence 90; synthetic-confidence score 74. The network records are broadly coherent, with plausible sensor segmentation, DNS diversity, proxy behavior, TLS visibility limits, and consistent protocol/file references. Two concrete defects change the verdict: every ICMP observation uses a connection-state classification inconsistent with upstream Zeek, and twelve connections explicitly owned by a plain Nmap TCP connect scan contain client payload. These are source semantics and activity-contract problems, not objections to complete matching or to the intrusion's narrative.

**Host Forensics:** Inconclusive; verdict confidence 70; synthetic-confidence score 38. The endpoint evidence is mostly production-like: process identities, parentage, privilege transitions, and visible session ordering survive broad consistency checks across Windows, Linux, and macOS. There are weak distributional tells in repeated Mac shell diagnostics and clustered Linux daily-maintenance startup, but I did not establish a hard contradiction that distinguishes a carefully constructed dataset from sanitized production telemetry.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 39 | 96.09 | 44 | 20 | 30 | 66 | 40.00 | mostly realistic | 49.50 | 47.90 |
| 40 | 96.09 | 43 | 35 | 56 | 44 | 44.50 | mixed/inconclusive | 49.50 | 46.30 |
| 41 | 96.09 | 64 | 63 | 84 | 63 | 68.50 | likely synthetic | — | 49.90 |
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |
| 44 | 96.31 | 54 | 28 | 83 | 64 | 57.25 | mixed/inconclusive | 72.25 | 54.25 |
| 45 | 96.31 | 35 | 34 | 65 | 29 | 40.75 | mixed/inconclusive | 49.50 | 53.50 |
| 46 | 96.31 | 38 | 67 | 20 | 82 | 51.75 | mixed/inconclusive | 76.25 | 50.15 |
| 47 | 96.31 | 24 | 45 | 90 | 78 | 59.25 | mixed/inconclusive | 84.00 | 52.60 |
| 48 | 96.45 | 30 | 54 | 74 | 38 | 49.00 | mixed/inconclusive | 64.75 | 51.60 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all117 data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.
