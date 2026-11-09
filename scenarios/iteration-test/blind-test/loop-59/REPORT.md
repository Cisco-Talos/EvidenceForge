# Mac-series loop59: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop16 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **95.5090**, 140,141 records. Hard acceptance status **REVIEW**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat52 / Detection81 / Network35 / Host76**, mean **61.00** (likely synthetic); lower is more production-like. Prior mean42.75; current rolling5 **53.60**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **69.75**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Sensitive-privilege data ownership

Canonical authentication now selects only event-native sensitive privileges from validated YAML profiles. The configuration separates that allowlist from profile membership, rejects duplicates/nonsensitive names, permits an explicitly empty profile, and retains modern session-user impersonation. A shared loader also supplies the low-level Windows AuthContext fallback, replacing independent hardcoded renderer lists. Ordinary elevation remains a separate fact: an elevated token with no sensitive rights does not acquire a fabricated4672companion.

Service, SYSTEM/machine, domain-admin and workstation-admin profiles retain distinct intended rights. The prior elevated-user pool consisted solely of nonsensitive rights; it is now empty instead of inventing Debug or other sensitive permissions. Explicit native raw rows remain caller-owned. Microsoft4672field semantics and a firsthand modern nativeXMLexport supporting DelegateSessionUserImpersonate are recorded in the contract; the older documentation omission was not treated as invalidity.

Twenty new cases and651focused checks cover valid/empty profiles, canonical emission/no-emission, duplicate/nonsensitive membership, shared fallback, existing auth/DC/account/source paths and a negative validate-config path. All101configurationfilesvalidatewithoutissues, and Ruff passes. Initial patch invocation used a Python interpreter without YAML and made no product edits; it was rerun correctly under uv before verification/generation. Test fixtures that formerly used ChangeNotify as a valid sensitive-list example now use Audit; the intentionally malformed-name fixture remains negative.

## Fresh native proof and scope

Fresh140141records/117files compare against58: only the ten Windows Security XML files change,107otherfiles remain byte-identical. Of409native4672records,273formerly contained one or more known nonsensitive token rights. The fresh set haszero such lists andzeroemptylists. This benchmark happens to exercise nonempty assigned profiles for every emitted occurrence, so its409count is unchanged; suppression for an empty elevated profile is verified independently by canonical tests rather than claimed from this sample.

Corrected4738SAMtokens, finalized request headers, file-sender locality and inspected-client TLS byte budgets remainvalid. Common physical/correlation probespass; Mac native census stays95forks/111execs/93exits complete and mounted exits11/11. EveryMacdatafileisunchanged, so the host-wide pidversionP0and exact shell-handoff texture are still present. Record counts alone do not validate those native invariants.

## Hard acceptance and review boundaries

Aggregate evaluation stays95.509009; hardpivot139/191=72.774869 remainsbelow80, statusREVIEW. The failing criterion is preserved, with no threshold, seed, scenario or observation-policy adjustment. Planned source-awareMacmatcher work must distinguish actual visibleEStraces from missing normalized rows and retain authored-time drift. Baseline-warning logic remains deferred by user request.

Standalone scores for this run must be interpreted against a ten-file source-native change. NativeMac/network reviewer findings concern byte-identical evidence and cannot be called regressions introduced by sensitive-privilege membership. Priority remainsP0nativeMacallocationchronology(high-leverage, repeated, high-risk authenticated identity/recovery work); P1failednative-source/evaluationreconciliation; P1scannerintentandforegroundshelltiming; qualifiedP1/P2ICMPaggregation, hourlySSHcloses, multipartcompletionandgpupdateartifactownership. Repeated binary-documentcat behavior is one workflow-texture cohort, not eight hard contradictions. The next60repair distinguishes pureconnectscans from explicitapplicationprobes at the scanner action owner, keeping coverage and process identity intact.

Initial52/81/35/76mean61.00: Detection andHost independently rediscover the unchanged nativeMacallocation defect and exact1ms handoffs. Threat identifies alphabetical executable-inode allocation on bothMacs with near-constant cross-host offsets; source inspection confirms sequential inode construction after catalog sorting. Treat that as a qualified filesystem-history model gap, not impossible APFSmetadata; changing emittedstatfields alone would violate shared file identity. Network's mobile-UAcohort is a weak application/environment lead and does not prove a desktop process emitted those headers. Original reviewer labels differ (DE hard_contradiction versusHost schema_or_format); preserve that distinction. Score rise from58is deeper/different investigative coverage of byte-identicalMac/networkfiles, not a sensitive-privilege regression.


## Independent reviewer summaries

**Threat Hunter:** Synthetic; verdict confidence 75; synthetic-confidence score 52. The operational evidence is substantially realistic: suspicious activity can be followed across host processes, authentication, network transport, proxying, and file movement without a demonstrated impossible lifecycle. My synthetic verdict rests chiefly on a reproducible filesystem-metadata pattern across the two Mac hosts, with a smaller contribution from the narrow way shared-document access is represented; these are distribution artifacts rather than proof that the observed intrusion could not work.

**Detection Engineer:** Synthetic; verdict confidence 94; synthetic-confidence score 81. Most of this dataset would ingest cleanly and supports credible process, session, and network correlation. My decisive finding is localized to MAC-MROSS-02: newly allocated native audit-token identity versions repeatedly move backward while both wall time and Mach time advance; a separate set of seven exactly 1 ms process handoffs adds a weaker timing fingerprint.

**Network Forensics:** Inconclusive; verdict confidence 76; synthetic-confidence score 35. The network data is mostly production-like: transport states, protocol timing, proxy traffic, and certificate relationships withstand a substantial set of consistency checks. The main reservation is a sustained mobile user-agent identity on an endpoint otherwise identified as a Mac; that is explainable and does not establish fabrication. I found no demonstrated impossible same-identity ordering or source-native protocol contradiction sufficient to call this dataset synthetic.

**Host Forensics:** Synthetic; verdict confidence 90; synthetic-confidence score 76. The host evidence is unusually competent at preserving process, session, and cross-source ownership, but the macOS process identity values and repeated exact timing boundaries suggest constructed telemetry. The strongest concern is the allocation pattern of native-looking Endpoint Security `audit_token.pidversion` values; a second, independent concern is repeated exactly 1 ms shell-command serialization. Neither the completeness of the suspicious activity nor the amount of source coverage affected this assessment.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 50 | 96.47 | 46 | 82 | 72 | 32 | 58.00 | mixed/inconclusive | 79.00 | 56.90 |
| 51 | 96.47 | 67 | 28 | 58 | 32 | 46.25 | mixed/inconclusive | 58.75 | 55.80 |
| 52 | 95.78 | 35 | 36 | 32 | 43 | 36.50 | mostly realistic | — | 51.25 |
| 53 | 95.78 | 28 | 34 | 82 | 43 | 46.75 | mixed/inconclusive | 71.50 | 50.80 |
| 54 | 95.51 | 62 | 84 | 66 | 84 | 74.00 | likely synthetic | — | 52.30 |
| 55 | 95.51 | 58 | 34 | 43 | 79 | 53.50 | mixed/inconclusive | 68.00 | 51.40 |
| 56 | 95.51 | 48 | 64 | 43 | 63 | 54.50 | mixed/inconclusive | 64.25 | 53.05 |
| 57 | 95.51 | 34 | 82 | 27 | 82 | 56.25 | mixed/inconclusive | 75.50 | 57.00 |
| 58 | 95.51 | 38 | 28 | 48 | 57 | 42.75 | mixed/inconclusive | 48.50 | 56.20 |
| 59 | 95.51 | 52 | 81 | 35 | 76 | 61.00 | likely synthetic | 69.75 | 53.60 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.
