# Blind Realism Panel Deliberation

## Facilitation scope and method

This deliberation reconciles the four independent reports in this directory: the SOC analyst,
incident responder, telemetry engineer, and threat hunter. The facilitator did not consult the
scenario, manifest, ground truth, source code, repository history, prior loops, or hard probes.
Only narrowly cited generated records were checked where the panel's outcome depended on whether
a claim was factually present in the data.

This is a report-based deliberation rather than a live second interview. The final reviewer
positions below are therefore reconciled positions: they preserve each reviewer's specialty and
stated weighting while incorporating verified evidence raised by the other reviewers.

## Round 1 — Initial positions

### SOC analyst

- Initial verdict: **Real**
- Initial verdict confidence: **83/100**
- Initial realism score: **87/100**
- Strongest evidence: coherent web exploitation and callback; two well-correlated SSH pivots;
  consistent database staging, SCP, SMB, firewall, Zeek, eCAR, and cleanup evidence.
- Unique emphasis: the corpus is highly huntable, independent sensor differences look natural,
  and a Security EventRecordID reset is correctly explained by Event ID 1102.
- Initial limitation: the review explicitly reported no exact duplicate JSON record and no
  impossible lifecycle ordering, but it did not test the cited SCP payload minimum against the
  downstream file size or compare records after excluding their top-level event IDs.

### Incident responder

- Initial verdict: **Synthetic**
- Initial verdict confidence: **88/100**
- Initial realism score: **66/100**
- Strongest evidence: repeated semantically duplicate endpoint/native events; broken file identity
  and actor continuity at the APP relay; fragmented Windows process/token lineage during staging
  and upload.
- Unique emphasis: response-critical ownership and chain-of-custody defects matter more than the
  otherwise high field and timing fidelity.

### Telemetry engineer

- Initial verdict: **Synthetic**
- Initial verdict confidence: **94/100**
- Initial realism score: **72/100**
- Strongest evidence: 116 destination-host file events expose exact remote-client process identity;
  mixed eCAR file-ID namespaces; nonstandard proxy CONNECT byte semantics.
- Unique emphasis: most parsers, Zeek parent/child joins, packet accounting, sensor offsets,
  Windows process ordering, and firewall lifecycles are strong. The verdict is driven by a repeated
  source-provenance contradiction rather than generally poor telemetry.

### Threat hunter

- Initial verdict: **Synthetic**
- Initial verdict confidence: **96/100**
- Initial realism score: **62/100**
- Strongest evidence: the complete 794,475-byte file appears downstream before the upstream SCP
  could deliver it; the APP-local file identity changes at the handoff; WEB-EXT has a source-local
  SSH close without its in-window open/authentication records.
- Unique emphasis: the transfer defect is one causal failure manifested in several artifacts, not
  several independent P0 findings. The malicious web source's concentration is a lower-severity
  texture issue, not a contradiction.

## Round 2 — Cross-examination and evidence reconciliation

### 1. Is the SCP-to-SMB sequence physically possible?

No plausible alternative explanation survives the cited records. The upstream SSH/SCP connection
starts at `1710783293.426720`, carries only 30,675 originator payload bytes over 27.609304 seconds,
and therefore ends near `1710783321.036`. The APP receiver records the named file creation at
`1710783302.406`; the SMB transport begins at `1710783302.068710`; and the SMB file record reports
all 794,475 bytes written by `1710783303.056816`, with the file analyzer reporting all 794,475 bytes
seen and zero missing bytes at `1710783303.111351`.

Starting a downstream connection while an upstream file is still streaming could be plausible in
isolation. It cannot explain delivering 794,475 bytes after the upstream channel carried only
30,675 originator bytes in total. Sensor clock offsets, SSH encryption, TCP overhead, or bounded
window truncation also cannot make the smaller observed upstream application payload contain the
larger pre-compressed object. This is a verified hard contradiction and overturns the SOC analyst's
initial conclusion that no impossible ordering was present.

Severity reconciliation: **P0** is appropriate. The incident responder's P1 file-continuity
finding captured part of the same handoff but did not assess the decisive payload/time constraint.
The threat hunter's P0 rating is better supported.

### 2. Are the file identity swap and premature relay separate P0 defects?

They are distinct symptoms within one transfer-family failure and must not be double-counted. The
APP receiver creates `/tmp/.cache/rpt_0318.sql.gz` with one object ID and receiver-process ownership,
then reads the same path roughly two seconds later with a different object ID and no actor/PID. The
second identity is reused on the FILE-LNX destination side. These records show broken provenance;
the SCP/SMB timing and byte records show broken physical causality.

Consensus treatment: one **P0 transfer lifecycle/causality defect**, with premature availability,
impossible payload accounting, object-ID replacement, actor loss, and downstream identity reuse
listed as symptoms. The identity symptoms also point to a broader file-authority weakness, but they
do not justify counting a second P0 for this exact transfer.

### 3. Are the endpoint duplicates real duplicates or legitimate repeated operations?

The incident responder's claim is verified. Cited adjacent eCAR pairs and triples have identical
millisecond timestamp, host, object/action, object ID, actor ID, PID, principal, and properties;
only the top-level event ID differs. Examples include duplicate `/etc/ssh/sshd_config` reads on
APP-INT-01, duplicate `svchost.exe`→`lsass.exe` process-open observations on DC-01, and a triple
`msiexec.exe`→`services.exe` process-open group on DC-02. The responder also cites corresponding
native Sysmon Event ID 10 duplication.

The SOC statement that there were no exact duplicate JSON records is literally compatible with
different top-level IDs, but it does not answer the relevant realism question. These are semantic
duplicates of the same occurrence, not byte-identical lines. A one-off repeated operation might be
natural; identical high-resolution time and full context recurring on unrelated hosts is a strong
distribution and occurrence-ownership fingerprint.

Severity reconciliation: **P1**, not P0. It is repeated and high leverage but does not create an
impossible physical sequence by itself.

### 4. Is destination-host use of a remote process UUID an impossible leak or valid enrichment?

The telemetry engineer's example is verified: a DC-01 file record names `/usr/bin/smbclient`, PID
1465012, and process UUID `5ecac865-...`, while that exact UUID/PID belongs to a process created on
WS-LNGUYEN-01. The destination record does not identify a remote host or label these values as
enrichment. The repeated scope reported by the specialist—116 records on three Windows servers—
makes this materially stronger than an isolated malformed field.

The best alternative explanation is that eCAR is a correlation-enriched schema rather than a
strictly source-native endpoint stream. That explanation would require explicit provenance because
the records are partitioned by destination host and use fields named as process identity without a
remote-host qualifier. In the visible representation, a Linux path and private remote process UUID
appear as if owned by a Windows destination. The panel therefore accepts this as a source-provenance
contract violation.

Severity reconciliation: **P0** for authenticity impact because the contradiction is repeated and
immediately diagnostic of cross-host omniscience. It remains independent of the SCP scheduling
defect, although both belong to the broader file-transfer/file-provenance family.

### 5. Do strong correlations support Real despite localized contradictions?

They support a relatively high realism score, but not a Real verdict. All four reviewers agree that
many source families are convincing: network tuples, independent Zeek sensor offsets, packet/loss
accounting, ASA build/teardown pairing, SSH/PAM ordering on APP and DB, Windows log clearing, and
large portions of process and file lifecycle telemetry. Complete correlation is not itself a
synthetic indicator.

The disagreement arose because the SOC analyst weighted the many successful chains more heavily
than defects it did not observe. Once the two verified hard contradictions and repeated semantic
duplicates are included, production-like background texture cannot neutralize them. A corpus can
be useful, detailed, and mostly plausible while still being distinguishable as synthetic.

### 6. Which remaining issues are independent?

- The WS-AISHA staging/upload process and token fragmentation is an **independent execution-
  ownership defect**. No single row is necessarily impossible, but the missing bridges among
  Network Service, interactive explorer, and SYSTEM/service lineages materially weaken actor
  attribution.
- The WEB-EXT orphaned SSH close is an **independent source-observation/lifecycle-grouping defect**.
  The session opens well inside the window in Zeek and eCAR, while local syslog contains only the
  close even though other sessions have complete local sequences.
- Mixed file-ID morphology is an **independent dataset-wide ID-authority symptom**, related to but
  broader than the APP handoff's identity swap.
- Proxy CONNECT byte-column semantics is an **independent source-format defect**.
- Narrow Windows EventRecordID gaps, dominant hostile web traffic, the unfinished `systemctl`
  outcome, thin TLS enrichment, broad IDS names, and incomplete email provenance are weaker,
  independent observations. None changes the verdict.

## Round 3 — Reconciled final positions

| Reviewer | Initial verdict | Initial verdict confidence | Initial realism score | Final verdict | Final verdict confidence | Final realism score | Main deliberation effect |
|---|---|---:|---:|---|---:|---:|---|
| SOC analyst | Real | 83 | 87 | **Synthetic** | **89** | **64** | Reverses after the verified SCP payload/time contradiction, cross-host process provenance leak, and semantic duplicates invalidate its no-contradiction premise. |
| Incident responder | Synthetic | 88 | 66 | **Synthetic** | **94** | **61** | Confidence rises because the threat hunter supplies a hard physical contradiction and the telemetry specialist establishes broader provenance leakage. |
| Telemetry engineer | Synthetic | 94 | 72 | **Synthetic** | **97** | **63** | Position is reinforced; the transfer-causality defect adds a second independent hard contradiction beyond the engineer's provenance finding. |
| Threat hunter | Synthetic | 96 | 62 | **Synthetic** | **97** | **60** | Position is reinforced by verified semantic duplicates and repeated remote-process leakage; original transfer finding remains decisive. |

The panel's reconciled mean realism score is **62/100**. The unanimous final verdict is
**Synthetic**, with high confidence. This is not a judgment that the corpus is broadly unrealistic:
it reflects a small number of high-specificity contradictions embedded in otherwise strong,
production-like telemetry.

## Round 4 — Consensus summary

### Key agreements

- The external web exploitation/callback chain is temporally coherent and cross-source pivotable.
- APP-to-DB SSH, PAM, endpoint, and Zeek evidence is mostly convincing before the flawed file
  relay.
- Independent Zeek sensor timing and packet differences, Zeek loss accounting, ASA connection
  lifecycle balance, and the DC-01 Security-log reset are strong realism features.
- The corpus has substantial benign activity and is operationally useful for hunting and response.
- The APP relay loses file identity and actor continuity; after verification, the panel also agrees
  that its byte/time sequence is physically impossible.
- Multiple strong symptoms from the same transfer must be grouped rather than counted as separate
  defects.

### Key disagreements that remain

- The panel cannot prove from the visible data alone whether eCAR is intended to be strictly
  source-native or correlation-enriched. It nevertheless agrees that remote process identity is
  presented without the provenance needed to make enrichment credible. This affects whether one
  calls the issue impossible collection or an undocumented schema contract violation, not whether
  it is a strong synthetic indicator.
- The panel differs on how much realistic evidence should preserve the overall realism score once
  a few hard contradictions are found. Final scores span 60–64, but this no longer affects the
  verdict.
- Hostile web-source concentration may be plausible for a quiet exposed server. It remains a weak
  texture issue rather than consensus evidence of synthesis.

## Ranked consensus findings

The list below ranks independent defects by expected effect on blind authenticity judgments.
Symptoms grouped beneath a parent finding are not additional independent findings.

| Rank | Consensus severity | Finding | Category | Scope | Reviewers | Independence and symptom grouping |
|---:|:---:|---|---|---|---|---|
| 1 | **P0** | SCP→SMB transfer violates physical availability and byte causality | `hard_contradiction` | One critical transfer, repeated across endpoint, Zeek conn, SMB, and file records | Threat hunter; incident responder and SOC observed parts of the chain | **Independent defect.** Symptoms: only 30,675 upstream originator bytes; full 794,475-byte downstream object completes about 18 seconds before upstream close; SMB starts before APP CREATE; APP CREATE→READ object swap; actor/PID loss; destination reuse of the replacement identity. Count once. |
| 2 | **P0** | Destination-host file telemetry leaks exact remote-client process identity | `hard_contradiction` / `contract_gap` | Repeated: 116 records on three Windows servers | Telemetry engineer | **Independent defect**, though in the same broad file-provenance family as rank 1. Linux `/usr/bin/smbclient` and a private remote process UUID/PID appear in a Windows destination-host file record without remote/enrichment provenance. |
| 3 | **P1** | Semantic duplicate canonical occurrences reach eCAR and native Sysmon | `distribution_texture` / `contract_gap` | Repeated across unrelated hosts | Incident responder | **Independent defect.** Adjacent pairs/triples differ only in event/record identity while timestamp and full operation context are identical; eCAR and native Sysmon examples are symptoms of duplicated occurrences, not separate defects. |
| 4 | **P1** | Windows staging/upload lacks one credible process-token ownership chain | `contract_gap` | One material workstation incident chain | Incident responder | **Independent defect.** Network Service `svchost`, interactive `explorer.exe`, and SYSTEM `services.exe` lineages alternately own one apparent workflow without visible token/process bridges. |
| 5 | **P1** | WEB-EXT SSH syslog lifecycle is source-locally orphaned | `contract_gap` | One long-lived, in-window SSH session | Threat hunter | **Independent defect.** Zeek/eCAR show in-window transport, login, shell, and close, but WEB syslog has only the matching close despite complete local sequences for other sessions. |
| 6 | **P1** | eCAR file object IDs expose mixed authorities and fixed-zero morphology | `schema_or_format` / `distribution_texture` | 188 of 391 FILE records use the fixed-zero form; three namespaces coexist | Telemetry engineer | **Independent dataset-wide authority defect**, with the APP object swap as a related sibling symptom already counted under rank 1. Do not count that exact swap again here. |
| 7 | **P2** | Proxy CONNECT repurposes the conventional combined-log byte field | `schema_or_format` | All 1,438 CONNECT rows | Telemetry engineer | **Independent format defect.** Control-message bytes occupy a field generic parsers interpret as response-body bytes, while tunnel accounting is carried in custom extensions. |
| 8 | **P3** | Windows record-counter gaps are narrowly bounded across diverse channels | `distribution_texture` | Dataset-wide weak pattern | Telemetry engineer | **Independent weak signal.** Plausible collection policies could explain high occupancy, so this is not a contradiction. |
| 9 | **P3** | Linux service-control command lacks privilege and outcome evidence | `contract_gap` | One command | Incident responder | **Independent but inconclusive.** A failed command is plausible, but neither failure nor successful privilege/service transition is represented. |
| 10 | **P3** | Hostile source contributes 46.9% of public web rows | `distribution_texture` | One public web source/population | Threat hunter | **Independent weak signal.** It makes the threat unusually easy to isolate but remains plausible for a low-volume exposed service. |

### Findings not promoted to consensus defects

- Missing JA3/JA3S and ALPN is compatible with Zeek script and collection policy; it is analytical
  thinness, not an authenticity contradiction.
- Broad IDS signature naming is ordinary alert noise and may improve rather than reduce realism.
- Partial email recipient/endpoint provenance has plausible routing and collection explanations.
- Complete cross-source pivotability, clean narratability, and loud adversary behavior were not
  scored as synthetic without a concrete contradiction or distribution defect.

## Most convincing evidence

1. **Impossible transfer minimum:** a 794,475-byte complete downstream file cannot be supplied by an
   upstream SSH/SCP flow carrying only 30,675 originator payload bytes, especially when downstream
   completion precedes upstream close by roughly 18 seconds.
2. **Cross-host private identity leak:** destination-host Windows file records contain exact process
   UUID/PID/image values owned by remote clients, including a Linux executable path, without any
   remote-host or enrichment provenance.
3. **Repeated semantic duplication:** full operation context and high-resolution timestamps repeat
   in adjacent eCAR pairs/triples and corresponding native Sysmon records, changing only record
   identity.
4. **Broken execution ownership:** one Windows collection/upload thread jumps among unrelated
   service and interactive principals without a visible transition that could preserve actor and
   token lineage.
5. **Source-local SSH asymmetry:** a session opening well inside the window has complete Zeek/eCAR
   lifecycle evidence but only a close in its host's syslog, unlike peer sessions in that source.

## Most debated points

- Whether excellent cross-source correlation should outweigh a few localized contradictions. The
  panel concluded it should raise realism scores, not erase high-specificity authenticity failures.
- Whether remote process fields in destination eCAR records are impossible native observation or
  undisclosed enrichment. Both interpretations require a correction to the visible provenance
  contract.
- Whether same-timestamp repeated process/file operations are natural retries. Their exact context,
  adjacency, recurrence across unrelated hosts, and native/eCAR projection make that explanation
  insufficient for the pattern as a whole.
- Whether web-source dominance is an artificial training shortcut or realistic exposure. The panel
  retained it only as a low-weight texture concern.

## Improvement recommendations — consensus

1. Make the transfer lifecycle authoritative for availability, byte accounting, completion, and
   dependent actions. Do not allow APP reads or SMB forwarding to consume the full object before
   SCP has delivered enough bytes and reached a compatible completion state.
2. Preserve explicit file lineage across copies. Host-local object IDs may differ, but the APP
   receive object must remain stable for its local READ, retain the reading actor/process, and link
   source and destination versions through a transfer/content identifier or hash.
3. Separate source-native and cross-host enriched provenance. Destination server records should
   identify locally observable server process/session/client facts; remote process references must
   include remote host and enrichment authority and must not masquerade as local endpoint identity.
4. Deduplicate occurrences before source rendering. If repeated operations are intentional, give
   them distinct times or native execution context so they represent separate acts rather than
   cloned projections.
5. Model Windows collection/upload under an explicit execution and token chain. When service,
   interactive, and alternate-credential contexts interact, emit the process/token transitions and
   attribute file/network effects to the process that performed them.
6. Apply source-observation decisions coherently to each SSH lifecycle group so connection,
   authentication, PAM/session open, logind, close, and removal evidence cannot become an isolated
   in-window close.
7. Standardize or label eCAR file ID authority, and restore conventional proxy byte-column
   semantics while retaining tunnel metrics in named source-specific fields.

## Final panel assessment

**Consensus verdict: Synthetic.** The dataset remains substantially realistic and highly useful,
but two independent high-specificity contradictions and several repeated contract defects make it
distinguishable from naturally collected production telemetry. The most important implementation
lesson is not to reduce correlation: it is to preserve the strong correlations while enforcing
physical transfer causality, source-local provenance, stable identity authority, and lifecycle
ownership.
