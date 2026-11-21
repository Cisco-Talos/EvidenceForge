# New assessment epoch — loop 18

Behavior553 repairs canonical NTLM credential-validation ownership across persistent
Windows SMB, generic Windows remote authentication and Samba member authentication.
The approved scenario, four authored hashes, seed42/default, pack and reviewer
instructions remain unchanged. The quantitative evaluator is a regression guardrail.

## Scores and review

Automated evaluation passed98.41037730212695for144748records, with acceptance and
all dynamic guardrails. JSON ran once; text was derived. Four fresh fork-none
independent experts reviewed116SHA-verified data-only files in a neutral study.
No code, scenario, ground truth, previous findings or targeted examination guidance.

|Expert|Initial verdict|Verdict confidence|Initial synthetic-confidence score|
|---|---|---:|---:|
|Threat Hunter|Inconclusive|82|45|
|Detection Engineer|Synthetic|84|72|
|Network Forensics|Real|70|20|
|Host/EDR|Inconclusive|84|55|
|Mean|||**48.0—mixed/inconclusive**|

Lower synthetic-confidence is better. Initial mean increased10points from17;
rolling five-loop mean43.40. This is a standalone comparison, not an A/B causal
estimate. The increase centers on carried Mac native process-generation and exact
fork-phase fingerprints, not an observed NTLM repair regression. Mac01 retains
12–112gapless versions from17; Mac02has12–133versus17's12–128with five more
canonical allocations. The exact fractional fork groups also persist unchanged.

Verdict disagreement and52point spread triggered actual deliberation. The same
four experts independently rechecked original reports/data and supplied their own
responses. A fresh facilitator summarized final68/76/58/68, mean67.5; TH/DE/Host
Synthetic, NetworkInconclusive. These actual revised scores remain separate from
initial trends. No hard process lifecycle contradiction was established.

Threat Hunter found practical Windows netonly/SMB and Linux/SSH transfer pivots;
its moderate concerns were repeated irqbalance vocabulary and ambiguous normalized
stdout-file creation ownership. Detection's72principally reflects both Macs'
gapless low process-generation sequences and PID jumps not reflected by native
versions; its native Windows/network checks remained strong. Network found no
substantive protocol defect and scored20. Host scored55on repeated microsecond-exact
fork phases, while process/parent/session and cross-source executable checks held.
All changed positions in deliberation came from confirmed existing Mac identity /
timing findings, with transformation/automation caveats retained.

## Selected family, owner and invariant

Classification:family_level, with generic/persistent callers adapting to one shared
authentication planner and occurrence factory. Credential authority and phase truth
belong with auth/session execution; immutable State owns session GUID availability.
Renderers do not invent companions, identities or timing corrections.

The shared authority resolver uses IdentityDirectory account scope. Domain NTLM
remote success selects an actual modeled Windows DC, including the target DC for
remote Type3; local Windows SAM authority is the actual target. Well-known,
unknown/unmodeled authority, Kerberos and cached/local interactive semantics remain
distinct. Domain-backed Samba members are siblings; standalone local Samba cannot
invent AD validation. Original client Workstation is preserved. Public NTLMSSP and
persistent internal ntlm fallback are recognized without changing authored protocol
schema or replacing NTLM with Kerberos.

The shared planner returns a canonical validation draft before authentication,
inside an existing transport when available. Optional strict/frozen
success_ntlm_validation8–120ms preferred support shrinks before continuous
TimingRuntime sampling for short transports; a temporal graph preserves causal
bounds. No arbitrary fixed source offset, clipped distribution or extra Netlogon
TCP flow is invented. Manual validation requests share the canonical builder and
retain explicit success/failure status and unmodeled-DC compatibility. Known
local authority uses its actual HostContext rather than fabricated DC facts.

Persistent SMB carries its new validation draft through the existing prepared /
authenticated source cohort, exact publication, retry and recovery. A distinct
credential_validation phase identifies its capsule. Exact capacity accounting
requires one new member: old5+3N+client becomes6+3N+client for known NTLM authority,
with structural maximum7+3*maxoperations. This provisions one real canonical fact;
operation allowance, manager guards, retention ceilings and RNG census are not
relaxed. No postcommit callback or source-row-triggered companion generation.

PersistentSmbRootIntent selects native LogonGuid availability at session planning:
known NTLM uses uncaptured zero, Kerberos keeps its existing identity. Downstream
sources reuse the same State identity; nonzero NTLM is not asserted universally
impossible. RDP/Type9/other mechanisms retain their contracts. Legacy raw direct
generators without IdentityDirectory have no automatic authority proof and retain
the explicit manual validation API.

Entry inventory: persistentWindows initial/direct/composite/auto SMB, genericremote
Windows, remoteDCtarget, SambaADmember/local, manualvalidation, failure, machine-
account and Kerberos bundles, observation and normal/exact rendering. Existing
machine-bundle validations remain independently owned. Consumers: Security4776/
4624/4634, canonical SMB sessions, Samba/eCAR, clocks/observation, retained source
receipts, fault recovery and checkpoints. No authored/reviewer changes.

## Actual output proof and gates

Before17:126domain NTLMType3,114unmatched account/workstation pairs and111nonzero
GUIDs. After18:121domain NTLMType3,all121zeroGUID andall121have successful validation
pairs somewhere in the supplied slice.119match the separate[-1,+5]second probe
window. Two target-clock logons have their nearest DCvalidation1.245/1.276seconds
later; cross-host source clocks remain a plausible explanation. The arbitrary
probe window is descriptive, not a native validity requirement; no forced shift
or claim that all121are tightly timestamp-coupled.174successful and4failed4776rows
remain, including independent machine/background validations.

Qualified native-before tests reproduce missing validation in DCtarget, Windows
member and Samba member public NTLMSSP paths. Initial unsupported ntlm public-alias
fixture failures were excluded and retained. After:3nativepass11.09s; expanded
9cases27.98s include four actual Windows member/publication lost-return faults and
two redundant Samba controls (not nine distinct fault paths). Each retains exactly
one matched validation.7scope/shorttransport/localSAM/Kerb/unknown/manualfailure/
frozenpolicy cases4.04s;70auth/projection siblings1.54s;11persistent26.39s;
18nativepersistentrecovery46.02s;34stampedmanifest/scope5.79s3deselected;2checkpoint
105.38s;105config files0issues;Ruff1671pass. Counts overlap; no full routine/release
gate. First behavior stamp rejected an overlong summary before writing; corrected.
An early unstamped checkpoint attempt correctly failed the declared/actual digest
guard and is retained separately; the stamped rerun passed.

Verification correction: global_temporal_rng_policy is slow and its three cases
were DESELECTED by the default18commands. Provenance labels were corrected; no553-
specific policy pass is claimed. A dedicated slow run against554(includes the NTLM
repair plus the integer root-identity adapter) passed3in7.21s with unchanged census.

Generation76388and post7792exited0with authoritative manifest before19source edits.
Other former-family probes remain in this folder, including native timing, files,
TLS, policy shares and Mac metadata. Passing these controls does not prove origin.

## Prioritized remaining findings

Categories/priorities are synthesis; reviewers did not assign P0–P4labels.

|Priority|Finding|Category / classification|Scope, owner, leverage, risk and action|
|---|---|---|---|
|P1|Mac host-wide native generation history|distribution_texture / carried sibling_defect|Detection reproduces223new identities exactly12–112/12–133despite large PID movement/old boots. High leverage; shared chronological MacosAuditIdentityLedger.seal currently uses dense row_number. State values are opaque handles, so changing them or renderer noise would miss the owner.20contract selects reuse of existing canonical POSIX hidden-birth history; preserve proof handles, source filtering/checkpoints and all token/eCAR reference positions. Medium-high risk.|
|P1|Mac filesystem population/stat history|distribution_texture / carried sibling_defect|17Host's compact executable inode and ordered month-spanning birthtime population persists in engineering18probe:29/31paths in96/108inode spans. Not independently highlighted by18panel, so not fixed. Canonical installed provisioning owns it. High leverage/high scope risk: qualify System snapshot namespace/install cohort and ordinary filesystem population; do not randomize IDs.|
|P2|Mac exact fractional fork groups|distribution_texture / carried sibling_defect|Host10/103forks in three groups; actual deliberation reproduces. Approved benchmark explicitly authors exact zero-jitter offsets. Preserve all four hashes and canonical birth/clock truth during this series; a deliberate scenario revision is separate. No emitter jitter to hide it.|
|P2|Mac presented root directory identity|schema_or_format / bounded adapter|Engineering native public-path stat and Apple's APFS reserved-role reference qualify root2;19adapter now generating. This only fixes canonical presented root identity and collisions, not full APFS/stat population. Same presented st_dev can legitimately span System/data paths and must not be changed merely for variety.|
|P3|Redirected database output CREATE|contract_gap / false_positive_or_unproven|Threat one mysqldump normalized FILE/CREATE occurs after exec. Redirection is visible in shell history and appropriately absent from argv. Normalized first-observed output may explain it; actual shell redirection can run in the child that later execs the utility. Do not invent a different helper PID/parent-owned create without establishing collector and pre-exec semantics. Medium local leverage/high lifecycle risk.|
|P3|irqbalance diagnostic vocabulary|distribution_texture / new_family|Threat four bodies repeated across Linux roles,52–155observations perhost. Daemon diagnostics naturally have finite formats; validate upstream messages/verbosity and host IRQ state before changing counts or adding strings. Low-medium leverage/medium risk, config+daemon activity owner.|
|P3|Secondary syslog destination|weak_signal / false_positive_or_unproven|Threat114/342core syslog flows(92UDP/22TCP, clarified in deliberation)targetFILE-LNX, including logmonitortraffic; relay/archive role plausible. Inspect world/service selection before enforcing collector exclusivity. Low leverage.|
|P4|One SMB mapping without conn summary|weak_signal / false_positive_or_unproven|Network/Detection explicitly excluded as scored defect; window or selected export can explain it. Do not fabricate a connection just to complete joins.|

No new protocol repair is justified by the network panel. Automated evaluation
passes while native Mac distribution texture drives the blind score. Missing
rediscovery of old inode findings is not a repair; quantify against the retained
engineering probes and keep initial/revised scores separate.

## Provenance

Behavior553digest786619f9fd442f980e5de71ee12458828beb662b3c982173ab366d25b2ea99a1.
Neutral study/private/tmp/authenticity-study-laatfju7,116files. Full briefing/persona
source hashes and all four canonical authored SHA256 values remain unchanged;
technology1.0.0pack unchanged. Fresh epoch only. Requested total30;19generating.
Primary authority/mechanism references: Microsoft4776and4624documentation linked
in family-contract.md. No historical/candidate scores inherited.
