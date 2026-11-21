# New assessment epoch — loop 17

The approved expanded scenario, seed42, default target, immutable pack and reviewer
instructions are unchanged. Two engine families were repaired: purpose-aware policy
repository provisioning, and an RDP logical traffic quota defect required to finish
this generation. The failed first attempt is preserved, not counted as another loop.

## Scores and independent review

Automated evaluation passed98.28211615063223for140123records and all acceptance /
dynamic guardrails. JSON ran once; text was derived. Four fresh fork-none experts
reviewed113SHA-verified neutral data-only files with the unchanged full briefing
and individual persona. No source code, scenario, ground truth, prior reports or
targeted examination guidance was supplied.

| Expert | Initial verdict | Verdict confidence | Initial synthetic-confidence score |
|---|---|---:|---:|
|Threat Hunter|Inconclusive|79|36|
|Detection Engineer|Real|62|32|
|Network Forensics|Real|65|18|
|Host/EDR|Synthetic|76|66|
|Mean|||**38.0—mostly realistic**|

Lower synthetic-confidence is better. The standalone mean improved0.75points from16;
rolling five-loop mean46.05. This is not a causal effect estimate. Different verdicts
and48point spread triggered actual deliberation. Each original reviewer independently
rechecked the other original reports and data, then supplied their own response. A
fresh facilitator summarized those actual responses: final scores54/62/62/72,
mean62.5; Threat remainedInconclusive, the other threeSynthetic. The final scores
stay separate from initial trends.

Threat Hunter found coherent RDP, LSASS access, SSH/export/receiver and multipart
upload pivots; only narrow intersensor clock spread and repeated background Windows
command vocabulary were weak concerns. Detection parsed native schemas and checked
process/session/network joins; small similarly initialized Mac pidversions were its
main initial concern. Network found no material protocol contradiction and gave18,
with correct connection states, TLS visibility, certificates and byte accounting.
Host found no hard lifecycle error but weighted repeated Mac executable/directory
stat identity patterns heavily. In deliberation all reproduced the compact inode
population and/or gapless small pidversions, without promoting them to demonstrated
kernel impossibilities. These are deeper carried native-metadata findings, not an
observed policy/RDP regression.

## Family contracts, owners and actual output proof

**Policy repository — family_level.** The private storage world compiler and typed,
optional storage_catalog.policy_repository own automatic known-domain Windows DC
SYSVOL/NETLOGON metadata. Domain-scoped finite GPO GUIDs, GPT.INI, Machine/User
Registry.pol and preference/security/scripts paths replace generic collaboration
files. NETLOGON contains script roles. Exact roots/seeds/file-set bindings and old
absent/disabled profiles remain authoritative. Separate DC filesystem objects keep
separate identities; initial path/size/MIME agreement does not implement live AD or
DFSR replication, filesystem aliasing or mutations. Data-only rendered probe finds
46/46SYSVOL rows with domain/GPO shape and64/64NETLOGON rows with script extensions.
Native Security roots match25/25SYSVOL and34/34NETLOGON accesses. Primary metadata
semantics: Microsoft Group Policy storage and SYSVOL/NETLOGON documentation.

Entry paths include automatic storage compilation, baseline and explicit SMB task
selection; explicit custom population bypasses automatic roles. Consumers include
SMB canonical file/version state, Security share/handle records, eCAR and Zeek SMB /
files output. Shared compilation prevents caller-specific path substitutions.

**RDP traffic envelope — family_level.** DeferredRdpApplicationIntent provisioned
logical byte quota from the first sampled physical transport times the existing
logical operation allowance8. A later independently valid reconnect could exceed
that tiny initial quota. The manager correctly rejected it. The first551 generation
exited21after fourth-hour progress; complete failed bundle/logs/provenance and
failure.json remain in failed-attempt-1, without eval/panel. Progress finalizers alone
are not proof of generation success.

Shared typed network_params.rdp_payload_bounds now owns the existing physical
50k–500k initiator /100k–2M responder supports. Three initial/legacy/reconnect paths
use the same exact two randint draws and order. Newly created logical sessions are
provisioned from max(actual first bytes, configured support maximum)*existing
operation allowance. Quota guards, payload counters and operation admission remain;
old immutable logical sessions are not enlarged behind their owner. Physical
reconnect count is distinct from logical operation count. No clipping, source
redispatch, new cache or arbitrary retention/admission ceiling.

Qualified before proof uses min-first/max-next and reproduces the exact guard.
After proof reserves/finalizes one real semantic operation per transport, verifies
cumulative bytes across8operations, then rejects ninth logical operation on another
physical transport. Initial fixture wrongly counted private physical sentinels as
logical payload; corrected and retained. Optional absent frozen config keeps exact
old byte draws; invalid present/custom/partial overlay policies validate explicitly.
Consumers include canonical RDP transport/application, source process/session holds,
eCAR/Windows/Zeek, exact recovery and checkpoints. Entry paths initial, compatibility,
reconnect and deferred session all use the shared support.

## Verification and limitations

Policy gates:135stamped centralpass4.51s3deselected;5actual native policy/RNGpass14.02s;
60task siblingpass2.73s;2checkpoint105.00s;105config files0issues;Ruff1667pass. RDP:
31policy/manager3.21s,58stampedcentral4.50s73deselected,74native/deferred/recovery/
concurrent/RNG31.68s25deselected,2checkpoint105.46s,105config0issues,Ruff1669pass.
Counts overlap; no full routine or release gate. Source552 was frozen through
successful retry47815EXIT0+authoritative manifest and post4393EXIT0. Other engineering
probes remain in this folder; quantitative score is a guardrail, not authenticity.

## Prioritized findings and next work

Categories and priorities are synthesis; original reviewers assigned no P0–P4labels.

|Priority|Finding|Category / classification|Scope, leverage, owner, risk and action|
|---|---|---|---|
|P1|Mac native filesystem population|distribution_texture / carried sibling_defect|Host reproduced two Macs'29/31executable paths in96/108inode spans with month-spanning perfectly ordered birthtimes; separate adjacent root/home directory IDs add texture. High leverage/medium-high risk. Installed filesystem/provisioning and directory owners must share coherent modeled facts. Qualify native examples and exact allocation/volume semantics before repair; do not randomize renderer fields.|
|P1|Mac host-wide process identity history|distribution_texture / carried new_family|Detection and Host: all101/117visible fork/exec allocations occupy gapless12–112/12–128ranges on older hosts. High leverage/high State/recovery risk. Inspect boot history and hidden allocation modeling at canonical State owner; ES client sequence0is legitimate and excluded as independent defect.|
|P1|NTLM validation companion ownership|contract_gap / carried new_family|16Detection, engineering17probe126domainType3/114unmatched/111nonzeroGUID. Not independently rediscovered here, so no repair claimed17. Shared auth/planning and persistent SMB source cohort own it;18qualified native repair now generating. Collection gaps remain a raw-data alternative.|
|P2|Mac root/home stat population|distribution_texture / sibling_defect|Both hosts' directory entries use adjacent huge inode IDs and fixed stat shapes separate from executable population. Same filesystem-family investigation; avoid counting correlated symptoms as independent hard contradictions.|
|P2|Mac exact fractional fork groups|distribution_texture / carried sibling_defect|Prior15finding persists in engineering probe. Benchmark explicitly authors exact zero-jitter offsets; preserve fixed inputs and native birth/wall-clock truth. A deliberate scenario revision would be a separate benchmark epoch.|
|P3|Shared Mac st_dev|environment_or_collection_plausibility / false_positive_or_unproven|Secondary17Host concern, reduced in actual deliberation. No mount inventory from logs. Later read-only native public-path stat on this Mac demonstrates shared presented device across System/writable paths; do not repair based on this value alone.|
|P3|Stable intersensor clock offset|weak_signal / false_positive_or_unproven|Threat5277unique tuples mean114.275ms/std1.109ms; actual clock skew is a strong explanation. Low leverage; no arbitrary drift/jitter.|
|P3|Windows background command concentration|weak_signal / false_positive_or_unproven|Threat9exactcommands471/901Sysmoncreates. Legitimate WMI/COM/task hosts repeat; validate population before expanding pools.|

No new network repair is justified by this panel. The evaluator passes while blind
review surfaces native identity texture not covered by deterministic checks.
Protocol/lifecycle joins remain strong; authenticity is not established by passing
engineering controls. Mac pidversions, directory population and exact authored
fork fractions remain open, even if later reviewers fail to rediscover them.

## Provenance

Successful behavior552 digestbc165d96086900c120d6cbc3e08e729078ffcb1c08a3752599d737b91f23b995;
first551failed attempt retained separately. All four authored SHA256 values and
technology1.0.0pack digest unchanged. Neutral study/private/tmp/authenticity-study-u8wj8t8i;
source briefing/persona hashes verified. Fresh epoch only; requested total30.
