### Family repair and rendered isolation

Selected family: ordinary Windows process creation must distinguish the requesting
canonical actor from the newly created process token. One stateless policy now
runs before source preparation in the shared process execution service, system
creates, parent-chain construction, Windows session bootstrap and persistent SMB
client construction. It fills existing AuthContext.subject_* and optional
ProcessTargetSecurityContext. Primary child principal/SID/LUID stay unchanged for
Sysmon, eCAR, process termination and canonical identity. Native4688 renders those
resolved creator fields, preserving unknown/explicit/raw compatibility.

This bounded model declares the ordinary process action's immutable actor as its
requester; it does not claim that every real Windows parent uses its primary
thread token, or prove arbitrary impersonation from ParentUser alone. Separately
modeled impersonation needs explicit requesting context. There is no emitter-side
State lookup, new identity allocator, State field, cache, quota or RNG site.

Actual native output contains931Security4688 creates,37populated alternate target
subjects (previously0),927unique Sysmon child joins and0effective-child-LUID
mismatches. The targeted native Type9 test also verifies same-user old/new LUIDs
and unchanged Sysmon/eCAR child identity. All115data filenames are unchanged;
exactly the10WindowsSecurityXMLfiles differ from24, and105otherdatafiles are
byte-identical. This is source isolation, not an authenticity score or proof that
all real Windows requesting-token cases are represented.

Validation:307owner/native/emitter/SMB/manifest tests passed,29deselected;
34routine source-timing/CLI tests passed,87deselected; those87exactWindows/source
preparation cases separately passed under slow. Temporal RNG census3passed,
configuration105files/zeroissues, Ruffcheck/format1683passed. Before controls
failed on actual creator/target facts, rather than merely a missing API. No full
routine, release, soak or packaging gate is claimed.

### Independent panel and actual deliberation

ThreatHunter: Inconclusive,verdict confidence80,initial synthetic-confidence45.
Operational process/session/account/proxy pivots were convincing; three RDP
intervals near887.866seconds on one reconnecting pair and repeated Linux noise
were qualified distribution concerns. After actual peer evidence rechecks the
reviewer revised toSynthetic,confidence87,score74.

DetectionEngineer: Inconclusive,confidence80,initial38. Native Windows layouts,
GUID lifecycles, endpoint actors and protocol tuples passed broad checks. The
main concern was MAC-MROSS-02PID1: process startOctober6, executable-file birth
October29, repeated in11actor rows. Metadata preservation/alteration remains
possible, so this was a qualified contract gap, not an impossible execution claim.
The orphan SMB mapping was explicitly unscored because independent export loss
can explain it. Actual deliberation revised toSynthetic,confidence84,score72.

NetworkForensics: Synthetic,confidence83,initial68. Same-sensor joins, byte/body
bounds, TLS ciphers/certificates and long SSH flows were credible. A conservative
selected set of479transparentCONNECT/client/upstream matches had90unequal tunnel
payload totals,47with stronger directional deficits/excesses; this independently
rediscovers the known paired opaque-stream owner gap. Example14:16:14assets.
signalwire.dev: proxy/client agree4074server tunnel bytes, upstream has2372,
a1702byte shortfall. Hostname/time association is inferred, not a shared cross-leg
UID, and undocumented interception/counter semantics remain alternatives. Actual
rechecks revised toSynthetic,confidence88,score74.

Host/EDR: Synthetic,confidence78,initial67. Windows/Linux identities and timed
utilities were convincing; all5visiblevmstat1x5children exceeded4seconds. The
main indicator was the unchanged authored Mac command-phase family:10forks in3
groups on2hosts retain exact microsecond fractions and whole-second Mach gaps.
It is one distribution family, not10independentcontradictions. Actual rechecks
of proxy examples and file chronology revised toSynthetic,confidence88,score76.

Actual revised scores74/72/74/76 average74.0; allfouractual final verdicts are
Synthetic. A fresh facilitator synthesized the four real responses; original and
revised reports remain separate. Revised scores do not enter standalone trends.

### Evidence qualification and next work

The stronger proxy finding remains owned by paired proxy/network/TLS planning.
Earlier controlled18request probes confirmed that small/omitted opaque budgets
can be expanded independently by each leg's framing/TLS floors. The client leg
commits before the origin leg, so a complete repair needs paired precommit truth,
consistent TLS1.2certificate minima and exact failure/recovery. Do not patch an
access-log number, copy one already committed leg, bypass the certificate floor
or relabel transparent tunnels as inspection. This high-leverage family is
explicitly deferred; it is not claimed fixed by the Windows token work.

The fixed authored Mac command groups retain their four-file benchmark hashes
through30. Changing native wall/Mach/birth clocks or silently editing the command
schedule would invalidate this assessment history. The distinct engine-owned
Finder1:2launch subdivision from24 is selected26; exact Mac SSH descendant equal
spacing is selected27candidate. Those owners can be repaired without revising
scenario timing or reviewer examination requirements.

The file-chronology concern is now a qualified28candidate. A bounded native census
found1later-birth case among214uniquehost/process-start/imageobservations: the
sameMAC-MROSS-02launchd, not11independentfiles. The provisioning model samples
installation age independently of already modeled boot facts. A candidate shared
owner repair would condition selected OS-product installation age on canonical
boot, preserve release availability and fixed maximum age support, and leave
third-party/user placement separate. Its contract was written before code; it
must not clamp all metadata to boot or invent restored-file history. No28source
change is claimed here.

RDP duration remains unproved as a defect. Exact reconnects intentionally honor a
shared logical idle_timeout, and hard deadlines also bound transport duration.
The specific887.866second source has not yet been established, so changing the
execute() sampler would be premature. Keep a valid policy timer if it explains
these records. Likewise the SMB mapping is known modeled per-format collection
loss, and Linux cifs-utils/smbclient unit labels originate in frozen authored
services; neither warrants fabricating companions or overriding benchmark input.

| Synthesis priority | Issue / taxonomy | Category | Reviewer original rating | Impact and disposition |
|---|---|---|---|---|
| P1 | Paired transparent opaque-stream budgets; sibling_defect | contract_gap | not labeled | High recurring cross-leg score leverage; verified owner gap, broad paired admission/recovery deferred. |
| P1 | Fixed authored Mac fork phases; exact_regression of existing benchmark limitation | distribution_texture | not labeled | High; source data unchanged25, preserve frozen epoch through30 and test scenario scheduling separately later. |
| P1 | Generated Finder subdivision and exact SSH close interpolation from24 | distribution_texture | not labeled | High bounded owner targets;26Finder generation active,27separate close contract pending. |
| P2 | Installed OS executable/boot chronology; new_family | contract_gap | not labeled | Moderate qualified case; selected28candidate to consume boot truth at provisioning, with restore/metadata alternatives retained. |
| P3 | Repeated RDP duration, daemon proportions, file timestamp coincidences | weak_signal | not labeled | Lower specificity; establish timer/installation/collection semantics first, no arbitrary jitter or filler. |

Categories and priorities are synthesis judgments; reviewers supplied noP0-P4
labels. Strong causal/source-native checks remain positive evidence without being
proof of production provenance. Narrative neatness and mere completeness have no
score weight in this synthesis.

### Quantitative guardrail and score movement

Evaluation passed98.25030082067876 over143703records. The tiny0.0028point change
from24 is within the accepted guardrail and was not optimized. Initial blind mean
54.5 increased4.5from50.0; rolling five46.60. Since105of115files are byte-identical,
including the Mac and network files driving the current high scores, this movement
primarily reflects what fresh reviewers examined; it is not evidence that native
creator/target correction worsened those unchanged families. No A/B score or
revised deliberation score is mixed into this trend.
