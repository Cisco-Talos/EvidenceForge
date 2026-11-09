# Mac-series loop67: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop4 of5 (64–68). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **96.5099**, 135,285 records. Hard acceptance status **PASS**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat63 / Detection38 / Network55 / Host46**, mean **50.50** (mixed/inconclusive); lower is more production-like. Prior mean53.00; current rolling5 **50.05**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **57.00**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Family repairs and verification

HTTP resource sizes and file content seeds now share origin/path ownership by default;
only explicitly configured shared content crosses origin boundaries. The existing Inter
font is declared as one modeled shared resource. Default favicon/logo/CSS resources are
site-owned, repeat retrieval remains stable, URI path case and dynamic query identity
are retained, and proxy client/origin content pairing consumes the same identity.
Explicit supplied content identities survive proxy context construction. This fixes
the content owner, not renderer-local randomized sizes or hashes.

A second primary-qualified repair composes Windows failure status, substatus and native
resource reason as one canonical typed condition. Microsoft4625defines FailureReason
as text describing mainStatus and pairs2307withlockout in its official example. The
old disabled branch combined generic006dstatus, disabled0072substatus andlocked2307
reason. It now retains generic2313reason plus the specific substatus; eCAR normalization
continues to distinguish disabled/unknown/password by numeric condition. Resource-only
fallback2307nowmeanslocked, notdisabled; generic2313doesnotbyitselfprovebadpassword.
No account state, SID, cadence, RNG or intended failure outcome is invented.

Fresh135,285records/119files pass96.509863 andhardacceptance.47favicon hosts have47
sizes;8logo hosts8sizes.4sharedfont hosts keep1size. Source content hashes are not
available for these sampled assets, so rendered proof is size/ownership consistency;
focused tests separately prove canonical shared versus site content seeds. All20
native Windows failures have consistent main status/reason, with3disabled substatuses
still normalized asdisabled.187content/native checks and190family-producer/proxy
checks pass (overlap), plus101configfiles andRuff. PID0reversals across209allocations,
113eCAR/nativeexecpairs, complete nativecensus/mountedexits,0browser-family mismatches
across802joins, and0HTTPcapturebudget defects across501qualified entities remain.
All nine carried repair probes pass. Changed content sizing shifts subsequent work;
unchanged six authored files/seed are verified, not a claim of a byte-only paired trial.

## Blind findings, movement and priorities

Initial63/38/55/46 mean50.50 is down2.50from66. Threat andHost independently report
one repeated96second editor cadence; their views are two investigations of the same
behavior, not two distinct defects. Network finds UDP state lifetime/optional-duration
issues. Native process identities and source distinctions remain strong in all reports.
The panel did not revisit MySQL, but coordinator19failed prerequisite observations
remain on67; silence is not evidence against the carriedP0. OriginalP0–P4labels are
not assigned by reviewers; priorities below are coordinator synthesis.

| Priority | Finding/category | Reviewer original rating | Scope/leverage/owner/risk | Disposition |
|---|---|---|---|---|
| P0 | MySQL confirmation prerequisites; hard_contradiction |66Network: not labeled |Repeated63–67; high; canonical protocol finalization; low-medium | Verified taggedZeek8.0.5 source and current19bad observations; select68. Keep data/history, do not fabricate greeting bytes. |
| P1 |96second interactive cadence; distribution_texture | Threat/Host: not labeled |10of16gaps near96s, one developer; high; task/workflow timing; medium | Repeated across66/67, strongest independently noticed current family. Scripted/timed real-workflow alternative stays explicit. |
| P1 | UDP firewall state expiry and Zeek duration; contract_gap/schema_or_format | Network: not labeled |11matched ASA flows,283oneway S0observations/200multipacket; high; source state/time and native optional fields; medium | New family. Source inspection finds datagram teardown83–8500us after application close, rather than an idle timer. Qualify DNS inspection, exceptional removal and exporter policy. |
| P1 | Mac inode lexical allocation; distribution_texture |64Host: not labeled |Two inventories,26/32paths; medium-high; canonical installed filesystem; low-medium | Currentmetadata probe confirms0lexical inversions and13/10birth-order inversions. Select68using existing modeled birth chronology. |
| P1 | Windows SMSS ownership, browser singleton, logind numbering; contract_gap/distribution_texture | Earlier specialists: not labeled |Repeated; high; session/application/identity owners; high | Carry qualified evidence; require dedicated lifecycle contracts. No scenario edits or fabricated unsupported native launch families. |
| P2 | Windows handle-use/request source order; contract_gap | Detection: not labeled |1of44groups,11.7488ms; low-medium; object action/source timing; medium | Qualified new lead. Different writer threads/asynchronous reporting remain plausible; verify semantic times before changing observations. |
| P2 | Mac nonbrowser/mobile headers, slow utilities and closure fences; weak_signal/contract_gap | Prior specialists: not labeled |Repeated owners/outlier/fences; medium; application and process lifecycle; medium | Known browser-family repair remains0;44Zoom-owned browser headers remain separate. Preserve intentional override/blocking alternatives. |
| P3 | thermald/irqbalance/snapd texture; distribution_texture/weak_signal | Detection: not labeled |Small messages pools andsamePID initialization text; low; daemon state/collection; medium | Do not add arbitrary noise; confirm selected release/lifecycle and task IDs. Missing optional files references are unproven/neutral. |

Fresh facilitator models66/49/60/53 mean57.00, explicitly hypothetical andexcluded
from initial/rolling trends. It retains the actual2Synthetic/2Inconclusive split.
Evaluation remains a guardrail; it misses activity cadence and source-state lifetimes.
Baseline-volume warning remains user-deferredP1 without changing benchmark intensity.


## Independent reviewer summaries

**Threat Hunter:** Synthetic; verdict confidence 77; synthetic-confidence score 63. The telemetry supports useful, technically coherent hunts across Windows, Linux, macOS, network sensors, and a proxy. I lean synthetic because a sustained interactive development session repeatedly advances on an approximately 96-second grid despite changing commands, editors, files, and command runtimes. This is a distribution finding, not a demonstrated impossible intrusion lifecycle; the otherwise strong operational correlations keep the score near the bottom of the “likely synthetic” band.

**Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 38. The supplied records are mostly production-like and should ingest and correlate successfully in a detection stack; I did not establish a decisive source-native impossibility or identity leak. One Windows file-handle sequence has a small within-source ordering inversion, and some Linux daemon diagnostics have repetitive texture, but neither outweighs the extensive coherent process, authentication, network and protocol evidence enough to classify the origin confidently.

**Network Forensics:** Synthetic; verdict confidence 76; synthetic-confidence score 55. The network data is substantially production-like: protocol-specific byte accounting, proxy behavior, TLS visibility, DNS variety, and independent sensor identities withstand detailed checks. My synthetic verdict rests on a narrower problem: one-way UDP syslog traffic repeatedly receives immediate firewall state deletion, while the corresponding Zeek flows systematically lose duration information. These are meaningful source-lifecycle and field-shape concerns, but they do not justify an assertion of pervasive impossible traffic or near-certain synthetic origin.

**Host Forensics:** Inconclusive; verdict confidence 83; synthetic-confidence score 46. The endpoint evidence is substantially production-like: process identities, visible lifetimes, Windows process cross-references, and macOS fork/exec transitions withstand direct checks. A conspicuous approximately 96-second cadence in one developer's varied editing activity is a concrete synthetic-looking distribution artifact, but I did not establish an impossible same-identity lifecycle or a native-format contradiction sufficient to decide the dataset's origin.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 58 | 95.51 | 38 | 28 | 48 | 57 | 42.75 | mixed/inconclusive | 48.50 | 56.20 |
| 59 | 95.51 | 52 | 81 | 35 | 76 | 61.00 | likely synthetic | 69.75 | 53.60 |
| 60 | 95.96 | 29 | 81 | 38 | 32 | 45.00 | mixed/inconclusive | 71.25 | 51.90 |
| 61 | 96.56 | 68 | 46 | 24 | 83 | 55.25 | mixed/inconclusive | 76.00 | 52.05 |
| 62 | 96.79 | 49 | 81 | 72 | 84 | 71.50 | likely synthetic | 79.50 | 55.10 |
| 63 | 96.79 | 65 | 72 | 27 | 82 | 61.50 | likely synthetic | 66.25 | 58.85 |
| 64 | 96.79 | 43 | 28 | 25 | 64 | 40.00 | mostly realistic | 49.75 | 54.65 |
| 65 | 96.64 | 27 | 67 | 20 | 67 | 45.25 | mixed/inconclusive | 62.25 | 54.70 |
| 66 | 96.29 | 39 | 42 | 76 | 55 | 53.00 | mixed/inconclusive | 65.75 | 54.25 |
| 67 | 96.51 | 63 | 38 | 55 | 46 | 50.50 | mixed/inconclusive | 57.00 | 50.05 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after68; historical43 and63 dashboards are preserved.
