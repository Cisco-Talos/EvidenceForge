# New assessment epoch — loop 15

The unchanged canonical scenario was generated with behavior549. This loop repairs
shared TLS first-detection timing and the current Windows5140 header version.
The four original authored files and reviewer examination instructions are unchanged.

## Scores and review

Automated evaluation passed:98.29003492968762,138536records, all acceptance and
dynamic guardrails. JSON was computed once and the text report derived from it.
Four fresh independent experts reviewed116SHA-verified data-only files without
code, scenario, ground truth, earlier results or targeted prompts.

| Expert | Initial verdict | Verdict confidence | Initial synthetic-confidence score | Actual revised score |
|---|---|---:|---:|---:|
| Threat Hunter | Real |64|31|62|
| Detection Engineer | Inconclusive |80|32|62|
| Network Forensics | Real |65|32|61|
| Host/EDR | Synthetic |80|64|60|
| Mean | | | **39.75—mostly realistic** | **61.25—likely synthetic** |

Lower synthetic-confidence is better. The initial mean improved12.75from14; rolling
five-loop mean48.15. This standalone comparison does not isolate the causal effect
of either repair. Deliberation followed verdict disagreement and score spread33:
all four actual reconsiderations, then a fresh facilitator, are retained verbatim.
All final verdicts are Synthetic with confidence77/76/75/76, although Host's60is
still in the mixed band. Only initial scores enter trends.

The main reweighted finding is localized native Mac fork-time texture. Each of two
Macs has a triple of different child forks preserving exactly one microsecond
fraction over whole-second command intervals. Fork/exec identities, varied exec
fractions and monotonic-clock increments corroborate the same pattern; these are
not independent defects. All four reconsidering experts confirm the rows. They
retain replay, reconstruction, sanitization and selection alternatives and do not
claim a kernel/schema impossibility or assign a formal collision probability.

The original Host review also cited seven binary-document cat reads and narrow
Linux irqbalance/snapd grammar. Cross-examination reduces their weight: terminal
inspection, scripts and verbosity are possible. Named endpoint-inventory xpcproxy
lineage explains repeated sw_vers invocations, so this is not missing ownership.
A history-only gzip command does not prove successful execution or a mandatory
missing companion; Threat withdraws its scoring contribution. ICMP payload-size
variation and short MySQL sessions remain qualified weak texture, with diagnostic
and non-pooled application alternatives. No new hard contradiction is established.

## Family repair and rendered proof

Primary classification:family_level. NetworkTransactionPlanner owns one canonical
TLS first-detection phase in existing NetworkTransactionPlan.phase_times. The
phase is chosen once after HTTP request time is known, bounded by transport close
and request time; HTTP children inherit it. SSL-only generic application-request
uses this phase, while SMTP plaintext request semantics remain distinct. Each
sensor projects that same fact through its existing source clock and route offset.
An emitter does not independently invent TLS detection latency.

The strict optional network_params.tls_detection_phase policy uses required finite
minimum/median/maximum/sigma, sampled through TimingRuntime. The new default3–650ms,
median119.46ms/sigma.78, preserves the former modeled marginal support; it is not
empirical calibration. Missing whole policy in an old frozen snapshot preserves
legacy/no-phase behavior; malformed present policy rejects. Partial overlay merge,
loader, named validator, shape schema and reference documentation agree. Explicit
legacy/raw occurrences without the phase retain their compatibility projection.
No new trust fields, cache, runtime ceiling or nonconforming continuous RNG call.

Entry inventory covers standard baseline/storyline transports, HTTP/browser/
download, proxy egress, IMAPS and SMTP upgrade paths. Distinct physical proxy legs
retain distinct phases. Consumers include Zeek SSL/X.509/files/HTTP/OCSP/PE and
source preparation/replay/filtering. This models first detection, not full packet-
level cryptographic handshake execution. The family contract records short/reset/
negative-flow and legacy sibling risks.

Actual native data probe:61unambiguous matching TLS sensor pairs,55same-counter/
state/zero-reported-loss controls. Before:26controls differ by>100ms, max588.515ms;
after:0differ by>50or100ms, max4microseconds. Decimal timestamps preserve native
precision. Equal aggregate counters do not establish identical packet capture;
this is a bounded physical-phase consistency check, not origin proof.

Secondary classification:source_native_single_schema. The authoritative Windows
format YAML now declares5140Version1for its supported modern AccessMask/AccessList
payload;5145remainsVersion0. The same source binds normal and exact renderers.
This is isolated header/payload consistency, not a generic event-version change or
a claim that every historical5140Version0record is invalid. Microsoft's current
example XML supports the chosen shape, despite the older prose version list.
Actual output:105of1055140recordsVersion1;55of555145recordsVersion0.

Primary references:
- [Zeek SSL first-detection timestamp](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html).
- [Microsoft5140 example XML](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140).

## Qualification

Meaningful before failures:7provided-phase projection cases,1actual native standard
IMAPS root missing the phase, and2normal/exact5140render cases;5145siblings passed.
Isolated prototypes were qualified separately, before production changes.
Production gates:46central21.98s;176network/HTTP/prepared/timing/OCSP30.66s;
63source-preparation/budget/RNG15.98s;20frozen/config/overlay cases2.28s;
25proxy/SMTP/mail59.30s;2checkpoint106.75s;105configuration files0issues;
Ruff check/format1660files pass. Counts overlap. No full routine or release gate
is claimed. Successful generation and post-processing exited0before16source edits.

## Remaining findings and next priorities

Priorities/categories are synthesis; reviewers gave no P0–P4labels.

| Priority | Finding | Category / classification | Owner, leverage, risk and action |
|---|---|---|---|
|P1|Mac exact fractional fork groups|distribution_texture / carried sibling_defect|All four after cross-examination. High leverage; high canonical/native timing risk. Investigate command intent versus actual execution planning, preserve authoritative birth/fork/exec/wall/monotonic relationships. Cosmetic source jitter or silent scenario retiming is not a repair.|
|P2|Automatic binary-document cat/tee population|environment_or_collection_plausibility / recurring sibling_defect|Shared SMB operation profile and baseline task selection. Medium leverage/risk;16qualified task/file eligibility is now generating. Explicit binary operations remain valid.|
|P2|Policy-share generic layout/name population|distribution_texture / carried new_family|14Threat, compiler/catalog of well-known SYSVOL/NETLOGON. Purpose-aware domain/GPO layout needs primary-source, explicit-seed, finite-capacity and replication/alias qualification before selection. Not rediscovered here; not fixed.|
|P2|Compact Mac identity populations|distribution_texture / carried new_family|14Host, State boot/process counter and installed filesystem registry. High implementation risk; verify native semantics and hidden population before changing allocation. No random offsets.|
|P3|ICMP size variation / MySQL short connection churn|weak_signal / new_family|15Network. Diagnostic tools and non-pooled clients remain plausible. Inspect owning client/action models before changing distributions; not verified hard defects.|
|P3|Linux maintenance grammar/prominence|environment_or_collection_plausibility / new_family|15Host initially, substantially downweighted. Inspect daemon state and verbosity binding, not arbitrary noise. Collection policy unknown.|
|P4|gzip history/endpoint gap|weak_signal / false_positive_or_unproven|History alone proves neither execution nor success; explicit scoring withdrawal retained. Do not invent required capture or count as broken lifecycle.|

Cross-sensor TLS and current5140shape are verified repairs. The score shift and
later deliberation reflect which older issues reviewers discovered and reweighted;
they do not show a new TLS regression or an authenticity pass. All scenario inputs,
seed42, default target and technology1.0.0pack remain fixed.

## Provenance

Behavior549,digest8e19c9839304eb1a56f91ba78f393626bd327a20bf795d7da7bd0d7071681d89.
Study/private/tmp/authenticity-study-0baaxvty,116files. Fresh epoch only; no scores
inherited from previous/candidate histories. User-requested total30,16generating.
Old scenario YAML remains preserved; prior obsolete artifacts were removed separately.
