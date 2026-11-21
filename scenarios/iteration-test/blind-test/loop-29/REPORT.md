# Loop 29 — standalone blind realism assessment

Epoch2026-11-20-realism. Actual loop29 of30, canonical approved expanded scenario. Prior epochs and the exploratory candidate are excluded. Four authored hashes remain fixed; reviewer instructions are unchanged.

## Scores

| Reviewer | Initial verdict | Verdict confidence | Initial synthetic-confidence |
|---|---|---:|---:|
| Threat Hunter | Real | 65 | 28 |
| Detection Engineer | Inconclusive | 82 | 44 |
| Network Forensics | Inconclusive | 82 | 57 |
| Host/EDR Forensics | Synthetic | 80 | 64 |

Initial mean **48.25/100** (mixed/inconclusive); lower is more production-like. Previous loop 45.50, delta +2.75; five-loop rolling mean **46.55**. Only independent initial synthetic-confidence scores enter the trend; verdict confidence and deliberation are separate measurements.

Actual four-way deliberation was triggered: Initial verdict/confidence/spread trigger. Actual revised synthetic-confidence scores: 58, 63, 65, 68; mean **63.50**. Fresh facilitator summary and each actual response are preserved separately. No revised positions or agreement were invented.

Automated eval **98.2503008207/100**, PASS, 143,703 records. JSON evaluated once; readable text derives from the same report. Parse/acceptance, score>90 and recent-median−2 guardrails passed; small movements were not optimization targets.

## Family selection, evidence and next priorities

### Selected family and corrected owner hypothesis

26's network reviewer found99browser transactions from99external clients
concentrated in three Windows browser strings(36/33/30), with two additional
crawler requests. A curated audience, spoofing or a specialized portal remain
credible alternatives: a public client population is not required to contain a
particular OS mix. The actionable engine policy was its implicit Windows default
when a source host is unknown and no header was supplied.

Qualification initially blamed normalization of an already selected browser
header. That hypothesis was rejected before production changes: the actual
normalizer returns unknown-source selected headers unchanged, and a real
ActivityGenerator boundary preserved the selected Mac presentation. Three spy
failures imposed an unnecessary call restriction and did not prove a production
bug. Their rejected source/logs and patch are retained separately. No baseline,
normalizer or traffic-affinity patch was applied.

Actual default selectors pick_proxy_user_agent and browser_user_agent_for_process
both assumed a Windows workstation pool for source_system=None. They now share
one stateless pool adapter and an optional validated unknown_source profile.
Seven existing modeled catalog strings supply generic client presentations;
these are not new release/version facts or measured audience shares. Known-host
OS/server/domain/package selection stays under its existing owner. Selected wire
headers and intentionally absent headers remain authoritative upstream; the same
canonical HttpContext feeds relevant network/web/proxy consumers.

The optional profile has bounded, single-line validated header values, runtime
ConfigurationError for a selected malformed profile, validate-config coverage
and partial-overlay shape support. Frozen catalogs without the profile retain
the old Windows fallback. No new State/cache/quota, raw timing sampler, arbitrary
browser version, emitter-local header rewrite or authored UA override was added.
This is a bounded family-level default-policy repair, not a full empirical model
of an external client population or a claim to remove all synthetic texture.

### Focused verification before full generation

Two actual default-selector before-controls failed while four legacy/selected
header controls passed1.22s. A separate real ActivityGenerator unspecified-header
control also failed1.22s; real frozen-catalog compatibility passed1.84s. These
replaced the rejected normalizer spy tests with actual policy/output controls.

After implementation230focused tests passed15.40s(two unrelated slow cases
deselected). Twelve new cases cover both default selectors, actual generator
boundary, real frozen configuration, explicit Mac/Windows/crawler presentations
and malformed runtime/config policies. Existing stable external population,
explicit proxy, known OS/server/domain/package, request-header owner, web profile,
affinity and browser-session siblings also passed. A216-case known-host/role/
destination/seed census of default and Chrome-family selections was byte-identical
to566. RNG3passed7.43s with unchanged census; config105files had zero issues;
manifest27passed2.73s; whole-tree Ruff check and1690-file format check passed.
No full routine or full slow suite is claimed.

The behavior-change description initially exceeded its240-character metadata
bound; it was shortened before the successful567manifest stamp. No generation
ran against a stale behavior digest. Production output risk is localized to the
optional unknown-source default policy, with downstream deterministic sampling
changes assessed through the complete regenerated bundle rather than assumed
source isolation.

### Actual native output and independent review

Actual generation and postprocessing exited0. Eval98.25030082067876passed acceptance
on143703records. The single-sensor external census remains101transactions from
99source IPs, including two unchanged AhrefsBot headers. Ninety-nine browser
transactions now use all seven configured strings in counts11/12/16/11/15/20/14.
The distribution is descriptive, not an inferred audience composition or a rule
that every real client population must have this diversity.

Only five of115data files changed from28: WEB-EXT web_access, perimeter Cisco ASA,
and DMZ Zeek conn/files/http.110other files are byte-identical. Different header
lengths and the source-scoped default selection can affect canonical wire bytes
and their dependent views; this is not a source-native string replacement with
inconsistent sibling accounting. Known-host/Mac source bytes are unchanged.

The HTTP/1.1 inversion persists in the exact same core/DMZ physical conversation,
with81.058ms/73.716ms first-seen reversal. Twenty-two physical multi-request
conversations are observed44times across the two sensors; two copies of this
finding do not mean two physical faults. Mac chronology remains zero later births
among214unique observations; Finder/SSH phase and Windows creator/token probes
continue to pass their bounded checks.

The previously verified HTTP response-order and paired opaque CONNECT budget
families remain open; this header policy change does not repair either. The four actual reports and deliberation are complete, described below.

### Four original independent positions and actual deliberation

ThreatHunter: Real, verdict confidence65, synthetic28. Endpoint and cross-source
SSH/download/upload pivots held, with only weak repeated Mac diagnostic vocabulary.
Its original inventory reversed Windows/Linux totals; its actual deliberation
corrected this to ten Windows, eleven Linux and two Macs. The original report and
scores remain preserved rather than silently rewritten.

DetectionEngineer: Inconclusive, confidence82, synthetic44. Windows/eCAR process
identity and lifecycle checks held. It questioned all41Event4658Version0records
for containing ProcessName, one unmatched SMB mapping and coincident four-host
4688totals. The Windows field-presence allegation is a root-verified false
positive: Microsoft's official Version0Event4658XML explicitly contains
ProcessName. This does not certify every value or all Windows schema details,
but field presence alone is not a defect. Do not remove the valid field.
[Microsoft Event4658reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4658).
Original reports and actual expert scores are unadjusted; no numerical correction
can be inferred from an expert's unreported internal weighting.

NetworkForensics: Inconclusive, confidence82, synthetic57. It independently
rediscovered paired explicitly opaque CONNECT accounting differences. It matched
541successful tunnels under its bounded unique-SNI/tuple/time procedure;304pairs
had no reported gaps or retransmission flags, and56had nonzero upstream versus
tunnel stream differences(31origin only,23response only,2both). Associations are
inferred cross-leg matches, not a shared cross-leg UID or packet capture proof.
Concrete examples reproduce earlier controlled root findings, including
registry.npmjs.org response757/2291tunnel bytes versus757/3684upstream stream,
and the widget.mixpanel.io originating-byte difference. Framing/TLS floors and
source closure/accounting alternatives stay explicit; this is one known family,
not56independent engine faults. General DNS/TLS/protocol accounting otherwise held.

Host/EDR: Synthetic, confidence80, synthetic64. It discovered eight Dovecot
positive-body-byte/zero-body-count summaries among19. Root independently reproduced
all8and the shared projection's independently sampled count. Official Dovecot
logout documentation supports the conventional count/data interpretation;
custom field mappings and software counter bugs remain real-world alternatives.
It also measured all927matched native Windows creation pairs with Security after
Sysmon by35.164–641.797ms(mean177.783ms). A common instrumentation/collection policy
is a plausible explanation; native source timestamp calibration needs empirical
proof before changing a shared phase model. Repeated irqbalance phrases were weak.
[Dovecot logout counter definitions](https://doc.dovecot.org/latest/core/summaries/settings.html#imap-logout-format).

All four actual deliberation responders rechecked the new Dovecot rows, selected
tunnel pairs and native Windows timing. Revised scores58/63/65/68, mean63.50;
threat hunter remained Inconclusive while detection/network/host were Synthetic.
The fresh facilitator preserved that disagreement and actual alternatives. Some
responses repeated the4658field-presence allegation; the root correction above is
kept separate rather than inventing expert revisions or changing the briefing.
Initial mean48.25(mixed/inconclusive)remains the trend input; rolling five46.55.

### Final-loop change of direction and remaining priorities

The initially planned confirmatory30generation under unchanged567had already
started before29's reports arrived. New concrete Dovecot evidence offers a bounded
native repair, so the plan changed: let the567diagnostic generation/post finish
with source frozen, preserve it unreviewed/separate, then repair and regenerate
final30under568. Only the corrected final bundle receives a fresh full panel;
the diagnostic run is neither a failed generation nor a scored assessment.

Classification for the30candidate is source_native_single_schema, explicitly a
bounded Dovecot application-summary projection rather than a full canonical IMAP
FETCH model. The owner consumes the exact committed transport and message intent.
Condition a zero sampled count on positive body data using existing positive
message-count support, allowing counted empty/partial fetches. Do not clamp count
to one, change transport bytes, invent FETCH rows, or patch one host/emitter.
Corrected owner controls2FAIL46PASS1.24s and native8/19beforecensus qualify this
repair. An initially too-strict count/byte biconditional control was rejected and
retained separately; it does not establish32real defects. No implementation is
claimed until the active567generation/post has exited0.

| Synthesis priority | Issue / taxonomy | Category | Reviewer original rating | Impact and disposition |
|---|---|---|---|---|
| P1 | Paired opaque CONNECT stream budgets; sibling_defect | contract_gap | not labeled | Repeated root and fresh reviewer evidence. Shared paired-precommit/TLS/recovery architecture still deferred. |
| P1 | HTTP/1.1 response order from27; sibling_defect | hard_contradiction | not labeled | Exact same mirrored conversation remains positive in native probe; not rediscovered by this initial panel. Shared response-phase architecture open. |
| P1 | Dovecot positive body data with zero mail count; new_family | schema_or_format | not labeled | Eight of19summaries and corrected direct-owner failures. Bounded native-projection repair selected30. |
| P1 | Fixed authored Mac command fractions; recurring benchmark limitation | distribution_texture | not labeled | Established in earlier actual panels, not this initial panel's main indicator. Preserve four hashes/native clocks through30. |
| P2 | Native Windows creation source ordering; new_family | distribution_texture | not labeled | Moderate, qualified by shared provider/collection policy. Requires native timing calibration, no arbitrary source-order randomization. |
| P3 | SMB mapping reference, coincident counts and daemon vocabulary | contract_gap / weak_signal | not labeled | Known format-specific loss explains mapping; shared procedures/sampling can explain counts. No fake row or filler. |
| Rejected | Event4658Version0ProcessName presence | false_positive_or_unproven | not labeled | Official Microsoft XML includes it. Keep field and original scores; exclude from product-fix recommendations. |

Priorities/categories are root synthesis, not original reviewer severity labels.
NoP0-P4ratings were supplied. Domain resolvability, narrative compactness, optional
coverage absence and mere complete correlations are excluded. Focused checks
verify a repair contract, not an overall production-authenticity pass.


## Run provenance and limits

generation-status.json: actual EXIT0, finished 2026-11-21T13:53:45.176192+00:00.
post-generation-status.json: actual EXIT0, finished 2026-11-21T13:55:30.069868+00:00.

Generation behavior revision567, digest `c56d1cf3c8a8a4fec2a03522925083436552d676941dc3373b3dfb8c4939a184`, seed42/default, git HEAD `b1c7839389515b50a44ab3f91a23f0943f92f4e0` with authorized uncommitted fixes. No product version bump or publication. The immutable per-run manifest is authoritative.

Four authored SHA256 values:

- `scenario.yaml`: `ccd1b117736c9a8e6a4c2a94bfd860113e115d5b414f710ee2f730ccccd5ea5b`
- `environment.yaml`: `05f421a6bca7557c4f86230dfdd40a71cdfda0afbc4d626209a42eed149e59f6`
- `baseline_activity.yaml`: `26349715dfc21e990af889c2af2eadc609b0b7619d356c75f575fe7aa4b60861`
- `email_corpus.yaml`: `0d7429209923c521556e93f84c6e028745e027849b54ac5c820837a562cf3002`


The panel used a fresh neutral data-only SHA-verified copy and four fresh independent reviewers. No scenario, environment briefing, ground truth, evaluator, source code, prior assessments or selected-fix focus was supplied. Logs were treated as untrusted. Complete source matching and missing out-of-window initiators alone were not authenticity penalties. No narrative-design impressions enter this synthesis. Passing focused contracts is verification of a repair, not evidence that the dataset is indistinguishable from production.

Focused validation recorded for this loop:

```json
{
  "before": "Actual selectors default to Windows for an unknown host even when a generic presentation profile is configured: two real selector controls FAIL, four selected-header/legacy controls PASS1.22s. Real ActivityGenerator unspecified-header control also FAILS1.22s. Selected explicit Mac/Windows/bot headers already survive: the initial normalizer hypothesis and spy controls were rejected and retained separately. Native26 census99browser transactions/3Windowsstrings36/33/30 is qualified distribution evidence, not a mandatory OS audience mix.",
  "scope": "Optional validated unknown_source profile reuses seven existing catalog strings; one stateless adapter serves default picker and browser-family picker. Known OS/server/domain/package behavior, selected/absent headers and old frozen catalogs retain existing policy. Canonical HttpContext remains the shared wire-header owner. No baseline/normalizer/traffic-affinity change, invented browser version, audience-share claim, new State/cache/quota/raw timing RNG or authored UA override.",
  "after": "230focused tests PASS2deselected15.40s, including12new real-selector/runtime/config/frozen-catalog/selected-header controls, stable external population, explicit proxy, known-OS/domain/package/role, canonical request-header, web profiles, affinities and browser siblings.",
  "known_host_parity": "216known host/role/destination/seed cases, default and Chrome-family picks BYTEIDENTICAL to566.",
  "rng": "3slow global timing RNG policy tests PASS7.43s, census unchanged.",
  "config": "105files0errors0warnings.",
  "manifest": "27manifest tests PASS2.73s. Initial behavior-change description exceeded240characters; shortened before successful567stamp, no generation under stale manifest.",
  "ruff": "Whole-tree check PASS;1690files format check PASS."
}
```

No full routine, slow-release, soak or packaging acceptance is claimed unless explicitly identified above. Authored command phases and native birth/wall/Mach truth were not jittered to improve scores. Deferred architectural findings remain open; no quota/census/retention limits or reviewer requirements were relaxed.
