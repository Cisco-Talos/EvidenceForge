# New assessment epoch — loop 3

Canonical expanded scenario and existing reviewer instructions are unchanged.
Behavior 536 completes the shared RSA identity/computation work and corrects
independent durable-session observation timing. This bundle is frozen at 536;
behavior 537 changes belong to loop 4.

## Scores

Automated evaluation **PASS 98.5941**, **144,150 records**. Parseability 100,
plausibility 96.8911, causality 99.7544, timing 98.9927, ground truth 97.3324.
No acceptance/parse failure or guardrail breach. JSON was evaluated once; the
human-readable report was rendered from that saved QualityReport.

| Expert | Initial assessment | Verdict confidence | Synthetic-confidence score | Actual deliberation score |
|---|---|---:|---:|---:|
| Threat Hunter | Inconclusive | 78 | 45 | 56 |
| Detection Engineer | Real | 71 | 18 | 46 |
| Network Forensics | Inconclusive | 83 | 47 | 51 |
| Host/EDR Forensics | Inconclusive | 84 | 54 | 57 |
| Mean | | | **41 — mixed/inconclusive** | **52.5 — mixed/inconclusive** |

Lower synthetic-confidence scores are better. Initial mean fell 1.5 points from
loop 2; five-score rolling mean is 46.4167 (n=3). Only independent initial scores
enter trends. No previous-epoch or candidate-trial scores are inherited.

## Individual expert summaries

Threat Hunter verified coherent local/outbound credential separation, Mac/Linux
SSH and transfer pivots. Seven Mac cat reads of office-format filenames were its
main behavioral reservation; narrow discovery and SMB filename vocabularies were
weak signals. It established no impossible operational lifecycle.

Detection Engineer judged the initial slice Real after checking source-native
Windows schemas, clear-event channel reset, process identifiers, native Mac
fork/exec distinctions and TLS-version-dependent certificate visibility. Two
orphan SMB mapping UIDs were explicitly unscored collection caveats. Its initial
18 is separate from confidence 71 and from its subsequent reconsideration.

Network Forensics found convincing proxy DNS/transport timing, separate tunnel
byte scopes, TCP histories and certificate identity. Its main reservation was
an exact population split: all positively SSL-classified SF and S1 observations
have SSL rows, while all reset/half-close/OTH observations lack them. A common
collection/export filter remains a credible alternative to a generator tell.

Host/EDR found coherent Windows and Mac process identities and lifecycle joins.
Twelve editor launches rotating among nano/vim/emacs and repeated project/file
combinations were its distinctive concern. It independently noted the same Mac
cat/document pattern, with storage latency and terminal blocking qualifying the
longer 10–30-second shared-file command durations.

## Deliberation

Verdict differences and a 36-point initial spread triggered the existing
procedure. All four actual reviewers rechecked the network population split and
endpoint examples. Their actual final positions are Inconclusive at 56/46/51/57,
mean 52.5. The Detection Engineer's change reflects a previously untested
availability distribution, not a retraction of its positive field/lifecycle
checks. Original reports and individual responses are preserved verbatim;
collection filters, unknown file contents and unusual workflows remain explicit
alternatives. Facilitator synthesis is retained in deliberation.md.

## Selected families, owners and verification

Both changes are `family_level`; contracts and entry/consumer inventories are in
family-contract.md. SourceTimingPlanner owns occurrence observation and closure
frontiers. A durable session's later dependent maximum no longer delays every
earlier independent lock, unlock or account observation; true login floors,
closure maxima and ordered non-session action groups remain enforced. The
isolated ten-minute example now retains 600.025743 seconds rather than zero.
The rendered nearest-LUID/session lock/unlock pairs span **239.96–1,953.72 s**;
none of those ten descriptive pairs is collapsed to sub-millisecond spacing.
These are nearest pairs, not claims that a LUID uniquely identifies a transition.

The shared RSA owner now preserves full generation-seeded identity width before
prime derivation and memoizes at most 512 immutable public moduli under fixed
64-character scoped digests. It retains no factors/private keys and does not
bypass binding validation. Forced-collision and generation-seed tests, native
RSA validation and cross-registry revalidation cover the family. Provider-owned
registration preserves derived-cache replacement and config-scope protections.
Rendered DKIM probe: **0/8** distinct keys have factors below 10,000; this limited
probe is not proof of primality. Native key-validation tests supply that stronger
mathematical verification. Repeated semantic derivation measured approximately
8 microseconds after first computation in the engineering probe.

Focused validation: source/RSA/registry contracts 179 passed; provider/config
scope controls 118 passed (explicit slow); RSA after cache registration 16 passed;
checkpoint/resume two formats 2 passed; RNG policy 3 passed (explicit slow).
Ruff, formatting and behavior-surface checks passed. The broad routine suite has
not completed; no full-suite or release-readiness pass is claimed.

## Prioritized reported issues

No P0 contradiction was established. Reviewers assigned no P0–P4 labels;
priorities and recurrence classifications below are synthesis, not invented
reviewer ratings.

| Priority | Issue and category | Classification / reviewers / scope | Original rating | Leverage / owner / risk / next action |
|---|---|---|---|---|
| P1 | TCP-state-conditioned application observations; distribution_texture | `new_family`; Network, independently verified by all in deliberation. Three sensor views show 3,531 SF plus 13 S1 SSL observations with companions, versus 0/177 other states. DMZ HTTP has 0/17 non-SF companions. Views overlap and are not independent proof. | not labeled | High/medium; canonical network/application protocol planner. Medium risk: separate actual protocol progress from TCP teardown, retain genuine partial/failed exchanges and wire/time budgets. Verify owner before changing contexts. |
| P2 | Mac shared-document tool binding; distribution_texture | `sibling_defect`; Threat and Host, all rechecked. Seven of nine visible Mac 02 FILE/READ observations are cat of PDF/XLSX/DOCX filenames. Contents and intended task are unknown. | not labeled | Medium; file-access intent, workload/software capability and SMB client bundle. Medium/high qualification risk. Bind task/tool/content deliberately; do not fabricate GUI activity or infer impossible bytes from extensions. |
| P2 | Linux editor/project recombination; distribution_texture | `new_family`; Host, independently rechecked in deliberation. Twelve editor starts among 89 user creations: nano 4, vim 3, emacs 5. No impossible overlap. | not labeled | Medium/low; persistent persona/workspace preferences and command catalog binding. Low/medium risk; preserve occasional alternative tools while reducing independent recombination. |
| P2 | Normalized Mac fork/exec compression; distribution_texture | `sibling_defect`; loop-2 Host, not a new claim by this panel. Root probe still reproduces collapsed short intervals in loop 3. | not labeled | Medium; SourceTimingPlanner collector queues. Verified bounded repair and sibling gates prepared for loop 4, not claimed fixed here. |
| P3 | Shared-file command duration class; weak_signal | `false_positive_or_unproven`; Host and Threat. Cat/ls last roughly 10–30 s. Storage delay, terminal output blocking and file size remain plausible. | not labeled | Low; command/storage lifecycle. Investigate intended duration semantics; no artificial delays or mandatory GUI evidence. |
| P4 | Discovery/SMB filename vocabulary; weak_signal | `false_positive_or_unproven`; Threat. Valid repeated administration and manual SMB names. | not labeled | Low; task/persona and storage vocabulary. No exact-sample renames. |
| P4 | Two orphan SMB mappings; unscored collection caveat | `false_positive_or_unproven`; Detection/Network. No mandatory completeness contract established. | not labeled | Low; source observation/export scope. Do not add rows merely to make coverage complete. |

Earlier Mac foreground/job-control concerns remain a deferred family requiring
shared intent/readiness and native qualification analysis. This panel did not
newly establish them. Earlier ambient TXT onset and snapd texture were not
repeated by this panel; existing root investigations remain engineering leads,
not new score drivers. None is counted as a demonstrated regression here.

## Priority rationale and next pass

The concrete normalized collector-queue correction was independently reproduced
before this panel and is already generating as loop 4 after 634 focused checks.
Next investigate the newly shared application-observation family: the current
planner explicitly gates automatic TLS/HTTP on SF and promotes HTTP-bearing
non-SF transports to SF. This is an owning-model issue, not missingness to patch
in Zeek emitters. Zeek's [SSL source](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/ssl/main.zeek)
logs handshake state at establishment/finalization; it does not require normal
TCP FIN teardown. Applying that to the generated population is an engineering
inference; bytes alone do not prove a specific handshake in the blind export.

## Score movement and quantitative comparison

The small initial decrease and different specialties' coverage are consistent
with reviewer variance plus newly surfaced distribution questions. There is no
rendered evidence that the latest session/RSA change introduced the protocol
partition; The same state-conditioned partition also reproduces in loop 2 (protocol-observation-recurrence.json), so it predates the latest fix. The much
larger deliberation movement reflects sharing previously independent findings
and is kept out of the trend. Quantitative evaluation catches structure and
causality but did not flag the application-availability or tool-choice texture.

## Provenance

Behavior 536, digest 4dd6e317d777219f5267469f7313799c88ef9dd802ea9aceb4e98e5daa815e6b,
seed 42. All four authored hashes match loop 1, so its zero-error/eight-warning
validation applies. Generation exited 0 with an authoritative manifest. Neutral
study `/private/tmp/authenticity-study-7gx1si3a` contains only verified data copies;
four fresh fork-none reviewers received unchanged briefing/persona hashes and
no fix hints, prior reports, scenario, ground truth or engine context.
