# New assessment epoch — loop 2

Unchanged canonical scenario and reviewer instructions. Behavior 535 repairs
implicit machine TGT reuse and shared RSA public-material mathematics. This
loop's bundle remains frozen at 535; later engineering changes belong to loop 3.

## Scores and change

Automated evaluation **PASS 98.2157**, 144,034 records. Parseability 100,
plausibility 96.8639, causality 99.6001, timing 97.5692, ground truth 97.0453.
The 0.3117 overall decrease stays above the automated guardrail, with no
parse/acceptance failure. This is not an eval-score optimization pass.

| Expert | Initial verdict | Verdict confidence | Synthetic-confidence score | Actual deliberation score |
|---|---|---:|---:|---:|
| Threat Hunter | Inconclusive | 86 | 45 | 54 |
| Detection Engineer | Inconclusive | 80 | 33 | 51 |
| Network Forensics | Real | 62 | 29 | 43 |
| Host/EDR Forensics | Synthetic | 77 | 63 | 56 |
| Mean | | | **42.5 — mixed/inconclusive** | **51 — mixed/inconclusive** |

Lower synthetic-confidence scores are better. Initial mean decreased 13.25
points from loop 1; five-score rolling mean is 49.125 (n=2). Only initial scores
contribute to trends. No prior epoch/candidate scores are included.

## Individual expert summaries

Threat Hunter found coherent mixed-fleet hunting and transfer pivots, with seven
Mac binary-document cat commands as a modest behavioral reservation. No
impossible lifecycle was established. Initial score 45, verdict confidence 86.

Detection Engineer found convincing schemas and checked process/network joins.
Repeated snapd package/message vocabulary across several Linux server roles was
a limited texture concern; generic Windows version resources remained weak.
Initial score 33, verdict confidence 80.

Network Forensics found coherent protocol, byte, certificate, proxy and firewall
relationships, including 13,466 checked protocol observations. Its sole scored
reservation was the late multi-host ordinary TXT onset. Initial score 29,
verdict confidence 62.

Host/EDR identified overlapping Mac SSH/local commands from the same local shell
and inherited terminal process group, plus near-uniform normalized fork/first
exec spacing compared with varied native ES spacing. Unknown job-control and
collection semantics limit the inference. Initial score 63, confidence 77.

## Deliberation

Different verdicts and a 34-point score spread triggered the existing procedure.
Actual final positions were 54/51/43/56, all Inconclusive, mean 51. Reviewers
reproduced the Mac shell/SSH overlap, including network transport intervals, but
qualified unobserved MONITOR settings, suspension/escape state and collection
semantics. No impossible native event was declared. Original reports and actual
individual responses remain verbatim; the facilitator did not invent votes.

## Selected families, implementation and verification

Both changes are `family_level`; baseline/domain-logon callers adapt into the
shared Kerberos/DC owner. Full contracts and entry/consumer inventories are in
family-contract.md and rsa-family-contract.md.

- Machine TGT: implicit baseline AS cycles and machine/domain-logon exchanges
  consult the shared ticket cache before choosing transport/audit intent. A
  valid machine TGT is reused, expiry requests a new exchange, and explicit
  forced TGT/pair requests remain intact. The rendered probe counts **41 fresh
  TGT audits versus 798 in loop 1**; ordinary Windows machine principals now
  have zero to three visible fresh TGTs over six hours. TGS audits remain 1,998.
  This does not claim service-ticket caching or a new per-LUID/realm-wide model.
- RSA: the shared public-key builder derives independently scoped large probable
  primes rather than wrapping arbitrary odd bytes as a modulus. This covers
  DKIM and certificate public material. The new dataset has **zero of nine**
  distinct DKIM keys with factors below 10,000 (loop 1: nine of twelve). Native
  RSA validation tests independently validate actual generated factors at
  2048/3072/4096 bits; the small-factor probe alone is not proof of full validity.

Focused Kerberos/sibling validation: 739 passed. RSA/registry validation: 60
passed. Ruff, formatting and behavior-digest checks passed. The initial broad
routine run was interrupted after 114 passed and two early checkpoint-smoke
failures; it is not a full-suite pass. Both smoke cases passed separately after
the manifest-summary correction. Broad validation will rerun after the RSA
computation cost is addressed.

The RSA family is **partial** at broader registry scope: an engineering probe
found a 32-bit seed collision between two distinct identities at 60,511 tested
identities, producing the same prime stream. This is not claimed as a defect
observed in this small generated dataset. Repeated canonical binding checks also
recompute expensive keys. Loop 3 must retain full scoped identity width and a
bounded immutable public-computation memo without weakening binding validation.

## Prioritized reported issues

No P0 contradiction was established. Reviewers supplied no P0–P4 labels; the
priorities below are synthesis ratings.

| Priority | Issue/category | Classification, reviewers and scope | Original rating | Leverage / owner / risk |
|---|---|---|---|---|
| P1 | Mac terminal job ownership/concurrency; contract_gap with caveats | `new_family`; Host, rechecked by all during deliberation. Both Macs show same-shell overlapping SSH/local commands and inherited groups; foreground state and shell settings are unobserved. | not labeled | High/medium; POSIX shell/job-control and SSH/process bundles. Medium/high risk: verify intended foreground/background state and qualification before changing snapshots or histories. |
| P1 | Durable-session source frontier compresses lock interval; distribution_texture in the earlier panel | `sibling_defect`; loop 1 Detection/Host, independently reproduced in an isolated source-planner probe. A ten-minute canonical interval becomes zero after unrelated later session activity; account audit is a sibling. Not newly claimed by this panel. | not labeled | High owner confidence; SourceTimingPlanner. Bounded correction prepared for loop 3, preserving login/closure and ordered transport groups. |
| P2 | Mac normalized fork/exec compression; distribution_texture | `sibling_defect`; Host. 93/94 visible eCAR first-exec gaps are 1–5 ms while native ES varies about 1–142 ms. Ingestion/normalization semantics remain an alternative. | not labeled | Medium; canonical execution/source timing. Investigate semantics before adding arbitrary jitter. |
| P2 | Shared snapd package/message texture; distribution_texture | `new_family`; Detection. Four different server roles show 53–100 snapd messages and a common desktop-integration/microk8s/lxd pool in six hours. Shared images and verbosity remain plausible. | not labeled | Medium/low; host software inventory, activity catalog and syslog scheduling. Verify role and cadence ownership. |
| P3 | Binary-document cat workload; weak_signal / distribution_texture | `false_positive_or_unproven` as human-viewing defect; Threat/Host. Seven PDF/Office reads take 9–27 s; scripted inspection, collection selection and remote I/O remain plausible. | not labeled | Low/modest; actual file-access intent and process binding. Do not invent GUI consumption or false failures. |
| P3 | Late ambient TXT burst; weak_signal | `sibling_defect` hypothesis; Network. 43 sensor observations across 19 clients all begin after 17:41. Root inspection finds attack-window-conditioned benign padding; observed data could still reflect a task. | not labeled | Low/modest; baseline DNS/task and host-role binding. Separate ambient behavior from attack-conditioned injection if verified as the intended model gap. |
| P4 | Generic/missing built-in file versions; weak_signal | `false_positive_or_unproven`; Detection. `.1` versions and selected missing resources can reflect real images/metadata. | not labeled | Low; installed binary/version registry. Require representative native evidence before adding precision. |

The independent RSA identity-width/cost follow-up is an engineering completion
item, not an added blind-score driver. Its owner and bounded verification are
recorded for loop 3.

## Priority rationale and next pass

Complete the verified durable-session timing correction and RSA identity/cost
work first: both have bounded owning abstractions and reproducible probes. The
new Mac job-control finding has high potential leverage but requires intent,
entry-path and native-qualification analysis; do not simply add background flags
or change one rendered PGID. Inspect local/remote SSH, ordinary terminal commands
and transfer-client siblings before coding that family.

## Score movement and quantitative comparison

The major RSA content tell is absent, consistent with the lower initial network
score and the rendered mathematical probes. New Mac observations and reviewer
coverage explain remaining disagreement; they are not automatically a regression
from the latest fix. Check earlier same-epoch data before assigning regression
causality. Automated scores remain high but did not expose the earlier key-content
or session-timing weaknesses. Native process/identity and protocol consistency
remain strengths, not synthetic indicators merely because matching is complete.

## Provenance

Behavior 535 / surface e380d7ed0f70cf89627be784063f95954ed57b3df86089b9da001c4aefa00de0,
seed 42. All four authored SHA256 hashes match loop 1; its zero-error/eight-warning
validation applies. The authoritative bundle, JSON/text eval, original reports,
actual deliberations, facilitator summary and rendered/engineering probes are
retained. Blind data was freshly copied and verified, with unchanged briefing
and persona hashes and no prior reports or fix hints supplied to the panel.
