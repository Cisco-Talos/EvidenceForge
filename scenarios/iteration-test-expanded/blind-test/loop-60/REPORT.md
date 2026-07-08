# Loop 60 Monotonic Blind Assessment

## Decision

Loop 60 is accepted under the monotonic blind-loop experiment rule.

| Metric | Value |
|---|---:|
| Prior accepted baseline | loop 59 |
| Prior average synthetic-confidence score | 38.25 |
| Candidate average synthetic-confidence score | 37.25 |
| Decision rule | candidate average < accepted average |
| Result | accepted |

No deliberation was run. This experiment explicitly uses the arithmetic average
of standalone blind reviewer synthetic-confidence scores.

The first 60-d reviewer panel was invalidated because a shared temporary review
copy was contaminated during review. See `invalid-panel-note.md`; only the clean
rerun scores below were used.

## Fix Under Test

- Candidate commit: `8ccc066b fix: limit collection profile to rendered logs`
- Target: the attempt-60-c Detection Engineer and Threat Hunter finding that the
  neutral review tree's `COLLECTION_PROFILE.json` advertised `mail_artifacts`,
  `email_artifacts`, and `eml` even though reviewers were given only rendered
  logs.
- Owning layer: collection-profile generation for the rendered review log tree.
- Family invariant: `COLLECTION_PROFILE.json` inside the review tree describes
  only files present inside that tree; packaged artifacts such as `.eml` files
  remain documented by the package-level artifact manifest.
- Verification: `hard_probe_collection_profile.json` confirms zero
  `mail_artifacts` families, zero `email_artifacts` formats, zero `eml` formats,
  and zero `.eml` files inside the review tree, while the package root still has
  `ARTIFACTS_MANIFEST.json` and 30 `.eml` artifacts.

## Individual Expert Summaries

Threat Hunter assessed the dataset as Real with verdict confidence 72 and
synthetic-confidence score 18. They found no scored hard contradictions,
contract gaps, or schema defects, and highlighted coherent DB exfiltration, AD
account operations, Security log clear evidence, proxy activity, and realistic
source-family mix.

Detection Engineer assessed the dataset as Inconclusive with verdict confidence
62 and synthetic-confidence score 35. They found no hard lifecycle or schema
contradiction, and scored only weak proxy timestamp semantics, Windows
Security-log-clear collection semantics, and sparse NTP visibility.

Network Forensics assessed the dataset as Real with verdict confidence 72 and
synthetic-confidence score 24. They found intact Zeek protocol contracts,
independent sensor identity, realistic DNS/TLS/proxy/ASA/Snort/web correlation,
and only weak OCSP and NTP texture concerns.

Host/EDR assessed the dataset as Synthetic with verdict confidence 76 and
synthetic-confidence score 72. The score was driven by concrete Linux shell
pipeline lifecycle contradictions where upstream `cat` processes outlive
downstream `head`, `grep`, or `cut` consumers by many seconds; SSH/RDP and
Windows endpoint correlation otherwise looked strong.

## Score Summary

| Reviewer | Assessment | Verdict Confidence | Synthetic-Confidence Score | Interpretation |
|---|---|---:|---:|---|
| Threat Hunter | Real | 72 | 18 | indistinguishable |
| Detection Engineer | Inconclusive | 62 | 35 | mostly realistic |
| Network Forensics | Real | 72 | 24 | mostly realistic |
| Host/EDR | Synthetic | 76 | 72 | likely synthetic |
| Average | - | - | 37.25 | mostly realistic |

Automated eval passed at 95.90845223387653 over 96,389 records. This was used
as a guardrail only, not as the acceptance score.

## Reported Issues

| Priority | Issue | Category | Reviewer Rating | Score Impact | Description |
|---|---|---|---|---|---|
| P0 | Linux shell pipeline process lifecycles | `hard_contradiction` | not labeled | High | Host/EDR found repeated bash/eCAR pipelines where upstream `cat` processes terminate 17-23 seconds after downstream `head`, `grep`, or `cut` consumers. This is a concrete endpoint lifecycle contradiction and is the obvious next fix target if the experiment resumes. |
| P1 | Short utility command durations | `distribution_texture` / `weak_signal` | not labeled | Medium | Host/EDR also found standalone commands such as `whoami` and simple `/proc` reads with implausibly long eCAR lifetimes. This likely shares the command-duration owner with the pipeline issue. |
| P2 | Proxy access timestamp semantics | `schema_or_format` / `weak_signal` | not labeled | Low | Detection Engineer noted proxy access rows can precede proxy-origin DNS/TLS by a few seconds. This is plausible if proxy access timestamps are request-start times, but the format does not make that interpretation explicit. |
| P3 | Security log-clear collection semantics | `environment_or_collection_plausibility` / `weak_signal` | not labeled | Low-medium | Detection Engineer noted that DC Security Event ID 1102 is followed by higher EventRecordIDs. This is plausible as SIEM-forwarded stream evidence but odd as a raw local EVTX export without collection/export context. |
| P4 | NTP and OCSP long-tail texture | `distribution_texture` / `weak_signal` | not labeled | Low | Network and Detection reviewers observed sparse NTP and light OCSP visibility. Both were treated as weak collection/profile texture signals rather than contradictions. |

## Comparison With Quantitative Eval

The automated evaluator did not catch the Host/EDR shell pipeline lifecycle
contradictions. It continued to pass because parser/spec, coarse causal ordering,
and source agreement checks remained high.

The blind reviewers also did not treat the now-fixed collection-profile
mail-artifact declaration as a continuing issue; the hard probe confirms that
the rendered review tree profile now describes only rendered logs.

## Recommendations

Stop after this loop per user instruction. If this branch is resumed, target the
Linux shell command action bundle or eCAR Linux process lifetime planner next:
pipeline components should terminate as a coupled process group, and short
utilities should use command-aware lifetimes.
