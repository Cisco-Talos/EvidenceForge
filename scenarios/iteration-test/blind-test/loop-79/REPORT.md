# Loop 79 — Debian sysstat cadence

The loop77 probe found 12 half-hour `debian-sa1` invocations per host on nine Debian systems.
Debian's current trixie `sa1` manual documents a ten-minute cron interval; the sysstat source
defaults `CRON_INTERVAL` to 10 minutes ([Debian sa1 manual](https://manpages.debian.org/trixie/sysstat/sa1.8.en.html),
[Debian sysstat configure source](https://sources.debian.org/src/sysstat/12.7.5-2/configure.ac)).
The schedule data and shared scheduler now model six minute-aligned firings per hour with stable
per-host phase. Each invocation retains its `/bin/sh` → `debian-sa1` lifecycle. Additional
occurrences use scoped deterministic randomness so they do not perturb unrelated baseline
activity. Generation behavior revision is 496.

## Validation and evaluation

Scenario validation passed. Config validation passed across 101 files. Focused schedule tests
passed (3); Ruff, formatting, diff checks, and generation behavior manifest check passed. Two
initial fixed-seed generations exposed unrelated RNG-sensitive RDP/profile failures after changing
the schedule; the final scoped-RNG version generated successfully at seed42. This exposed why the
additional periodic activity needed isolated draws while preserving the legacy shared stream for
two slots.

The final output has **142,740 records** and evaluates **96.5648 / 100, PASS** (parseability 100.00,
plausibility 96.93, causality 97.17, timing 90.20). The schedule probe shows 36 `/bin/sh` and 36
`/usr/lib/sysstat/debian-sa1` process starts per host across ten Linux hosts. The visible cron
timestamps are minute-aligned at the configured host phase.

## Independent reviews

- **Threat Hunter — Inconclusive, confidence 62, synthetic-confidence 34.** Considered the
  ten-minute cadence plausible cron behavior; found the database export/SCP chain coherent and no
  concrete anomaly.
- **Detection Engineer — Synthetic, confidence 72, synthetic-confidence 69.** Flagged exactly 36
  invocations on each of ten Linux hosts, all at second 00 with narrow fractional jitter, as strong
  distribution texture. Found no schema or lifecycle break.
- **Network Forensics — Inconclusive, confidence 78, synthetic-confidence 24.** Found complete
  Zeek protocol UID/tuple integrity, strong proxy/ASA joins, and no hard contradiction.
- **Host/EDR Forensics — Synthetic, confidence 82, synthetic-confidence 78.** Found broadly
  coherent lifecycle ordering; the identical ten-host, 36-invocation pattern was the main synthetic
  signal.

Standalone synthetic-confidence mean is **51.25** (spread 54). Verdict disagreement and spread
triggered deliberation; the final deliberative mean is **51.00**. Two reviewers regard the exact
same schedule as a synthetic fingerprint;
Threat Hunter regards it as a normal package schedule. Network correlation and host lifecycle
coherence are positive evidence about internal consistency, not proof of provenance. No hard
contradiction or schema/lifecycle defect was established. Deliberation is pending.

## Prioritized findings

| Priority | Finding | Category | Original reviewer rating | Scope / leverage | Disposition |
|---|---|---|---|---|---|
| P2 | Identical 36-entry ten-minute sysstat cadence across ten Linux hosts | `distribution_texture` | not labeled | Fleet-wide, but exact package default is plausible; medium | Keep the package-consistent cadence. Do not randomize cron timestamps or invent missed executions without collection evidence. Reassess after deliberation. |
| P4 | Sparse Mac Unified Log and bounded source coverage | `environment_or_collection_plausibility` | not labeled | Low, no collection profile supplied | Defer; reviewers did not show required companions missing. |

Deliberation retained two Inconclusive and two Synthetic positions. The higher synthetic suspicion
is tied to the exact count and near-identical timing across ten hosts, while the valid package
schedule remains a plausible explanation.

Next loop checks whether independent blind scoring on the post-fix output reproduces the cadence
disagreement. Artifacts include `family-contract.md`, `sysstat-cadence-probe.json`, evaluation,
four reviewer reports, and `deliberation.md`.
