# Loop 75 — Scanner and forwarding queue findings

## Selected families and result

Loop74's Network reviewer flagged near-equal scan counts across four service ports, and Detection
flagged high rsyslog forwarding queue values. The scanner owner is the Nmap command probe bundle;
queue state is owned by baseline rsyslog health generation and emitted as source-native syslog.
The family contract was written before review. Investigation found no impossible sequence or
source-native contradiction, so loop75 made no code changes.

The scan is an explicitly authored Nmap command from WEB-EXT-01: `nmap -Pn -sT -p
22,80,443,445,3306 10.10.2.0/24`. The Nmap connect planner uses a 6–12 second window. In the fixed
seed output, Zeek core records 253–254 distinct destinations for each of the five ports from
14:40:30.705 to 14:40:36.901 UTC; the DMZ sensor sees 252–260 per port over its own source clock.
The core view contains 1,235 S0 attempts plus a smaller mix of REJ/RST states. The count symmetry
reflects one large cross-product scan and a bounded window; a fast scan remains plausible. Reviewer
scan concerns are classified `false_positive_or_unproven`, not a generator defect.

The baseline rsyslog model maintains per-host pending counts and checkpoints asynchronously. The
final output has 39 queue reports over 11 Linux hosts; seven hosts have a reported value above
1,000, with a maximum of 3,698. Values change across checkpoints and hosts. Since a forwarding
queue can include messages outside a partial local export and no impossible transition was found,
this remains a `distribution_texture` hypothesis, not a hard contradiction. No arbitrary cap or
invented jitter was added.

## Validation and evaluation

- Scenario validation passed with the existing warning/info findings.
- The clean fixed-seed generation completed. Human and JSON evaluations passed: 96.3400/100,
  135,966 records; parseability 100, plausibility 96.82, causality 95.90, timing 90.79.
- This output is deterministic with loop74: record count, score and pillars match exactly.
- No code changed, so no additional tests or lint pass were needed; loop74's revision495 validation
  applies to this same code snapshot. Full routine pytest remains unrun.

## Blind panel and deliberation

Initial reports disagreed: Detection chose Synthetic while Threat, Network and Host chose
Inconclusive. Initial synthetic-confidence scores were 55 / 66 / 57 / 52 (mean 57.50, spread 14);
initial verdict-confidence mean was 78.75. Verdict disagreement triggered deliberation.

The disputed macOS claim treated fork-time `/sbin/launchd` images as extra launchd processes. The
raw Endpoint Security and eCAR records show each PID as a fork snapshot at `/sbin/launchd`, then
exec transitions under the same process identity to `/usr/libexec/xpcproxy` and the user app within
milliseconds. Detection withdrew the hard-contradiction claim; all four final verdicts are
Inconclusive. Revised synthetic-confidence scores were Threat46 / Detection44 / Network55 /
Host43 (mean 47.00, spread 12); revised verdict-confidence mean was 79.25. No hard contradiction
remains. The mean score fell 10.50 points after deliberation because the strongest cue was a
fork/exec interpretation error. Against loop74's 43.00 mean, the final loop75 mean is up 4 points;
there was no implementation change, so this is panel variation rather than a fix effect.

## Prioritized findings

- **P3 — [distribution_texture], Network Forensics, authored scan shape:** the near-subnet sweep is
  visible in both sensor views and is strongly regular. Its owning Nmap process and 6–12 second
  schedule explain the pattern; retain it as explicit activity rather than an authenticity defect.
- **P3 — [distribution_texture], Detection Engineer, rsyslog queue counters:** seven of eleven
  Linux hosts report over 1,000 pending messages, maximum 3,698. Checkpoint and pending values
  evolve without an impossible transition. Follow up only if a broader queue-state probe finds a
  mismatch with the modeled throughput or forwarding profile.
- **False positive — Detection Engineer, macOS launchd:** fork-time inherited image was mistaken for
  a second persistent launchd. Fork, exec and final application identities agree across native ES
  and eCAR.
- **Unscored — synchronized six-hour window:** reviewers noted the common observation boundaries;
  the visible collection window explains this, and boundary alignment alone is not a valid
  synthetic indicator.

Full reports, original and revised votes, the family contract and probes are in this loop folder.
