# New assessment epoch — loop 11

Unchanged expanded canonical scenario and full reviewer instructions. Behavior544
repairs attack-owned background DNS activity; it does not remove genuine lookup
intent or change the campaign's authored parameters.

## Scores and actual review

Quantitative eval PASS98.3648819175/145010records, JSON once/text derived; all
acceptance and dynamic guardrails pass. Four fresh fork-none experts reviewed
115 verified data-only files, without code, scenario, old reports or focused hints.

| Expert | Initial verdict | Verdict confidence | Initial synthetic-confidence score | Actual revised score |
|---|---|---:|---:|---:|
| Threat Hunter | Inconclusive | 82 | 40 | 69 |
| Detection Engineer | Synthetic | 78 | 63 | 70 |
| Network Forensics | Synthetic | 74 | 62 | 68 |
| Host/EDR | Real | 64 | 31 | 68 |
| Mean | | | **49.0—mixed/inconclusive** | **68.75—likely synthetic** |

Lower synthetic-confidence is better. Initial mean rises2.75 from10; last-five
rolling initial mean46.35. Verdict disagreement triggered actual same-expert
reconsiderations, then a fresh facilitator. All final verdicts Synthetic, verdict
confidence83/86/82/80. Original reports/responses/synthesis remain verbatim; only
initial scores enter trends. No old/candidate scores are inherited.

Threat and Host initially credited coherent endpoint/session/transfer evidence;
Host leaned Real with modest confidence. Detection's main concern was repeated
native Mac fork fractional phases, preserving whole-second gaps in mach_time as
well as wall time. Network found a new cross-sensor file-analysis duration gap,
while crediting transport/protocol/byte/certificate/tuple consistency. Actual
cross-checks led all experts to accept both timing concerns with replay/export/
analysis-configuration alternatives, not as an unconditional proof of origin.

Network's specific support-upload example: same physical client-to-proxy tuple,
1572864seen bytes, duration9.723180s core versus10.994234s DMZ, enclosing connection
19.649629/19.649788s and identical1162/539packet counts/no reported loss. A separate
151293700B HTTP response has file1.792268/2.344185s versus connection8.884730/8.884979s.
Its paired population is266HTTPfiles,43duration differences>10ms and23>100ms;
median connection-duration difference.227ms, max1.624ms. Count these as one
recurring family, not independent proofs. Detection independently reproduced the
two examples. Root comparison confirms the support-upload rows are identical in
loops10and11, so this is a newly surfaced preexisting gap, not a demonstrated
regression of the DNS change. Proxy upstream versus downstream legs are distinct;
the cited pair is the same physical tuple across two sensors.

## Family repair and rendered proof

Classification family_level. Owner typed DNS campaign intent handler shared by
storyline entry paths. Invariant: the tunnel owns its explicit source/campaign
and required transport/DNS/IDS companions; it must not invent unrelated host
activity as camouflage. Baseline and explicit DNS retain their own owners.
Family-contract.md records entry/consumer inventory and sibling risks.

Removed the entire unrelated-host TXT publication block and dead imports, not a
host/domain-specific sample. No new fleet diagnostic, no emitter filtering or
replacement cover story. Payload/pacing RNG now has no camouflage draws; replay
and peer-count independence are tested rather than preserving its former sample.

Actual core campaign observations228→206, all fromAPP10.10.2.30; wrong-source
campaign rows remain0. Non-campaign TXT37records/19sources→1record/1source; DB2→0,
DMZ1→0. The surviving core TXT is the explicitly authored standalone query for
metrics.westbridge-services.net. This is not a blanket TXT removal. These counts
are sensor observations, not independent physical queries or a claim that every
unrelated TXT row would be illegitimate. See dns-campaign-ownership-probe.json.

Before fix,3TXT/CNAME/NULL peer-independence tests failed. After fix224 focused
checks passed,55deselected26.61s, including ordinary DNS/native accounting and
window fences. Two old tests required camouflage; their expectations were changed
to campaign-only source ownership while preserving all transport-close/window/
byte accounting assertions. Additional4ownership/IDS tests passed1.28s; authored
SID2029706 attachments remain on campaign transports. One existing IDS beacon
slow gate passed6.17s; the all-transport soak was not run. Checkpoint2passed
106.27s,15deselected; global temporal-RNG3slow7.37s; behavior27pass2.86s;config105
files no issues; Ruff/format1649files pass. Counts overlap; no full routine or
release gate is claimed. Canonical generation exit0/authoritative manifest.

## Prioritized remaining work

Priorities/categories below are synthesis; original reviewers supplied no P0–P4 labels.

| Priority | Finding / classification | Owner, evidence, leverage, risk and next action |
|---|---|---|
| P1 | Cross-sensor HTTP file-analysis intervals; new_family, contract_gap | Network initially, actual Detection/others reproduce two examples. Shared physical file interval and network-source observation timing; high leverage, medium/high risk. Inspect NetworkObservationPlanner._sample_file_duration and transfer contexts, preserve bounds/clocks/proxy legs/loss semantics, verify Zeek field semantics before changing. Newly found in11 but visible unchanged in10. Prioritize this ahead of weaker file-task texture. |
| P1 | Native Mac fractional fork groups; recurring sibling_defect, distribution_texture | Detection initially, actual deliberators;3groups10forks across2Macs. High leverage/high semantic risk. Authored exact offsets feed canonical process creation timestamps. Preserve frozen scenario/exact low-level/prepared actor contracts; no emitter jitter or invented scheduling cover story. Separate intent/realization design qualification needed. |
| P2 | Policy file purpose/type size population; carried new_family, distribution_texture | Earlier14/48UNCpath-size versions>1MiB. _StorageWorldCompiler/root config. Behavior545loop12isgenerating after policy/legacy/seed/SMB/config/native/checkpoint gates; await actual native12probe, not just sampler output. |
| P3 | Automatic binary-document cat/tee; recurring sibling_defect, environment_or_collection_plausibility | Earlier Host/Threat/Detection; raw-byte inspection remains legitimate. Baseline task/file eligibility plus typed client profiles; preserve explicit binary reads and approved manifest read/save, no unqualified GUI. Draft retained but lower priority than new cross-source timing gap. |
| P3 | Windows console/server vocabulary and SQL/LDAP byte envelopes; carried new_family, distribution_texture | Earlier panel9; no new hard failure here. World/activity/service-operation owners; require semantic/capture evidence before arbitrary entropy. |
| P4 | Exact clock conversion, quiet exit status mix, isolated source gaps; false_positive_or_unproven | Collection/export/selection alternatives remain. Do not randomize valid clocks, invent failures, or add optional sources to game origin assessment. |

The selected DNS ownership repair is verified in actual output, but the new
cross-source file timing finding and old Mac groups dominate assessment. The
score is not a causal estimate of this repair's contribution. Quantitative
consistency does not cover these across-sensor physical file interval comparisons.

## Provenance

Behavior544/digest00945ea53ddee81a994f8e8d270f1c8641abb18966fe2acce15f2865ff0e21a4,
seed42,defaulttarget,all4authoredSHA/exactimmutabletechnology1.0.0pack unchanged.
Study/private/tmp/authenticity-study-iwu24t8x;115datafiles. Reviewer instructions,
examination and score semantics unchanged. New epoch only; obsolete exploratory
artifacts deleted separately, all authored previous/candidate YAML preserved.
