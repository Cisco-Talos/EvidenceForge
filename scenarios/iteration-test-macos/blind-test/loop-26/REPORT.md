# Loop26 — coherent TCP header/MTU accounting

# Loop26 TCP directional wire accounting

Classification: family_level. Owner: shared canonical network_transport packet/header calculation. For complete no-loss IPv4/TCP directions, IP bytes are payload plus word-aligned IP/TCP headers, at least40 bytes per packet, within MTU capacity. Clamp optional header budget, not total IP bytes independently of payload. Entry paths: network transaction planner, explicit payload reconciliation, SMB/HTTP/TLS/RDP/SSH and generic process effects; consumers: source-observation views, all Zeek sensors and endpoint FLOW. Retain gaps/retransmissions and packet history; no emitter correction or row removal. Test odd bulk byte totals, explicit overhead and multiple protocol/history siblings. Repair counts if the caller cannot contain mandatory headers; do not silently serialize impossible counters.

## Verification

Revision422.47focused tests passed, covering bulk odd payloads, explicit overhead, protocol/history siblings and TLS. Ruff/format passed. Eval96.341564PASS,133351records,120identicalblind files. Acrossall3sensors,85clean directional header-word failures becamezero. No source rows were removed or gaps concealed.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive; verdict confidence 78; synthetic-confidence score 43. The sampled activity is operationally coherent and supports practical pivots across endpoint, authentication, network, shell-history, and proxy evidence. One specific SSH transfer has inconsistent session identifiers between Linux syslog and normalized endpoint telemetry, but the broader checks did not establish enough independent defects to confidently determine origin. This is a bounded assessment, not an exhaustive certification of every record.

**Detection Engineer:** Synthetic; verdict confidence 80; synthetic-confidence score 64. The records are generally convincing and should support practical SIEM parsing and correlation. My synthetic verdict rests on repeated timing distributions rather than broken schemas: macOS shell activity repeatedly preserves fractional-second anchors across different commands, and matching Windows Security process creations always follow Sysmon with a similar bounded delay on every inspected host. I found no demonstrated impossible lifecycle or source-native schema contradiction, so these findings support a moderate synthetic-confidence score rather than certainty.

**Network Forensics:** Inconclusive; verdict confidence 78; synthetic-confidence score 24. The network records are mostly production-like: TCP states, DNS shapes, proxy paths, TLS visibility, certificate identity, and protocol-to-flow relationships withstand representative checks. I found two limited accounting/distribution questions, but neither establishes synthetic origin without packet/header context; the supplied records do not support a high synthetic-confidence score.

**Host Forensics:** Synthetic; verdict confidence 82; synthetic-confidence score 68. The endpoint evidence has credible process identities, Windows session behavior, and Linux administrative activity, and the sampled visible lifecycles are generally coherent. My synthetic verdict rests primarily on repeated, exactly preserved microsecond fractions across separate macOS fork notifications, including unrelated shell commands and the same browser startup offsets on both Macs; this is a concrete timing texture rather than an inference from how complete the activity appears. I found no demonstrated impossible process lifetime in the bounded checks, so the score stays in the “likely synthetic” band.

## Deliberation Findings

Standalone43/64/24/68 mean49.75; confidence mean79.5. Split verdicts triggered facilitator-modeled52/65/35/68 mean55.0. These are not actual new reviewer turns or measured consensus.

## Prioritized Improvements

P1 contract_gap: Threat independently reproduced APP-INT-01 root SCP session378852 in syslog versus378837 in eCAR;1of71matched Linux starts. Canonical temporal allocation and renderer identity ownership, high leverage/moderate risk; loop27 targets it.

P2 environment_or_collection_plausibility: previously verified root desktop indexer schedule on infrastructure servers; catalog/host capability owner, medium leverage, low/moderate risk.

P2 distribution_texture: Detection's uniform positive Security-versus-Sysmon process timestamp delays are a qualified provider/export concern; validate native timestamp semantics before changing timing profiles. High source correlation alone is not a defect.

P3 distribution_texture: Mac command fractions and Chrome helper offsets are explicitly scenario-authored. Their score effect is preserved but no generator randomization is justified.

P4 weak_signal: Network HTTP accounting and repeated TTL30 questions were explicitly qualified; no protocol contradiction was established. Verify resolver/application truth before any change.

## Quantitative Comparison and Priority Rationale

Eval/counts matchloop25. Higher blind score49.75 versus36.0 is not a demonstrated packet repair regression: direct accounting probes pass, while independent reviews emphasized different authored timing and source-delay patterns. changed-data-files.json documents the data delta. Concrete shared session identity and role placement outrank uncertain timing preferences. No scenario edits or commits.
