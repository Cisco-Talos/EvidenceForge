# Loop 32 assessment

Completed the tenth requested iteration (loops 23–32), revision 428. The canonical responder/preauth generator now distinguishes a TCP/22 transport from a requested SSH authentication. Unnamed probes retain connection and preauth closure evidence; explicit user attempts retain auth-failure semantics. DNS payload planning now includes a two-byte prefix per present TCP message and full TCP response sizes, shared by explicit and fallback contexts. No emitter filtering or benchmark edits were used.

## Verification

45 focused SSH/DNS tests and 7 terminal-admission tests pass without coverage. Ruff passes;1441 files satisfy formatting. Behavior manifest digest matches source. Generated output has 134551 records in 119 files; quantitative eval 96.6753048354 passes, unchanged from 31. All 10 validation/generation/eval runs passed; this is focused feature verification, not a full-suite/release certification.

Rendered scanner-host invented-unknown auth rows fell 8 to 0, while 4 unnamed preauth closures remain. Minimal DNS framing failures fell 14 to 0 across 11 complete TCP DNS observations. The source verification artifact cites RFC1035 and Nmap's native connect-scan semantics. The valid Event 4658 ProcessName field was retained after rejecting the earlier false-positive proposal.

## Scores and movement

Standalone synthetic-confidence 72/43/84/72 averages 67.75 (likely synthetic), versus 60.75 in 31 and 56.25 in 23. Five-loop rolling average 56.8. Deliberation was triggered by split verdicts and 41-point spread; facilitator-modeled scores 84/80/87/84 average 83.75, recorded separately from the standalone panel. These modeled positions are not actual reconvened votes. The later increase reflects a new concrete collection-accounting defect, a qualified SSH packet-budget concern, and repeated authored Mac timings. Historical scores remain unchanged; standalone panels are noisy and do not establish causal model-capability improvement.

## Individual expert summaries

**Threat Hunter:** Synthetic; verdict confidence 92; synthetic-confidence score 72. The collection supports useful, technically coherent hunting across Windows, Linux, macOS, network sensors and an explicit proxy. The strongest authenticity defect is a repeated timing fingerprint in native macOS Endpoint Security records: separate shell commands share exactly the same six fractional timestamp digits in many batches, while every observed inventory process lives exactly two seconds; a successfully authenticated interactive SSH session also has implausibly small client packet accounting.

**Detection Engineer:** Inconclusive; verdict confidence 82; synthetic-confidence score 43. The data is largely usable as production-shaped security telemetry: XML and JSON parse, Windows event fields have appropriate representations, and the tested process and network identities have coherent visible lifecycles. A few software/module combinations and repeated macOS metadata values look curated, but I did not establish an impossible field value, impossible ordering, or broken cross-source relationship that would justify a high synthetic-confidence score.

**Network Forensics:** Synthetic; verdict confidence 93; synthetic-confidence score 84. The network evidence has convincing protocol diversity, proxy routing, TLS certificate handling, and source-local UID and timing integrity. The decisive defect is repeated, physically implausible packet-loss accounting between sensors: the same TCP flow loses one captured packet while its total IP-byte count decreases by as little as three or four bytes. This is a concrete measurement contradiction, rather than an objection to complete coverage or an orderly activity narrative.

**Host Forensics:** Synthetic; verdict confidence 93; synthetic-confidence score 72. The endpoint data is substantially credible in process identity, session ownership, platform separation, and source correlation. My synthetic verdict rests on reproducible timing fingerprints in the macOS Endpoint Security records: arithmetic command cadences preserve identical microsecond fractions, and six inventory process lifetimes are exactly two seconds. I did not find a comparably strong impossible process lifecycle or demonstrated native-schema contradiction in the Windows/Linux evidence examined.

## Prioritized improvements

| Priority | Issue/category | Original reviewer rating | Scope/leverage | Owner/risk | Concrete next action |
|---|---|---|---|---|---|
|P0|Cross-sensor packet loss/header accounting; hard_contradiction|Network 32: not labeled|318 directional comparisons; high|Source observation plus canonical wire ledger; medium/high|Subtract captured packet headers and payload together, preserving coherent tuple-level observations and protocol companions. Root reproduced 318 cases; avoid changing only Zeek output counters.|
|P0|TCP syslog data history with zero bytes; hard_contradiction|Network 31: not labeled|53 sensor rows (50 without missed bytes); high|Shared network semantic reconciliation; medium|Reconcile directional data markers with final payload after service/state shaping, covering success/reset siblings. Probe confirms the 53 rows remain in 32.|
|P1|SSH application phases vs packet budget; contract_gap|Threat 32: not labeled|One verified tuple; medium|SSH bundle/network contract; medium|Derive transport lower bounds from handshake/auth/channel/command phases. Five client packets for 970 s of authenticated interactive use is implausible; capture/aggregation alternatives prevent treating aggregate data as absolute proof.|
|P1|Browser build vs User-Agent; contract_gap|Detection 30: not labeled|195/286 exact-correlated rows; medium|Canonical application identity/profile; medium|Share browser build identity across process metadata and generated requests, preserving explicit UA overrides. Verify custom-build/compatibility alternatives before fixing.|
|P1|Opaque CONNECT stream conservation; contract_gap|Network 27: not labeled|Repeated tunnel observations; medium|Proxy transaction graph; architectural risk|Plan a common opaque byte ledger before either leg publishes. Inspected TLS and per-leg framing need explicit distinctions; do not mutate published client rows.|
|P2|Automatic mounted-document activity cadence; distribution_texture|Threat 23/Host 29: not labeled|Repeated across Macs; medium|Baseline arrival planner and application recipes; medium|Replace fixed per-host period with a shared activity-arrival model across mixed-platform and inline paths, then review shell-vs-document intent. Both entry paths are inventoried; no speculative GUI evidence was added.|

Priority rationale: hard physical/native contradictions outrank texture. The narrow TCP syslog fix can reasonably precede the broader packet-observation redesign because of lower implementation risk. Authored Mac event_spacing and exact 2 s inventory lifetimes explain several reviewer timing findings; preserve the benchmark unless a separate authoring change is requested. Unusual private module inventories and zero exit statuses remain weak/unproven rather than hard validity claims. Same-millisecond ordering is replay ambiguity, not demonstrated impossible causality.

## Quantitative comparison

The automated guardrail remains above 96 throughout this set but does not check cross-sensor packet/header deltas, SSH application phase budgets, or all history/payload contradictions. Its passing score supports parseability and existing contracts; the expert probes identify additional missing contracts. The objective zero-failure probes demonstrate selected fixes independently of the noisy blind score trend.

## Family contract

# Generic SSH transport versus authentication intent

Owner: canonical network responder/preauthentication evidence construction before rendering. Completed TCP/22 does not prove SSH user authentication. Generic responder evidence without an attempted principal must emit connection/preauth closure only; explicit known and invalid-user attempts retain failure evidence. Shared path covers storyline scans, baseline probes and raw generic connections; SSH bundle sessions remain separate. Preserve responder process/transport identities, no sample keys or emitter filtering. Unauthenticated close intent follows transport rather than invented password delay. Verify 24/100-byte scans, known/invalid-user siblings, and rendered tuple joins. Low-to-medium risk.

Second family: transport-aware DNS payload accounting. The shared protocol planner owns mandatory two-byte TCP message prefixes and full TCP message sizes; UDP budgets remain unchanged. Explicit DNS contexts and contextless modeled-DNS fallback both use the helper before packet/IP-byte planning. Cover A/AAAA/TXT, unanswered queries, and TCP responses beyond the UDP1232-byte ceiling. No emitter budget patch.
