# Loop27 — canonical Linux session identity

# Shared Linux session identity across deferred SSH

Family-level owner: StateManager temporal logind allocator; renderer only serializes canonical truth. A session ID must remain stable across syslog, eCAR, process/session state and close continuation. Out-of-order allocation must fit between already-owned earlier/later IDs; never steal a future session's interval or repair IDs in source finalization. Entry paths: baseline generic Linux logons, typed SSH, deferred SCP receiver and world-planner sessions. Consumers: syslog open/remove, eCAR LOGIN/LOGOUT/process session identity, checkpoint state. Verify out-of-order subsecond allocations and deferred SCP plus ordinary SSH siblings. Risk moderate: integer interval exhaustion must fail explicitly rather than renumber published identity. Preserve explicit raw lines; no emitter-local ID reassignment.

## Verification

Revision423;31routine tests plus4bounded slow SSH publication/checkpoint/direct-threaded tests pass. Eight existing nested allocator assertion bodies were separately invoked and passed because original nesting prevents pytest collection. Ruff/format pass. Eval96.341564PASS,133351records,120identicalfiles.64matched Linux SSH starts now havezero session-ID disagreements, versusone previously;unmatched0.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive; verdict confidence 80; synthetic-confidence score 43. The sampled operational trails work technically: endpoint processes, SSH authentication, network tuples, transferred artifacts, and Windows persistence evidence permit useful pivots without a demonstrated impossible lifecycle. A narrow file-access vocabulary on the two Macs and questionable creation attribution for a redirected database export suggest constructed telemetry, but the evidence does not justify a confident synthetic verdict.

**Detection Engineer:** Inconclusive; verdict confidence 85; synthetic-confidence score 20. The examined records are production-like and should support ordinary SIEM parsing and joins. Representative Windows, Zeek, Linux and macOS checks did not demonstrate a source-native contradiction or an impossible visible lifecycle; this supports a low synthetic-confidence score, but correctly structured and correlated telemetry cannot establish provenance.

**Network Forensics:** Synthetic; verdict confidence 76; synthetic-confidence score 64. The network records have convincing protocol variety, plausible timing, and generally coherent connection-to-protocol relationships. My principal reason for judging them likely synthetic is a repeated mismatch between successful proxy tunnel byte counts and the corresponding upstream TCP stream, even in completed connections with no reported capture gaps. That conclusion depends on the visibly advertised tunnel being a pass-through connection; unrecorded TLS interception or nonstandard counter definitions would weaken it substantially.

**Host Forensics:** Inconclusive; verdict confidence 70; synthetic-confidence score 35. The representative endpoint evidence is mostly production-like: Windows process identities and hashes remain stable, Linux SSH sessions have sensible authentication and close sequences, and macOS records distinguish forks from successive executable images. I found limited repeated background-process texture but no demonstrated impossible lifecycle or source-native contradiction in the bounded checks; the remaining clues do not reliably distinguish a carefully modeled collection from real filtered telemetry.

## Deliberation Findings

Standalone43/20/64/35 mean40.5, confidence mean77.75. Facilitator-modeled48/35/64/42 mean47.25; not new reviewer turns or measured consensus.

## Prioritized Improvements

P1 contract_gap: Network found4of16matched pass-through proxy tunnels with bytes differing from upstream TLS. High leverage/moderate-high risk. Verify pairing, interception, partial forwarding and counter scope; repair canonical graph budgeting before either leg publishes, not emitter counters.
P2 environment_or_collection_plausibility: root Tracker user service scheduled as machine timer; loop28 corrects catalog/deployment/baseline scope using Debian package evidence.
P2 distribution_texture: mounted-share cat/tee operations include office/PDF formats; verify client recipe and authored intent before adding GUI evidence. P3 unproven contract_gap: redirected mysqldump creation may reflect normalized create/write semantics; verify canonical ownership first. P4 weak metadata clues remain qualified.

## Quantitative Comparison and Rationale

Eval/counts unchanged; scorefell9.25. Direct probe clears the ID gap; broad scores remain sampling-sensitive. Proxy graph budgeting needs architectural verification; exact1ms request timing is a separate verified family forloop29. Preserve explicit Mac timings/scenario; no commits.
