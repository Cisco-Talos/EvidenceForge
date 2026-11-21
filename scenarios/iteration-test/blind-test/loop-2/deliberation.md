# Deliberation Summary

This summary facilitates the four supplied independent reports and the four reviewers' actual deliberation responses. It introduces no fifth review or additional data inspection. Initial votes below come from the original reports; final votes come from each reviewer's own response.

The final assessment is **unanimously Inconclusive**, with synthetic-confidence scores from **43 to 56**. This is agreement that provenance remains unresolved, not a unanimous synthetic lean or a determination that the telemetry is real. The Network Forensics reviewer changed from Real to Inconclusive; the Host/EDR reviewer changed from Synthetic to Inconclusive. The Threat Hunter and Detection Engineer retained Inconclusive while increasing their synthetic-confidence scores. The panel continues to differ over the weight of explainable endpoint and collection patterns.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 86 | 45 | Inconclusive | 86 | 54 |
| Detection Engineer | Inconclusive | 80 | 33 | Inconclusive | 84 | 51 |
| Network Forensics | Real | 62 | 29 | Inconclusive | 80 | 43 |
| Host/EDR Forensics | Synthetic | 77 | 63 | Inconclusive | 83 | 56 |

Scores and confidences are preserved exactly. Verdict confidence describes confidence in the stated assessment; it is not the probability of synthetic origin. The arithmetic mean of final synthetic-confidence scores is **51**, and their range is **43–56**. That descriptive mean is not an additional panel vote or a calibrated provenance probability.

## Round 1 — Present Findings

- **Threat Hunter — Inconclusive / 86 / 45 initially.** The strongest favorable evidence was operational feasibility: Mac SSH transport precedes target authentication; database `mysqldump`, `gzip`, transfer and receiver-file effects form a workable sequence; account changes occur while their responsible processes remain alive. A useful specialty observation was seven Mac 02 `cat` executions against PDF/XLSX/DOCX files, with normalized lifetimes around 9–27 seconds. The reviewer treated this as modest workflow texture, allowing binary inspection, access testing, remote storage and blocked output as alternatives.
- **Detection Engineer — Inconclusive / 80 / 33 initially.** Event-dependent Windows field structures, successful XML/JSON parsing, and checked process/GUID/LUID lifetimes were strong favorable findings. Matched Zeek protocol tuples and timing also agreed with their connection records. The distinctive concern was shared snapd package/message vocabulary across web, file, application and logging servers. Generic or absent Windows version metadata received little weight. One unmatched SMB mapping was recorded as an unscored join limitation, not proof of fabrication.
- **Network Forensics — Real / 62 / 29 initially.** Connection states, packet/byte accounting, protocol intervals, explicit-proxy interpretation, TLS visibility, certificate relationships and matched firewall denials were mutually plausible in the checks performed. All 13,466 checked DNS/HTTP/SSL observations joined their same-sensor connections. The unique residual concern was the late onset of ordinary TXT activity: 43 sensor observations outside the suspicious namespace, across 19 client IPs, all beginning after 17:41 in a window starting around 13:00. A coordinated task or deployment could explain it.
- **Host/EDR Forensics — Synthetic / 77 / 63 initially.** The strongest adverse finding combined overlapping same-local-shell commands with repeated inherited terminal process groups on both Macs. A second concern was normalized fork/exec interval concentration: 93 of 94 pairs were 1–5 ms despite broader native ES intervals. Favorable specialty findings included all 954 visible Windows Sysmon creations matching Security 4688 PID/image/command, stable hashes and process identities, and macOS distinctions among fork, exec, pidversion, credentials, audit sessions and POSIX groups/sessions. The reviewer did not allege an impossible native schema.

## Round 2 — Cross-Examination

### Shell ownership versus successful lifetime and transport checks

This was the most consequential blind spot exposed by deliberation. On Mac 01, SSH PID 66778 starts at 16:27:40.693524 and exits at 17:00:44.761399, while `id` PID 67424 starts at 16:34:32.048370 under the same parent shell 42156, group/session 42155 and `/dev/ttys000`. On Mac 02, SSH PIDs 45509 and 46192 overlap under shell 19001, group/session 19000 and `/dev/ttys001`; the second starts at 16:09:07.153351 before the first exits at 16:18:00.427669. The histories lack background operators for the cited SSH commands.

The Detection Engineer and Threat Hunter reported independently reproducing the native records. The Network reviewer also rechecked native records and confirmed that the relevant transport intervals genuinely overlap: Mac 01's SSH connection lasts until 17:00:43.800092, encompassing `id`, while Mac 02's first represented SSH transport remains open when the second begins. This narrows the alternative that an SSH process merely lingered after an early connection close.

All reviewers accepted that this is stronger than overlap alone, but none's final response calls it impossible. Foreground-terminal ownership, MONITOR configuration, signals, suspension and SSH escape actions are unobserved. Missing `&` is not proof that a command remained foreground throughout its lifetime; `ssh -tt` specifies remote PTY allocation, not local job control. Repeated inherited groups make conventional explanations less comfortable without excluding nonstandard configuration. Overlap and process-group inheritance are one related finding family and must not be counted as separate independent contradictions.

Correct process lifetimes and coherent SSH transport/authentication ordering do not establish shell readiness. Conversely, the shell concern does not invalidate the successful identity or network checks. The panel resolved this apparent conflict as a difference in tested properties, not contradictory measurements.

### Native occurrence time versus normalized observation time

The host report's concentration is concrete: 59 pairs at 1 ms, 17 at 2 ms, 11 at 3 ms, five at 4 ms, one at 5 ms and one at 67 ms. The Threat Hunter independently reproduced the aggregate. The Network reviewer rechecked the PID 18998 example, not all 94 pairs: native fork/exec is 15.960 ms, normalized CREATE/first exec is 1 ms.

The important strength challenge is that `timestamp_ms` does not promise native occurrence time. Ingestion, batching, processing-order stamps or monotonic increments could compress intervals. The Host/EDR reviewer explicitly reduced this finding's independent weight after the Detection Engineer and Threat Hunter emphasized those semantics. The Network reviewer still gives the pattern modest concern. The final shared position is a collection-texture question requiring a timestamp contract, not a demonstrated native timing impossibility.

### Behavioral repetition versus ordinary operations

The seven binary-document `cat` operations were accepted as modest behavioral texture; Host/EDR additionally reported verifying all seven in native ES. No reviewer claims that `cat` cannot read binary data or that missing Office telemetry proves an error. Remote storage, output blocking, scripted inspection and omitted redirection remain alternatives. The XLSX command inside the Mac 02 SSH lifetime must not be counted again as an independent concurrency defect.

The snapd concern is similarly bounded: shared packages and messages across roles may indicate reused background vocabulary, but common images and verbose collection are credible. The DB host's lack of snapd records is an internal counterexample to a completely uniform fleet. Ordinary TXT onset across 19 clients is a concrete weak signal, with coordinated checks or rollout a plausible explanation. Several explainable patterns do not become a hard contradiction merely by being added together.

### Coverage qualifications and provenance claims

The Network review's complete protocol-UID result covers DNS, HTTP and SSL. It does not claim that every SMB mapping joined, so the Detection Engineer's orphan SMB UID is a coverage qualification rather than a contradiction. All reviewers leave that orphan unscored without a lossless collection guarantee.

Successful native parsing, joins and realistic operational sequences establish technical plausibility. They do not prove production origin. This distinction was central to the Network reviewer's withdrawal of the initial Real lean. No reviewer advocates penalizing complete joins, sanitized names, absent unrequired sources, or processes continuing beyond the six-hour window. Generic/absent Windows version metadata was reduced to negligible weight by the Detection Engineer; no incorrect native version value was demonstrated.

## Round 3 — Actual Revised Positions

- **Threat Hunter: Inconclusive / 86 / 54.** Verdict and verdict confidence unchanged; synthetic-confidence increases by 9. The native shell-ownership finding added operational evidence beyond the original pivot checks. Snapd and TXT patterns added small concerns; normalized timing remains limited by timestamp semantics. Feasible transfers, account effects and SSH ordering remain favorable evidence.
- **Detection Engineer: Inconclusive / 84 / 51.** Verdict unchanged; verdict confidence increases by 4 and synthetic-confidence by 18. Independently reproduced native terminal records matter substantially more than the original metadata and snapd concerns. Greater confidence concerns the appropriateness of an inconclusive judgment, not certainty of synthetic origin.
- **Network Forensics: Inconclusive / 80 / 43.** Changed from Real; verdict confidence increases by 18 and synthetic-confidence by 14. Verified endpoint and network session overlap broadens the concerns beyond the original network scope. The favorable network checks remain intact; their success is no longer considered sufficient for a Real verdict.
- **Host/EDR Forensics: Inconclusive / 83 / 56.** Changed from Synthetic; verdict confidence increases by 6 and synthetic-confidence falls by 7. The observations remain reproducible. Unspecified normalized timestamp semantics reduce timing's independent weight, and missing foreground/job-control state limits the ownership inference. Peer evidence of operational and network plausibility further constrains a provenance claim. Corroborated binary-document activity adds modest behavioral concern without restoring the original Synthetic lean.

## Key Agreements

- All four actual final verdicts are Inconclusive. No supplied final response establishes a hard contradiction, generator leak or impossible native event schema.
- Native local-terminal ownership/concurrency is the most influential adverse finding. Peers reproduced or extended it, but retain operational alternatives and count it as one related family.
- Network/protocol relationships, Windows process identities and macOS native identity distinctions are substantial strengths. Plausible attack or administration sequences are usable hunting evidence irrespective of provenance.
- Normalized fork/exec compression warrants clarification of occurrence versus ingestion time. It does not establish that native execution timing is false.
- Binary-document streaming, shared server package noise and late ordinary TXT onset are bounded texture concerns, each with plausible real-world explanations.
- Collection boundaries, source selection and one orphan SMB mapping do not justify invented lifecycle failures or demands for lossless collection.

## Key Disagreements

The initial Real and Synthetic verdicts converge to Inconclusive, but evidential weighting does not become identical. The Network reviewer retains the lowest synthetic-confidence at 43; Host/EDR retains the highest at 56, with Threat Hunter 54 and Detection Engineer 51 between them. Network coherence remains especially persuasive to the Network reviewer; native ownership/workflow texture remains more concerning to the host-oriented reviewers.

Normalized timing retains modest concern for the Network reviewer, while Host/EDR explicitly reduces its independent weight and the Threat Hunter and Detection Engineer emphasize ingestion alternatives. No timestamp contract resolves that difference. Likewise, no foreground-terminal record or shell configuration resolves the local-job interpretation. The panel has agreement about the limits of the evidence, not proof of a common hidden cause for all patterns.

## Most Convincing Evidence

The following ordering summarizes the weight and impact expressed in the supplied responses; it is not a new independent assessment or a numerical panel ranking ballot.

1. **Repeated native shell-overlap and inherited-group combination — strongest synthetic-leaning observation.** Two Macs repeat the pattern, peers reproduce it, and the Network reviewer confirms corresponding open transports. Missing foreground/job-control state prevents a hard-contradiction claim.
2. **Coherent source-specific network semantics — strongest broad favorable evidence.** Tested state/history, byte totals, TLS/certificate/file relationships, proxy paths and matched denial outcomes remain plausible. They support credibility while permitting a careful simulation.
3. **Stable endpoint identities and feasible operation effects — strong favorable evidence.** Windows cross-provider PID/image/command matches, stable hashes, macOS fork/exec/pidversion distinctions and workable export/account-change sequences survive the checks described. These test different properties from interactive shell readiness.
4. **Repeated normalized fork/exec compression — limited-to-modest adverse collection texture.** The aggregate is reproduced by the Threat Hunter; the representative source discrepancy is also checked by the Network reviewer. Unspecified timestamp semantics materially reduce its strength and caused Host/EDR to revise.
5. **Seven binary-document `cat` operations — modest adverse workflow texture.** Host/EDR confirms native executions in addition to the Threat Hunter's normalized examples. The operation is valid and its durations may have storage or output explanations. Snapd repetition and the ordinary-TXT boundary remain lower-weight supporting observations rather than independent proof.

## Most Debated Points

- Whether same-shell overlapping jobs with inherited groups are sufficiently unconventional to infer fabrication when terminal foreground state and shell configuration are missing.
- Whether eCAR expresses occurrence or ingestion time, and consequently whether compressed elapsed intervals deserve behavioral or collection-only interpretation.
- Whether successful parser, lifecycle and network checks establish real origin or only technical plausibility. The Network reviewer changed verdict on this distinction.
- Whether repeated binary-document reads, package vocabulary and TXT onset reflect generic behavior pools or actual standardized/coordinated operations. None of these is settled by the supplied observations.
- How to avoid double counting one shell-ownership family, or treating several weak texture signals as an impossible lifecycle. Reviewers explicitly retained these limits.

## Improvement Recommendations (Consensus)

These recommendations synthesize changes supported by all or most responses, conditional on the data being synthetic. They target the observed patterns and preserve legitimate alternative operating behaviors.

1. **Coordinate terminal scheduling and job ownership.** Model foreground, background and suspended jobs together with shell readiness, process groups and terminal ownership. For the cited Mac 01 SSH/`id` overlap and Mac 02 overlapping SSH clients, make native snapshots and history reflect the intended control behavior. Preserve legitimately long-lived or background SSH sessions; merely ending them earlier would not establish coherent ownership.
2. **Specify and honor normalized timestamp semantics.** If eCAR records occurrence time, retain meaningful native fork/exec elapsed intervals. If it records ingestion/observation time, document and model arrival/batching behavior that explains the repeated 1–5-ms gaps. Do not force unrelated source timestamps to be equal or infer a contract from the field name alone.
3. **Represent the actual document operation.** Use application/file behavior appropriate to human PDF/Office reading, and retain `cat` for deliberate byte-stream inspection or access testing with that purpose reflected in the command behavior. Check duration against file size, SMB/storage behavior and output blocking before changing the observed 9–27-second lifetimes.
4. **Tie background activity to host software and operational schedules.** Align snapd inventory, package mix and verbosity with each host's installed software and role, while allowing standard images. Distribute ordinary TXT lookups according to responsible clients/applications and active periods, or represent a coordinated check/rollout that explains the late shared onset. Do not treat concentrated suspicious TXT activity as a defect by itself.
5. **Preserve successful semantic contracts.** Keep stable Windows identities/hashes, macOS native identity/session distinctions, feasible operation effects and coherent transport/protocol/certificate relationships. Do not add arbitrary missing sources, deliberately broken joins, gratuitous attack failures or unrelated noise as an authenticity treatment.

The metadata observation does not justify inventing precise per-binary versions without representative evidence. The isolated SMB mapping does not justify declaring collection loss impossible. Both remain below the consensus priorities above.
