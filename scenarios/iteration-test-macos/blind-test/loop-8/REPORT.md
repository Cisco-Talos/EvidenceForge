# Iterative assessment loop 8

## Outcome

Loop 8 verified a root-cause SSH fix from the prior review. The exact deferred Linux SSH path committed its canonical transport/session graph but skipped the bundle's Linux sshd connection, accepted-auth, PAM-open, and logind source observations. It now dispatches those bundle-owned syslog rows after retaining the exact continuation. This covers typed SSH and transfer receivers that converge on the same exact-deferred path, rather than patching either APP-INT-01 root session.

The rendered-output probe confirmed both APP-INT-01 root SSH login sessions now have matching connection, accepted-auth, and PAM-open syslog records for their exact source tuples. Focused exact-caller and sibling transport tests passed (2 passed). Ruff checks and formatting passed. Behavior manifest validation passed at revision 407 when this output was generated.

Fresh generation completed at `/private/tmp/eforge-iteration-test-macos-loop-8`; the bundle contains **141,247 records**. One JSON evaluation passed at **96.880577** (parseability 100, plausibility 96.7070, causality 97.0009, timing 92.2677). All applicable hard criteria passed.

The same loop's direct Mac probe reproduced the prior eCAR timestamp collapse: multiple Endpoint Security fork/exec transitions for one process lifetime still share a single eCAR millisecond. After loop 8's output was frozen, source-timing inspection found that process-exec repair keys used the shared process object ID. The planner now keys each transition by its execution identity (behavior revision 408). Its source-timing regression and 82-test source-timing suite pass, but the loop 8 bundle predates that change; loop 9 is validating it with a fresh generation.

## Family probes

- **Linux SSH contract:** 2/2 visible APP-INT-01 root SSH eCAR LOGIN records have matching source-tuple `Connection from`, `Accepted`, and sshd PAM session-open lines. The second SCP receiver session also has its corresponding logind lifecycle.
- **Mac process timing:** the loop 8 data copy contains five relevant eCAR fork/exec rows for the inspected PID family but only two distinct timestamps overall; the four PID 42171 fork/exec transitions collapse to one timestamp despite distinct native Endpoint Security event times. This is the first target for loop 9's fresh-output verification.
- **Blind-copy integrity:** all **120** `data/` files were copied without metadata and SHA-256 verified against the generation manifest before review.

## Independent expert panel

| Expert | Verdict | Verdict confidence | Synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Likely synthetic | 76 | 72 |
| Detection Engineer | Likely synthetic | 87 | 84 |
| Network Forensics | Likely synthetic | 65 | 62 |
| Host/EDR Forensics | Likely synthetic | 81 | 78 |
| **Mean** | **likely synthetic** | **77.25** | **74.0** |

Verdicts agree, so deliberation was not triggered. The mean synthetic-confidence score rose from loop 7's 56.5 to 74.0 (+17.5). This is not evidence that the SSH fix regressed: reviewers no longer reported the two APP-INT-01 root syslog gaps, while identifying separate Mac authentication ordering, process timing, and sensor-shape concerns. The expired R3 intermediate also recurred as a network finding.

## Prioritized findings

1. **P0 — macOS eCAR process transitions collapse distinct execs to the same timestamp (`contract_gap`).** The direct probe shows distinct native Endpoint Security events for PID 42171 rendered at one eCAR millisecond. This breaks process-image transition ordering for all consumers; loop 9 validates the execution-identity timing-key fix across fresh output.
2. **P0 — Mac SSH accepted-auth messages follow dependent shell execs (`contract_gap`).** Detection Engineering found this on both Macs: the `/bin/zsh` exec precedes the Unified Log accepted-auth message by 778 ms on MAC-MROSS-01 and 32 ms on MAC-MROSS-02. Inspect the SSH bundle's native source timing and readiness ordering so visible auth acceptance precedes shell readiness on every Mac receiver path.
3. **P1 — Expired R3 intermediate recurs in a completed TLS session (`environment_or_collection_plausibility`).** Network review again found a www.reddit.com chain with an intermediate expired before the capture. Confirm chain validity behavior and fix the owning data-driven TLS issuer/certificate profile if the modeled client is intended to accept only currently valid chains.
4. **P2 — Dense five-minute scan and compactly staged high-risk actions (`distribution_texture`).** The WEB-EXT-01 nmap burst is visible and plausible in an incident; do not alter attack intent based on narrative legibility alone. Verify the owning scan traffic and baseline distribution if later reviews show this concentration as a repeatable renderer fingerprint.
5. **P3 — Mac Endpoint Security `seq_num` appears event-type-local (`weak_signal`).** Host/EDR review observed counters restarting per event type while `global_seq_num` supplies merged order. This needs validation against the modeled ES export contract before changing serialization.

## Loop 9 candidate

Validate the Mac eCAR process-execution timing fix against a fresh full generation and multiple fork/exec lifecycles. Then investigate the two-host SSH auth-before-shell ordering through the shared Mac SSH startup timing contract; preserve the distinction between canonical auth time, source-observed Unified Log time, native ES process startup, and eCAR session readiness.

Artifacts include the family contract, four reports, automated evaluation, root-cause probes, and scores. Loop 8 is complete for the Linux SSH family. The additional Mac timing family is explicitly carried to loop 9 because the available generated output predates its planner fix.
