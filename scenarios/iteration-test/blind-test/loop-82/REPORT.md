# Loop 82 — independent blind checkpoint

This fresh panel reviewed a neutral copy byte-identical to loop81's 113 source files. No generator behavior changed. Reused scenario validation and authoritative evaluation: **96.5648 PASS**, 142,740 records (parseability 100.00, plausibility 96.93, causality 97.17, timing 90.20).

## Independent reviews

- **Threat Hunter — Synthetic, confidence 78, synthetic-confidence 68.** Identified a missing source-local process chain around WEB-EXT-01's encoded shell pipeline, despite routine pipeline children appearing elsewhere; repeated Linux diagnostics were weaker.
- **Detection Engineer — Synthetic, confidence 82, synthetic-confidence 72.** Flagged Endpoint Security fork/exit notification messages as carrying an authorization result. Apple documentation confirms the shape: NOTIFY uses the `action.notify` `es_result_t` union, whose result type selects auth vs flags.
- **Network Forensics — Synthetic, confidence 67, synthetic-confidence 62.** Reported 5,134 matching core/DMZ tuples with a median −114.245 ms offset and 99.9% within 5 ms; the configured distributed-tap model explicitly uses controlled per-sensor offsets and shared clock wander; this is a weak signal, not a proven defect.
- **Host/EDR Forensics — Inconclusive, confidence 62, synthetic-confidence 36.** Found high Windows Security/Sysmon and macOS ES/eCAR process correlation; did not identify a hard endpoint contradiction.

Standalone mean synthetic-confidence is **59.50** (mixed/inconclusive), spread 36. The 3–1 verdict split and score spread triggered deliberation; its calibrated mean is **65.50**. The strongest inspectable candidate is the typed Linux process event's shell-pipeline visibility. Independent validation resolved the Endpoint Security claim as source-native and found the sensor offset within the configured distributed-tap model. The Linux pipeline process gap remains the only concrete candidate for a family repair.

## Candidate findings and status

| Priority | Finding | Category | Status |
|---|---|---|---|
| P2 candidate | WEB-EXT-01 records `bash -c 'echo ... | base64 -d | bash'` and a related flow, but no `base64` or nested `bash` process records | `contract_gap` | Verify whether typed storyline process handling emits pipeline stages and preserves process-to-flow ownership. `echo` is normally a shell builtin and should not be assumed to have a separate PID. |
| Candidate | ES notification messages have nested `result_type: 0`, `result.auth: 0` | `schema_or_format` | Verify Apple's action union: `action_type=NOTIFY` uses `action.notify` (`es_result_t`), whose own `result_type` selects auth vs flags. |
| Weak signal | Core/DMZ tuple timestamps cluster around −114 ms | `distribution_texture` | Within `distributed_taps` clock-offset bounds and consistent with shared clock wander + route delay. No timing change; see `network-clock-probe.json`. |
| P4 | Repeated Linux diagnostics across roles | `distribution_texture` | Weak pattern; hold without cross-host behavioral evidence. |

No code change is selected for loop82. Loop83 will repair the typed Linux process pipeline path if owner-level inspection confirms the source-local child-process gap. Next loop will resolve the Endpoint Security claim from Apple's message schema and validate the Linux pipeline gap against current typed-event/process-action owners. Artifacts: `scenarios/iteration-test/blind-test/loop-82/`.


## Post-deliberation technical checks

- Apple documents `es_message_t.action` as an AUTH/NOTIFY union. With `action_type=NOTIFY`, the active arm is `action.notify` (`es_result_t`); `result_type` then chooses `auth` or `flags`. The data's `action_type=1`, `result_type=0`, `auth=0` is therefore valid notification/result serialization, not an authorization request on a fork/exit event. See [`macos-action-probe.json`](macos-action-probe.json) and Apple's [action_type](https://developer.apple.com/documentation/endpointsecurity/es_message_t/action_type), [action union](https://developer.apple.com/documentation/endpointsecurity/es_message_t/action), and [result union](https://developer.apple.com/documentation/endpointsecurity/es_result_t/result) docs. No format or emitter change.
- The −114 ms core/DMZ offset falls within the declared `distributed_taps` clock-offset range. The source model deliberately uses per-sensor clocks, route delays, and shared slow wander; the narrow cluster is a weak configured-model texture, not a demonstrated defect. Do not inject arbitrary per-flow jitter.
- For WEB-EXT-01's shell command, Bash pipeline members execute as child processes; `echo` is a builtin but in a pipeline it runs in a subshell. The generated eCAR has only the root `bash -c` create/terminate and a flow attributed to that root PID, whereas ordinary pipeline commands on another Linux host emit child-process records. The typed storyline process path currently creates a single process; the catalog/bash activity path expands pipeline stages. Investigate this shared process-execution family before implementing a repair.
