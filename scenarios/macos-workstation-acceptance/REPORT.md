# Mac workstation acceptance after native Chrome integration

The complete workload now generates successfully, including Chrome and all three
required helper roles. Every modeled process start/successful exec in both full
runs reconciles exactly with ES, with zero aggregate starts. This is bounded
engineering acceptance, not universal macOS or Chrome authenticity.

The primary seed remains **not fully exercised** for the original positive
background requirement: it schedules no background process starts. The separate,
predeclared supplemental seed does exercise that path and remains separately labeled.

| Full workload | Forks expected / ES | Execs expected / ES | ES rows | Background execs | Native census |
| --- | ---: | ---: | ---: | ---: | --- |
| Primary seed 373 | 33 / 33 | 39 / 39 | 84 | 0 | Exact; background unexercised |
| Supplemental seed 375 | 37 / 37 | 44 / 44 | 93 | 5 | Exact; positive background |

Both runs retain all authored target activities, two Macs, Terminal and iTerm2,
SSH with and without a PTY, browsing, inventory jobs, the thirty-minute window,
medium baseline intensity and complete native coverage policy. There are no
missing executable roles, authored PID/image traces or fork/exec obligations.
The two explicitly optional warmup cleanup logoffs may be no-ops when no warmup
session exists; only their typed no_matching_session result is accepted.
Skipped process starts and other unsuccessful actions cannot use that exception.

The reference corrected the GPU physical-image expectation: the generic Chrome
Helper ran GPU work. The fixture preserves renderer, GPU and network roles, and
measurement requires their argument vectors independently. Sharing a helper
executable cannot let one operational role satisfy another. This corrects the
variant; it does not remove the GPU activity or lower the completeness policy.

Verification on the primary full bundle:

- All 33 forks and 39 execs agree with eCAR, including exec identity versions,
  paths and canonical argument vectors.
- Native-only output is byte-identical across both hosts: all 84 ES records.
- Deterministic evaluation verifies the authoritative bundle and passes every
  applicable hard gate, with score 88.9227/100. Low behavioral diversity and
  noise volume remain reported limits of this small lab.
- The separate twelve-hour native browser-helper checkpoint gate passes
  suspension, integrity verification, exact resume and deterministic output
  equivalence while retaining live helpers at the checkpoint. Unit fault tests
  cover both fork and exec before-commit/lost-return recovery, one pipe allocation,
  State snapshot restoration and no duplicate process identities.

The exact thirty-minute source has no usable intermediate hourly suspension
boundary. A checkpoint-enabled attempt finished without reaching the test hook;
it does not count as full-workload recovery acceptance. No source time or duration
was changed to disguise that limit. The component recovery gate is explicitly
separate from this remaining full-workload acceptance condition.

The producer uses frozen synthetic release identities and declared environment,
pipe-slot and timing choices. Static vendor templates and bounded macOS 27
relationships are qualified independently; the private installed Chrome build
differed from the frozen catalog and does not establish exact release parity.
Dedicated-GPU, Crashpad double-fork, alerts and arbitrary helper invocations remain
outside this bounded producer. Unknown exit outcomes stay unknown. No general
app-launch Unified Log family, browser IPC or helper-owned network traffic is inferred.
No private capture, native record or observed private value is included here.

Machine-readable current results: [CHROME-RESULTS.json](CHROME-RESULTS.json).
Synthetic bundles are retained under
`runs/macos-workstation-acceptance/2026-11-02-chrome-native-374/` (ignored).
Generation behavior revision: 374. No product release version is changed.

The [initial measurement](INITIAL-REPORT.md) and [original slice results](RESULTS.json)
remain historical evidence of the former Chrome blocker; they are superseded by
this report for current capability. No assessment loop was started.
