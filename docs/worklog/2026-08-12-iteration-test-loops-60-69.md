# Iteration-Test Assessment Loops 60–69

## Scope

Completed ten counted `eforge-assess` loops (60 through 69) against
`scenarios/iteration-test/scenario.yaml`. Each loop used deterministic scenario/config validation,
the default non-slow regression suite before generation, forced generation into a new immutable
loop directory, quantitative evaluation, targeted hard probes, four fresh isolated blind experts,
and a family-level fix selected from the blind findings. Loop 68 and loop 69 exceeded the mandatory
disagreement/spread threshold and received fresh report-only deliberations.

Blind agents were restricted to each loop's `output/data` plus the expert briefing/persona
references. They could not read the scenario, ground truth, evaluation, probes, source, parent
directories, or prior reports. Dataset integrity manifests confirm the reviewed output did not
change during each panel.

## Results

| Loop | Records | Eval | Threat / Detection / Network / Host | Initial avg | Deliberation |
|---:|---:|---:|---|---:|---:|
| 60 | 80,096 | 97.783 | 66 / 66 / 74 / 94 | 75.00 | — |
| 61 | 82,379 | 97.086 | 68 / 89 / 82 / 95 | 83.50 | — |
| 62 | 82,690 | 97.241 | 77 / 86 / 85 / 96 | 86.00 | — |
| 63 | 82,690 | 97.241 | 77 / 86 / 85 / 96 | 86.00 | — |
| 64 | 82,676 | 97.241 | 77 / 86 / 73 / 96 | 83.00 | — |
| 65 | 82,817 | 97.261 | 90 / 86 / 73 / 95 | 86.00 | — |
| 66 | 80,763 | 97.581 | 74 / 82 / 74 / 91 | 80.25 | — |
| 67 | 81,573 | 97.403 | 85 / 93 / 71 / 98 | 86.75 | — |
| 68 | 78,872 | 97.006 | 92 / 70 / 24 / 99 | 71.25 | 91.50 |
| 69 | 77,567 | 97.291 | 86 / 88 / 28 / 74 | 69.00 | 82.50 |

Loop 69's initial five-loop rolling mean was 78.65. The falling initial mean in loops 68–69 did
not indicate broad regression: network specialists increasingly judged that subsystem Real, while
host specialists found sharper endpoint identity contradictions. Deliberation explicitly resolved
this as scope weighting.

## Family-Level Changes

- **Loop 60:** repaired Windows background-process lifecycle ownership, including durable
  `taskhostw.exe` identity and dependent-aware termination.
- **Loop 61:** made scenario IP ownership the canonical source for internal PTR identity and private
  reverse-zone authority.
- **Loop 62:** made retained historical process lifetimes participate in host-local PID reservation.
- **Loop 63:** added data-driven TLS SNI predicates so domain-specific IDS rules attach only to an
  exact eligible flow.
- **Loop 64:** made the Linux sudo bundle own the visible `/usr/bin/sudo` lifecycle and PAM PID.
- **Loop 65:** attached sudo to a live user shell/session, modeled its elevated child, and terminated
  child then sudo after PAM close.
- **Loop 66:** allowed out-of-order baseline planning to deterministically bootstrap/reuse the sudo
  owner session.
- **Loop 67:** leased one stable TTY/session shell per host/user/TTY, serialized foreground sudo
  commands, made resolver recovery stateful, and constrained image loads to process lifetime.
- **Loop 68:** reused historical Linux sessions, unified PAM/eCAR login PID ownership, leased TTYs
  exclusively, restricted `wsqmcons.exe` to rare workstation-only activity, and improved multipart
  curl ownership metadata.
- **Loop 69 post-review:** resolved Security authentication/Kerberos provider PIDs through the
  host's canonical LSASS identity; registered pre-window sudo sessions as carried state instead of
  visible boundary logins; reused the PAM-owned local-login process for shell ancestry; and made
  child creates a termination floor for the eCAR parent process.

## Final Loop Findings

The loop-69 hard probes verified zero duplicate eCAR event IDs, exclusive TTY ownership across 67
successful sudo chains, no module-after-termination rows, and workstation-only `wsqmcons.exe`.
Twenty-seven of 31 successful PAM local-login records matched the exact eCAR `/bin/login` PID,
substantially improving loop 68. The blind panel then isolated the remaining two owner seams:
duplicate login processes/boundary session initialization and literal PID 600 across selected
Windows Security authentication families. It also confirmed one 28 ms eCAR
parent-termination-before-child inversion.

Network evidence is the strongest subsystem. The loop-69 network reviewer found coherent
sensor-local identities for 1,866 shared flows, fully contained protocol/file lifecycles, exact
loss-aware proxy byte reconciliation, realistic DHCP T/2 renewals, and complete ASA connection/NAT
lifecycle behavior. The initial network synthetic-confidence score was 28.

## Verification

- Scenario validation: valid with only expected advisory warnings.
- Config validation: 89 configuration files valid, zero errors.
- Every generated loop: automated evaluation PASS.
- Loop-69 quantitative evaluation: 97.29138173504755 over 77,567 records.
- Focused post-review regression tests: passed.
- Ruff lint and format checks: passed.
- Full post-review regression suite: 5,516 passed, 20 skipped in 359.16 seconds; no generated loop
  was mutated after its blind review began.

## Remaining Work

1. Regenerate to verify the post-loop-69 provider-PID and carried-session fixes against output-level
   probes and a new blind panel.
2. Add coherent source-process visibility/drop semantics for RDP and PsExec initiating endpoints.
3. Expand public scanner actor and TCP-fingerprint populations with a long one-off tail.
4. Correct the isolated explicit-credential source-context leak and addressless KDC 4771 request.
5. Continue reducing local-console density on Linux server roles.

Artifacts are under `scenarios/iteration-test/blind-test/loop-60` through `loop-69`; the aggregate
report is `scenarios/iteration-test/blind-test/REPORT.md`, and the trend visualization is
`scenarios/iteration-test/blind-test/assessment-effectiveness-dashboard-last-20-loops.svg`.
