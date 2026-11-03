# Fixed Mac workstation acceptance workload

This is an invented development lab with one developer and two macOS 27 arm64 Macs.
MAC-APPLE uses Apple Terminal; MAC-ITERM uses iTerm2. No packs, local inventory,
native captures or private values are inputs. The Schema 3 draft is a complete
managed artifact (`draft.json` plus `source/`); it is not published.

The fixed thirty-minute scope includes fresh terminal starts, local commands,
non-PTY and PTY Mac-to-Mac SSH, real catalog Chrome and its three helper roles,
browsing, two background OS-inventory job activations, and ordinary medium-intensity
baseline activity. Both terminals and every target command/app/job start are
inside collection. `WORKLOAD.yaml` records the intended activities independently
of what native generation currently accepts. Do not remove a failing family,
substitute the reference app, change the seed, move target starts into warm-up or
suppress background process activity to obtain a passing result.

The Chrome reference corrected one physical-image expectation: GPU work used the
generic Helper executable, which also runs the network role. The fixture now
selects that observed variant, preserving all three required operational roles.
Measurement checks each role's argument vector as well as file identity, so a
network helper alone cannot satisfy GPU coverage. The unobserved dedicated-GPU
variant remains outside the bounded native producer. No activity, time, seed,
baseline requirement or completeness gate was removed by this correction.

The first low-intensity diagnostic scheduled no user timestamps at this seed.
During initial workload construction, intensity was raised to medium to exercise
the background requirement. The seed, time window and all intended activities
were retained. Both initial and active-baseline results are reported; a zero-start
baseline never counts as acceptance.

The OS-inventory job and its fixture provisioning caller are explicitly installed
and registered before collection. The caller is pre-existing setup state; its
startup is **not** claimed as qualified. Registration starts no job. Both actual
job activations and their known completed exits occur during collection. This
boundary is part of the original workload, not a workaround added after failure.

Four validation warnings are intentional: three pre-collection setup steps, and
no firewall sensor in this endpoint/SPAN-focused lab. No ASA evidence is claimed.
Sources are native ES, eCAR, bounded Unified Log, zsh history and Zeek. Unified Log
selection does not imply general app-launch or launchd message coverage.

Run from the repository root:

```sh
uv run eforge validate scenarios/macos-workstation-acceptance/source/scenario.yaml --json --checkpoint-hours 0
uv run eforge generate scenarios/macos-workstation-acceptance/source/scenario.yaml --output /path/to/a/new/bundle --checkpoint-hours 0
uv run python scripts/measure_macos_workstation.py --workload scenarios/macos-workstation-acceptance/WORKLOAD.yaml --output /path/to/a/new/measurement
```

The full unchanged scenario is the acceptance target. A failed run is not an
accepted bundle. Diagnostic slices retain the same environment, apps, window,
seed and baseline but select activity groups and explicitly request partial
coverage. Their counts include common startup and baseline, overlap across runs,
and must never be summed or presented as full-workload acceptance.

Acceptance requires a successful full bundle, positive background process evidence,
every intended activity realized, exact independent fork/exec reconciliation with
no aggregate starts, ingestible native records and matching eCAR relationships.
Then native-only filtering and checkpoint/resume must preserve the result. Passing
parsing/count checks establishes implementation coverage, not universal Mac fidelity.
