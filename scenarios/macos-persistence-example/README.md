# Explicit Mac system-job workflow

`native-system-job.yaml` selects the bounded `root_xpcproxy_v11` native preset for Apple's
installed `/usr/bin/true`. Two activations after plist removal produce **two real forks,
four exec records and two explicit zero exits**, while preserving the loaded environment
and distinct process groups. Native-only filtering and active-job checkpoint/resume are
covered by CLI acceptance tests. Registration and dormant unload have no native message.

```sh
uv run eforge generate scenarios/macos-persistence-example/native-system-job.yaml --output ./output/macos-native-system-job --seed 372
```

The invented provisioning caller starts explicitly during warm-up, before collection. Its
unqualified startup is outside this measured workload; validation retains an out-of-window
warning. An arbitrary provisioner starting during collection still fails complete coverage.
No private capture/token is used. Other job images, domains, automatic triggers and launchd
Unified Log messages remain unqualified. See the
[bounded reference](../../docs/design/macos-workstation-feasibility/launchd-reference/REFERENCE.md).

The following older examples retain the explicit partial/aggregate workflow:

This invented macOS 27 arm64 example writes and bootstraps a system LaunchDaemon definition, removes its file, then activates the already-loaded definition. It models a completed leader exit, a second activation and group unload. The provisioning process and all file/process identities are synthetic.
Run from the repository root:
```sh
uv run eforge validate scenarios/macos-persistence-example/scenario.yaml
uv run eforge generate scenarios/macos-persistence-example/scenario.yaml --output ./output/macos-persistence-example --seed 123
```
The workflow produces eCAR process/file evidence and ordinary selected network/history evidence. Registration has no supported native observation and is explicitly marked unobserved in ground truth. Root provisioning commands are noninteractive and do not imply shell history. No native plist artifact, ES lifecycle stream, policy denial or launchd message is generated. `run_at_load` does not schedule activation; stages must be explicit, and the bounded workflow requires unload before scenario end.

`group-cleanup.yaml` adds two invented long-running descendants using the existing `--keep-alive` lifetime convention. Both inherit the system job's POSIX group, and explicit unload closes all three processes. Ordinary short-lived descendants can instead exit before unload; surviving children are adopted by the modeled PID 1 without changing their original ancestry or group. The same source and artifact limitations apply.
