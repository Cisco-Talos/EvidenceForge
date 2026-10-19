# Explicit Mac system-job workflow
This invented macOS 26 arm64 example writes and bootstraps a system LaunchDaemon definition, removes its file, then activates the already-loaded definition. It models a completed leader exit, a second activation and group unload. The provisioning process and all file/process identities are synthetic.
Run from the repository root:
```sh
uv run eforge validate scenarios/macos-persistence-example/scenario.yaml
uv run eforge generate scenarios/macos-persistence-example/scenario.yaml --output ./output/macos-persistence-example --seed 123
```
The workflow produces eCAR process/file evidence and ordinary selected network/history evidence. Registration has no supported native observation and is explicitly marked unobserved in ground truth. Root provisioning commands are noninteractive and do not imply shell history. No native plist artifact, ES lifecycle stream, policy denial or launchd message is generated. `run_at_load` does not schedule activation; stages must be explicit, and the bounded workflow requires unload before scenario end.
