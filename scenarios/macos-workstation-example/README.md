# Experimental Mac workstation examples

These compatible Scenario 1.0 inputs use invented identities and the existing configuration fields. `scenario.yaml` models one macOS 27 arm64 workstation; `mixed-fleet.yaml` adds independent Windows and Linux workstations. They generate evidence about Macs and do not require the generator host to be a Mac. `smb-client.yaml` adds an explicitly logged-in Mac client reading a mounted Windows share. These are experimental examples, not complete native-investigation demonstrations.

From the repository root:

```sh
uv run eforge validate scenarios/macos-workstation-example/scenario.yaml
uv run eforge generate scenarios/macos-workstation-example/scenario.yaml --output ./output/eforge-mac-example --seed 123
uv run eforge validate scenarios/macos-workstation-example/mixed-fleet.yaml
uv run eforge generate scenarios/macos-workstation-example/mixed-fleet.yaml --output ./output/eforge-mixed-example --seed 123
```

Choose unused output directories. The Mac source set is eCAR, visible Zeek traffic and experimental zsh history. Bash history is selected to exercise source isolation: only an explicitly modeled interactive Bash session can produce Mac Bash history. Windows and Linux endpoint logs remain local to their respective hosts. The examples intentionally omit firewall sensors and therefore produce a validation warning about unavailable firewall evidence.

The selected history profile models single-line ASCII commands with incremental append and zero elapsed time at submission. It does not reconstruct personal shell configuration or exit-only history persistence. Native Endpoint Security generation, complete Unified Log lifecycle coverage, persistence and security-control outcomes remain separate implementation gates; do not treat successful generation as validation of those capabilities.

For mounted SMB, run `uv run eforge validate scenarios/macos-workstation-example/smb-client.yaml` and generate it with the same CLI pattern. The existing mapping, `client_access: auto` and `path_style: mounted` resolve `/Volumes/team`; no Mac configuration block is needed. Client file evidence requires an eligible local session. The operation actor owns file activity, while the shared transport has no invented process attribution. Windows server records remain on FS-TEST. Native Mac SMB logs, Finder mount discovery and Mac SMB serving are not implemented.

`ssh-client.yaml` models a local Mac login followed by SSH to Linux. Validate and generate it with the same CLI pattern. Its receiver-side `ssh_session` names the Mac through `source_ip`; an eligible Mac session owns the native client and its interactive history. The authored receiver logoff closes that SSH client and transport within the collection window. Separate baseline sessions may extend beyond collection. The shared bundle keeps process lifetime and transport consistent, while Linux owns receiver syslog. Bounded Mac receivers now support explicit arm64 workstation/local-user/service configuration and automatic or paired authored closure. Native Mac SSH logs and SCP/SFTP receiver helpers remain unavailable.

`native-workspace.yaml` adds `macos_unified_log` through existing `output.logs` syntax and an explicit local login. Generate it with the same CLI pattern. Its per-host NDJSON contains only loginwindow workspace-method entry; it does not prove desktop startup completed. Writer UID, PID, thread, image and uptime come from canonical owners. The experimental profile uses synthetic callsite offsets and modeled timing; it makes no external SIEM or other native-event claim.

`history-exposure.yaml` uses the existing `spillage` event with `surface: shell_history` to submit an invented ASCII value through the local zsh session. Validate and generate it with the same CLI pattern. Collect `zsh_history`; selecting Bash history does not change the modeled shell. The record proves submission, not execution success or network effects. Unsupported or unavailable shell ownership yields no emitted exposure label. Explicit Mac Bash sessions remain supported through their existing history owner, but this authored exposure profile selects zsh.
