# Experimental Mac workstation examples

These compatible Scenario 1.0 inputs use invented identities and the existing configuration fields. `scenario.yaml` models one macOS 26 arm64 workstation; `mixed-fleet.yaml` adds independent Windows and Linux workstations. They generate evidence about Macs and do not require the generator host to be a Mac. `smb-client.yaml` adds an explicitly logged-in Mac client reading a mounted Windows share. These are experimental examples, not complete native-investigation demonstrations.

From the repository root:

```sh
uv run eforge validate scenarios/macos-workstation-example/scenario.yaml
uv run eforge generate scenarios/macos-workstation-example/scenario.yaml --output ./output/eforge-mac-example --seed 123
uv run eforge validate scenarios/macos-workstation-example/mixed-fleet.yaml
uv run eforge generate scenarios/macos-workstation-example/mixed-fleet.yaml --output ./output/eforge-mixed-example --seed 123
```

Choose unused output directories. The Mac source set is eCAR, visible Zeek traffic and experimental zsh history. Bash history is selected to exercise source isolation: only an explicitly modeled interactive Bash session can produce Mac Bash history. Windows and Linux endpoint logs remain local to their respective hosts. The examples intentionally omit firewall sensors and therefore produce a validation warning about unavailable firewall evidence.

The selected history profile models single-line ASCII commands with incremental append and zero elapsed time at submission. It does not reconstruct personal shell configuration or exit-only history persistence. Native Endpoint Security/Unified Log generation, full execution-epoch projection, SSH receivers, persistence and security-control outcomes remain separate implementation gates; do not treat successful generation as validation of those capabilities.

For mounted SMB, run `uv run eforge validate scenarios/macos-workstation-example/smb-client.yaml` and generate it with the same CLI pattern. The existing mapping, `client_access: auto` and `path_style: mounted` resolve `/Volumes/team`; no Mac configuration block is needed. Client file evidence requires an eligible local session. The operation actor owns file activity, while the shared transport has no invented process attribution. Windows server records remain on FS-TEST. Native Mac SMB logs, Finder mount discovery and Mac SMB serving are not implemented.

`ssh-client.yaml` models a local Mac login followed by SSH to Linux. Validate and generate it with the same CLI pattern. Its receiver-side `ssh_session` names the Mac through `source_ip`; an eligible Mac session owns the native client and its interactive history. The authored receiver logoff closes that SSH client and transport within the collection window. Separate baseline sessions may extend beyond collection. The shared bundle keeps process lifetime and transport consistent, while Linux owns receiver syslog. Mac receivers and native Mac SSH logs are not implemented.
