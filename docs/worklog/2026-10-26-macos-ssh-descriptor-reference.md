# Private SSH descriptor experiment

## Authorized scope and privacy

The user requested data collection before each remaining Mac producer item.
The [GUI audit-origin milestone](2026-10-26-macos-gui-audit-reference.md) is
implemented and pushed as `5569348e`. The human confirmed that **Remote Login
is already enabled locally**. The next experiment may use that existing
loopback service; no service/security changes, log inspection or agent-run
collection are authorized. The human alone runs and reviews with agents closed.

This code-only kit queries only the controlled probe's own FD list and selected
standard-stream metadata. It never reads stream contents, environment, personal
paths, other processes or system logs. Numeric/stat/opaque pipe identities are
compared only in native process memory and never exported or retained. Even the
private observation files contain only fixed comparisons. Code provenance hashes
stay private and cannot enter the report. No captured data belongs anywhere in
Git, including ignored directories. Do not inspect any old or handed-off kit.

The human launcher compiles locally, takes a normal local iTerm2 control, then
runs two external commands through SSH at `127.0.0.1`, without and with a PTY.
It bypasses client configuration, disables agent/X11/other forwarding, local
command hooks and multiplexing, and confines known_hosts updates to this kit.
Host-key verification remains enabled and human authentication stays private.
The agent has not connected or inspected the service. The wrapper execs the
probe without replacing stdin/out/err with collection pipes. It passes one
exclusive owner-only report FD; the probe validates/excludes that exact
instrument and verifies a stable bounded own-FD inventory. Extra descriptors
are an explicit failed standard-only control, not silently omitted evidence.

This measures the controlled post-exec command, not sshd's startup FD graph,
shell-internal descriptors or native ES export. Human-attested loopback context,
reference review required and gate not evaluated remain explicit. A result can
inform a bounded canonical SSH command-descriptor producer after review; it
cannot authorize invented server helper tables or new native event families.

## Code and human handoff

- `scripts/macos_ssh_descriptor_reference.py`
- [human instructions](../design/macos-workstation-feasibility/ssh-descriptor-reference/PRIVATE-RUN.md)
- `tests/unit/test_macos_ssh_descriptor_reference.py`

Prepared code-only kit: `/private/tmp/eforge-ssh-fd-kit-7jltcd6q`.
**Do not inspect this directory after handoff**, even to check for result files.
The human can run `/bin/bash` against its `RUN-LOCAL.sh` with all agents closed,
then share only the privately reviewed fixed JSON. On failure, accept only the
fixed report and last `PRIVATE_STEP_...` marker. Never request a screenshot,
banner, host key, SSH error text or private file. New attempts need fresh kits.

## Verification

All **378 invented-input private-kit tests** pass, including 53 new SSH contracts
and the unchanged 325 GUI/capture/reviewer contracts. They cover enum-only
reports, canary redaction, partial/unknown inputs, explicit context attestation,
safe preparation, Git/path/file boundaries, source provenance, preserved stream
inheritance and mocked compilation/exec. No native preflight or probe was run.
The C source passes syntax-only compilation with strict warnings; the shell
launcher passes `bash -n`. Neither was executed. Full Ruff checks/formatting pass
(1,339 files). This kit changes no generation code, behavior revision or gate;
the completed GUI producer remains revision 334. Collection/review remain human work.
