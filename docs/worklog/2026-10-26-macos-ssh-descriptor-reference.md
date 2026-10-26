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

## Human-reviewed result and bounded producer

The human shared only the fixed comparison report in this chat. Contexts were complete,
provenance passed, and all inventory, instrumentation, standard-only, open-stream, type and
close-on-exec controls passed. No private path, file, native record, identifier or service
process was inspected by the agent.

The tested external command without a PTY had three distinct pipe objects: stdin was read-only,
stdout/stderr write-only, and none was a tty. Local iTerm2 and SSH with a PTY instead had three
read/write VNODE handles to the same terminal node. That comparison does not prove a shared
open-file description or offset. This is own-process post-exec evidence only; helper inventories,
server-side sockets and ES export were not collected. `reference_review: REQUIRED` and
`gate_status: NOT_EVALUATED` remain the kit's deliberate scope, not an automatic acceptance claim.

Revision 335 selects `ssh_command_descriptors: standard_pipes` in the frozen execution policy.
The existing authenticated SSH start batch reserves three pipe identities in the existing
host-native namespace. The new immutable `MacosSshCommandStreams` attaches them to the session;
allocation, rollback and recovery share existing owners, with no new pipe registry. Each later
qualified external command without a PTY receives fd 0/1/2 at its canonical exec boundary from
that channel. Its exact bound shell, audit identity, terminal absence and readiness are checked.
Already known inherited tables remain authoritative. The shell/helper table and the fork's
pre-exec table remain unknown; nothing backfills them from the post-exec observation.

Native v11 exec publication can now render those commands with their actual requested image,
argv, canonical metadata and pipe descriptors. Output selection does not change canonical
allocation. Subsequent commands share channel identities; new channels get fresh IDs. PTY
generation, helper startup exec tables, GUI responsible-process ownership and unknown exit
outcomes remain outside this milestone. No new scenario field or event family is introduced.

StateManager checkpoint schema 9 retains channel metadata through active-session record v3
and validates exact owner/counter relationships before adoption. Older no-stream session records
retain v2 encoding; heads 6/7/8 remain explicitly compatible and restore unknown streams.
Corrupt owners, missing native counters and new metadata disguised as an old head are rejected.

### Producer verification

The broad Mac/State/manifest selection passed 3,217 tests; its only three failures were old
fork-only output counts. Those tests now verify the additional command exec rows and recovery
cardinality. The subsequent 161-test selection passes, including all 23 new SSH stream cases,
storyline commands, segmented/incremental recovery and unchanged lifecycle schema compatibility.
Invented real-engine cases cover selected/filtered native output and current/disabled policy.
No live collector, native probe, SSH connection, private reviewer or local-log reader was run.
All 13 selected slow integration/CLI/fresh-process checks pass without coverage. Full Ruff
check and formatting pass (1,341 files), as do the revision-335 behavior digest and whitespace
checks. Canonical Mac skill references were regenerated into the ignored project installation.
