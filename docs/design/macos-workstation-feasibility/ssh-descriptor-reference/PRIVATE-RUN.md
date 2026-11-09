# Private SSH descriptor comparison

HUMAN ONLY. Close Codex and all other agents before running any collection,
setup, native probe or report. An agent may prepare a code-only kit, syntax-check
the C/shell sources without executing them, and run invented-input tests only.
Never let an agent inspect a kit after handoff, including to check for a report.

## What this measures

The user has confirmed that Remote Login is already enabled locally. The launcher
uses that existing service at **127.0.0.1**, as the current user, without sudo or
service/security configuration changes. It runs a local control, an SSH command
without a pseudo-terminal and an SSH command with one. The probe reads only its
own descriptor list, standard-stream flags/stat **metadata**, and whether those
streams refer to the same object. It does not read descriptor contents, system
logs, environment variables, other processes, personal paths or command history.

Native PID, device/inode and opaque pipe identifiers are used only inside the
human-run probe and discarded. They are never printed or written to a file.
The probe exports only enum/check values, even to its private result file. The
Python report validates those values and rejects unknown keys or free text.
Source/binary hashes stay in a private provenance file and never enter the report.

The reporting FD is added by the wrapper and excluded by its exact identity.
The probe validates it as a newly created owner-only regular file, verifies a
stable bounded own-FD inventory, and records whether any additional descriptors
exist. It preserves the inherited stdin/stdout/stderr: no subprocess capture pipe
or redirection changes the standard streams being measured. The eight-second
probe alarm bounds its execution. No kernel handle or numeric descriptor extent
is exported. Additional FDs are a reported limitation, never silently discarded.

The client's normal authentication happens privately. Its config files are
bypassed; agent/X11/other forwarding, connection multiplexing and local-command
hooks are disabled. Host keys are confined to `known_hosts` inside this kit;
host-key verification remains enabled and keys are not auto-accepted. This does
not change your normal known_hosts file. Any authentication prompt, server banner
or host-key information is for your eyes only. Existing system endpoint/audit
monitoring may observe the test like any other SSH login; it is not disabled.

## Run the three samples

1. Copy these instructions, save work as needed, then quit Codex and other agents.
   Use a normal **local iTerm2** window, without SSH/tmux/screen, pipes or redirection.
   No logout is needed. Do not move the kit into a repository or reuse an old kit.
2. Replace `KIT` below with the new code-only kit path provided by Codex:

   ```sh
   /bin/bash KIT/RUN-LOCAL.sh
   ```

3. The first step compiles the reviewed C probe (bounded to 30 seconds). Expect
   `KIT_READY`, three `SAMPLE_SAVED_PRIVATELY` markers and a final JSON report.
   Fixed `PRIVATE_STEP_...` markers show the current phase. The two loopback
   connections may ask for your normal SSH authentication and first-use host-key
   verification. Verify the localhost key privately using your usual trusted
   local procedure; do not bypass verification or paste its fingerprint here.
4. Privately review the **final JSON only**. The intended complete run reports
   `error: NONE`, `contexts: COMPLETE` and `provenance: PASS`. Each observation
   reports descriptor kinds, access modes, terminal presence and object
   relationships. These are observations, not outcomes to force into a pattern.
5. Reopen Codex and paste only the final JSON. No screenshots, banners, prompts,
   SSH errors, fingerprints, private paths or other files should be shared.

If the launcher stops early, do not rerun or overwrite samples. You may privately
run the fixed report command:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B KIT/private_ssh_descriptors.py report --private-run
```

Share only that fixed report and the last `PRIVATE_STEP_...` marker. A failed
authentication/host-key check is a setup limitation, not permission to change
Remote Login, keys, SSH server settings or privacy controls. A fresh attempt uses
a newly prepared kit. Keep any private troubleshooting local.

## Evidence boundary

The sample is the controlled external command after SSH exec, not sshd's complete
startup graph, the shell's internal FD table, a server-side socket inventory or
an Endpoint Security export. A Python-to-C exec preserves inherited standard
streams; the added report FD is instrumentation. An SSH context is explicitly
human-attested and constrained by the reviewed loopback launcher; the probe does
not inspect connection addresses, environment or another process to establish it.
`reference_review: REQUIRED` and `gate_status: NOT_EVALUATED` remain present.
No generator policy or native gate is changed by collection alone.

For VNODE streams, `SAME` compares the underlying terminal node; it does not establish a shared
open-file description, file offset or access history. Pipe comparisons distinguish the opaque
pipe objects only within the native probe. Neither comparison exports a native identifier.

API meaning follows Apple's public
[proc FD structures](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/proc_info.h)
and [libproc declarations](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/libsyscall/wrappers/libproc/libproc.h).
These version-sensitive interfaces are used only against `getpid()`. The human
macOS 27 result is needed for the modeled SSH descriptor policy.
OpenSSH's [client manual](https://man.openbsd.org/ssh.1) documents the explicit
PTY and client-configuration controls. No source implementation was copied.
