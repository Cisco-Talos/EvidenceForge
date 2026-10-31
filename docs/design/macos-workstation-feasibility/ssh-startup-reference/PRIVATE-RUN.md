# Private macOS 27 SSH startup reference

This is a human-run experiment. Close agents before setup or collection. Keep all native
records, provenance, terminal text and account details private. Share only the final fixed
JSON report from Window A. The kit must stay outside Git; never copy its run files into the
repository. The agent may prepare code and test invented records, but may not run this capture.

This measures one non-PTY loopback connection through the already enabled Remote Login
service. It changes no SSH/server/privacy settings and installs no persistent job. It checks
client and receiver exec shapes, helper ancestry, credentials/audit/responsibility, runtime
security, CPU slice, public entitlement templates and descriptor layouts in one experiment.
It collects no Unified Log or PTY workload.

The collector's machine-wide process stream is inspected only in bounded local memory. A
random marker proves the exact receiver ancestry; a separate controlled client environment
marker and private PID control prove the client. Only that connected tree/client may be
saved, privately, after provenance/linkage checks and collector cleanup. Unrelated records
never reach disk or the report. Captured environment and arguments may contain private data;
the report returns only fixed labels. Original captures remain private even after success.

Use a terminal app that already has Full Disk Access. iTerm2's permission does not apply to
Apple Terminal. Remote Login must already be enabled and allow your own account. No changes
to those settings are part of this procedure. Local password or keyboard-interactive
authentication must be available: the client disables agent use, public-key authentication,
forwarding, proxy hooks, multiplexing and user/system SSH configuration. Host-key verification
stays enabled, with an isolated kit-local known_hosts file. Authenticate and verify any
loopback host-key prompt privately; do not share prompts, fingerprints, passwords or banners.

## 1. Setup, once

Open two windows in the permitted terminal app, both as your normal user. In each window,
change into the fresh kit directory supplied by the agent. In Window A run:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py setup --private-run
```

Continue only if it returns `stage: SETUP_READY` and `error: NONE`. Setup compiles/signs a
small no-output marker and a bounded collector guard; it starts no SSH connection or collector.
Do not rerun setup in a used kit. If setup fails, share only its fixed JSON and use a fresh kit
for a new attempt. Keep the same directory for the remaining steps.

## 2. Window A: start collection

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py capture --private-run
```

Only the internal collector runs with sudo. Never prefix Python with sudo.
Wait for the single-line `stage: COLLECTOR_READY` message. Then move immediately to Window B.
The connection window is 140 seconds; the guard has an independent 180-second hard stop.
Ctrl+C in Window A cancels and cleans up the collector. A used kit needs replacement even
after failure; do not delete locks or rerun capture in it.

## 3. Window B: connect and run the marker

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py connect --private-run
```

This prints a private `PRIVATE_REMOTE_COMMAND`, then replaces itself with the loopback SSH
client, preserving the window's standard descriptors. Copy that one printed command privately.
Complete SSH authentication. After authentication, paste the printed `exec ... --sample ...`
command and press Enter. A non-PTY shell may show no prompt. This command runs the marker and
ends the remote shell; SSH should return to your local prompt. Do not paste any other commands.
Do not run `id`, `env`, `ps`, or debugging commands to diagnose a failure.

## 4. Share the report

Window A drains termination events, stops the collector, and prints the fixed JSON. Share that
JSON only. The report deliberately retains `reference_review: REQUIRED` and
`gate_status: NOT_EVALUATED`; successful acquisition does not automatically qualify generation.

If you need to print that saved fixed report again:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py report --private-run
```

This reads the saved report only. Do not share native JSONL, setup/provenance/control files,
terminal output from Window B, screenshots or private paths. If the report fails, share only
its fixed JSON; do not open capture records for the agent. Any additional offline review needs
separate approval under the standing local-log rule.
