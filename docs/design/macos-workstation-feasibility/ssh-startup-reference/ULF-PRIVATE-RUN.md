# Private SSH Unified Log reference

This opt-in extends the existing controlled loopback SSH workflow. Remote Login
must already be enabled. Setup snapshots the same installed SSH code and compiles
the same controls; it changes no accounts, SSH server configuration, logging policy,
Full Disk Access or persistent settings. Agents prepare code only. Setup and capture
are human-run after closing agents, in a terminal already permitted to run eslogger.

The ES marker authenticates one connection tree. A normal-user ULF reader keeps
SSH input in a bounded in-memory ring, never on disk while the connection is
unproved. Retention requires an exact server PID and executable path during a closed,
ES-authenticated execution interval in that selected tree. Launchd, clients, shells,
other connections, different images, reused PIDs outside that interval and unclosed
executions are excluded. Two streams have independent bounds. Only test-bound rows
reach private disk, outside Git; reports expose fixed classes and counts.

The ULF readiness marker contains only a generated nonce and authenticates its own
marker channel. It does **not** prove SSH ULF visibility. Zero SSH rows remains an
inconclusive native reference; no template is automatically enabled. Unknown message,
subsystem, category, format and identity values stay private. Do not paste native
records, terminal transcripts, private command text, names or paths into chat.

## Window A: setup and collection

Use the new `KIT` path supplied in chat. As your normal user:

```sh
cd KIT
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py setup --private-run
```

Continue only for `SETUP_READY` and `error: NONE`. Then:

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py capture --private-run
```

Wait for `COLLECTOR_READY`. The readiness deadline is ten seconds; the connection
window is at most 140 seconds with a short drain/cleanup. Only the internal bounded
eslogger guard uses sudo. The whole Python command must remain a normal-user process.

## Window B: the controlled connection

After Window A is ready, open another local terminal window and run:

```sh
cd KIT
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py connect --private-run
```

It prints a **PRIVATE_REMOTE_COMMAND**, then starts SSH to `127.0.0.1`. Enter your
password privately; confirm the loopback host-key prompt if needed. After authentication
there may be **no remote prompt**. Paste the printed `PRIVATE_REMOTE_COMMAND` and press
Enter once. It runs only the controlled marker and exits. The absence of a prompt is
expected for this non-PTY connection. Keep all SSH output and the printed command private.

## Share only the fixed ULF report

Wait for Window A to return. If it reports `COMPLETE`, `error: NONE`,
`collector_cleanup: PASS` and `unified_log: FIXED_REPORT_AVAILABLE`, run:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py ulf-report --private-run
```

That command reads only saved fixed JSON and starts no processes or queries. Share
only that JSON, stored privately as `SHAREABLE-SSH-ULF-REPORT.json`. If capture fails,
share just its compact fixed error JSON instead.
Do not retry in a used kit or open/share native files. One Ctrl+C requests cleanup;
the root guard also has an independent watchdog. Native collection or private-file
review by an agent requires separate explicit authorization.
