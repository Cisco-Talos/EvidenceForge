# Private macOS 27 interactive SSH / PTY reference

Close agents before setup or collection. This is a human-run experiment using the already
enabled loopback Remote Login service. It changes no SSH, account, privacy or shell settings.
Use the terminal app that already has Full Disk Access. Do not change apps between windows.
Run Python as your normal user; only the internal collector uses sudo.

The kit requests a PTY with `ssh -tt`. It observes one controlled connection, its actual
server helpers and one harmless compiled command launched from the interactive login shell.
The command exits zero without printing output, opening files or querying identities. The
shell then exits. Existing shell startup files may run privately; they are not portable
simulation defaults. No Unified Log is collected.

The machine-wide fork/exec/exit stream stays in bounded local memory. A random marker,
executable identity, exact ancestry and controlled client prove the connected tree before
any native rows can be saved. Version 3 selects the proved SSH ancestry, authentication and
fork-only helper siblings, the controlled command and client before applying retention limits.
Unrelated connections and personal shell-startup child trees are excluded. Only that bounded
core can be saved privately after collector cleanup. Arguments, environments and captured paths
can be sensitive: never share those records or put any kit file in Git.

The shareable report contains only closed-vocabulary labels and opaque lifetime aliases.
It includes core fork/exec/exit relationships, credential/audit/job-control comparisons,
terminal equivalence, runtime/code-signing/entitlement comparisons and descriptor slots/types.
It deliberately keeps `reference_review: REQUIRED` and `gate_status: NOT_EVALUATED`.
`retained_scope: CONTROLLED_SSH_CORE` describes this reference experiment, not a reduction
of the simulator's all-process accounting. Any safety limit returns a fixed `limit_scope`
label; limits remain enforced. The version-2 attempt is single-use and must not be reused.

## 1. Setup once in a fresh kit

Open two ordinary windows in the same permitted terminal app. In **both windows**, change
into the fresh PTY kit directory supplied by the agent. In **Window A**:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py setup --private-run
```

Proceed only with `stage: SETUP_READY`, `error: NONE`, `terminal_mode: PTY`. Setup compiles
and signs controls, but starts no SSH connection, collector or probe. A setup failure needs a
fresh kit; share only the fixed JSON. Never rerun setup in a used kit.

## 2. Window A: start the collector

```sh
sudo -v && /Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py capture --private-run
```

Wait for `stage: COLLECTOR_READY`, then immediately use Window B. The connection window is
140 seconds; the independent guard stops by 180 seconds or parent cancellation. Ctrl+C in
Window A cancels and cleans up. A used kit is single-use even after failure; leave locks intact.

## 3. Window B: connect, then paste one command

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py connect --private-run
```

The helper first prints a private `PRIVATE_REMOTE_COMMAND` line ending in `; exit`, then
replaces itself with SSH. **Copy that one command before authentication.** Authenticate and
verify any loopback host-key prompt privately. The client uses a kit-local known_hosts file,
bypasses SSH config and disables agents, public keys, forwarding, proxies, local hooks and
multiplexing. Never share prompts, fingerprints, passwords, banners or Window B output.

At the remote shell prompt, paste the printed command and press Enter. It runs one controlled
child and then exits the remote shell. SSH should return to your local prompt. Do not add
`exec` before the command: this experiment needs a child of the shell. Do not paste other
commands, launch personal applications or run `ps`, `env`, `id` or debugging commands.

## 4. Save and share the fixed report

Window A stops its collector and prints a short fixed status. It intentionally does not dump
the full report into scrollback. After it returns to your prompt, run in **Window A**:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_ssh_startup.py report --private-run > SHAREABLE-SSH-PTY-REPORT.json
```

Attach **only `SHAREABLE-SSH-PTY-REPORT.json`** to the chat. Read this report privately first.
This command validates and reads only the saved shareable report; it opens no native records
and starts no SSH connection or collector. If needed, repeat this report command, never
capture. Successful acquisition is not automatic generation qualification.

For failure, share only the fixed JSON/status. Do not share native JSONL, provenance, setup,
client controls, terminal text, screenshots or private paths. Do not delete locks or rerun a
collector to retrieve output. Any later offline native-record review needs separate permission.
