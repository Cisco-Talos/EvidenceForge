# Private macOS GUI audit identity experiment

## Scope and handoff

The user requested working through the remaining Mac coverage items one at a
time, beginning each with data collection. The agreed order is GUI audit
identity, SSH descriptors, explicit exit results, then Gatekeeper denial.
Implementation context remains in the
[macOS 27 profile worklog](2026-10-24-macos27-native-process-profile.md).

The absolute privacy constraints persist: no agent inspection of local logs,
old private kits, captured records or private reports; no potentially sensitive
native values shown to an agent; no captured data anywhere in Git, including
ignored directories. The human alone collects and reviews, with agents closed.
The agent may prepare code-only kits, syntax-check C without execution and run
tests on invented inputs. No new native collection or preflight was run.

The first experiment uses the public Mach self-task audit token API rather
than a system-wide Endpoint Security/log subscription. It collects only the
controlled probe family's selected own numeric identity facts and code digests.
Fork and exec snapshots use an owned private pipe. Normal-user execution,
timeouts, fixed subprocess environment, owner-only regular files, bounded
reads, no symlinks/hardlinks and exclusive creation constrain the private path.
No process inventory, environment enumeration, log reader, network, sudo,
security setting change or audit setter is used.

Three samples compare a current Terminal window, a new window and a new tab.
The optional fourth sample requires the human to save work, log out/in as the
same user without rebooting, and explicitly attest to those conditions. The
kit does not inspect boot or login logs to verify the attestation. Initial
samples may be shared before scheduling that disruption.

The public Pydantic report accepts only fixed enum/check values. Numeric IDs,
digests, file paths, native text and unknown fields cannot enter it. It reports
relationships without prescribing their outcomes. Controls cover token/POSIX
agreement, known parent linkage, provenance, distinct shell contexts and one
real user. An unset audit identity is never substituted with the effective
user or POSIX session. The report never changes generation admission and keeps
reference review required. It does not qualify GUI startup/native log layout
or every GUI application's behavior.

Source and human instructions:

- `scripts/macos_gui_audit_reference.py`
- [probe/instructions](../design/macos-workstation-feasibility/gui-audit-reference/PRIVATE-RUN.md)
- `tests/unit/test_macos_gui_audit_reference.py`

Prepared code-only kit handed to the human:
`/private/tmp/eforge-gui-audit-kit-639nkbtp`.
**Do not inspect this directory after handoff**, even to check whether samples
exist. Read only a fixed report the human deliberately shares. New attempts
require a fresh code-only kit; do not inspect or overwrite prior samples.

## Verification and remaining work

All **325 invented-input tests** pass: 77 GUI kit tests plus the unchanged
100 capture-kit and 148 offline-review contracts. They exercise report vocabulary,
canary redaction, inheritance and cross-context comparisons, failed controls,
fresh-login attestation, source changes, safe code-only preparation, Git refusal,
file boundaries and mocked subprocess invocation. Native execution/preflight
are forbidden or replaced with invented test stubs. The C source passes
`clang -std=c11 -Wall -Wextra -Werror -fno-modules -fsyntax-only`; it was not
linked or run. Full Ruff checks and formatting pass (1,336 Python files).
No generation code, behavior revision, product version or admission gate changed.

Next: obtain the human-reviewed initial fixed report, then the optional
same-boot GUI-relogin comparison. Review the bounded evidence before implementing
canonical GUI audit-origin ownership and its regression tests. SSH, additional
explicit exit producers and Gatekeeper remain later steps; no new native
evidence for them is claimed by this kit.
