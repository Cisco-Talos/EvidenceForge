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

## Human-reviewed initial result: iTerm2

The human shared only the fixed report and identified **iTerm2**, rather than
Apple Terminal, as the sampled app. This is a bounded protocol variation:
the selected own-process relationships remain usable for the tested iTerm2
context. No evidence about Apple Terminal or the terminal app's own token is
claimed, and no repeat in Apple Terminal is required for this experiment.
Future instructions allow either app, require one consistent app across all
samples, and retain human identification of the app rather than process
inventory. The already handed-off private kit must remain untouched.

The initial report is complete with no error. Source/binary provenance,
token/POSIX agreement, attributed audit identity, audit user matching the real
user, fork linkage, audit inheritance through fork/exec, POSIX session/group
inheritance, distinct shell contexts and one real user all pass. The three
contexts share one audit user and audit session while their POSIX sessions
differ. This supports keeping audit-session ownership separate from POSIX
session and process-group identity in the canonical GUI producer.

The fresh GUI-login context was not collected, so its comparisons remain
inconclusive. Next human step: save work, close agents, log out/in as the same
user without rebooting, reopen **iTerm2**, and record `fresh_login` with the
explicit same-boot GUI-relogin attestation using the unchanged private kit.
Then privately run/review `report` and share only its fixed JSON. This does not
collect GUI startup log layout or Endpoint Security exports, and no generation
gate is closed by the initial result. No agent inspected any private kit,
native value or log. Only this aggregate interpretation is recorded in Git.

## Human-reviewed fresh GUI-login result

The human shared the fixed report after the same-boot GUI-relogin step. All
initial controls still pass. The fresh login has a **different audit session**
and the **same audit user**; `fresh_login_context` is `HUMAN_ATTESTED_SAME_BOOT`.
No native values, raw records or private files were inspected or committed.
The bounded identity comparison is complete for the tested iTerm2 context.
The script deliberately still requires reference review and does not evaluate
generator admission. GUI startup log layout and Endpoint Security export were
not collected by this experiment.

## Canonical producer implementation

Revision 334 selects `gui_audit_origin: authenticated_local_account` in the
frozen execution profile. Older frozen policies default to absent selection.
The auth bundle creates normal-user local GUI sessions and their independent
audit origins in one existing materialization batch, before workspace or
terminal processes publish. It uses the exact local account UID, independently
of an overridden effective UID. An unqualified login or old existing session
retains unknown origin. GUI sessions no longer allocate Windows session IDs.
SSH and GUI share the existing host-local monotonic audit namespace; no new
mutable registry or namespace inferred from a process/LogonID was introduced.

Explicit user launches consume the authenticated origin only with matching
host, principal, account credentials, session and chronology. Known foreign
origins cannot be overwritten. Ordinary children keep the existing credential
inheritance path; no emitter adds audit facts. Generic session metadata cannot
reassign a published GUI audit owner. Recovery supports GUI origins alongside
SSH origins and rejects invalid or duplicated ownership. All checkpoint data
uses the existing records and allocator segments.

This closes the audit-origin producer item within its selected model. It does
not qualify the terminal app's responsible-process relationships, GUI native
startup layout, or complete GUI fork/exec export. The ordinary GUI native path
also requires explicit responsibility metadata; those unknowns remain guarded.
The human's reference must not be described as a full Terminal.app or native
ES validation. SSH descriptors, additional explicit exit-result producers and
Gatekeeper remain later steps. A question about existing SSH availability is
pending before designing a private SSH experiment; no service or privilege
change has been made.

Verification: the broad Mac/behavior unit run passed **2,748 tests** with 30
extended cases excluded. The final shared-state/identity/auth/recovery and GUI
regression selection passed **413 tests**, including 28 new GUI contracts.
The extended Mac SSH client case initially exposed a test-harness seed mismatch:
the boot collector was initialized outside the declared run seed while later
activity used it. The harness now scopes both consistently, preserving the
native boot/profile guard. GUI SSH clients are checked against the real canonical
login origin rather than the earlier unknown-origin expectation. Native source
fresh-process, CLI selection and checkpoint-byte checks also pass. Ruff and the
revision-334 surface digest pass; generated ignored skill references were
refreshed through the installer. No product version was changed.

The human subsequently confirmed that Remote Login is already enabled locally.
The next private SSH descriptor experiment can therefore use localhost without
changing that service. The agent has not connected to it or inspected its state.
