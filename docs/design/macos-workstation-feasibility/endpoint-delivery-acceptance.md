# Finite Mac endpoint delivery sequence

This is the completion plan authorized on 2026-11-02, not an expanding catalog
roadmap. The target is useful, correlated evidence for the fixed two-Mac workstation
workload on macOS 27 arm64. All scenario identities are invented. Raw native references
stay outside Git and are never inspected by agents without specific permission.

On 2026-11-04 the user agreed to leave launchd ULF gated and proceed with a fresh
generation and review of their `MacOS-test` scenario. This is the next user
acceptance step beyond the fixed engineering workload. Keep all work on the
feature branch; no PR into `dev` is authorized until the user is satisfied.
The existing launchd result does not qualify a message family, and no further
native collection is requested for this acceptance run.

The November 4 user-scenario trial now **fails complete ES coverage**. Its macOS 27
working copy preserves all application/command/timing intent: 148/239 expected
execs are exported, with 66 aggregate starts and 25 unknown-entitlement execs
uncovered. All 163 modeled forks and 84/85 authored Mac process requests have
native evidence; the remaining authored caller and sleep job need native owners.
A separate partial diagnostic is manifest-verified, but is not a coverage pass.
The fixed matrix below remains valid evidence for its narrower scope, not proof
that this broader default catalog works. See the November 4 results in the
[worklog](../../worklog/2026-10-28-macos-es-exec-completeness.md). Launchd ULF is
separately gated and does not cause these ES gaps. Integration remains on hold.

| Phase | Completion evidence | Current state |
| --- | --- | --- |
| 1. Process starts | Every modeled in-window fork/exec reconciles against independent State, all required application/argument roles run, positive baseline is exercised, native filtering and full exact recovery agree. | Complete for the bounded workload, reconfirmed at revision 377. Primary: 33 forks/39 execs. Final recovery companion with ASP negative control: 63 forks/78 execs, 39 background execs, all 22 deterministic files identical. |
| 2. Lifecycle and contradictions | Known outcomes render with their exact status; unknown outcomes are visible as coverage limitations. Repair concrete chronology, identity, parentage or cross-source failures in this workload. An unknown result cannot silently become success. | Complete for the bounded outcome contract: 13 known native exits in each workload, with 13/51 explicit unknown observations. Query completion and reconciliation pass; arbitrary GUI/SSH teardown remains unknown, not successful. |
| 3. Minimum useful ULF | GUI workspace entry, qualified ASP policy refusal, ordinary-verbosity SSH accepted authentication, and launchd activation/completion, each produced by its canonical action and a qualified native writer/callsite profile. | Workspace entry, ASP refusal, observed PAM success and source-derived plain-public-key success through the same qualified logger exist. On 2026-11-03 the user retained ordinary daemon verbosity and left VERBOSE session messages gated. The final corrected category-or-message capture passed job/cleanup controls but retained zero rows. The agreed collection sequence has ended; launchd ULF stays gated and no template is enabled. See the [reference note](launchd-ulf-reference/REFERENCE.md). |
| 4. Final acceptance | One combined exact recovery/filter run, one deterministic evaluation of its bundle and a bounded review of these supported families. Fix concrete blockers; no repeated blind panel loop. | Revision 377 passes combined exact recovery, ES+ULF filtering and deterministic evaluation for all implemented minimum families, including the ASP negative control. Original full-scope acceptance remains unpassed because launchd ULF is unqualified; finite reference collection has ended. |

The quiet thirty-minute primary is preserved as a quiet sampling case. The
predeclared positive seed and longer same-seed recovery companion exercise background
coverage separately; neither substitutes for the original primary.

The completion goal does not require arbitrary applications, every Chrome auxiliary
helper, Dock/Spotlight-specific attribution, every GUI message, browser IPC modeling,
or every ES event family. Those are separate future requirements. Selecting ULF is
not a claim that every process start has a ULF message; ES is the process evidence.

## Remaining evidence, with a stopping rule

Use one bounded reference for each missing ULF family. Launchd collection uses a
nonce-labelled transient system job and `/usr/bin/true`, not real workloads. SSH
collection must authenticate a controlled loopback connection before retaining its
writer's messages. Existing account/terminal configuration must not be changed.
Each diagnostic must return fixed comparisons, keep unknown fields/values private,
preserve failed captures and make cleanup failures visible. Prepare and test code
without collecting. Human execution remains a distinct step.

If the reference cannot establish a message or native envelope, leave that family
gated and report the exact missing classification. Do not continue collecting unrelated
process metadata, expand the scenario, or repeat an authenticity assessment to compensate.
An own-process readiness marker is not proof of visibility into a root service's
logs. A separate launchd diagnostic file must not be passed off as ULF or added as
an implicit new product requirement. A zero under a narrow predicate is not proof
of global absence.
Reference-qualified generation still uses explicit synthetic build offsets and invented
entity values; it does not claim byte identity with the private system's executable.

The launchd diagnostic is documented in
[launchd-ulf-reference/PRIVATE-RUN.md](launchd-ulf-reference/PRIVATE-RUN.md).
After its initial unobserved result, the user ran the bounded
[SSH ULF check](ssh-startup-reference/ULF-PRIVATE-RUN.md). It reused the existing
controlled loopback connection and ES ancestry solely to authenticate ULF retention;
it does not expand the ES metadata research scope. Its first fixed report retained
38 bound rows with successful cleanup but failed the implemented schema. The approved
[offline shape review](ssh-startup-reference/ULF-REFERENCE.md) resolved that failure:
17 valid ordinary logs and 21 activity-creation entries. One ordinary log records
successful keyboard-interactive/PAM authentication from root-owned sshd-session.
The separately approved grouped comparison qualifies its static main-image callsite
with PRIVATE_DATA flag and public %.500s format. That bounded PAM-success producer
is now implemented. Plain public-key success reuses that qualified envelope through
the common logger established by Apple's public OpenSSH code; its payload basis is
source-derived, not a separate local observation. Canonical key type and SHA256
fingerprint are required. Other SSH/PAM messages remain gated. The user explicitly
chose ordinary verbosity on 2026-11-03, so VERBOSE session-start/close messages are
outside this delivery scope; increasing collector verbosity cannot enable them.
No capture is requested for those messages. See the same reference note for exact
source and visibility limits. Launchd ULF remains the only unclosed minimum-family
evidence gate; ES already covers the controlled job's process start and known exit.

The human-run corrected launchd selector subsequently returned failed job activation
and removal/file controls. Its zero rows are inconclusive, not a qualified absence.
Exact-label cleanup also failed its original fixed checks; a tested grouped cleanup
diagnostic subsequently verified both test directory and exact service ABSENT.
The temporary-resource concern is closed and no cleanup is needed. This does not
establish activation or ULF visibility in the failed attempt. No further collection
is requested, and no native files were opened by the agent. Launchd ULF remains
gated; it is not silently removed from full-scope phase 3/4 acceptance. See the
launchd reference note for the fixed reports and their limits.

The user subsequently authorized the next finite step: a collector-free activation/
cleanup check with fixed stage/reason diagnostics. Its private version-4 report now
passes every control, guard_exit ZERO and result PASS. This establishes launchctl
acknowledgements and cleanup only. The separate fresh version-4 bounded ULF capture
subsequently passed job/collector controls and cleanup but retained zero rows under
the corrected category-or-message selector. This is a valid bounded empty result,
not a global absence claim. The agreed stopping rule is now exercised: collection
ends, launchd ULF remains gated, and no alternate file source or broader metadata/
assessment investigation is added. Known launchd process evidence remains in ES.
Current supported-family acceptance passes; original full-scope phase 3/4 acceptance
is still explicitly incomplete because launchd ULF has no qualified message/envelope.
