# Finite Mac endpoint delivery sequence

This is the completion plan authorized on 2026-11-02, not an expanding catalog
roadmap. The target is useful, correlated evidence for the fixed two-Mac workstation
workload on macOS 27 arm64. All scenario identities are invented. Raw native references
stay outside Git and are never inspected by agents without specific permission.

| Phase | Completion evidence | Current state |
| --- | --- | --- |
| 1. Process starts | Every modeled in-window fork/exec reconciles against independent State, all required application/argument roles run, positive baseline is exercised, native filtering and full exact recovery agree. | Complete at revision 374. Primary: 33 forks/39 execs. Recovery companion: 45 forks/55 execs, 16 background execs, all 22 deterministic files identical. |
| 2. Lifecycle and contradictions | Known outcomes render with their exact status; unknown outcomes are visible as coverage limitations. Repair concrete chronology, identity, parentage or cross-source failures in this workload. An unknown result cannot silently become success. | Complete for the bounded outcome contract: 13 known native exits in each workload, with 13/32 explicit unknown observations. Query completion and reconciliation pass; arbitrary GUI/SSH teardown remains unknown, not successful. |
| 3. Minimum useful ULF | GUI workspace entry, qualified ASP policy refusal, ordinary-verbosity SSH accepted authentication, and launchd activation/completion, each produced by its canonical action and a qualified native writer/callsite profile. | Workspace entry, ASP refusal, observed PAM success and source-derived plain-public-key success through the same qualified logger exist. On 2026-11-03 the user retained ordinary daemon verbosity and left VERBOSE session messages gated. The first controlled launchd ULF test completed all controls but retained zero rows; message-only filtering limited that test. The category-filter correction is code-tested. No launchd template is enabled. See the [reference note](launchd-ulf-reference/REFERENCE.md). |
| 4. Final acceptance | One combined exact recovery/filter run, one deterministic evaluation of its bundle and a bounded review of these supported families. Fix concrete blockers; no repeated blind panel loop. | Revision 377 passes combined exact recovery, ES+ULF filtering and deterministic evaluation for the implemented families. Final acceptance of the full ULF scope still depends on the remaining phase 3 evidence. |

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
acknowledgements and cleanup only, with no native execution evidence or ULF gate
closure. A separate fresh bounded ULF capture is prepared and pending human execution;
the one-shot control kit cannot be reused. If this capture passes its controls but
has no qualifying records, leave launchd ULF gated and stop collecting. Do not restart
broader process metadata research or repeat a blind panel to compensate for this gate.
