# Native Windows CI and checkpoint smoke coverage

## Approved objective

Run the Python 3.12 routine suite on native Windows and Linux for PRs/pushes to dev and main.
Add one short real generation/checkpoint/cooperative suspension/verification/fresh-process resume
smoke test to the routine suite (also exercised locally on macOS). Keep broad slow checkpoint
matrices and Python-version portability in the Linux release gate. Require green Windows CI;
do not weaken publication safety or skip portable behavior to obtain green tests.

Branch: `codex/windows-ci-checkpoint-smoke`, based on `origin/dev` after the 2.0.1 release.
No package version bump, merge, or release is authorized by this effort.

## Repository enforcement inspection

On September 14, GitHub's ruleset list was empty. The main branch protection requires
`Required CI` and `Required Release CI`; the dev branch-protection endpoint returned
`Branch not protected`. The matrix aggregate retains the existing Required CI name.
Dev protection still needs resolution before claiming the gate is enforced there. No branch
protection settings are changed by this draft groundwork PR.

## Implementation in progress

- Linux/Windows routine test matrix, fail-fast disabled, existing pytest marker exclusions.
- Removed the explicitly temporary dev-push trigger from release-slow.
- Shared directory syncing retains strict POSIX errors and deliberately omits unsupported Windows
  directory sync; regular files still flush and atomic publication still applies. Windows does
  not receive a POSIX-equivalent power-loss directory durability guarantee.
- Checkpoint byte-descriptor I/O explicitly requests Windows binary mode.
- Process ownership checks use the existing psutil dependency, which queries native Windows
  process state without sending signals; indeterminate owners cannot authorize reclamation.
- Smoke test uses one warmup hour and three collection hours, a fixed seed, Windows/Zeek output,
  hourly checkpoints and the existing synchronization barrier after collection hour one. It
  requests CLI suspension, verifies without changing the recovery index, resumes fresh, compares
  deterministic bundle bytes against an uninterrupted run, and checks workspace cleanup.

## Newly discovered platform boundary

The initial issue understates the native Windows gap. `WindowsEventEmitter` and Sysmon's exact
source-finalization path explicitly require POSIX dir_fd/no-follow/effective-owner operations;
Syslog has a similarly attested POSIX-only publication implementation. They cannot safely be
ported by deleting capability checks or disabling verification. This needs a native backend that
preserves publication and directory/file identity contracts. The user explicitly chose to prepare the groundwork as a draft PR and plan the native backend
separately. Therefore native Windows is expected to remain red in this draft; passing Windows CI
and required-check enforcement on dev are deferred to the backend effort. No publication guards
will be removed to make the groundwork appear compatible.

## Validation

- Initial host-platform unit tests: 6 passed on macOS.
- First smoke run correctly rejected a stale generation behavior manifest; refreshed the internal
  behavior declaration (no public package version or checkpoint schema change).
- Further results pending.

- The initial integrated run passed all 148 component/operations tests and completed real smoke
  generation/suspension/verify/resume with byte-identical output. Its final nonempty-network check
  expected conn.log, while the default target emits conn.json; corrected the assertion.
- Routine macOS suite and four targeted slow checkpoint tests are running.
- Checkpoint spool capture now uses sequential reads on exclusively owned binary descriptors,
  preserving offsets and avoiding unavailable Windows pread. Syncing an existing file on Windows
  opens it for writing as required by file-buffer flushing.
- Windows CI disables checkout CRLF conversion to preserve source/config bytes used by the
  generation behavior fingerprint.
