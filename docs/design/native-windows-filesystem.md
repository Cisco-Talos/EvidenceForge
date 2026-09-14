# Native Windows filesystem backend: follow-up implementation plan

## Objective and current boundary

Complete native Windows generation and checkpoint recovery without WSL and without weakening the
protected publication contracts. Build on draft PR #419 (`codex/windows-ci-checkpoint-smoke`),
which adds the required Linux/Windows routine matrix and a real checkpoint smoke test. The
maintainer explicitly separated this backend from the groundwork effort after inspection found
POSIX-only output-journal requirements.

WindowsEventEmitter and Sysmon's source-finalization path require no-follow, directory-relative
operations and effective-owner metadata. Their shared `source_journal` code owns directory/file
identity, SQLite initialization, and retryable publication. Syslog additionally captures an
attested registry of filesystem functions and requires descriptor-relative traversal and pread.
Snort and bash history have related private-spool/publication contracts. Simply bypassing these
capability checks, fabricating POSIX ownership, or switching to an independent renderer would
break existing guarantees.

Initial supported host scope: Python 3.12 on 64-bit Windows with local NTFS volumes and a normal
user token. Keep macOS/Linux behavior unchanged. Network shares, non-NTFS Windows output, cloud
placeholder/reparse paths, cross-OS checkpoint transfer, and the full slow suite on Windows are
outside the first implementation. Reject unsupported storage during preflight with an actionable
message; do not silently reduce protection.

## First native CI measurement

[Run 34844565216](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/34844565216)
on Windows/Python 3.12.10 at `ca146454` installed dependencies successfully but stopped during
collection: **257 errors**, including 237 occurrences of `_TemporaryFileWrapper` lacking a class
`fileno` attribute and 20 cascading partial-import errors. The source is Syslog's module-level
`_make_security_registry` (`syslog.py:467` at this revision). This is one shared import blocker,
not 257 independent defects. No Windows test or smoke-test execution was established by this run.

## Backend contract and implementation order

0. Make module import independent of POSIX temporary-stream probing. Capture trusted syscall
   bindings separately from runtime storage capability checks and bind a platform-correct owned
   stream implementation. Preserve Syslog's attestation; do not use delegated wrapper attributes
   as an unchecked substitute for trusted methods. Require `pytest --collect-only` to succeed on
   Windows before inventorying execution failures.

1. Introduce a small internal protected-filesystem interface with owned directory/file handles,
   immutable volume/file identity, metadata inspection, no-follow child open/create, exclusive
   temporary creation, binary read/write, offset reads, flush, directory enumeration, atomic
   child publication, and identity-checked removal. Resource objects own and close handles;
   copied numeric descriptors must not imply ownership. Preserve distinct errors for absent,
   occupied, unsafe, unsupported, and indeterminate operations. Keep current checkpoint schemas
   free of runtime handles, ACL blobs, or platform-specific identity encodings.
2. Implement the POSIX adapter using the existing descriptor-relative operations. Move shared
   operations behind the interface first and prove unchanged evidence, publication receipts,
   failure recovery, and cleanup. Do not monkeypatch Python's global os module or emulate it with
   a broad compatibility shim. Make syscall/capability bindings explicit so existing exact-owner
   and Syslog attestation contracts remain enforceable.
3. Implement the native adapter with typed ctypes bindings loaded only on Windows. Use native
   directory handles and handle-relative single-component opens through NtCreateFile; reject
   reparse points on every opened component. Obtain volume/file identity and attributes from the
   opened handles. Use native handle-based rename/disposition for publication/removal, with
   deliberate sharing modes and retained handles preventing parent substitution. Use synchronous
   binary handles; serialize seek/read only for exclusively owned handles, or use an explicit
   positioned-read operation when shared. Do not replace secure opens with check-then-open path
   resolution. Microsoft documents directory-relative RootDirectory semantics and explicit
   reparse-point opening in [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile),
   and handle-based rename/deletion in
   [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle).
4. Establish real Windows ownership using process-token SIDs and security descriptors. Create
   private spool/workspace leaves with protected DACLs granting the owning user, SYSTEM, and
   administrators access; inspect existing protected objects and reject unexpected write/delete
   principals. Validate ancestry against replacement rights, including parent delete-child
   access. Do not interpret synthetic st_uid or chmod bits as ACL proof. Restrict SQLite journals
   to the protected private directory and preserve schema/identity checks. Windows file access
   is defined by [security descriptors and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
5. Preserve regular-file flushing and atomic replacement. Keep directory-entry power-loss
   durability explicitly weaker on Windows; do not report POSIX-equivalent durability merely
   because a native handle opens. Probe required capabilities once before generation. Native
   file flushing requires a suitable writable handle; see
   [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
6. Migrate checkpoint store/control/spools and every enabled emitter's private journal/publication
   operations through these owners. Prioritize Windows/Sysmon, then Syslog, Snort, bash history,
   and remaining paths found by CI. Preserve source-finalization lifecycle, exact receipts,
   rollback/lost-return adoption, and bounded spool retention. Close SQLite connections and
   borrowed views before unlink/rename; do not hide leaked handles with unbounded retry loops.

## Test and acceptance requirements

- Start from native Windows CI logs captured by the groundwork PR. Fix collection portability
  before execution and classify failures by missing primitives, protected publication, path/text
  conventions, or genuinely POSIX-specific tests.
- Run common backend contract tests on macOS, Linux, and native Windows: exact identity,
  exclusive creation, binary newline/control-byte preservation, parent/file substitution,
  occupied destination, links and reparse points, invalid types, ACL rejection, lock ownership,
  descriptor cleanup, and retry after failed publication. Native junction/reparse tests must run
  without relying on administrator-only symlink creation. Keep POSIX-specific mode/signal tests
  explicitly scoped rather than skipping portable source behavior.
- Add injected failures before and after journal creation and publication to prove that lost
  returns preserve ownership and retries cannot delete or overwrite another actor's artifacts.
  Cover changes to ACLs/ancestry and SQLite handle-sharing failures. Keep broad expensive fault
  matrices in the release tier; narrow ownership and lifecycle regressions stay routine.
- Pass the unmarked short checkpoint smoke test on actual Windows: first collection checkpoint,
  CLI suspension, unchanged recovery index after verification, fresh-process resume, exact bundle
  bytes against a same-host uninterrupted control, nonempty Windows/Zeek evidence, and cleanup.
- Pass the entire routine suite on both Linux and Windows, with fail-fast disabled and no
  continue-on-error. Run the same suite locally on macOS. Run affected POSIX slow publication and
  checkpoint tests to ensure the shared-interface migration preserves existing guarantees.
- Make only host-platform filesystem behavior changes; generated event truth and checkpoint
  schema stay unchanged. Update the internal behavior declaration when its tracked surface
  changes, and verify compatibility with preserved checkpoints from the baseline build.

## Rollout

Keep #419 draft until the backend and Windows routine gate pass. Update the worklog with exact
commit SHAs, runner/Python versions, failing/passing counts, justified platform exclusions, and
smoke-test runtime. Replace interim native-Windows caveats with the supported local-NTFS scope
only after validation. Main already requires Required CI and Required Release CI. Dev currently
has no protection: establish Required CI enforcement there as part of activating Windows support,
preserving any protections added in the meantime. Broad release slow/Python-version portability
remains Linux-only; routine CI remains Python 3.12. No feature-branch package version bump.
