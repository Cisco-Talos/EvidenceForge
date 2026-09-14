# Native Windows filesystem support

## Scope and platform boundary

EvidenceForge uses native Windows Python and Windows filesystem APIs; WSL is not involved.
Protected generation journals and checkpoint workspaces require a local, fixed NTFS volume.
UNC/network shares, non-NTFS volumes, and reparse points (including junctions and cloud
placeholders) along active protected paths are rejected. Output, temporary storage, and
`EFORGE_SPOOL_DIR` must satisfy these requirements.

macOS and Linux remain the primary supported platforms. Their existing implementations remain
in place. OS branches select Windows operations, and shared wrappers call the original POSIX
operations with their original arguments. Native Windows modules are imported only on Windows.
Generated event semantics, checkpoint schemas, and the package version are unchanged.

Validation uses Python 3.12: macOS 26.6.2/arm64 locally and GitHub-hosted Ubuntu and Windows
Server 2025 runners. Windows 10, Python 3.13 on Windows, cross-OS checkpoint transfer, and the
broad Windows slow suite are not established by this effort's tests. Release slow tests and
Python 3.12-to-3.13 checkpoint portability remain on Linux.

## Native operations

`utils/windows_filesystem.py` owns the native handle and ACL operations. Typed ctypes bindings
load system DLLs from System32. Directory-relative `NtCreateFile` calls open single components;
opened-handle metadata rejects reparse points and unsupported volumes. Retained directory
handles omit delete sharing, pinning their names and ancestry while in use. File handles use
binary, non-inheritable CRT descriptors. Unsupported open flags fail before mutation.

File identity comes from the opened descriptor's volume/device and file identity. Native rename
and deletion operate relative to retained directories, with explicit replacement policy and
identity checks for owned cleanup. SQLite connections and leaf directory handles close before
removal. The existing emitter schemas, rendering, receipts, retry state, and publication lifecycle
remain the owners of logical journal behavior.

The Windows-only `windows_journals.py` and `windows_journal_directory.py` modules connect these
operations to Security/Sysmon and Bash/Snort directory lifecycles. Syslog retains its attested
operation registry and uses a Windows stream facade with explicit methods. Its private anonymous
storage uses delete-pending files; duplicate descriptors retain the same kernel object. Windows
positioned reads serialize with the journal's ordinary reads, writes, and seeks, save the shared
file pointer, and restore it before releasing the lock. No pathname reopen is needed.

Native API references:

- [NtCreateFile and RootDirectory semantics](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
- [Native file rename information](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
- [CompareObjectHandles](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-compareobjecthandles)
- [Handle-based file information and deletion](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)

## Ownership and privacy

Private directories and files receive protected DACLs granting access to the current user,
SYSTEM, and Administrators. Existing objects are checked through their security descriptors;
synthetic POSIX owner IDs and mode bits are not accepted as Windows security evidence. Private
objects reject access granted to outside principals, including read access. Ancestors reject
outside rights that could replace existing protected entries or change their security, while
allowing ordinary creation of new siblings in a temporary root.

The current token's default object owner can be Administrators for elevated processes. It is
accepted only within the trusted privileged principal set. OWNER RIGHTS entries are evaluated
only after authenticating the object's owner. Windows-managed ancestors may also be owned by
TrustedInstaller. Null DACLs, unexpected owners, and unsupported ACE types fail closed.

See Microsoft's [file security model](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
and [special identities](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-special-identities-groups).

## Durability and lock ownership

Regular-file writes still flush before publication. Windows uses writable handles for
`FlushFileBuffers`, including final-output reconciliation. POSIX read-only opens and strict
`fsync` failure propagation remain unchanged.

Windows checkpoint publication uses a separate `WindowsCheckpointIO` boundary. Its
file creation and rename handles opt into `FILE_WRITE_THROUGH`; existing native emitter
callers keep their default I/O behavior. Complete buffered binary contents are explicitly
flushed before publication, and regular-file metadata is flushed again after rename.
New checkpoint directories, including missing output/workspace ancestors, are created under
private staging names and published through write-through directory renames. Directory
handles close before publication, while retained parent handles preserve path identity.

The commit order is dependencies (resolved input, segments, catalogs), participant heads and
manifest, recovery-directory publication, then atomic `CURRENT.json` publication. Only then
may the checkpoint be acknowledged. Existing dependencies are authenticated and republished
once per store before a new acknowledgment; copies stream in 1 MiB chunks. Windows readers
close before replacing the file they authenticated. An uncertain index publication stops
further publication and reclamation on that store. Recovery retention and garbage collection
use the recovery index, and removing an object invalidates its cached durability proof.
Suspension records and restored append spools use the same Windows publication primitives.

The POSIX directory-sync helper remains a no-op on Windows; it is not the checkpoint's
namespace barrier. The native NTFS write-through rename is that barrier. This interpretation
uses Microsoft's documented [write-through metadata behavior](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew#caching-behavior)
and [native create options](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile),
alongside [explicit file flushing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
No unbuffered I/O, administrative privilege, or whole-volume flush is required.

The durability contract assumes a stable pre-existing filesystem ancestry, local NTFS, and
storage that honors these flush requests. All ancestors newly created by checkpoint
initialization receive write-through publication. Physical power-loss certification, hardware
that ignores flushes, final bundle publication durability, other filesystems, and cross-OS
checkpoint transfer are outside this contract. The guarantee applies while the checkpoint
remains retained; successful final generation intentionally removes the workspace.

### Simulated power-loss validation

A test-only observer records actual native checkpoint I/O and the flags requested by its rename
calls. The independent storage model separates file bytes from parent/name directory entries,
tracks volatile and durable state, and crashes before/after every operation across three small
commits. Profiles discard, retain, reorder, or partially persist unsynchronized operations,
including 512-byte and 4-KiB torn writes. Directory renames do not implicitly flush descendants.
Materialized crash images are checked by the production recovery reader. Deliberately missing
write-through protection and inverted index/recovery ordering must fail this contract.

After acknowledgment the selected recovery must be that checkpoint or a newer complete one;
falling back to an older point is a test failure. Before acknowledgment, either the previous
complete checkpoint or the new complete point is allowed. Before the first acknowledgment,
no resumable point is also allowed. Corrupt or incomplete points must never be accepted.

A real fixed-seed CLI run supplies representative crash images before index publication,
between index publication and acknowledgment, and after acknowledgment. Fresh CLI processes
verify and resume those images, compare every deterministic bundle file with an uninterrupted
control, and confirm workspace removal. A second interruption exercises spool restoration.
Process termination only controls the experiment; the model, not surviving OS cache contents,
defines what survives the simulated power loss.

These are **write-through checkpoint publication tests using native APIs and simulated
power-loss recovery**, not physical Windows/disk power-cycle tests. The dedicated 20-minute
Windows CI job runs the focused slow module without coverage on PRs and pushes to dev/main,
rejects skipped/empty test execution, and contributes to `Required CI`. Failure artifacts retain
operation traces, crash profiles, subprocess output, and runner/filesystem metadata. The broad
Linux release-slow suite is unchanged.

Windows process-owner checks use psutil's native process query instead of `os.kill(pid, 0)`.
An inaccessible or indeterminate process cannot justify reclaiming its lock. The earlier CI
groundwork introduced this shared psutil query; the native-backend implementation preserves it.
Checkpoint byte I/O is binary, and verification retains the original index/segment integrity
checks and schema.

## Other portability repairs

Logical configuration, pack, and installed-skill references use slash-separated paths on Windows.
Native filesystem paths remain `Path` objects. Windows skill cleanup uses the same logical keys
as its installation manifest. The Windows dependency set includes timezone data. Windows-only
paths handle negative epoch conversion, CRLF parsing, Bash byte accounting, and writable sorted
export handles without changing the POSIX implementations.

Tests use portable fixture paths and text encodings. POSIX-only signal/timer/mode contracts have
explicit platform reasons; portable generation, checkpoint, and publication behavior still runs
on Windows. Native regressions cover binary data, Unicode names, ACL rejection, file identity,
exclusive publication, junction rejection, pinned ancestors, anonymous stream identity, ordinary
versus exact evidence, and journal cleanup.

## CI and acceptance evidence

The routine Python 3.12 matrix runs `uv run pytest --no-cov` on Ubuntu and native Windows for
PRs and pushes to `dev` and `main`, with matrix fail-fast disabled. `Required CI` requires lint
and every test entry to succeed. One unmarked real CLI smoke test covers generation, a first
collection-hour checkpoint, cooperative CLI suspension, verification without index mutation,
fresh-process resume, nonempty Windows/Zeek evidence, byte equality with uninterrupted output,
and checkpoint workspace cleanup. The same test runs during ordinary local macOS testing.

The [worklog](../worklog/2026-09-14-windows-ci-checkpoints.md) records exact CI revisions,
failure inventories, validation counts, and completion status. The first native run stopped at
257 collection errors from a shared temporary-stream import assumption. After that fix, the
full routine inventory exposed 468 failures; subsequent native storage and path repairs reduced
this to 39 while the checkpoint smoke test and full Linux suite passed.

[Run 34859531009](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/34859531009)
at `7160bfc6` passed the complete routine matrix: Windows **8,659 passed, 30 skipped** and Linux
**8,639 passed, 50 skipped**, with 2,019 slow/soak tests deselected on each. The same revision's
local macOS routine run passed **8,639 tests, 50 skipped**. The real checkpoint smoke passed on
all three hosts. The worklog records subsequent final cleanup validation.

Repository settings were inspected without modification. `main` requires `Required CI` and
`Required Release CI`. `dev` has no branch protection or effective rules, so workflow failure
alone does not enforce a merge block there. PR #419 targets `dev`; merging remains a manual
maintainer action. No merge, release, or package version bump is part of implementation.
