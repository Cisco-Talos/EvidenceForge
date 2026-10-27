# Private Gatekeeper reference kit

## Authority and privacy

After the exit-producer milestone `850d3bea`, the user authorized preparing the Gatekeeper
experiment and requested a simple server because no web server is installed. No VM is available.
This authorizes code-only staging and invented-input verification. The human alone runs setup,
server, browser delivery, collectors, app attempts, control and review with all agents closed.
No private capture directory or local log has been inspected. No native command/probe, service,
listener, browser, app or collector was run by the agent; C/Objective-C verification was syntax only.

No potentially sensitive native values may be seen by agents. Raw matched records and private
provenance stay outside every Git tree, including ignored folders. The shareable report has a
strict fixed vocabulary; no names, paths, hashes, timestamps, counts or native message text.
The human's browser delivery and alert observation are explicit attestations. The report never
opens retained record files. No agent may inspect the staged kit after handoff, even to locate
files or troubleshoot. Fresh attempts require fresh code-only kits.

## Procedure and components

- `scripts/macos_gatekeeper_reference.py`
- [complete human instructions](../design/macos-workstation-feasibility/gatekeeper-reference/PRIVATE-RUN.md)
- `marker_probe.c`, `metadata_probe.m`, `collector_guard.c` in that source directory
- `tests/unit/test_macos_gatekeeper_reference.py`

Setup builds a uniquely named, ad-hoc-signed harmless app whose sole behavior is an exclusive
private marker write. No app is executed during setup. Its ZIP is served by an included
temporary Python HTTP server at `127.0.0.1` with an OS-assigned port. One random namespace exposes
only a static download page and the one archive: no directory listing, uploads, access logs,
DNS lookup, external resources or service installation. The listener stops on Ctrl+C or after
15 minutes. The human uses Safari private browsing and Archive Utility, saving into the kit's
new private downloads folder; there is no Downloads search or command-line quarantine synthesis.
The exact OS release/build and arm64 architecture are retained privately and checked again at
capture/control, without appearing in the shared report. Compilation explicitly selects arm64.

Before launch the helper verifies server delivery, exact archive/binary/Info.plist content,
signature integrity and OS quarantine presence using Foundation's documented URL resource key.
The same-content local control runs only after the downloaded test attempt, reducing prior-run
interference. No policy assessment, quarantine removal, security override or trust-cache reset
is used to manufacture a denial. A daily-use system can still allow the item or redact useful
correlation; those are inconclusive outcomes, not reasons to weaken the boundary.

Live Unified Log filtering first restricts writer/message predicates to a fresh item name or
CDHash, then rechecks exact-item correlation before retaining raw rows. Default redaction stays
enabled. ES is system-wide in memory, but only this app's matching target exec/exit records are
retained. Subsequent identity matching includes PID/version/start. Each source has byte/record
limits and a fixed time window. The separate own-process readiness helper must be observed in
both streams before the downloaded app is opened through LaunchServices.

Only the auditable collector guard runs under internal `sudo -n`; Python and server stay normal
user. The guard accepts no arguments, launches exactly `/usr/bin/eslogger exec exit` with a clean
environment, owns its child's separate process group, and has a 55-second watchdog plus cleanup.
It stops/reaps its own collector on interrupt. It reads no files and changes no services. This
addresses privileged collector orphaning without inspecting other processes or running Python
as root. The instructions identify this scope explicitly. Missing access/tools stop the kit;
no automatic permission grants or installation are implemented.

Capture/control use exclusive phase markers so interrupted attempts cannot silently relaunch
or overwrite evidence. Control rejects failed collector cleanup, launcher timeouts or a marker
that changed after the test snapshot. Old native rows and broad uncorrelated writer records
are never a fallback. A successful open helper or missing marker is not proof of policy denial.

## Reference meaning and remaining gate

Apple's [trusted-execution guidance](https://developer.apple.com/forums/thread/706442) supports
browser quarantine, Archive Utility propagation, separate controls and cache-related limits.
[Gatekeeper diagnostics](https://developer.apple.com/forums/thread/706379) distinguish signature,
notarization and per-item CDHash correlation. Foundation's
[`quarantinePropertiesKey`](https://developer.apple.com/documentation/foundation/urlresourcekey/quarantinepropertieskey)
provides the presence check without depending on undocumented quarantine flag encodings.
These establish API/procedure meaning, not a macOS 27 denial template. No source or native
record from those pages was copied into fixtures.

The report always keeps `reference_review: REQUIRED` and `gate_status: NOT_EVALUATED`.
`PRIVATE_REVIEW_CANDIDATE` requires all acquisition/control prerequisites and an attested block,
but does not classify the native message as a denial. A separate private meaning/layout review
must still establish the decision and actual process consequences. No exec is fabricated for a
pre-execution rejection, and missing matching ES observations alone cannot prove one occurred.
Native Gatekeeper generation remains disabled; generation behavior stays at revision 336.

## Verification and handoff

All 477 private-kit tests pass, including 99 new Gatekeeper cases. They use invented JSON and
mocked compilation, processes, selectors, clocks and HTTP servers; no sockets are bound. Coverage
includes fixed-enum canaries, provenance, symlink/hardlink/permission/file bounds, exact download
and quarantine checks, server routes/origins/no logging, strict readiness before launch, PID reuse,
raw-byte filtering, caps, interruption cleanup, single-use attempts and control/report separation.
C and Objective-C sources pass strict syntax-only compilation without producing/running binaries.
Full Ruff check and format pass (1,344 files), as do whitespace and the unchanged revision-336
behavior digest. No engine generation code, release version or native admission gate changed.

Prepared code-only kit: `/private/tmp/eforge-gatekeeper-kit-1789241v`.
**Do not inspect this directory after handoff.** No setup, listener, probe, app or collection
was run there by the agent. The human's next action is to read the linked instructions, close
all agents, then run setup and the included server privately. Only the final fixed report may
return to this chat; any missing/redacted evidence leaves Gatekeeper output gated.
