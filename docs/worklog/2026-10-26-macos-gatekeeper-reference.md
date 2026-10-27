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

## Version-2 verification diagnostic

The human reported only `INTERNAL` after `PRIVATE_STEP_VERIFYING_DOWNLOAD`, then attested that
both the ZIP and extracted app appear directly in the printed save folder. No private path,
directory, file or log was inspected by the agent. That does not identify the failing check:
version 1 converted unclassified filesystem errors into a generic INTERNAL report.

Version 2 adds `diagnose --private-run` to a separately prepared code copy. The human enters
the existing kit folder at a hidden TTY-only prompt; echo fallback is prohibited. It replays
the same provenance, platform, delivery-marker, archive, bundle, signing and quarantine checks,
reporting an exact fixed step and error category. It uses the old kit's already verified metadata
helper; it does not modify/rebuild the old kit, search directories, start a server/collector,
launch the test app or open captured-record/summary files. Signature/quarantine verification is
read-only, not a new capture. The original handed-off kit remains off limits to agents.

Missing/access/type/I/O failures now have fixed codes; absent helper output is also explicit.
Future captures print fixed verification-step markers. Private config compatibility is retained
for v1 kits. The 25 new invented tests cover read-only replay of an old source hash, record-file
nonaccess, missing individual inputs, native-verifier errors, canary redaction and hidden-input
failure. These diagnose possible causes without claiming the human's cause is already known.

All 502 private-kit tests pass, including 124 Gatekeeper cases. Full Ruff check/format and the
unchanged revision-336 behavior digest pass. Prepared diagnostic-only handoff:
`/private/tmp/eforge-gatekeeper-diagnostic-v2-a9c47f23`. This contains code/instructions only;
do not inspect it after handoff. The human runs `diagnose --private-run` there and supplies the
original kit folder at the hidden prompt. No setup, server, capture, test-app launch or private
verification was run by the agent, and the original kit was neither opened nor modified.

## Scoped input-file repair authorized by the human

The human's v2 report identified `ARCHIVE_CONTENT` / `FILE_MISSING`. They then explicitly asked
the agent to inspect safe kit contents directly. Under that narrower authorization, the agent
checked only directory/file metadata and compared the known generated test archive, executable
and bundle metadata using non-disclosing equality checks. No private configuration, captured
record or summary was opened; no native tool, verifier, collector or test app was executed.
No names, content, hashes, identifiers or native values were returned from those checks.

The exact `private/downloads` folder was empty. Both downloaded test items were instead at the
kit's top level. The capture-start marker and expected native capture files were absent. After
verifying the items matched the kit's original test artifacts, the agent moved just the ZIP and
app into `private/downloads`. Same-filesystem object identity was preserved; no quarantine,
signature, source, provenance or security setting was changed. Acquisition has still not begun,
so the human can proceed with the original first capture after closing all agents. No rebuild,
redownload or running server is required. This authorization does not extend to native records,
private configuration or other handed-off kits.

## Acquisition outcome and offline shape diagnostic

The human's fixed acquisition report passed platform/provenance, browser quarantine, both
collector readiness checks, bounded collection and cleanup. Matching policy rows were observed;
the downloaded app's marker and matching ES exec/exit were absent. Its open helper returned
success, which is not execution proof. At least one retained Unified Log row failed the existing
closed native schema. No retained record or private value was exposed.

The human explicitly authorized agent execution of the existing control/report commands because
they export fixed labels. Control returned DUPLICATE without launching again; the fixed report
confirmed an already successful local control with its marker present. The human then described
the downloaded attempt's Move to Trash/Done security dialog. The fixed report was regenerated
with BLOCK_ALERT. Denial remains NOT_ESTABLISHED because native structure and decision meaning
are still unqualified. These explicit permissions override the default human-only instructions
for those commands; they do not authorize direct log inspection or another collection.

Added `review-shapes` to a separate code-only copy. It starts no native command, app, collector,
server or network operation and writes nothing. It verifies the original kit's recorded
provenance and v1/v2 bounded-capture summary, then reads only the expected test UL file. Original
byte/line/record limits, a nesting limit and exact test-item/writer correlation apply before any
shape results are returned. Unsafe, malformed, unrelated or unqualified input returns fixed
errors with an empty field diagnostic. ES rows, control summaries and markers are not opened.

Only predeclared native schema field aliases appear in the output, with fixed presence/type and
missing/type/value/unsupported failure classes. Extra names and values, nested keys, validation
messages, counts, paths and all native identifiers remain private. Missing optional fields stay
distinct from invalid required fields. Shape success never reviews message meaning or opens GK-R1.

All 555 private-kit tests pass, including 53 new offline cases for read-only v1 replay, strict
schema classification, unknown-key/value canaries, file/JSON/bounds safety, correlation, version
tags and non-disclosing failure output. Full Ruff check/format (1,344 files) and whitespace pass.
No generation or gate policy changed. Prepared code-only copy:
`/private/tmp/eforge-gatekeeper-shape-review-v1-4e76ab92`.

The first code-only handoff awaited separate permission to process the retained UL file under
the human's standing no-local-log-inspection rule. Do not replace original acquisition code or
repeat the test. After structural diagnosis, native decision meaning still needs private review.

## Approved fixed-output review and remaining human boundary

The human explicitly selected “Run the fixed-output checker.” The agent ran only the prepared
offline command with native stderr suppressed. Provenance, capture summary and retained scope
passed; every known field passed its structural checks. Additional top-level fields account for
the native schema rejection. No discovered names, native values, record text or error details
were returned. The bounded private records were processed locally only under that permission.

Version-2 diagnostics add a closed list of candidate API/export names, with presence and JSON
types only. Candidate validation stays INCONCLUSIVE and the native codec remains unchanged.
Public collector/API names are hypotheses, not equivalent aliases. The same permitted offline
review against the same bounded input found those candidates absent and unrecognized fields
remaining. Further guessing or exposing discovered names is not an admission path.

Added `inspect-field-names` for human-only private terminal use. It shares the same verified
input path, requires TTY input/output before reading, and displays only bounded additional
top-level names after all inputs pass. Non-identifier/control characters, excessive lengths and
name counts are refused before anything is printed. No field value, message or nested key is
displayed. The agent must never run this name-discovery command: the human must first inspect
any names privately and decide which contain no identifying information before sharing them.
Sensitive-looking names stay private. No permission to show unknown names was inferred from
the fixed-report authorization.

All 567 private-kit tests pass, with full Ruff check/format (1,344 files) and whitespace clean.
The 12 additional tests cover candidate nonadmission, closed output keys, TTY refusal before
reads and safe name-only private display from invented records. No native app, collector,
server, capture mutation, codec or generation gate changed. The final code-only handoff is
`/private/tmp/eforge-gatekeeper-field-review-v2-c6b08d91`; only the human runs its
`inspect-field-names --private-run` command. Preserve the original capture and share no values.

## macOS 27 persona export metadata and passing shape review

The human privately checked and supplied only six technical names: launchPersonaID,
launchPersonaName, launchPersonaType, personaID, personaName and personaType. Those names were
added to the fixed diagnostic vocabulary. Under the existing explicit fixed-checker permission,
local bounded processing confirmed integer IDs within unsigned 32-bit bounds, integer types
within signed 32-bit bounds and string names. No actual value was exported. These six names
accounted for every extra top-level field; no unrecognized name remained.

The Unified Log import codec now preserves these optional fields with strict ID/type/string
contracts. It retains individual absence and rejects present null, coercions and overflow.
Unknown fields remain forbidden. Persona identities are not aliased to userID, audit origins,
each other or EvidenceForge's modeled behavioral personas. Kernel persona declarations provide
type context, not a verified mapping of launch/current export semantics. No canonical persona
producer, native emitted metadata or Gatekeeper template was invented.

The same approved offline checker against the untouched original capture now reports
unified_log_shapes PASS, additional_fields ABSENT_ALL and unrecognized_fields ABSENT_ALL.
Provenance, capture summary and scope still pass. The acquisition-time summary remains unchanged
with its historical shape failure. No native record, raw message, persona value or private
exception was seen by the agent. GK-R1 still requires terminal decision/template meaning review.

Behavior revision 337 records an impact-none codec change because the covered source digest
changed. Existing generated records retain omitted persona metadata; native projection and
ingestion regressions verify this boundary. All 742 selected tests pass (one slow case excluded),
covering the five private kits plus native contracts, ingestion, projection, profiles and output
lifecycle. Full Ruff check/format (1,344 files), whitespace and behavior validation against the
predecessor pass. No product version or native generation gate changed.

Prepared the next human-only `inspect-policy-layouts` step. In a private TTY it verifies all
inputs and schemas before showing bounded unique writer/subsystem/category/format-template
combinations. It omits rendered messages, paths, timestamps, PIDs, hashes, persona values and raw
records. The literals themselves can contain private text, so they are never agent output:
only the human can inspect them and decide which technical constants contain no identifying
information before sharing. TTY refusal, invalid later rows, limits, omission and deduplication
are tested using invented records. This command is not a denial classifier or new capture.

Code-only handoff: `/private/tmp/eforge-gatekeeper-policy-review-v2-73dc019b`. The agent has not
run its human-only policy-layout command. The human's next step is to close agents and inspect
these layouts privately, sharing only verified nonsensitive technical literals. If a literal is
sensitive or ambiguous, keep it private and leave the gate open; do not redact a full record,
collect more data or weaken privacy. No additional data acquisition is needed for shape repair.
