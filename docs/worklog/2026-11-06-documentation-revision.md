# Release-preparation documentation revision

The user authorized a comprehensive documentation review after the bounded Mac
helper/filesystem and shared realism work, specifically requesting a README map
from simulated OS to log sources, with a separate network category. This pass
describes the current source tree at behavior revision 474. Product version
remains 2.2.0a4; older installers do not acquire the branch's new capabilities.

## Revisions

- README groups Windows/Linux/Mac host logs, network sensors/control points, and
  application/server logs and email artifacts. Canonical IDs, host ownership,
  role/visibility prerequisites and optional output presence are explicit. A
  separate format-reference grid records each source's platform eligibility.
- Added [Simulating macOS workstations](../macos.md): execution host versus
  simulated OS, available sources, examples, qualified launch/helper scope,
  nominal Code file activity, coverage interpretation and remaining limits.
- Reconciled the human format/schema/configuration manuals and the canonical Mac
  evidence/config references. Removed old macOS 26/v10-only and process-only
  guidance; documented v11 file families, current helpers, close semantics,
  snapshots and independent process/file coverage. eCAR FILE/CLOSE is identified
  as an EvidenceForge extension. Config skill reference stays within its existing
  150-line budget, with progressive detail in the existing Mac evidence reference
  and human manuals; no new installer manifest or generated skill edits.
- Updated Studio's actual macOS/Linux installer guidance and current coverage UI;
  source-checkout additions are distinguished from published installer features.
  Release documentation retains user acceptance and final-snapshot gates.
- Corrected example guidance about native process generation, PTY and SSH ULF.
  Reconciled current architecture/capability summaries and preserved explicitly
  historical implementation/assessment evidence. Also corrected the architecture's
  obsolete Python-hash RNG example and 13-member Zeek group count.
- Output-target/parser guidance now separates unchanged native rendering from
  ingestion acceptance. Current external-parser discovery ignores Mac NDJSON and
  zsh-history files; passing mixed-fleet harness results do not validate those
  files. This known limitation is documented, not silently promoted to support.
- Clarified README project-root behavior and replaced a scenario-local persona
  example under the project-wide configuration workflow.

## Verification and remaining work

Reviewed claims against SourceCatalog, packaged native profiles, workload schema,
file/eCAR renderers, Studio coverage controls, parser discovery and release
contracts. A Markdown parser checks the 18 revised pages, their local links and
anchors, source-catalog coverage, exact 16-member Zeek group, Mac source set,
server role/platform eligibility, native event/collector subscription and the
documented overlay example. All checks pass. Existing installer/config-skill/parser
reference tests: 61 passed. Whole-repository Ruff, formatting and whitespace checks
pass. No generator/GUI/schema behavior changed in this documentation pass.

Historical worklogs, assessment reports, changelog/release history and raw private
references remain intact. No new collection, generation campaign, version bump,
commit, PR or publication was performed. Next steps remain representative Mac and
Studio user acceptance, integration when authorized, then final release validation;
the full routine/coverage/slow/platform/installer gates are not closed by this pass.

## Reader-facing scenario follow-up

The user deprioritized worklog-only references and authorized replacing the
external-parser quickstart's local healthcare input if the quickstart's purpose
is preserved. Both inputs select the same nine format groups and deploy network,
IDS, firewall, web and proxy owners. The committed branch-office workload is
smaller (9 systems/5 users/6 hours versus 24/17/14) and has fewer event types;
it is now explicitly a quickstart, with exhaustive family coverage assigned to
the existing purpose-built parser smoke tests. Both target commands use separate,
explicit output roots and corresponding parser data paths. Branch-office CLI
validation succeeds against packaged defaults; two existing parser-documentation
tests and local path/Git-inclusion checks pass. No live parser/container run or
new generation campaign was performed for this documentation-only change.

The old macOS 26 assessment has no source/test/build path dependency in the
current tree; it is retained by historical design/provenance links. Its README
now identifies it as historical, points to current Mac guidance, and names the
two already-committed revision inputs rather than a nonexistent top-level source.
No archived scenario/report was added or deleted. Ruff/format/whitespace checks pass.
