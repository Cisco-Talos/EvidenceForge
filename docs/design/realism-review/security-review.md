# Security Review

Baseline: `0a035e97d94cd2a35ebd1498cc4e133336fe14a4`

Scan ID: `8b382b68-e6ad-4638-8725-d5800897d49f`

Snapshot: `codex-security-snapshot/v1:sha256:42528a309387007d2298edd853bcbcea8c9159cb2aa90175bf4eecc014bdf612`

Status: **complete, sealed, and indexed** on 2026-08-05

Remediation status: **SEC-001 through SEC-010 resolved and SEC-DEFER-001 closed in Batch 6** on
2026-08-07. The sealed scan evidence remains unchanged; the implementation evidence is additive.

## Result

The standard repository scan produced ten validated findings: eight medium-severity and two
low-severity. No critical or high finding survived attack-path calibration for the current local,
operator-invoked CLI boundary. The baseline scan deferred one evaluator-capacity candidate;
Batch 6 subsequently measured the memory curve and closed it with a bounded default contract.

All 1,127 repository files in scope were accounted for. The review closed 664 authoritative
worklist receipts, validated 14 discovery candidates, and completed attack-path analysis for the
12 eligible candidates. The canonical sealed scan artifacts are retained by the Codex Security
workbench; the corresponding entries are also normalized into this package's `findings.json`.

## Threat model

Assets:

- confidentiality and integrity of the invoking user's filesystem;
- CPU, memory, disk, and wall-clock availability;
- integrity and determinism of generated evidence;
- dependency, packaging, and workflow integrity.

Trust boundaries:

- authored or shared scenario/configuration input entering validation and generation;
- scenario assets entering host filesystem reads;
- artifact identifiers becoming output paths;
- supplied datasets entering evaluation parsers;
- host staging trees entering optional Docker parser containers;
- repository dependencies and third-party workflows.

The attacker may supply a crafted scenario bundle or evaluation dataset and may influence paths,
fan-out cardinalities, CIDRs, attachment metadata, and parser records. Optional Splunk application
packages remain operator-selected. Severity therefore reflects the shipped local CLI, while the
report records how unattended, privileged, or multi-tenant deployment would raise impact.

## Validated findings

| ID | Security severity | Remediation priority | Finding | Primary evidence |
| --- | --- | --- | --- | --- |
| SEC-001 | Medium | P2 | Email artifact IDs can escape the output tree | `generation/activity/generator.py:16658` |
| SEC-002 | Medium | P2 | Scenario workload cardinality has no aggregate budget | `models/scenario.py:1052` |
| SEC-003 | Medium | P2 | Attachment size can drive eager allocation and MIME amplification | `models/scenario.py:1588` |
| SEC-004 | Medium | P2 | Port-scan CIDRs are eagerly materialized before target limiting | `generation/engine/storyline.py:5923` |
| SEC-005 | Medium | P2 | Acyclic include graphs have no depth, file, node, or byte budget | `utils/files.py:123` |
| SEC-006 | Medium | P2 | Snare expanded-field parsing has adversarial quadratic behavior | `evaluation/parsers/windows.py:51` |
| SEC-007 | Medium | P2 | Email corpus paths can read outside the scenario asset root | `validation/schema.py:1138` |
| SEC-008 | Medium | P2 | Splunk log staging follows supported-name symlinks | `external_parsers/splunk.py:437` |
| SEC-009 | Low | P3 | Splunk app archives have traversal checks but no extraction quotas | `external_parsers/splunk.py:1230` |
| SEC-010 | Low | P3 | Splunk application-directory staging dereferences symlinks | `external_parsers/splunk.py:561` |

The local CLI boundary is important but not dispositive: scenarios and generated artifacts are
normal sharing units. A downloaded scenario can therefore cross a human trust boundary even when
the process itself is not a network service.

## Batch 6 remediation disposition

| IDs | Disposition | Enforced boundary |
| --- | --- | --- |
| SEC-001, SEC-007 | Resolved | No-follow, regular-file scenario reads and exclusive contained artifact writes |
| SEC-002, SEC-003 | Resolved | Allocation-free generation, duration, occurrence, render, and email-expansion budgets |
| SEC-004 | Resolved | CIDR host selection proportional to requested targets, including IPv6 |
| SEC-005 | Resolved | Include depth, file-count, source-byte, and expanded-node limits |
| SEC-006 | Resolved | Linear Snare parsing plus a shared 16 MiB record ceiling |
| SEC-008, SEC-010 | Resolved | No-symlink/no-special-file Splunk log and application-directory staging |
| SEC-009 | Resolved | Preflighted and stream-counted ZIP/TAR extraction budgets with cleanup |
| SEC-DEFER-001 | Closed | Measured evaluator envelope: 512 MiB, 10,000 files, and 500,000 parsed records |

Every boundary has a malicious regression and a legitimate control. Trusted resource overrides
are named API/CLI decisions and do not disable path, file-type, YAML ambiguity, or archive-member
safety. Exact contracts, commands, capacity measurements, and validation results are recorded in
`batch6-results.json` and `evaluator-capacity-results.json`.

## Candidate dispositions

- **Closed after measurement:** the evaluator still retains its bounded parsed corpus in memory.
  Batch 6 measured retained-record RSS and now rejects inputs above 512 MiB, 10,000 files, or
  500,000 parsed records by default. `--allow-large-evaluation` is an explicit trusted-corpus
  override; this is the final disposition of `SEC-DEFER-001`.
- **Suppressed:** out-of-root scenario includes are intentional composition semantics at this
  baseline; no scenario-package confinement promise currently exists.
- **Ignored after attack-path analysis:** the secret-family overlay regex is written only by the
  same local operator, so no lower-privileged writer was established.
- **Suppressed:** email MIME `content_type` CRLF is rendered into deliberately synthetic evidence;
  no trusted first-party consumer or privilege boundary was established.

## Effective controls

- YAML loading uses safe constructors rather than executable object construction.
- Jinja rendering is sandboxed.
- XML inputs reject DTD and entity declarations.
- Workflow actions are pinned and build surfaces did not produce a reportable supply-chain path.
- SOF-ELK® staging has stronger containment controls than the affected Splunk paths.
- Raw records are an explicit escape hatch, and adversarial payload text is treated as inert
  generated evidence rather than executed content.

## Baseline limitations at scan time

- Docker/Podman Compose was unavailable, and Splunk checks additionally require a locally accepted
  license. The three Splunk findings therefore have complete static traces but no runtime parser
  reproduction in this environment.
- At the sealed scan baseline, evaluator capacity lacked an approved corpus-size/RSS contract and
  calibrated benchmark. Batch 6 supplied both; this is no longer an open limitation.
- Phase 1 authoring skills were excluded except where they define or consume the scenario-schema
  contract.

The first two limitations were subsequently narrowed by Batch 6: archive and staging behavior is
covered by static review plus unit-level filesystem/archive controls, and the evaluator capacity
candidate has a calibrated bounded-RSS probe and a default rejection envelope. A licensed Splunk
runtime parser execution remains unavailable and is still recorded as an external integration
limitation rather than inferred.

## Original recommended security sequence

1. Establish the proposed input/resource-budget and safe-asset/path contracts.
2. Fix artifact write containment and corpus read containment at shared boundaries.
3. Apply aggregate budgets to scenario duration, expanded events, CIDRs, attachments, includes,
   parser records, and archives.
4. Replace the Snare parser's repeated broad regex with a bounded single-pass parser.
5. Introduce one no-symlink, containment-enforcing staging helper for both Splunk input trees.
6. Define the evaluator capacity envelope and close `SEC-DEFER-001` with a measured test.

These recommendations were not implemented during the frozen review itself. They were approved
through the separate contract gate and implemented on the Batch 6 feature branch; the sealed scan
remains the historical source for discovery evidence.
