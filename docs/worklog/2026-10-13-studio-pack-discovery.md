# Studio published pack discovery

## Report and scope

The user published the Talos Enterprises organization pack as 1.0.0 through Studio, then opened
the INC001-Ransomware scenario chat. The chat reported that no Talos pack or draft existed.
The initial investigation was read-only, apart from this record and the durable backlog entry.
The user subsequently approved implementation of the proposed discovery fix. Implementation is
complete in the source checkout; the installed application and CLI have not been replaced.

## Confirmed evidence

- Selected workspace: `/Users/dabianco/Documents/EvidenceForge`.
- Studio indexes the published organization at
  `.eforge/artifacts/releases/davidjbianco/organization/talos-enterprises/1.0.0/source/pack.yaml`.
- The authenticated, read-only source and lifecycle endpoints returned its Schema 3 manifest,
  `status: published`, publisher `davidjbianco`, identifier `talos-enterprises`, display name
  `Talos Enterprises` and version `1.0.0`. Lifecycle inspection verified the release receipt,
  source files and captured technology industry dependency. Receipt digest:
  `8b1d99c4363120152715fb1c62bcf71b22a19ff17bcb7f06b374760d20cd2772`.
- The retained scenario chat shows it used
  `eforge pack list --json --project-root /Users/dabianco/Documents/EvidenceForge`.
  The response had only six bundled packs, no Talos entry and no reported issues. This was the
  correct workspace selection. `pack drafts` correctly returned none after publication.
- The shell CLI used by the chat is installed EvidenceForge `2.2.0a2`. Its exact-reference
  resolver has the same Schema 3 fallback as the source checkout.
- Direct Documents reads from this agent process were blocked by macOS privacy controls.
  Diagnosis used the existing Studio source/lifecycle APIs with its private token; no token was
  displayed and no settings, permissions or service lifecycle were changed.

## Cause

`PackRepository.list()` enumerates package packs and `.eforge/packs`. The CLI then adds legacy
imported immutable inventories from `.eforge/releases` and the user's corresponding library.
Neither path enumerates managed Schema 3 publications in `.eforge/artifacts/releases`.
Studio uses the artifact repository for library discovery, so it shows the publication while
the pack skill's initial `pack list` does not.

`PackRepository.resolve()` already falls back to `artifacts.lifecycle.resolve_reference()` for
an absent project-repository path. Consequently exact project references can resolve these
publications despite their omission from inventory. The scenario agent never attempted the
known exact reference because discovery reported no matching entry.

## Immediate guidance

Use this identity in the scenario chat:

```text
project:davidjbianco:organization:talos-enterprises@1.0.0
```

Its read-only inspection command is:

```sh
eforge pack show project:davidjbianco:organization:talos-enterprises@1.0.0 \
  --project-root /Users/dabianco/Documents/EvidenceForge --json
```

Direct CLI inspection was not executed against Documents in this session because that process
lacked macOS access. The existing chat can use its established access. Exact resolution support
was confirmed in both source and installed CLI code; release existence and integrity were
confirmed through Studio. No republishing, manual copying or hydration is needed for discovery.

## Approved repair

Extend the common pack inventory to include verified managed Schema 3 industry and organization
publications, with their exact publisher/name/version, source, paths, exports, dependencies and
resolvability. Preserve the existing scope/JSON contracts and legacy imported-library semantics.
Define consistent handling for duplicate exact identities and isolate corrupt receipt findings
without discarding other valid entries. Keep discovery read-only and independent of Studio's
database; never add parent-directory searches or silently choose another root.

Add regressions for publishing an organization and industry pack, discovery after its draft is
completed, exact show/scenario composition, display names differing from identifiers, duplicate
identities, corrupt releases and legacy inventories. CLI discovery and the existing resolver
must agree about usable references.

## Implementation

- Added shared, read-only publication discovery under `artifacts/discovery.py`. It enumerates
  only the selected workspace's managed releases, rejects symbolic links and verifies each
  receipt independently. Invalid entries become individual issues while valid peers remain
  available. Studio pack discovery and completed-draft filtering use the same enumeration.
- `PackRepository.inventory()` now includes published Schema 3 industries and organizations.
  CLI JSON exposes their exact `reference`, `display_name` and `pack_schema_version` alongside
  the existing digest, exports, dependencies and source paths. Managed publications have
  `scope: project-release`, `source: project`, `mutable: false`, `resolvable: true` and
  `hydration_state: native`.
- `--scope project` includes usable project references, including managed publications.
  `--scope project-release` includes managed publications and existing imported releases.
  Legacy imported Schema 2 releases retain their existing hydration/resolvability semantics.
  Invalid inventory entries produce the existing partial JSON envelope and exit status 2.
- Identical copies under `.eforge/packs` deduplicate to the verified canonical publication.
  Conflicting contents for the same project identity are reported and exact resolution fails;
  explicit paths remain available for inspection. Corrupt publications cannot silently fall
  back to a mutable copy.
- Organization dependency locking now discovers published Schema 3 industries through the
  same inventory, allowing subsequent scenario composition to use their exact references.
- Updated the canonical pack skill and reference documentation. Installed/generated skills
  were not changed. Added 21 regression cases covering both pack kinds, completed drafts,
  scopes, exact inspection, dependency locking, scenario composition, duplicate/conflicting
  identities, corrupted publications, aliases, links, long names, staging entries, no implicit
  parent lookup, read-only discovery and legacy import/hydration.
- Updated two artifact-naming test expectations to use `DATABASE_VERSION` after the preceding
  chat effort's database v3 migration. Migration declarations and checksums were unchanged.

## Verification

- Related routine suites: **234 passed, 1 deselected** (`--no-cov`), including all 21 new cases,
  pack CLI/releases, artifact lifecycle/naming/lineage/properties, desktop discovery, skill
  installation, CLI info and Studio pack/artifact identity and lifecycle tests.
- Extended pack lifecycle: **31 passed** (`-m slow --no-cov`).
- Extended scenario composition: **29 passed** (`-m slow --no-cov`).
- Generated Studio API type check passed (`npm --prefix desktop-ui run types:check`).
- Repository Ruff checks and format check passed; **1,043 files** already formatted.
  `git diff --check` passed.
- Tests published real artifacts into isolated temporary workspaces and exercised the CLI,
  resolver, dependency locks and scenario composition. The user's Talos pack and scenario
  were unchanged. A later check found the existing Studio service discovery file absent;
  no service was started to obtain another live sample. The initial verified layout and
  isolated regression fixtures provide the acceptance evidence for this repair.

## Initial delivery state

Source implementation is ready for integration. The installed `2.2.0a2` CLI and Studio require
an updated build to use it. No application restart, installation, user-pack repair, automatic
validation, product-version change, commit, tag or publication was performed.

## Generation guard follow-up

After updating their installation and validating a scenario, the user reported a fatal generation
behavior mismatch: declared `0a35207424914905c6295861aeefab721b113a29ee4c49daa8fe4fa8813abbad`,
actual `0aa7df4dc07f6dfb84b03740bfc114bcf4c7ef121e7b103967df4e3d72ac3941`.
This was an implementation omission in this discovery fix: `composition/packs.py` belongs to
the guarded behavior surface, and its change needed a matching manifest revision. The earlier
pack-focused suites did not include the behavior-manifest checker.

Confirmed both the source checkout and the user's newly installed CLI had those exact hashes.
The only modified file covered by the surface was `composition/packs.py`. Hashing with that
file's HEAD bytes restored in memory reproduced the old declared digest exactly, establishing
the cause without touching the scenario, installation or running Studio.

Appended behavior revision **164**, `discover-managed-schema3-pack-publications`, with impact
`none` for equivalent resolved inputs and deterministic rendering, and declared the actual
surface digest. Preserved all prior behavior history and the runtime guard. This is independent
of the product version and Studio state migrations.

`uv run --no-sync python scripts/check_generation_behavior.py --base-ref HEAD` passed at
revision 164 with the exact reported actual digest. Ruff check/format and `git diff --check`
passed. No additional tests or generation were run. Future discovery/composition verification
must include this checker before delivering a source or packaged build.

The installed noneditable CLI still contains revision 163 and needs rebuilding/reinstalling
from the corrected source before another generation attempt. This session did not update the
installed package, rebuild/restart Studio or replace the failed run's output.

## Source commit handoff

The user authorized committing and pushing this fix with the Studio chat improvements on the
existing `dev` branch. Final pre-commit checks include Ruff, generated API types, synchronized
unchanged product versions and the generation behavior checker against HEAD. Installation,
restarting Studio and release publication remain outside this source delivery.
