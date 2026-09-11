---
name: eforge-pack-release
description: Build, inspect, import, hydrate, and verify immutable EvidenceForge .efpack releases.
---

# EvidenceForge Pack Release Operations

Use this skill for immutable pack release operations, not substantive catalog or organization edits.
Use `/eforge pack` to discover/copy packs and the industry or organization skills to edit them.
Read `/eforge:references:project-context` and `/eforge:references:pack-reference` before
selecting a release root or scope.

Run from the intended project root. Project- and user-library releases are immutable, non-resolving,
and initially dehydrated. Never make an immutable release an implicit scenario dependency.

Before `pack init` or `pack copy`, inspect `eforge pack publisher show --json`. If the CLI returns
`identity_required`, ask the user to configure an explicit ID and display name with `pack publisher
set`; never derive identity from a username, hostname, repository, or pack name.

1. Preview `eforge pack lock <project-ref> --json`; apply only when requested with `--apply`.
2. Validate the editable root pack and its exact locked dependency closure.
3. Build a local share artifact with `eforge pack build <ref> --output /absolute/release.efpack --json`.
4. Inspect a received artifact with `eforge pack inspect /absolute/release.efpack --json`.
5. Import only after the user selects `project` or `user` scope. After complete validation, pass one
   `--accept-publisher <id>` for every distinct declared publisher on every import. This is namespace
   acknowledgement, not authenticity or persisted trust.
6. Discover immutable entries with `eforge pack list --scope project-release|user-release --json`.
7. Hydrate an explicitly selected root and its complete locked closure with
   `eforge pack hydrate publisher:type:name@version --scope project|user --json`.

`.efpack` files are local release artifacts; this skill does not upload to a registry or remote host.
