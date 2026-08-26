---
name: eforge-pack-release
description: Build, inspect, import, hydrate, and verify immutable EvidenceForge .efpack releases.
---

# EvidenceForge Pack Release Operations

Use this skill for immutable pack release operations, not substantive catalog or organization edits.
Use `/eforge pack` to discover/copy packs and the industry or organization skills to edit them.
Read `/eforge:references:project-context` and `/eforge:references:pack-reference` before
selecting a release root or scope.

Run from the intended project root. User-library releases are dehydrated: offer them to the user,
then hydrate only after confirmation. Never make a user-library release an implicit scenario dependency.

Before `pack init` or `pack copy`, ensure the publisher identity is explicitly confirmed. If the CLI
returns an identity-required result, show the proposed locally derived value and ask the user to
confirm it or configure another value. Do not silently persist a username/hostname-derived identity.

1. Validate the editable root pack and its locked dependency closure.
2. Build a local share artifact with `eforge pack build <ref> --output /absolute/release.efpack --json`.
3. Inspect a received artifact with `eforge pack inspect /absolute/release.efpack --json`.
4. Import only after the user selects `project` or `user` scope. Import validates archive paths,
   hashes, manifests, locks, and every contained pack before publishing any release.
5. Hydrate an explicitly selected user-library release with
   `eforge pack hydrate publisher:type:name@version --json` before scenario use.

`.efpack` files are local release artifacts; this skill does not upload to a registry or remote host.
