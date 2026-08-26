# Pack release validation

## Scope

Validate the Pack Schema 2.0 portable-release vertical slice and replace the
generic shared slow generation fixture with the official MetroLink Specialty
Care consumer.

## Test-tier decisions

- **Normal:** Pack Schema/lock models, deterministic .efpack construction,
  archive traversal/hash safety, closure validation, project/user immutable
  import, explicit hydration, collision rejection, rollback, and CLI JSON
  contracts. These are bounded ZIP and temporary-filesystem operations and do
  not require generation.
- **Slow:** One shared fixed-seed MetroLink consumer generation. It proves the
  exact resolved healthcare and organization release digests plus representative
  email, endpoint, SMB storage, and Zeek network evidence. Northstar remains
  covered by normal composition tests; a second organization-generation run
  would duplicate release-path coverage.
- **Soak:** Retain the pre-existing 100-user/eight-hour medium-dataset
  generation diagnostic. No additional pack-release soak test is needed until
  release-closure scale or archive-size performance targets are established.

## Evidence

- MetroLink slow consumer: eight assertions selected, one shared generation;
  the observed generation setup was about 75 seconds on the development
  machine.
- Fast focused pack/release tests passed after adding archive and CLI coverage.

## Follow-up

The release workflow still needs the broader roadmap items tracked in TODO.md,
including complete publisher-qualified resolution, identity consent, SemVer lock
refresh, all-scope inventory, and the remaining documentation and
skill-contract coverage.
