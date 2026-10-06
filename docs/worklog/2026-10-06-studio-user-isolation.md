# Studio account isolation

User approved implementation October 6 and explicitly deferred creating additional OS accounts.
Branch: `codex/gui`. This effort strengthens ownership around the previously implemented helper
lifecycle and upgrades, without changing database/settings/layout schema versions or engine
formats. No accounts, production-state modifications, application version bump or DMGs.

## Contracts and implementation

- `ownership.py` reads the actual POSIX account UID or Windows process token **TokenUser** SID.
  POSIX real/effective/saved process IDs must agree; mixed elevation refuses. No username or
  client-provided account header serves as evidence of ownership. The Windows target process
  adapter uses limited query rights, closes process/token handles and propagates access failures.
  Native API basis: [Microsoft process enumeration](https://learn.microsoft.com/en-us/windows/win32/procthread/process-enumeration)
  and [OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken).
- `service.json` now has independent discovery schema version 1 and an account identity.
  Existing version-0 descriptors remain readable only from protected owned storage, followed by
  verification of the actual live process. Legacy descriptors lacking an executable must match
  the connecting interpreter. Future/malformed discovery blocks instead of triggering a new
  helper. Credential reads are bounded, no-follow, regular single-link handles with POSIX mode
  restrictions or native private DACL checks. Errors and model representations omit tokens.
- Bootstrap verifies declared and actual owner, PID creation time, executable and exact helper
  module command before every authenticated probe/handoff. It rechecks immediately before
  termination. An exited/reused PID is stale; access denial, foreign ownership or unrelated
  commands are refusals. A verified starting helper is awaited, not replaced by another writer.
  `service-instance.lock` prevents competing server publication, separately from launch locking.
  Discovery and launch-agent files use flushed atomic publication. Graceful idle shutdown removes
  discovery; Uvicorn can leave stale discovery after replaying SIGTERM, which is safely rejected
  by the next launch's identity check.
- Native concurrent attachment exposed a reproducible macOS `O_CREAT|O_NOFOLLOW` creation race
  returning `ENOENT` for a missing launch lock. POSIX state-file opens now atomically create with
  `O_EXCL`, or attach to an existing inode without `O_CREAT`; a disappearing existing file is a
  refusal. Existing-file inode identity is checked after opening. No-follow, ownership and
  single-link checks remain enforced. A 20-round barrier test retains the winner until all
  contenders attempt acquisition, proving one owner per round; native attachment is repeated
  against three independently created helpers. Failed descriptor publication closes the listener
  and releases instance ownership, including before service initialization.
- Private config/data/state/cache/log roots are verified before bootstrap attachment,
  coordinator inspection or settings loading. Root/file ownership checks happen before
  POSIX permission repair. Owned application defaults can be tightened to 700 without changing
  existing contents; explicit custom roots must be private already. Standard XDG paths retain
  the default policy even when explicitly selected by environment variables. Missing roots are
  created privately. System ancestors are checked, never chmodded; unsafe writable ancestry
  refuses except root-owned sticky temporary-directory ancestry. Handle checks reject root
  substitution. Windows reuses native owner/SID, DACL and reparse-point protection.
- Direct stores independently require protected storage; state-file primitives reject foreign
  POSIX leaves, including locks. Failed coordinator preflight produces blocked maintenance
  status without inspecting authoritative records or initializing the database. Workspace
  ownership remains separate; no engine bytes or permissions are changed by private adoption.
  `StudioPaths.custom_roots` is internal policy metadata, excluded from API serialization.
  Explicit paths supplied by trusted application/test code retain default repair policy unless
  they declare custom roots; normal environment selection declares overrides automatically.
- Bearer authentication remains required. Session/window IDs track lifetime, never authorization.
  Same-account windows on one data directory share settings, workspace, scheduler and concurrency
  cap. Different accounts use separate private paths/helpers/caps; no machine-wide generation
  limit or client-user header has been introduced.

## Test traceability

| Guarantee | Named evidence |
| --- | --- |
| Foreign claims never connect, start or signal | `test_foreign_claimed_owner_never_sends_token_or_starts_or_signals` (UID and SID) |
| Actual process checked before token delivery | `test_actual_process_checked_before_any_authenticated_request` (foreign, denied, exe, command) |
| Identity rechecked before termination | `test_replacement_rechecks_identity_after_authenticated_handoff`; existing reused-PID runtime test |
| Idle authenticated replacement, no force kill | `test_verified_idle_helper_is_replaced_without_force_kill` |
| Starting helper cannot spawn a second writer | `test_verified_starting_helper_never_starts_second_writer` |
| Atomic concurrent launch-lock creation/exclusive ownership | `test_concurrent_creation_and_ownership_of_launch_lock` (20 rounds) |
| Publication failure releases listener/instance lock; actual executable recorded | `test_failed_discovery_publication_releases_listener_and_instance_lock` |
| Future/malformed discovery and errors protect credentials | `test_discovery_refusals_do_not_disclose_credentials` |
| Independent legacy verification | `test_legacy_discovery_is_accepted_only_after_live_process_verification` |
| Unsafe credential paths/modes refuse | `test_unsafe_discovery_entry_cannot_be_read` (broad mode, symlink, hardlink, directory, FIFO) |
| Foreign root/file refuses before repair or adoption | `test_foreign_root_refuses_before_other_roots_are_modified`; `test_foreign_authoritative_file_is_not_adopted_or_overwritten` |
| Owned defaults repair, unsafe custom roots do not | `test_owned_default_roots_are_tightened_without_modifying_contents`; `test_custom_insecure_root_is_refused_without_repair_or_store_creation` |
| Custom aliases and root substitution do not escape | `test_custom_link_is_not_resolved_away`; `test_directory_substitution_after_open_never_changes_external_permissions` |
| Independent leaf replacement during open is refused | `test_file_substitution_between_inspection_and_open_refuses_changed_inode` |
| OS adapters reject mixed IDs/use token SIDs | `test_current_and_process_identity_use_os_values_not_usernames`; `test_windows_account_adapter_uses_token_sid_on_every_platform` |
| Independent data roots/settings/records | `test_separate_account_roots_preserve_independent_settings_and_records` |
| Session/account claims are not credentials | `test_spoofed_account_and_session_headers_do_not_authorize_requests` |
| Schema generation has no private-state effects | `test_schema_generation_does_not_prepare_or_repair_private_state` |
| Native same-account helper, concurrency, locks and replacement | `test_native_windows_share_one_verified_helper_and_instance_lock` (windows means UI connections, all OSes) |
| Native unrelated child cannot masquerade as helper | `test_native_process_owner_is_distinct_from_a_descriptor_claim` |
| Shared scheduler cap across windows | Existing `test_multiple_windows_share_one_generation_concurrency_limit` session contract |
| Recovery remains safe under publication/crash faults | Existing routine preservation suite and required 145-case extended persistence-boundary matrix |

Simulations inject identities or stat ownership; they do not prove native kernel access denial
between actual separate accounts. Native tests use only disposable state and harness-owned child
processes, with synchronized concurrent attachment and bounded startup readiness polling. The
required Linux/macOS/Windows recovery CI matrix includes both ownership test files alongside
helper lifecycle tests. No account creation is added to CI.

## Validation and remaining acceptance

Final macOS evidence:

- Routine Studio service/runtime/lifecycle/contracts, ownership and upgrade/recovery regression:
  **324 passed, 1 skipped**, 87.37 seconds. The skip is the native Windows ACL test. The final
  ownership-only suite adds the independent-leaf substitution check and passes **37 tests**.
- Required extended recovery matrix on the final filesystem implementation: **145 passed**,
  93.02 seconds, without coverage.
- Final native ownership/lifecycle gate: **6 passed**, 16.90 seconds. Includes three concurrent
  attachment trials, actual native process account verification, unrelated-child refusal, graceful
  idle shutdown and worker preservation. Local process inspection/loopback tests needed sandbox
  escalation; they touched only harness-created helpers and disposable data.
- All **216 frontend tests** passed; API types are current and TypeScript/Vite build passed
  (existing bundle-size advisory). Full Ruff lint/format and diff checks passed.
- An initial new authentication test inherited the default workspace; it was corrected to an
  explicit disposable workspace before the final gates. Read-only metadata checks confirmed the
  existing default-workspace layout and owner lock remained unchanged from October 5. Production
  records and engine content were not modified.
- Delivery preflight removed trailing whitespace at the end of four newly added SQL fixtures;
  SQL statements and saved records are unchanged. The fixture preservation/recovery suite was
  rerun before pushing. Implementation commit: `86d5f6f0`.

Linux/Windows native CI remains required before release; no native execution on those hosts is
claimed here. The user requested committing and pushing the cumulative upgrade, lifecycle and
isolation effort on October 6. The feature branch retains the existing application version.

**Explicitly deferred:** use genuinely separate accounts on each supported OS to launch Studio
simultaneously, verify separate private data/settings/queues/limits, refuse foreign discovery and
custom data roots, verify no cross-account connection/signal/permission repair, and independently
verify Windows ACL denial from the other account. Include same display names/different SIDs and
account/session switching where the host supports it. This is durable backlog work in `TODO.md`,
not a reason to block the user-approved local implementation or to create accounts now.
