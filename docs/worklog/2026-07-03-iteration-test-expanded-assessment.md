# Iteration-Test-Expanded Assessment

## Context

Running 10 additional eforge-assess loops for
`scenarios/iteration-test-expanded/scenario.yaml`, continuing after prior loops 1-7 from the
original assessment history. This worktree is using branch
`codex/iteration-test-expanded-assessment`.

## Loop 8

- Automated eval passed at `96.07106951276535` over 93,947 records.
- Blind panel final deliberated mean synthetic-confidence: `53.75` (`mixed/inconclusive`).
- Main selected fixes for loop 9:
  - SSH/RDP native auth/session rows must not visibly precede same-tuple eCAR `FLOW CONNECT`.
  - Sysmon Event ID 1 Version 5 must include `ParentUser`.
  - Same-millisecond endpoint FLOW texture remained a lower-priority issue.

## Loop 9

- Automated eval passed at `95.48480741954764` over 88,731 records.
- Blind initial mean synthetic-confidence: `62.5`; deliberated mean: `61.0`.
- Hard probe results:
  - RDP login-before-flow: `0 / 23`; missing inbound eCAR FLOW: `0 / 23`.
  - SSH login-before-flow: `0 / 123`; missing inbound eCAR FLOW: `2 / 123`.
  - Sysmon Event ID 1 missing `ParentUser`: `0 / 881`.
  - Same-millisecond endpoint FLOW pairs: `6`.
- Deliberation downgraded the host reviewer claim that syslog files were absent; syslog files were
  present. Proxy exfil byte accounting was downgraded from impossible contradiction to ambiguous
  source-native accounting.
- Selected loop 10 fixes:
  - Make eCAR remote-session source observation coherent for SSH/RDP transport plus session rows.
  - Merge duplicate same-source/same-destination email route hops before Postfix/syslog/EML
    rendering.
  - Add proxy `cs_bytes`/`sc_bytes` metadata to the default combined-log tail.
  - Resolve known remote 4648 target endpoints so remote explicit-credential events are joinable.
  - Exclude `COLLECTION_PROFILE.json` from blind reviewer bundles.

## Loop 10

- Automated eval passed at `95.47312087705855` over 87,796 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `96.14681535601788`
  - Causality: `88.86552396878484`
  - Timing: `96.10018022928934`
- Hard probe results:
  - RDP login-before-flow: `0 / 26`; missing inbound eCAR FLOW: `0 / 26`.
  - SSH login-before-flow: `0 / 92`; missing inbound eCAR FLOW: `0 / 92`.
  - Sysmon Event ID 1 missing `ParentUser`: `0 / 870`.
  - Postfix duplicate queue lifecycles: `0`.
  - Duplicate EML `Received` hops: `0`.
  - Proxy upload rows missing `cs_bytes` metadata: `0 / 30`; max upload `cs_bytes`:
    `314782942`.
  - Remote-target Windows 4648 blank endpoints: `0 / 48`.
  - Same-millisecond endpoint FLOW pairs: `4`.
- Blind bundle was copied to `loop-10/review-data` without `COLLECTION_PROFILE.json`.
- Blind initial mean synthetic-confidence: `49.75`; deliberation was not triggered.
- Loop 10 reviewer priorities:
  - Mail queue identity split across Zeek SMTP `last_reply`, Postfix queue IDs, and EML
    `Received` headers.
  - Short-lived endpoint process lifecycles, especially RDP clients and one-shot Linux/Windows
    wrapper commands.
  - Admin-share browser upload path requiring stronger access evidence or a normal staging path.
  - Linux PAM/sudo actor texture and public web-client diversity.

## Loop 11 Fix Target

- Selected family: mail queue identity.
- Owning abstraction: email delivery bundle / canonical SMTP hop construction in
  `ActivityGenerator`, with Postfix receive-side lifecycle IDs as the source-native identity for
  Linux receiving MTAs.
- Invariant: for any plaintext SMTP hop accepted by a Linux Postfix receiver, Zeek SMTP
  `last_reply`, the receiver's Postfix queue lifecycle, and EML `Received` relay ID share the
  receiver's queue identity; upstream Postfix delivery rows reporting `queued as ...` use the
  downstream receiver's queue identity.
- Entry paths: storyline `email_message`, baseline background email, inbound external mail,
  internal submission, internal relay, mixed internal/external recipient routing, and outbound
  external relay paths.
- Consumers: Zeek `smtp.json`, Postfix `syslog.log`, EML artifacts, email artifact manifest,
  ground truth SMTP UID references, plausibility/causality eval, and blind reviewer mail pivots.
- Layer rationale: the delivery bundle knows message ID, route hop, receiver system, TLS
  visibility, and Postfix-vs-Exchange receiver family before renderers run; emitter-only string
  rewrites would not fix syslog/EML/Zeek agreement across sibling hops.
- Residual sibling risks: encrypted STARTTLS rows intentionally hide message fields and may expose
  only STARTTLS replies; Exchange-like Windows receivers use native InternalId-style replies rather
  than Postfix queue IDs.
- Implemented tests:
  - `test_plaintext_smtp_reply_uses_postfix_receive_queue_id`
  - `test_plaintext_external_inbound_reply_uses_postfix_receive_queue_id`
  - `test_mixed_internal_external_outbound_hops_scope_recipients`
- Focused verification passed:
  `uv run pytest --no-cov tests/unit/test_email_evidence.py::test_plaintext_smtp_reply_uses_postfix_receive_queue_id tests/unit/test_email_evidence.py::test_plaintext_external_inbound_reply_uses_postfix_receive_queue_id tests/unit/test_email_evidence.py::test_mixed_internal_external_outbound_hops_scope_recipients`

## Loop 11

- Automated eval passed at `95.47312087705855` over 87,796 records.
- Hard probe `hard_probe_mail_identity.json`:
  - In-scope SMTP queue rows checked: `14`.
  - Postfix/EML queue mismatches: `0`.
  - Distinct Windows/Exchange-style MTA rows skipped: `1`.
- Blind initial mean synthetic-confidence: `46.5`; deliberation was not triggered.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `70`, synthetic-confidence `44`.
  - Detection Engineer: Inconclusive, confidence `74`, synthetic-confidence `45`.
  - Network Forensics: Inconclusive, confidence `73`, synthetic-confidence `38`.
  - Host/EDR: Inconclusive, confidence `72`, synthetic-confidence `59`.
- Selected loop 12 candidates:
  - P1 short-lived endpoint process lifecycle closure for `mstsc.exe`, `cmd.exe /c`,
    PowerShell wrappers, `runas.exe`, `systemctl`, and `timedatectl`.
  - P1 admin-share browser upload path, either via normal staging or visible access evidence.

## Loop 12 Fix Target

- Selected family: browser/upload staging path.
- Owning abstraction: staged archive SMB-read action bundle plus storyline exfil handoff helpers.
- Invariant: SMB/network file evidence can preserve the server-side archive filename, but an upload
  browser reads only a user-accessible local staged path. The local stage has a visible source create
  before the browser read and the copy/staging process terminates.
- Entry paths: storyline `Compress-Archive` staging followed by large exfil `connection` events from
  the same or different source host.
- Consumers: Zeek `files.json`, eCAR file/process rows, proxy upload rows, host forensic pivots, and
  threat-hunting cross-source staging timelines.
- Implemented tests:
  - `test_compress_archive_exfil_emits_archive_sized_smb_download`
  - `test_compress_archive_exfil_handoff_uses_upload_host_source_read`
  - `test_staged_archive_smb_read_bundle_anchor_is_stable`
- Focused verification passed:
  `uv run pytest --no-cov tests/unit/test_storyline_command_networks.py -k "compress_archive_exfil or staged_archive_smb_read_bundle_anchor"`
- Broader focused verification passed:
  `uv run pytest --no-cov tests/unit/test_storyline_command_networks.py tests/unit/test_activity.py tests/unit/test_email_evidence.py tests/unit/test_proxy_referrer.py tests/unit/test_zeek_eval_parsers.py tests/unit/test_dispatcher.py tests/unit/test_ecar_spec_compliance.py tests/unit/test_zeek_activity_contexts.py tests/unit/test_world_model.py tests/unit/test_sysmon_new_events.py`
  (`815 passed, 10 skipped`).
- Ruff verification passed:
  - `uv run ruff check .`
  - `uv run ruff format --check .`

## Loop 12

- Automated eval passed at `95.52322362070365` over 87,803 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `96.34722633059829`
  - Causality: `88.86552396878484`
  - Timing: `96.10018022928934`
- Hard probe `hard_probe_upload_staging.json`:
  - Copy process creates: `1`; copy process terminates: `1`.
  - Browser/admin-share file reads: `0`.
  - Local staged file creates: `1`; local staged file reads: `1`.
  - Copy process created local stage: `1`; Chrome read local stage: `1`.
  - Local stage create before read: `true`.
  - SMB `files.json` preserved server-side admin-share filename: `true`.
- Blind initial mean synthetic-confidence: `33.5`; deliberation mean: `37.0`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `74`, synthetic-confidence `40`.
  - Detection Engineer: Real, confidence `74`, synthetic-confidence `24`.
  - Network Forensics: Real, confidence `66`, synthetic-confidence `32`.
  - Host/EDR: Inconclusive, confidence `66`, synthetic-confidence `38`.
- Deliberation was triggered by verdict disagreement. The panel agreed there were no hard
  contradictions and ranked the remaining issues as source texture/cache-contract problems.
- Selected loop 13 target:
  - P1 Linux eCAR user/admin CLI ancestry. `systemctl`, `loginctl`, `pkcon`, and
    `timedatectl` rows should not repeatedly appear as direct PID 1 children for user/admin
    principals unless the action is modeled as service/timer owned.
  - P1 backup candidate: machine-account Kerberos TGT caching.

## Loop 13 Fix Target

- Selected family: Linux polkit companion CLI ancestry.
- Owning abstraction: baseline polkit action companion process materialization.
- Invariant: user-facing polkit CLI tools (`systemctl`, `loginctl`, `pkcon`,
  `timedatectl`, `nmcli`) are foreground user processes with visible shell parents and bounded
  termination; daemon helpers (`packagekitd`, `NetworkManager`) may remain service/systemd-owned.
- Implemented tests:
  - `test_polkit_cli_companion_process_uses_visible_user_shell`
  - Existing daemon-companion assertion preserved in
    `test_polkit_action_messages_materialize_companion_process`.
- Focused verification passed:
  `uv run pytest --no-cov tests/unit/test_phase5_system_traffic.py -k "polkit"`.
- Broader focused verification passed after formatting:
  `uv run pytest --no-cov tests/unit/test_phase5_system_traffic.py tests/unit/test_activity.py tests/unit/test_email_evidence.py tests/unit/test_proxy_referrer.py tests/unit/test_zeek_eval_parsers.py tests/unit/test_dispatcher.py tests/unit/test_ecar_spec_compliance.py tests/unit/test_zeek_activity_contexts.py tests/unit/test_world_model.py tests/unit/test_sysmon_new_events.py`
  (`809 passed, 10 skipped`).

## Loop 13

- Automated eval passed at `95.9069928415457` over 95,978 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `97.10299166795664`
  - Causality: `90.65955111711948`
  - Timing: `94.83178572638337`
- Hard probe `hard_probe_linux_polkit_cli_ancestry.json`:
  - CLI creates: `59`.
  - CLI rows with direct system/PID1 parent: `0`.
  - CLI rows terminated: `59`.
  - Daemon/systemd child rows preserved: `1`.
- Blind initial mean synthetic-confidence: `47.25`; deliberation mean: `52.0`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `78`, synthetic-confidence `47`.
  - Detection Engineer: Inconclusive, confidence `74`, synthetic-confidence `52`.
  - Network Forensics: Inconclusive, confidence `72`, synthetic-confidence `38`.
  - Host/EDR: Inconclusive, confidence `74`, synthetic-confidence `52`.
- Deliberation calibrated scores to Threat Hunter `53`, Detection Engineer `55`, Network
  Forensics `44`, Host/EDR `56`.
- Selected loop 14 target:
  - P0 transport-to-auth/session contract for SMB baseline traffic. Failed/reset SMB transport
    must not anchor a successful Windows Type 3 logon on the same tuple.

## Loop 14 Fix Target

- Selected family: SMB baseline transport plus Windows network logon pairing.
- Owning abstraction: baseline SMB connection generation in the file-server and workstation SMB
  browsing paths, before `_emit_smb_logon_pair` creates successful Type 3 logon/logoff evidence.
- Invariant: an SMB transport that is intentionally reused as the source tuple for a successful
  Windows Type 3 logon must be `conn_state="SF"` across Zeek/eCAR/Windows evidence; generic SMB
  traffic that does not produce successful auth may still use reset/failure texture.
- Implemented test:
  - `test_successful_logon_requires_successful_smb_transport_state`.
- Focused verification passed:
  `uv run pytest --no-cov tests/unit/test_file_server_logon.py tests/unit/test_phase5_system_traffic.py -k "smb or polkit"`.
  (`13 passed, 56 deselected`).

## Loop 15 Fix Target

- Selected family: browser/proxy application realism for modern SaaS browsing.
- Owning abstraction: browser session site-map rendering plus proxy/browser User-Agent selection.
- Invariant: modern SaaS/browser page-load sessions should use supported Chrome/Firefox/Edge-style
  browser identities, not legacy IE11/Trident, and time-bearing browser API paths should be derived
  from the modeled session time instead of a fixed future date.
- Entry paths: baseline browser-session action bundle, direct `ActivityGenerator` HTTP/proxy URI
  synthesis, web/session profile browser UA selection, and proxy access rendering via `ProxyContext`.
- Consumers: proxy access logs, Zeek HTTP rows, eCAR source process ownership for browser/proxy
  flows, detection-review browser/SaaS pivots, and browser-session tests.
- Layer rationale: the site-map and UA catalogs own the semantic browser/application identity before
  emitters render rows; proxy emitters should only serialize the already-selected path and UA.
- Residual sibling risks: non-browser API/tool traffic can still intentionally use tool UAs such as
  curl or python-requests, and broader proxy appliance format realism remains a separate follow-up.

## Loop 15

- Automated eval passed at `95.26504771703925` over 94,496 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.35468821926963`
  - Causality: `89.62248219110784`
  - Timing: `95.10377557222441`
- Hard probe `hard_probe_proxy_browser_calendar.json`:
  - Proxy access rows scanned: `2078`.
  - Legacy IE/Trident proxy rows: `0`.
  - Legacy IE/Trident modern SaaS rows: `0`.
  - Fixed future calendar rows: `0`.
  - Calendar `timeMin` values: `2024-03-01T00:00:00Z`.
- Blind initial mean synthetic-confidence: `37.75`; deliberation mean: `38.0`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `64`, synthetic-confidence `58`.
  - Detection Engineer: Real, confidence `64`, synthetic-confidence `29`.
  - Network Forensics: Real, confidence `72`, synthetic-confidence `26`.
  - Host/EDR: Inconclusive, confidence `68`, synthetic-confidence `38`.
- Deliberation kept the dataset mostly realistic but identified identity/software placement as the
  highest-value next fix: `svc_mhsync` was created in-window for the attack and later appeared in
  unrelated Veeam/Commvault baseline service-account activity on several hosts.

## Loop 16 Fix Target

- Selected family: service-account lifecycle boundaries between storyline-created identities and
  generic baseline service-account noise.
- Owning abstraction: baseline service-account selection in `BaselineGenerator`, while preserving
  storyline account lifecycle availability for the attack narrative itself.
- Invariant: accounts created, deleted, or otherwise lifecycle-owned by the storyline must not be
  selected for unrelated backup, Commvault, Veeam, scheduled-service, or generic explicit-credential
  baseline noise unless a visible provisioning/configuration event connects them to that family.
- Entry paths: Windows service-account delegation baseline, explicit credential noise, backup-agent
  maintenance flows, and storyline-created service-account activity such as `svc_mhsync`.
- Consumers: Windows Security 4648/4624/4634, Sysmon process evidence, eCAR process/file/FLOW rows,
  host and threat-hunting account-lifecycle pivots, and blind review environment-realism checks.
- Layer rationale: the generator owns which identities are eligible for baseline noise before
  source-specific renderers materialize Security, Sysmon, and eCAR rows; emitter-side suppression
  would only hide symptoms and risk cross-source disagreement.
- Residual sibling risks: preexisting durable service accounts can still be overused across
  workstation backup/software cohorts; host-role software placement remains a likely follow-up.

## Loop 16

- Automated eval passed at `95.74646190719345` over 87,850 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `96.54449051656928`
  - Causality: `89.09209230336289`
  - Timing: `96.68658101105204`
- Hard probe `hard_probe_service_account_lifecycle.json`:
  - `svc_mhsync` baseline delegation bad count in Windows Security: `0`.
  - `svc_mhsync` baseline delegation bad count in eCAR: `0`.
  - Storyline `svc_mhsync` Security events preserved: `20`.
  - Storyline `svc_mhsync` eCAR events preserved: `18`.
- Blind initial mean synthetic-confidence: `51.0`; deliberation mean: `57.0`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `68`, synthetic-confidence `52`.
  - Detection Engineer: Synthetic, confidence `72`, synthetic-confidence `68`.
  - Network Forensics: Real, confidence `72`, synthetic-confidence `28`.
  - Host/EDR: Inconclusive, confidence `68`, synthetic-confidence `56`.
- Deliberation calibrated scores to Threat Hunter `58`, Detection Engineer `70`, Network
  Forensics `40`, Host/EDR `60`.
- Selected loop 17 target:
  - P1 Type 3 network-logon lifecycle closure for anonymous Windows network logons. MAIL-FIN-01
    had 46 successful Type 3 logons and no Type 3 logoffs, while peer Windows servers had paired
    network sessions.

## Loop 17 Fix Target

- Selected family: Windows anonymous network-logon lifecycle completeness.
- Owning abstraction: anonymous Windows network-logon action bundle adapter in
  `ActivityGenerator`, not the Windows emitter.
- Invariant: every generated successful anonymous Type 3 logon is short-lived and paired with
  same-logon-id logoff evidence within the visible session interval, while still avoiding durable
  `StateManager` session creation for anonymous enumeration noise.
- Entry paths: Windows server/DC anonymous SMB enumeration and mail-server background network-logon
  noise that calls `generate_anonymous_logon`.
- Consumers: Windows Security 4624/4634, eCAR USER_SESSION LOGIN/LOGOUT, Type 3 session-duration
  detections, detection-review lifecycle checks, and host forensic pivots.
- Layer rationale: anonymous-logon generation owns the canonical LUID, remote source metadata, and
  SMB transport timing before renderers serialize Windows/eCAR rows; emitters should not invent
  lifecycle companions after the fact.
- Residual sibling risks: named MAIL-FIN-01 Type 3 sessions from protocol-specific mailbox access
  can still need family-specific logoff ownership if reviewers continue to find gaps after the
  anonymous-logon repair.

## Loop 17

- Automated eval passed at `94.77476489808859` over 98,924 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.79078689066739`
  - Causality: `89.09298159908809`
  - Timing: `94.01911387824856`
- Hard probe `hard_probe_type3_logon_lifecycle.json`:
  - MAIL-FIN Type 3 logons: `39`; logoffs: `39`; unpaired: `0`.
  - Anonymous logons: `38`; logoffs: `38`; unpaired: `0`.
  - All anonymous unpaired logons: `0`.
- Blind initial mean synthetic-confidence: `36.5`; deliberation mean: `39.5`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `68`, synthetic-confidence `44`.
  - Detection Engineer: Real, confidence `64`, synthetic-confidence `32`.
  - Network Forensics: Real, confidence `72`, synthetic-confidence `28`.
  - Host/EDR: Inconclusive, confidence `72`, synthetic-confidence `42`.
- Deliberation calibrated scores to Threat Hunter `46`, Detection Engineer `36`, Network
  Forensics `30`, Host/EDR `46`.
- Residual top findings:
  - eCAR `USER_SESSION.objectID` stability across login/logout.
  - More natural source-window/eCAR cutoff texture.
  - Less mechanically tight Security/Sysmon/eCAR timestamp deltas.
  - SMTP recipient/header mapping and lower-impact email/proxy/Linux command texture.

## Loop 18 Fix Target

- Selected family: eCAR `USER_SESSION.objectID` lifecycle stability.
- Owning abstraction: canonical session event construction for unmanaged anonymous Windows
  network-logon rows, using `EdrContext` to carry source-native session identity into eCAR.
- Invariant: every visible successful session lifecycle pair that shares a concrete session key
  (`logon_id`/`session_id`) or a remote source tuple must render the same eCAR `objectID` on
  `LOGIN` and `LOGOUT`.
- Entry paths: normal managed logon/logoff action bundles, SSH/RDP bundles, and anonymous Windows
  Type 3 network-logon noise.
- Consumers: eCAR `USER_SESSION` rows, Windows Security 4624/4634 pivots, host/threat-hunting
  session lifecycle analysis, and blind-review source-contract checks.
- Layer rationale: event construction owns the canonical LUID and remote source tuple before eCAR
  renders rows. The emitter should render a supplied session object identity rather than inventing
  one per row.
- Residual sibling risks: local desktop sessions can share the same visible host/principal/local
  tuple across multiple distinct LUIDs; reviewers should key those by `logon_id` or session id
  rather than by host/principal alone.
- Focused verification passed:
  `uv run pytest --no-cov tests/unit/test_baseline_canonical.py::TestAnonymousLogon`.
- Automated eval passed at `94.77476489808859` over 98,924 records.
- Hard probe `hard_probe_ecar_user_session_objectid.json`:
  - Exact session pairs: `682`; objectID mismatches: `0`.
  - Remote visible tuple pairs: `669`; objectID mismatches: `0`.
  - Anonymous exact session pairs: `132`; objectID mismatches: `0`.
- Blind initial mean synthetic-confidence: `41.5`; deliberation mean: `41.5`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `58`, synthetic-confidence `46`; deliberated to
    Inconclusive, confidence `60`, synthetic-confidence `42`.
  - Detection Engineer: Inconclusive, confidence `68`, synthetic-confidence `42`; deliberated to
    Inconclusive, confidence `70`, synthetic-confidence `42`.
  - Network Forensics: Inconclusive, confidence `64`, synthetic-confidence `38`; deliberated to
    Inconclusive, confidence `66`, synthetic-confidence `39`.
  - Host/EDR: Inconclusive, confidence `64`, synthetic-confidence `40`; deliberated to
    Inconclusive, confidence `68`, synthetic-confidence `43`.
- Deliberation consensus: no hard contradiction; the strongest concrete remaining issue was
  DB-PROD local eCAR `USER_SESSION LOGIN` rows for `lina.nguyen` and `priya.patel` without
  nearby `systemd-logind`/PAM companions despite active DB-PROD syslog collection.
- Selected loop 19 target:
  - P1 Linux/syslog/eCAR local-session companion evidence, especially self-sourced Linux Type 3
    compatibility paths that render as local endpoint sessions.

## Loop 19 Fix Target

- Selected family: Linux local session companion evidence across eCAR and syslog.
- Owning abstraction: successful logon action bundle compatibility adapter plus
  `StateManager` session metadata and source-observation policy.
- Invariant: every successful Linux local endpoint `USER_SESSION LOGIN` row has a source-native
  logind session ID and, when syslog is collected for the host, a nearby `systemd-logind`
  `New session ... of user ...` companion. Linux self-sourced Type 3 compatibility calls are
  normalized to local Type 2 sessions before canonical/eCAR rendering.
- Entry paths: baseline/suspicious-noise successful logons, generic activity-created logons,
  storyline compatibility logons, world-planner interactive Linux sessions, and local-looking
  legacy sessions that may carry stale session-kind metadata.
- Consumers: eCAR `USER_SESSION` rows, syslog `systemd-logind` rows, session IDs in
  `StateManager`, host forensic pivots, and source-observation missingness policy.
- Layer rationale: the logon adapter owns the semantic distinction between remote network logon
  and local Linux session before eCAR or syslog renderers run. Observation policy owns whether a
  correlated lifecycle row may be dropped.
- Residual sibling risks: true SSH sessions remain owned by the SSH action bundle; unrelated
  Linux service or network logons intentionally do not get local logind companions.
- Implemented changes:
  - `generate_syslog_event` can carry an optional `AuthContext`, so logind syslog companions share
    logon/session identity with endpoint session rows.
  - Linux self-sourced Type 3 successful logons are normalized to local Type 2 before canonical
    event construction.
  - Local-looking Linux sessions with stale `ssh` session kind no longer skip logind allocation.
  - Observation policy preserves `systemd-logind` open/close lifecycle rows from syslog
    missingness.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "linux_local_session or self_sourced_type3 or stale_ssh_kind or overlapping_linux_local_sessions"`
  - `uv run pytest --no-cov tests/unit/test_dispatcher.py -k "logind_lifecycle or ssh_lifecycle_rows_are_not_dropped"`
  - `uv run ruff check .`
  - `uv run ruff format --check .`

## Loop 19

- Automated eval passed at `95.0356755211698` over 92,803 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.55280860042693`
  - Causality: `88.49221306685368`
  - Timing: `95.12210052174817`
- Hard probe `hard_probe_linux_local_logind_companions.json`:
  - Local eCAR successful logins checked: `19`.
  - Local eCAR successful logins with companion: `19`.
  - Missing companions: `0`.
  - The former DB-PROD self-sourced Type 3 local-looking reviewer samples no longer render as
    eCAR-local orphan sessions.
- Blind review started against `loop-19/review-data` with `COLLECTION_PROFILE.json` excluded.
- Blind initial mean synthetic-confidence: `33.5`; deliberation mean: `36.75`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `68`, synthetic-confidence `34`; deliberated to
    Inconclusive, confidence `70`, synthetic-confidence `38`.
  - Detection Engineer: Real, confidence `64`, synthetic-confidence `28`; deliberated to
    Inconclusive, confidence `66`, synthetic-confidence `34`.
  - Network Forensics: Inconclusive, confidence `66`, synthetic-confidence `36`; deliberated to
    Inconclusive, confidence `68`, synthetic-confidence `38`.
  - Host/EDR: Inconclusive, confidence `66`, synthetic-confidence `36`; deliberated to
    Inconclusive, confidence `67`, synthetic-confidence `37`.
- Deliberation consensus: the Linux local-session companion contract held, and the strongest
  remaining concrete gap was an RDP session with source endpoint FLOW, target endpoint FLOW, and
  Windows Type 10 logon evidence for `10.10.1.35:56156 -> 10.10.2.20:3389` but no matching
  Zeek/firewall transport tuple.
- Selected loop 20 target:
  - P1 RDP transport visibility and timing, especially successful visible RDP sessions whose
    endpoint/target telemetry survives while Zeek/firewall transport evidence is missing or whose
    transport-to-auth timing is overly uniform.

## Loop 20 Fix Target

- Selected family: RDP transport visibility and timing.
- Owning abstraction: RDP action bundle plus the canonical network-connection contract and
  source-observation policy.
- Invariant: when a successful RDP session renders both endpoint source/target session evidence
  and a Type 10 target logon for a concrete source tuple, the corresponding network transport
  evidence must either render in Zeek/firewall sources or be omitted coherently by an explicit
  collection-loss decision that also explains dependent endpoint evidence.
- Entry paths: storyline/modelled RDP sessions, baseline remote-admin RDP sessions, and
  compatibility Type 10 logon paths that delegate into the RDP bundle.
- Consumers: Zeek `conn.log`, ASA/firewall connection rows, eCAR endpoint `FLOW` rows, Windows
  Security 4624/4634 Type 10 rows, source-side RDP client process telemetry, and reviewer
  cross-source transport pivots.
- Layer rationale: RDP owns the remote-session intent and target authentication ordering, while
  the network-connection bundle owns tuple allocation, transport visibility, Zeek UID/state, and
  firewall rendering. Fixing this at the bundle/observation boundary avoids emitter-local patches
  and keeps endpoint/session evidence aligned with the transport contract.
- Residual sibling risks: real packet sensors can miss isolated flows, so the fix should preserve
  source-observation texture rather than forcing all RDP traffic to be globally complete.
- Implemented changes:
  - Dispatcher source-observation contracts now promote dropped `zeek_conn`/`cisco_asa` rows back
    to visible only for successful SSH/RDP transport events when the same event's endpoint eCAR
    transport telemetry survives.
  - Failed RDP/SSH transport rows and scanner/noise traffic remain eligible for normal Zeek
    missingness, preserving collection texture outside successful remote-interactive sessions.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_dispatcher.py -k "rdp_transport or zeek_visible_child_promotes_dropped_conn_parent or ecar_rdp_tuple"`
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "rdp_session or rdp"`
  - `uv run ruff check .`
  - `uv run ruff format --check .`

## Loop 20

- Automated eval passed at `94.885679564687` over 92,804 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.95282477449575`
  - Causality: `88.49221306685368`
  - Timing: `95.12210052174817`
- Hard probe `hard_probe_rdp_transport_visibility.json`:
  - Successful unique endpoint-visible RDP tuples: `30`.
  - Successful unique endpoint-visible RDP tuples with Zeek conn: `30`.
  - Missing Zeek conn companions: `0`.
  - Former failing tuple `10.10.1.35:56156 -> 10.10.2.20:3389`: endpoint-visible and
    Zeek-visible.
  - Type 10 login transport-to-auth gaps: `28` measured; min `2519.2ms`, max `3995.3ms`, mean
    `3338.3ms`, population stdev `496.2ms`.
- Blind review started against `loop-20/review-data` with `COLLECTION_PROFILE.json` excluded.
- Blind initial mean synthetic-confidence: `38.0`; deliberation mean: `46.0`.
- Reviewer scores:
  - Threat Hunter: Real, confidence `68`, synthetic-confidence `28`; deliberated to
    Inconclusive, confidence `60`, synthetic-confidence `44`.
  - Detection Engineer: Inconclusive, confidence `68`, synthetic-confidence `36`; deliberated to
    Inconclusive, confidence `72`, synthetic-confidence `48`.
  - Network Forensics: Real, confidence `66`, synthetic-confidence `24`; deliberated to Real,
    confidence `62`, synthetic-confidence `30`.
  - Host/EDR: Synthetic, confidence `72`, synthetic-confidence `64`; deliberated to Synthetic,
    confidence `70`, synthetic-confidence `62`.
- Deliberation consensus: loop 20 resolved the prior network/RDP contract gap and network
  evidence now reads strongly realistic. The most convincing remaining synthetic evidence is
  Host/EDR's `DC-01` Windows process-tree semantics: `services.exe` and `taskhostw.exe` parent
  wrapper `cmd.exe` processes for service/task creation, plus repeated 1 ms wrapper-child timing.
- Selected loop 21 target:
  - P1 Windows remote-admin process-tree semantics and wrapper-child source timing, especially
    service creation, scheduled-task creation, and high-signal command wrappers on `DC-01`.

## Loop 21 Fix Target

- Selected family: Windows remote-admin process-tree semantics and wrapper-child source timing.
- Owning abstraction: Windows remote-admin and persistence action bundles, with canonical
  `ProcessContext` parentage and source timing planning as the renderer contract.
- Invariant: `services.exe` starts service binaries and SCM-owned service processes; it must not
  parent the client-side tools used to create services. `taskhostw.exe` runs scheduled task
  actions; it must not parent ad hoc `schtasks.exe /Create` authoring unless a prior task action
  explains that context. Wrapper `cmd.exe /c <tool>` children should have source-native,
  non-mechanical timing, not repeated 1 ms deltas.
- Entry paths: explicit Windows remote-admin bundles, storyline command/process events,
  persistence events that create services or scheduled tasks, PsExec/service-control tooling,
  and generic command execution compatibility paths.
- Consumers: Windows Security 4688/4689, Sysmon 1/5, eCAR `PROCESS`/`SERVICE` rows, Host/EDR
  process-tree pivots, Detection Engineering process-parent checks, and future expert reviews.
- Layer rationale: the process owner and parent relationship are canonical execution facts, not
  emitter formatting details. Fixing the action bundle/process-construction path prevents Windows
  Security, Sysmon, and eCAR from faithfully rendering the same wrong parent.
- Residual sibling risks: service-start events should still be parented by `services.exe`, and
  legitimate scheduled task execution can still involve `taskhostw.exe`; only authoring/tooling
  relationships should move to credible caller processes.
- Implemented changes:
  - Remote/service-context `sc.exe create` and `schtasks.exe /Create` wrapper shells now parent
    from WMI/DCOM-style remote command owners instead of `services.exe` or `taskhostw.exe`.
  - Scheduled task execution paths that are not authoring (`schtasks.exe /Run`) can still use
    `taskhostw.exe`, preserving the sibling task-action semantics.
  - eCAR parent/create-order normalization now uses bounded deterministic repair gaps instead of
    forcing child process creates to exactly parent+1 ms.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_spawn_rules.py -k "system_admin_utility or scheduled_task_execution_can_still_use_taskhostw_owner or remote_execution_wrapper"`
  - `uv run pytest --no-cov tests/unit/test_ecar_spec_compliance.py -k "close_moves_child_process_create_after_visible_parent or close_moves_child_process_create_after_parent_pid_without_actor_id"`
  - `uv run pytest --no-cov tests/unit/test_source_timing.py -k "ecar_process_create_normalization_preserves_canonical_order"`
  - `uv run ruff check .`
  - `uv run ruff format --check .`

## Loop 21

- Automated eval passed at `94.885679564687` over 92,804 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.95282477449575`
  - Causality: `88.49221306685368`
  - Timing: `95.12210052174817`
- Hard probe `hard_probe_windows_remote_admin_process_tree.json`:
  - eCAR high-signal wrappers checked: `3`.
  - eCAR/Security/Sysmon bad authoring wrapper parentage: `0`.
  - Wrapper-child pairs checked: `3`.
  - Exact 1 ms wrapper-child deltas: `0`.
  - Wrapper-child delta range: min `44ms`, max `136ms`, mean `101.333ms`.
- Blind review started against `loop-21/review-data` with `COLLECTION_PROFILE.json` excluded.
  The first panel was discarded because one reviewer accidentally overwrote
  `review-data/WS-MCHEN-01.meridianhcs.local/windows_event_security.xml` with scratch search
  output. The file was restored from pristine `output/data`, validated as XML, and the review
  was rerun into `loop-21/review-rerun/`; only rerun reports are canonical for loop 21.
- Blind initial mean synthetic-confidence: `42.5`; deliberation mean: `51.25`.
- Reviewer scores:
  - Threat Hunter: Real, confidence `61`, synthetic-confidence `34`; deliberated to
    Inconclusive, confidence `58`, synthetic-confidence `48`.
  - Detection Engineer: Real, confidence `68`, synthetic-confidence `28`; deliberated to
    Inconclusive, confidence `60`, synthetic-confidence `43`.
  - Network Forensics: Inconclusive, confidence `62`, synthetic-confidence `46`; deliberated to
    Inconclusive, confidence `65`, synthetic-confidence `50`.
  - Host/EDR: Synthetic, confidence `63`, synthetic-confidence `62`; deliberated to Synthetic,
    confidence `70`, synthetic-confidence `64`.
- Deliberation consensus: the Windows remote-admin parentage/timing fix held and broad
  cross-source realism remains strong, but the strongest synthetic evidence is now
  `WS-LNGUYEN-01` bash-history commands whose exact eCAR process creates occur 23-60 minutes
  later under the same user and `/bin/bash` parent.
- Selected loop 22 target:
  - P1 Linux shell-command timeline contract. Bash-history timestamps and correlated eCAR
    `PROCESS CREATE` rows for the same external command must share one per-shell foreground
    schedule, with process start within a small realistic tolerance of the history timestamp.

## Loop 22 Fix Target

- Selected family: Linux bash-history and eCAR process timeline coherence.
- Owning abstraction: Linux shell command action bundle plus foreground shell availability state in
  `ActivityGenerator`.
- Invariant: when a generated bash-history command emits correlated process telemetry, the
  history timestamp and first eCAR/Linux process-create timestamp for the same command must be
  near the same scheduled shell command time. Foreground shell serialization may delay both
  artifacts together, but it must not delay process telemetry while leaving bash history at an
  earlier requested time.
- Entry paths: baseline Linux workstation shell command noise, direct `generate_bash_command`
  calls, storyline process-friction shell commands, Linux process activity that emits bash
  history, and SSH/local interactive session command bundles.
- Consumers: bash_history files, eCAR `PROCESS`/`FLOW`/`FILE` rows, syslog session timing,
  foreground process lifetime tracking, host forensic pivots, and shell-session validation
  probes.
- Layer rationale: the shell action bundle owns a single user-entered command occurrence. Bash
  history and process telemetry are sibling evidence for that occurrence, so separate history and
  process reservations are the root cause rather than source-native rendering.
- Residual sibling risks: background or script-owned one-liners that should not appear in bash
  history still need a separate script/scheduler owner; DNS/PTR realism remains a later
  network-family target.

## Loop 22

- Implemented changes:
  - Bash-history scheduling now aligns with the same foreground-shell slot used by process
    telemetry for generated shell commands.
  - Foreground shell availability follows source-visible process termination time, not only
    canonical termination time, so eCAR close-time jitter cannot make the next command visibly
    overlap.
  - Foreground shell queue keys use the actual shell process logon ID when available, preventing
    blank-logon and session-logon callers from maintaining separate queues for the same bash PID.
  - Bash-history-synchronized Linux process rows carry an internal `bash-history:*`
    concurrency marker. The eCAR shell foreground normalizer strips the marker but preserves the
    action-bundle-owned timestamp instead of shifting the row independently.
  - Synthetic Linux proxy socket-owner helper rows now parent to a non-shell session process
    (`systemd --user` / terminal / session root) rather than occupying the user's interactive
    `/bin/bash` foreground timeline.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "bash_history or generate_bash_command or foreground_shell or foreground_termination_uses_source_visible_release_time or linux_proxy_client_process_uses_non_shell_session_parent"`
  - `uv run pytest --no-cov tests/unit/test_source_timing.py -k "linux_shell_foreground_order"`
  - `uv run pytest --no-cov tests/unit/test_activity.py tests/unit/test_source_timing.py`
  - `uv run ruff check .`
  - `uv run ruff format --check .`
- Automated eval passed at `95.55644473749022` over 94,597 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `96.17083728577973`
  - Causality: `89.67411207926047`
  - Timing: `95.47603698115087`
- Hard probe `hard_probe_linux_bash_ecar_timeline.json`:
  - Bash-history commands scanned: `314`.
  - Near eCAR process matches checked: `189`.
  - Late bash-history to eCAR process mismatches: `0`.
  - Near-match max offset: `2.986s`; p95 offset: `2.666s`.
  - Linux proxy helper rows parented by `/bin/bash`: `0 / 43`.
- Additional reviewer-finding probe `reviewer_finding_probes.json`:
  - Verified sudo timing defect: `124` visible sudo triplets, `101` under 1 second, and `7`
    interval commands (`vmstat 1 5` / `iostat -xz 1 3`) closing in `0.401-1.048s`.
  - Verified Host/EDR SSH eCAR lifecycle gaps for the reported APP-INT-01, DB-PROD-01, and
    MAIL-EDGE-01 tuples: eCAR retained related `sshd`/shell process context but lacked matching
    inbound FLOW and USER_SESSION LOGIN rows.
- Blind initial mean synthetic-confidence: `51.75`; deliberation mean: `61.25`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `76`, synthetic-confidence `67`; deliberated to
    Synthetic, confidence `80`, synthetic-confidence `72`.
  - Detection Engineer: Synthetic, confidence `68`, synthetic-confidence `64`; deliberated to
    Synthetic, confidence `74`, synthetic-confidence `69`.
  - Network Forensics: Real, confidence `72`, synthetic-confidence `24`; deliberated to
    Inconclusive, confidence `64`, synthetic-confidence `42`.
  - Host/EDR: Inconclusive, confidence `74`, synthetic-confidence `52`; deliberated to
    Synthetic, confidence `76`, synthetic-confidence `62`.
- Deliberation consensus: network protocol realism remains a major strength, but the loop surfaced
  stronger endpoint/source-contract issues: sudo interval-command runtimes, high-value proxy/C2
  endpoint ownership mismatch, and SSH eCAR lifecycle-group gaps.
- Selected loop 23 target:
  - P1 Linux sudo runtime contract. Sudo PAM open/COMMAND/close triplets should use
    command-aware runtime modeling so interval commands keep the session open for their implied
    duration and ordinary sudo lifetimes are varied rather than uniformly sub-second.
  - P1 follow-up candidates after sudo: endpoint/proxy ownership for high-value proxy/C2
    transactions, then eCAR SSH lifecycle group visibility.

## Loop 23

- Implemented changes:
  - Extra Linux sudo syslog triplets now use command-aware session runtime instead of closing
    within a uniform sub-second window after the `COMMAND=` row.
  - `vmstat`/`iostat` interval commands parse numeric interval/count arguments and hold PAM
    session close evidence open for the implied runtime plus source-native jitter.
  - Longer-running families such as package management, service restart, `journalctl`, `find`,
    `lsof`, `iptables`, and `systemd-analyze` receive broader runtime envelopes; quick status
    and inventory commands keep shorter but varied lifetimes.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_baseline_canonical.py -k "sudo or pam" tests/unit/test_systemd_ecar_correlation.py -k "sudo" tests/unit/test_syslog_family_renderer.py -k "sudo"`
  - `uv run ruff check src/evidenceforge/generation/engine/baseline.py tests/unit/test_baseline_canonical.py`
  - `uv run ruff format --check src/evidenceforge/generation/engine/baseline.py tests/unit/test_baseline_canonical.py`
- Automated eval passed at `95.29205091144773` over 95,819 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.29351259983402`
  - Causality: `89.47668953519369`
  - Timing: `95.49750188845404`
- Hard probe `hard_probe_sudo_runtime.json`:
  - Visible sudo triplets: `138`.
  - Subsecond command-to-close durations: `1`.
  - Minimum duration: `0.806s`; maximum duration: `15.750s`; p50 duration: `3.724s`.
  - Interval commands checked: `6`; interval-command runtime violations: `0`.
- Blind initial mean synthetic-confidence: `40.75`; deliberation mean: `44.75`.
- Reviewer scores:
  - Threat Hunter: Real, confidence `64`, synthetic-confidence `34`; deliberated to Real
    synthetic-sensitive, realism `80`, synthetic-confidence `41`.
  - Detection Engineer: Inconclusive, confidence `64`, synthetic-confidence `43`; deliberated to
    Inconclusive, realism `76`, synthetic-confidence `48`.
  - Network Forensics: Real, confidence `72`, synthetic-confidence `28`; deliberated to Real,
    realism `78`, synthetic-confidence `32`.
  - Host/EDR: Inconclusive leaning Synthetic, confidence `72`, synthetic-confidence `58`;
    deliberated unchanged, realism `62`, synthetic-confidence `58`.
- Deliberation consensus:
  - Network, Windows/Sysmon, RDP, SSH/SCP, and Zeek UID/FUID contracts remain strong.
  - The strongest synthetic-sensitive finding is eCAR Linux process/thread semantics:
    `PROCESS/TERMINATE` rows often changed `tid` away from the matching `PROCESS/CREATE` main
    thread without visible thread lifecycle.
  - Follow-up families: eCAR FLOW actor attribution coherence, Windows endpoint background
    templating, proxy source-native profile/identity texture, public web/scanner distributions,
    and direct-root SSH administration texture.
- Selected loop 24 target:
  - P1 eCAR Linux process/thread lifecycle semantics. Linux `PROCESS/CREATE` and
    `PROCESS/TERMINATE` rows for the same process object should share the main-thread TID, while
    dependent FLOW/FILE/MODULE rows can still carry source-native thread texture.

## Loop 24

- Implemented changes:
  - eCAR Linux `_stable_tid(...)` now returns `pid` for both `process_create` and
    `process_terminate` lifecycle rows.
  - Linux non-lifecycle eCAR rows still use deterministic source-thread texture so host telemetry
    does not become flat.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_ecar_spec_compliance.py -k "linux_process_lifecycle_tid or linux_dependent_tids or linux_stable_tid or pid_morphology"`
  - `uv run ruff check src/evidenceforge/generation/emitters/ecar.py tests/unit/test_ecar_spec_compliance.py`
  - `uv run ruff format --check src/evidenceforge/generation/emitters/ecar.py tests/unit/test_ecar_spec_compliance.py`
- Generated loop 24 output successfully.
- Automated eval passed at `95.29205091144773` over 95,819 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.29351259983402`
  - Causality: `89.47668953519369`
  - Timing: `95.49750188845404`
- Hard probe `hard_probe_ecar_linux_tid.json`:
  - Linux process terminations: `764`.
  - Matched Linux create/terminate lifecycles: `753`.
  - Create/terminate TID mismatches: `0`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-24/review-data`.
  - Neutral read-only copy: `/private/tmp/eforge-review-dataset-charlie.zmo2OW`.
  - `COLLECTION_PROFILE.json` excluded from both review copies.
  - Four-reviewer blind panel completed.
- Blind initial mean synthetic-confidence: `51.25`; deliberation mean: `59.5`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, realism `68`, confidence `70`, synthetic-confidence `43`;
    deliberated to Synthetic, realism `60`, synthetic-confidence `56`.
  - Detection Engineer: Inconclusive, realism `82`, confidence `66`, synthetic-confidence `31`;
    deliberated to Inconclusive, realism `76`, synthetic-confidence `44`.
  - Network Forensics: Synthetic, realism `61`, confidence `74`, synthetic-confidence `67`;
    deliberated to Synthetic, realism `60`, synthetic-confidence `70`.
  - Host/EDR: Synthetic, realism `58`, confidence `72`, synthetic-confidence `64`;
    deliberated to Synthetic, realism `57`, synthetic-confidence `68`.
- Deliberation consensus:
  - Linux SSH/session lifecycle ordering is the top failure: repeated `/bin/bash -bash`
    process creates appeared before matching SSH Accepted/PAM/logind/eCAR login rows.
  - DNS answer-to-destination/proxy-origin binding is the next highest-priority family.
  - Additional follow-ups: interactive shell/session ownership, staged exfil process ownership,
    Windows 4648 source-native field names, Linux eCAR `tid == pid` texture, perimeter/proxy
    distribution texture, and repeated Linux command pools.
- Selected loop 25 target:
  - P1 Linux SSH/session lifecycle ordering. In eCAR, interactive Linux login-shell
    `PROCESS/CREATE` rows must not render before the same-user successful `USER_SESSION/LOGIN`.
    Parent ordering must then keep child command rows behind the shifted shell.

## Loop 25

- Implemented changes:
  - Added eCAR host-buffer normalization for interactive Linux login-shell creates. If a
    `/bin/bash` or `/usr/bin/bash` login shell (`-bash`, `bash`, `/bin/bash`, `/usr/bin/bash`)
    renders shortly before a same-host/same-user successful `USER_SESSION/LOGIN`, it is shifted
    after that login with deterministic source-local jitter.
  - Re-ran eCAR process-parent ordering after the shell shift so command child rows remain after
    their shell parent.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_ecar_spec_compliance.py -k "linux_login_shell_create_shifted_after_session_login or remote_user_session_login_shifted_after_late_inbound_flow or linux_process_lifecycle_tid"`
  - `uv run ruff check src/evidenceforge/generation/emitters/ecar.py tests/unit/test_ecar_spec_compliance.py`
  - `uv run ruff format --check src/evidenceforge/generation/emitters/ecar.py tests/unit/test_ecar_spec_compliance.py`
- Generated loop 25 output successfully.
- Automated eval passed at `95.29205091144773` over 95,819 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.29351259983402`
  - Causality: `89.47668953519369`
  - Timing: `95.49750188845404`
- Hard probe `hard_probe_ssh_shell_order.json`:
  - Interactive shell creates scanned: `74`.
  - Shell-before-login contradictions: `0`.
  - Remaining sessionless/orphan shell rows: `11`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-25/review-data`.
  - Neutral read-only copy: `/private/tmp/eforge-review-dataset-delta.DOpedZ`.
  - `COLLECTION_PROFILE.json` excluded from both review copies.
  - Four-reviewer blind panel completed.
- Blind initial mean synthetic-confidence: `45.5`; deliberation mean: `51.5`.
- Reviewer scores:
  - Threat Hunter: Synthetic, realism `72`, confidence `68`, synthetic-confidence `58`;
    deliberated to Synthetic, realism `70`, confidence `72`, synthetic-confidence `60`.
  - Detection Engineer: Inconclusive, realism `72`, confidence `66`, synthetic-confidence `34`;
    deliberated unchanged, realism `68`, confidence `70`, synthetic-confidence `42`.
  - Network Forensics: Real, realism `78`, confidence `72`, synthetic-confidence `22`;
    deliberated to Inconclusive, realism `74`, confidence `68`, synthetic-confidence `34`.
  - Host/EDR: Synthetic, realism `56`, confidence `74`, synthetic-confidence `68`;
    deliberated unchanged, realism `54`, confidence `76`, synthetic-confidence `70`.
- Deliberation consensus:
  - The highest-priority synthetic tell is a shared browser/session identity contradiction on the
    high-value exfil path: endpoint evidence showed Chrome while proxy/Zeek HTTP evidence could
    collapse to Firefox/generic browser ownership for the same upload.
  - eCAR endpoint lifecycle/actor ownership remains the broader follow-up family, including thin
    service actor metadata and missing FLOW actor/process ownership where adjacent evidence has
    context.
  - Bulk transfer/staging texture, attacker infrastructure reuse, and tidy collection/profile
    texture remain lower-priority follow-ups.
- Selected loop 26 target:
  - P0 shared endpoint/browser/proxy/network session ownership for staged HTTPS exfiltration.
    Authored browser UAs and staged-upload browser processes must remain bound so endpoint file
    reads, eCAR FLOW rows, proxy access rows, and Zeek CONNECT rows agree on the browser family.

## Loop 26

- Implemented changes:
  - Added a data-driven browser process-to-User-Agent helper backed by
    `proxy_user_agents.yaml`, so known browser process images can receive a matching full
    source-native User-Agent.
  - Storyline staged-upload exfil now selects a Windows browser process that matches an authored
    browser User-Agent (`Chrome`, `Firefox`, or `Edge`) and infers a process-native User-Agent for
    blank/generic upload HTTP metadata.
  - Explicit proxy context building now treats caller-supplied full browser User-Agents as
    overrides for HTTP-originated requests, preventing non-browser-like API destinations from
    replacing them with a source-sticky generated browser family.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_storyline_command_networks.py -k "compress_archive_exfil"`
  - `uv run pytest --no-cov tests/unit/test_explicit_proxy.py -k "build_proxy_context_preserves_caller_browser_user_agent_for_api_domain or preserves_override_browser_user_agent or collapses_generated_browser_family"`
  - `uv run ruff check src/evidenceforge/generation/activity/proxy_user_agents.py src/evidenceforge/generation/activity/generator.py src/evidenceforge/generation/engine/storyline.py tests/unit/test_storyline_command_networks.py tests/unit/test_explicit_proxy.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/proxy_user_agents.py src/evidenceforge/generation/activity/generator.py src/evidenceforge/generation/engine/storyline.py tests/unit/test_storyline_command_networks.py tests/unit/test_explicit_proxy.py`
- Generated loop 26 output successfully.
- Automated eval passed at `95.30102273163071` over 94,798 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.46977954516477`
  - Causality: `89.47668953519369`
  - Timing: `95.3220273077055`
- Hard probe `hard_probe_exfil_browser_identity.json`:
  - Proxy upload rows: `1`; all use `Chrome/121.0.0.0`.
  - Zeek CONNECT rows for the upload tunnel: `2`; all use `Chrome/121.0.0.0`.
  - Endpoint Chrome pid: `7184`; staged ZIP read pid: `7184`; eCAR proxy FLOW pid: `7184`;
    source port: `64794`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-26/review-data`.
  - Neutral read-only copy: `/private/tmp/eforge-review-dataset-echo.VNfkns`.
  - `COLLECTION_PROFILE.json` excluded from both review copies.
  - Four-reviewer blind panel completed.
- Blind initial mean synthetic-confidence: `51.5`; deliberation mean: `55.75`.
- Reviewer scores:
  - Threat Hunter: Synthetic, realism `70`, confidence `72`, synthetic-confidence `61`;
    deliberated to Synthetic, confidence `74`, synthetic-confidence `64`.
  - Detection Engineer: Inconclusive, realism `76`, confidence `70`, synthetic-confidence `42`;
    deliberated to Inconclusive synthetic-leaning, confidence `72`, synthetic-confidence `50`.
  - Network Forensics: Inconclusive, realism `74`, confidence `66`, synthetic-confidence `42`;
    deliberated unchanged, confidence `68`, synthetic-confidence `45`.
  - Host/EDR: Synthetic, realism `74`, confidence `70`, synthetic-confidence `61`;
    deliberated to Synthetic, confidence `73`, synthetic-confidence `64`.
- Deliberation consensus:
  - All four reviewers either directly or indirectly pointed to eCAR `FLOW` actor attribution as
    the highest-leverage realism problem.
  - The main synthetic tell is no longer the staged browser upload path; it is the patterned
    absence or contradiction of process/principal attribution on high-confidence service and
    user-owned flows.
  - Concrete examples include WEB-EXT MySQL flows, MAIL LDAP flows, DB/server proxy and SMB
    flows, WS-AJOHNSON SSH flows, and DC/server proxy activity.
  - Secondary follow-ups are large proxy-mediated transfer durations, public HTTP client
    diversity, Linux TID texture, direct root SSH, and process-before-login/session edge cases.
- Selected loop 27 target:
  - P1 eCAR `FLOW` actor attribution for known-owner and high-confidence flows. The network
    connection owner should materialize plausible user or service process identity at the
    canonical event layer so eCAR can render coherent `pid`, `principal`, and `image_path`
    without source-specific patching.

## Loop 27

- Implemented changes:
  - Added a high-confidence connection-owner materialization path in the network connection
    bundle. Existing caller-supplied and inferred PIDs still win; when those are missing, stale,
    future-dated, or expired, the bundle can now create/reuse canonical source-side process
    ownership before rendering.
  - Server/service-owned flows now get source-native daemon/client owners for common high-signal
    families: web/app to database, mail/app/web to LDAP, server SMB, and server/proxy HTTP(S)
    traffic.
  - Workstation SSH/SMB flows now materialize user-mode owners only when a visible interactive
    user session exists, preserving the collection-window/session contract.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "connection_materializes"`
  - `uv run pytest --no-cov tests/unit/test_explicit_proxy.py -k "proxy or build_proxy_context"`
    (`72` passed after tightening direct proxy listener fallback to use UA-matching tool owners).
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "generate_connection or ssh_process_network_effect or generic_ssh_preauth or connection_materializes"`
    (`31` passed).
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py tests/unit/test_explicit_proxy.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py tests/unit/test_explicit_proxy.py`
- Generated loop 27 output successfully.
- Automated eval passed at `95.092505124442` over 96,786 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.07492337480768`
  - Causality: `88.80992196209588`
  - Timing: `95.60646895108057`
- Hard probe `hard_probe_ecar_flow_attribution.json`:
  - Total eCAR `FLOW` rows missing identity dropped from loop 26 `2329` to loop 27 `1525`.
  - Outbound high-value `FLOW` rows missing identity dropped from loop 26 `1309` to loop 27
    `418`.
  - Key reviewer buckets improved:
    - WEB-EXT MySQL missing: `308/310` -> `5/361`.
    - MAIL-CLIN LDAP missing: `77/77` -> `0/80`.
    - MAIL-EDGE LDAP missing: `73/73` -> `0/85`.
    - APP-INT LDAP missing: `23/23` -> `0/31`.
    - DB-PROD proxy missing: `37/37` -> `0/23`.
    - DC proxy missing: `45/54` -> `3/66`.
    - DB-PROD SMB missing: `31/31` -> `0/19`.
    - WS-AJOHNSON SSH missing: `19/19` -> `0/16`.
  - Remaining focus gaps:
    - Workstation SMB remains partially actorless (`WS-OHADDAD-01:445` `20/60`,
      `WS-LNGUYEN-01:445` `14/38`).
    - WS-AJOHNSON proxy listener rows remain partially actorless (`24/73`), likely cases without
      a compatible live browser/tool session.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-27/review-data`.
  - Neutral read-only copy: `/private/tmp/eforge-review-dataset-foxtrot.lUy9yV`.
  - `COLLECTION_PROFILE.json`, `GROUND_TRUTH.md`, and `GROUND_TRUTH.json` excluded from both
    review copies.
  - Four-reviewer blind panel completed.
- Blind initial mean synthetic-confidence: `46.0`; deliberation mean: `64.25`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `84`, synthetic-confidence `72`; deliberated to
    Synthetic, confidence `88`, synthetic-confidence `76`.
  - Detection Engineer: Inconclusive, confidence `68`, synthetic-confidence `42`; deliberated to
    Synthetic, confidence `76`, synthetic-confidence `64`.
  - Network Forensics: Real, confidence `64`, synthetic-confidence `34`; deliberated to
    Inconclusive, confidence `62`, synthetic-confidence `56`.
  - Host/EDR: Inconclusive, confidence `66`, synthetic-confidence `36`; deliberated to
    Synthetic, confidence `72`, synthetic-confidence `61`.
- Deliberation consensus:
  - The eCAR actor-omission fix materially improved endpoint ownership, and Host/EDR plus Network
    initially scored the dataset as mostly realistic.
  - The consensus-dominant defect is now a harder proxy/eCAR contradiction: same client IP,
    source port, proxy IP, and proxy port can show one endpoint command-line target while Zeek
    HTTP/proxy access show a different host and User-Agent for the same socket.
  - Threat Hunter reported `98` mismatches among `137` joined explicit proxy tuples with exposed
    command-line targets.
  - eCAR command lines also leak planning/classification annotations such as
    `# proxy-check internal-service` and `# smb FILE-SRV-01.meridianhcs.local`.
  - Secondary findings: DC/server health-check target/account texture, eCAR parent lifecycle
    orphan for DC scheduled task, workstation event-volume homogeneity, x509 SAN simplification,
    TXT resolver egress visibility, and proxy 304 byte semantics.
- Selected loop 28 target:
  - P0 explicit proxy transaction semantic consistency. The source endpoint `FLOW` owner
    command line, Zeek HTTP host/URI/User-Agent, proxy access host/User-Agent, source port, and
    eCAR process context must be generated from the same transaction truth. Rendered endpoint
    command lines must not contain hidden planning labels or comments.

## Loop 28

- Implemented changes:
  - Target-bearing connection-owner process keys now include the proxy/origin host so
    `service-healthcheck`, Java integration workers, `curl`, `wget`, Python requests, and
    Windows service-health owners are not reused across different destinations.
  - Existing proxy caller PID validation now rejects same-image processes when their
    target-bearing command line does not match the current proxy transaction host.
  - Proxy client process reuse now requires exact command-line matches for target-bearing tools.
  - Removed hidden planning/comment labels from rendered service-owner command lines, including
    `# proxy-check`, `# smb`, and `# db-maintenance` variants.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "proxy_service_owner_is_not_reused_across_targets or command_lines_do_not_leak or connection_materializes"`
    (`4` passed).
  - `uv run pytest --no-cov tests/unit/test_explicit_proxy.py -k "proxy or build_proxy_context"`
    (`72` passed).
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py tests/unit/test_explicit_proxy.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py tests/unit/test_explicit_proxy.py`
- Generated loop 28 output successfully.
- Automated eval passed at `95.40020233866719` over 94,318 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.9681362136533`
  - Causality: `90.27553588475223`
  - Timing: `95.44642157032901`
- Hard probe `hard_probe_proxy_tuple_semantics.json`:
  - Loop 27 target-bearing proxy `FLOW` rows checked: `682`; non-browser mismatches:
    `96/232`; command-line comment leaks: `219`.
  - Loop 28 target-bearing proxy `FLOW` rows checked: `640`; non-browser mismatches:
    `0/237`; command-line comment leaks: `0`.
  - Remaining raw host mismatch rows are browser-family processes (`firefox`, `chrome.exe`,
    `google-chrome`, `msedge.exe`) where the launch command line can source-natively preserve
    an initial URL while later proxy rows represent subsequent browsing.
- Blind review:
  - Initial review bundle accidentally included `OBSERVATION_MANIFEST.json`, which Threat Hunter
    correctly identified as package metadata rather than raw-log evidence. Rebuilt a clean bundle
    excluding `GROUND_TRUTH.md`, `GROUND_TRUTH.json`, `data/COLLECTION_PROFILE.json`,
    `OBSERVATION_MANIFEST.json`, `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Corrected review bundle:
    `scenarios/iteration-test-expanded/blind-test/loop-28/review-data-clean`.
  - Neutral corrected copy: `/private/tmp/review-dataset-hotel.Bqcr6U`.
  - Re-ran Threat Hunter only on the corrected bundle; the other three reports did not use the
    manifest leak and were retained.
- Corrected blind initial mean synthetic-confidence: `40.5`; deliberation mean: `41.5`.
- Reviewer scores:
  - Threat Hunter corrected: Synthetic, confidence `67`, synthetic-confidence `62`;
    deliberated to Synthetic, confidence `61`, synthetic-confidence `56`.
  - Detection Engineer: Inconclusive, confidence `64`, synthetic-confidence `34`; deliberated to
    Inconclusive, confidence `63`, synthetic-confidence `38`.
  - Network Forensics: Real, confidence `66`, synthetic-confidence `32`; deliberated to Real,
    confidence `62`, synthetic-confidence `35`.
  - Host/EDR: Inconclusive, confidence `68`, synthetic-confidence `34`; deliberated to
    Inconclusive, confidence `66`, synthetic-confidence `37`.
- Deliberation consensus:
  - The Loop 28 fix removed the prior hard proxy tuple target mismatch and command-line comment
    leaks; reviewers now emphasized texture and weaker identity issues rather than impossible
    ordering.
  - The strongest synthetic-leaning issue was repeated corpus texture in benign email prose and
    Linux bash history command pools.
  - The strongest concrete cross-source issue was DC/server proxy traffic where eCAR attributes a
    flow to `service-healthcheck.exe` while proxy/Zeek HTTP carries Chrome-like browser identity
    on the same source port.
  - Lower-priority follow-ups: Windows 4624 EventData order, forwarded-vs-local Security 1102
    collection semantics, proxy SSL-inspection/tunnel grammar texture, NTP precision, and Zeek
    public-mail `local_resp` ambiguity.
- Selected loop 29 target:
  - P1 proxy User-Agent/process ownership binding for server/service-owned proxy traffic. When
    source endpoint ownership is a service or tool process, proxy access and Zeek HTTP must carry
    a compatible service/tool User-Agent, or the generator must render explicit evidence of
    deliberate browser-UA spoofing. Prefer binding the canonical `ProxyContext` to the source
    process family before the proxy transaction bundle renders sibling evidence.

## Loop 29

- Implemented changes:
  - Added proxy User-Agent normalization inside canonical proxy context construction so
    server/service-owned proxy transactions cannot silently reuse browser-family User-Agents.
  - Server-like proxy sources that would otherwise render Chrome/Firefox/Edge/Safari-style
    User-Agents now receive a compatible service/tool client identity (`Go-http-client/1.1`)
    before proxy access, Zeek HTTP, and endpoint flow evidence are rendered.
  - Caller-authored workstation browser activity continues to preserve the browser User-Agent
    when it is compatible with the source process family.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_explicit_proxy.py -k "server_browser_user_agent or binds_server_proxy_user_agent or preserves_caller_browser_user_agent_for_api_domain or proxy or build_proxy_context"`
    (`74` passed).
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "proxy_service_owner_is_not_reused_across_targets or command_lines_do_not_leak or connection_materializes"`
    (`4` passed).
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_explicit_proxy.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_explicit_proxy.py`
- Generated loop 29 output successfully.
- Automated eval passed at `95.09772243176974` over 94,627 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.15430840807609`
  - Causality: `90.27508723160896`
  - Timing: `94.95186760924241`
- Hard probe `hard_probe_service_proxy_ua_binding.json`:
  - Service-healthcheck joined HTTP rows with browser User-Agent mismatches dropped from loop 28
    `18` to loop 29 `0`.
  - DC westbridge proxy access browser rows dropped from loop 28 `20` to loop 29 `0`; matching
    service/tool rows increased from `0` to `20`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-29/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-india.YBaesU`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
- Blind initial mean synthetic-confidence: `53.0`; deliberation mean: `58.5`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `72`, synthetic-confidence `67`; deliberated to
    Synthetic, confidence `74`, synthetic-confidence `70`.
  - Detection Engineer: Inconclusive, confidence `63`, synthetic-confidence `34`; deliberated to
    Inconclusive leaning Synthetic, confidence `60`, synthetic-confidence `46`.
  - Network Forensics: Synthetic, confidence `68`, synthetic-confidence `64`; deliberated to
    Synthetic, confidence `70`, synthetic-confidence `66`.
  - Host/EDR: Inconclusive, confidence `66`, synthetic-confidence `47`; deliberated to
    Inconclusive leaning Synthetic, confidence `64`, synthetic-confidence `52`.
- Deliberation consensus:
  - The service-owned proxy User-Agent contradiction was fixed for the targeted family.
  - The new highest-confidence hard contradiction is outbound SMTP evidence: external recipient
    `Received:` headers show RFC1918 internal sender IPs even though ASA evidence for the same
    sessions shows NAT to `203.14.220.1`.
  - Reviewers cited examples where external MTAs such as `smtp1.greatplains-mail.net` appear to
    receive directly from `10.10.2.26`, while perimeter logs show the boundary-translated source.
  - Secondary follow-ups include missing proxy-origin flows after CONNECT to internal mail
    targets, endpoint timestamp texture, and public scan/PTR/web texture.
- Selected loop 30 target:
  - P0/P1 SMTP delivery boundary identity. The email delivery bundle/artifact construction path
    should render external-facing `Received:` headers with the peer address seen at the boundary
    (NAT/public identity for outbound perimeter hops) while preserving RFC1918/private identity
    on internal relay hops. The fix should live where SMTP hop truth is built, before EML
    artifacts, Zeek SMTP, Postfix/syslog, ASA, and manifest consumers render sibling evidence.

## Loop 30

- Implemented changes:
  - Added a canonical SMTP `Received:` peer-identity helper in the email delivery construction
    path. External-facing server-to-server hops from modeled internal sources now render the
    receiving MTA's boundary-visible peer IP, using configured outbound NAT source identity
    without consuming PAT state.
  - Internal relay and submission headers continue to render the private/source-local peer
    identity, preserving source-native internal mailbox evidence.
  - Added a focused mixed internal/external outbound route regression with an outbound PAT
    firewall sensor. The test asserts external `Received:` headers show `203.14.220.1` while
    internal relay headers still show RFC1918 source IPs.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_email_evidence.py -k "mixed_internal_external_outbound_hops_scope_recipients or outbound_route_group_override_and_global_isp_relay or email_generation_writes_smtp_artifacts"`
    (`3` passed).
  - `uv run pytest --no-cov tests/unit/test_email_evidence.py` (`33` passed).
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
- Generated loop 30 output successfully.
- Automated eval passed at `95.09772243176974` over 94,627 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.15430840807609`
  - Causality: `90.27508723160896`
  - Timing: `94.95186760924241`
- Hard probe `hard_probe_smtp_received_nat.json`:
  - Loop 29 external-facing `Received:` headers exposing private sender IPs: `7`.
  - Loop 30 external-facing `Received:` headers exposing private sender IPs: `0`.
  - Loop 30 external-facing NAT/public sender headers: `7`.
  - Loop 30 internal relay headers retaining private peer IPs: `33`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-30/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-juliet.8UdP8o`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was not triggered: all reviewers returned Synthetic, average verdict
    confidence was above 60, and synthetic-confidence spread was `12`.
- Blind initial mean synthetic-confidence: `71.5`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `62`, synthetic-confidence `66`.
  - Detection Engineer: Synthetic, confidence `84`, synthetic-confidence `78`.
  - Network Forensics: Synthetic, confidence `78`, synthetic-confidence `70`.
  - Host/EDR: Synthetic, confidence `78`, synthetic-confidence `72`.
- Panel consensus and prioritized findings:
  - The loop 30 SMTP NAT/header contradiction was absent from reviewer reports after the fix.
  - The dominant multi-reviewer hard contradiction is now SSH/eCAR command target and network
    destination identity binding: Windows `ssh.exe <host>` process identities are reused across
    flows to different hosts/IPs, and some eCAR `FLOW` rows name one internal host while the
    tuple reaches another.
  - Detection reported `84` eCAR command-target versus `dst_ip` mismatches plus a related
    Windows 4648 target/address mismatch.
  - Host/EDR cited repeated SSH examples on `WS-AJOHNSON-01`, `WS-MCHEN-01`, and
    `WS-SMARTINEZ-01` where the same PID/command line owns sessions to multiple unrelated
    hosts.
  - Threat Hunter found a sibling process-command ownership gap on FILE-SRV where `net.exe net
    view \\FILE-SRV-01` is parented by a `cmd.exe /c net.exe` process rather than the sibling
    `cmd.exe /c net view \\FILE-SRV-01`.
  - Network Forensics independently found proxy request-target and referer URL fragments in
    `proxy_access.log`; this is a strong single-reviewer source-native proxy target for a later
    loop if it persists.
- Selected loop 31 target:
  - P0/P1 SSH/eCAR command target and network destination identity binding. Owning abstraction:
    canonical process/network ownership in `ActivityGenerator` plus SSH action entry paths.
    Invariant: if a source-visible client process command line names an internal host, that
    process can own only flows to that host/IP unless explicit tunnel or multiplex evidence is
    modeled; otherwise allocate or reuse a target-specific process identity. Consumers include
    eCAR `FLOW`, Sysmon Event 3, process-create/terminate rows, SSH target-side syslog/eCAR
    sessions, Windows 4648 companion evidence, and blind reviewer host/IP probes.

## Loop 31

- Family contract:
  - Owning abstraction: canonical process/network ownership in `ActivityGenerator`; this is where
    source-visible client process reuse is selected before eCAR/Sysmon/source timing renderers
    consume process identity.
  - Invariant: target-bearing client command lines (`ssh`, `scp`, `sftp`, SMB browse commands)
    may only reuse an active process when the command line names the same target host. A process
    whose command line names one internal host must not own `FLOW` rows to another internal host
    unless explicit tunnel/multiplex evidence is modeled.
  - Entry paths: high-confidence process ownership for generated user connections, SSH baseline
    and storyline paths that materialize source client ownership, SMB browse/network noise, and
    source-visible endpoint flow rendering.
  - Consumers: eCAR `FLOW`, process create/terminate lifecycle rows, Sysmon Event 3, Windows 4648
    companions, SSH target-side syslog/eCAR sessions, and rendered-output probes that compare
    command-line target host to `dst_ip`.
  - Sibling risk: direct remote-admin command parent/child grammar (`cmd.exe /c net.exe` vs
    `cmd.exe /c net view ...`) remains a separate process-tree grammar issue; loop 31 scoped to
    target-bearing network owner reuse.
- Implemented changes:
  - Added target-bearing exact-command matching for `ssh`, `ssh.exe`, `scp`, `scp.exe`, `sftp`,
    `sftp.exe`, and `gvfsd-smb-browse` process owners.
  - `_ensure_user_connection_owner_process` now refuses to reuse an active candidate process for
    target-bearing command lines unless the existing command line exactly matches the requested
    target-bearing command.
  - Added focused tests proving Windows `ssh.exe <host>` and Linux `gvfsd-smb-browse
    smb://<host>/...` allocate target-specific owner processes and reuse only for the same
    target.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "ssh_owner_is_scoped or smb_browse_owner_is_scoped or workstation_ssh_connection_materializes_user_owner or ssh_process_network_effect"`
    (`5` passed).
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "connection_materializes or high_confidence or proxy_service_owner_is_not_reused_across_targets or command_lines_do_not_leak or ssh_process_network_effect or workstation_ssh"`
    (`7` passed).
  - `uv run pytest --no-cov tests/unit/test_explicit_proxy.py -k "build_proxy_context or proxy"`
    (`74` passed).
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py`
- Generated loop 31 output successfully.
- Automated eval passed at `95.48137933988775` over 94,935 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.40265788614258`
  - Causality: `90.32296183444666`
  - Timing: `96.49987204870217`
- Hard probe `hard_probe_ecar_target_bearing_owner.json`:
  - Loop 30 target-bearing eCAR `FLOW` rows checked: `148`.
  - Loop 30 target/destination mismatches: `80`.
  - Loop 31 target-bearing eCAR `FLOW` rows checked: `163`.
  - Loop 31 target/destination mismatches: `0`.
  - Loop 31 multi-target process reuse count: `0`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-31/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-kilo.0x4qUA`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement.
- Blind initial mean synthetic-confidence: `39.25`; deliberation mean: `45.0`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `66`, synthetic-confidence `43`; deliberated to
    Inconclusive, confidence `70`, synthetic-confidence `48`.
  - Detection Engineer: Real, confidence `57`, synthetic-confidence `34`; deliberated to
    Inconclusive, confidence `58`, synthetic-confidence `43`.
  - Network Forensics: Real, confidence `72`, synthetic-confidence `26`; deliberated to Real,
    confidence `68`, synthetic-confidence `31`.
  - Host/EDR: Synthetic, confidence `63`, synthetic-confidence `54`; deliberated to Synthetic,
    confidence `66`, synthetic-confidence `58`.
- Panel consensus and prioritized findings:
  - The loop 30 SSH/eCAR target-bearing command mismatch was absent from reviewer reports after
    the fix. Detection explicitly reported no SSH auth outside visible transport windows, and
    Host/EDR called Linux SSH evidence source-native.
  - The strongest new consensus target is Linux reboot lifecycle modeling: `loginctl reboot` or
    `systemctl reboot` commands plus polkit authorization appear on multiple Linux hosts without
    shutdown/boot evidence, daemon PID churn, service stops, DHCP reacquisition, or explicit
    failure/inhibitor text. This is a source-visible lifecycle gap and moved Detection from Real
    to Inconclusive in deliberation.
  - Secondary targets:
    - Windows Sysmon CBS package-state registry writes are repeatedly attributed to `msiexec.exe`
      across roles; likely should be TrustedInstaller/TiWorker servicing activity or retargeted
      to MSI/product registry keys.
    - Linux admin/sudo command pools and SSH auth/PAM timing remain distribution-texture tells.
    - Detection still found one Windows 4648 `TargetServerName=DC-01` with
      `NetworkAddress=10.10.1.99`; investigate as a residual explicit credential-use companion
      source/destination binding issue.
    - Proxy `304` byte semantics, NTP stratum/ref_id, UDP/88 zero-byte denies, and a single
      incomplete bash history command are lower-impact weak signals.
- Selected loop 32 target:
  - P0/P1 Linux reboot lifecycle semantics. Owning abstraction: Linux command/process/session
    lifecycle generation plus syslog/eCAR side effects, likely in the ActivityGenerator/Linux
    baseline command path and any canonical command/network side-effect helpers. Invariant: a
    visible successful `loginctl reboot`, `systemctl reboot`, or equivalent shutdown command must
    either produce a coherent reboot lifecycle (session termination, service stop/shutdown,
    kernel/boot messages, daemon PID churn, DHCP reacquisition, post-boot gap) or be rendered as
    visibly denied/failed/inhibited with no subsequent boot expectations. Consumers include
    syslog, eCAR PROCESS lifecycle, bash history, DHCP syslog/Zeek, and blind host lifecycle
    probes. Sibling risk: package/service restart commands may need a lighter lifecycle contract
    but can be deferred unless the reboot fix surfaces shared command-outcome modeling.

## Loop 32

- Family contract:
  - Owning abstraction: Linux polkit/background syslog command-outcome generation in
    `BaselineMixin`, plus the eCAR companion process materialization it invokes.
  - Invariant: generic background polkit reboot noise must not claim a successful reboot unless a
    coherent host reboot lifecycle is modeled. A visible `loginctl reboot`/`systemctl reboot`
    attempt without boot/session/daemon/DHCP lifecycle evidence must be explicitly failed or
    unauthorized.
  - Entry paths: extra syslog `polkitd` workstation entries, polkit action/profile selection,
    companion CLI process materialization, eCAR process lifecycle, and syslog rendering.
  - Consumers: Linux syslog, eCAR PROCESS create/terminate, bash-history-adjacent host lifecycle
    probes, DHCP/syslog daemon continuity checks, and blind Host/EDR review.
  - Sibling risk: true modeled reboot/shutdown remains future work; this loop fixes generic
    background noise by preventing accidental successful reboot semantics.
- Implemented changes:
  - Added `_polkit_action_message_template` so `org.freedesktop.login1.reboot` generic polkit
    messages render as explicit failure/not-authorized text rather than successful authorization.
  - Retained endpoint-visible `loginctl reboot` or `systemctl reboot` process attempts so analysts
    see a plausible failed attempt instead of a hidden event.
  - Added a focused regression test forcing the reboot action and asserting no successful
    authorization text is emitted while the reboot command process remains visible.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_phase5_system_traffic.py -k "polkit_action or polkit_reboot"`
    (`3` passed).
  - `uv run pytest --no-cov tests/unit/test_phase5_system_traffic.py` (`62` passed).
  - `uv run ruff check src/evidenceforge/generation/engine/baseline.py tests/unit/test_phase5_system_traffic.py`
  - `uv run ruff format --check src/evidenceforge/generation/engine/baseline.py tests/unit/test_phase5_system_traffic.py`
- Generated loop 32 output successfully.
- Automated eval passed at `95.0425237961009` over 95,354 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.56367827855763`
  - Causality: `88.79128058921359`
  - Timing: `96.01892039579043`
- Guardrail note:
  - Causality pillar dipped below 90 because event-presence scoring stayed at `89.1`; causal
    ordering remained `100.0` and acceptance passed. The reported sample failures are existing
    scenario traceability gaps rather than a reboot-fix ordering regression.
- Hard probe `hard_probe_linux_reboot_polkit_outcome.json`:
  - Loop 31 reboot command processes: `6`.
  - Loop 31 successful reboot authorizations: `6`.
  - Loop 32 reboot command processes: `7`.
  - Loop 32 successful reboot authorizations: `0`.
  - Loop 32 unsuccessful reboot authorizations: `7`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-32/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-lima.coqi5h`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement and synthetic-confidence spread over 30.
- Blind initial mean synthetic-confidence: `44.75`; deliberation mean: `52.25`.
- Reviewer scores:
  - Threat Hunter: Real, confidence `68`, synthetic-confidence `36`; deliberated to
    Inconclusive, confidence `64`, synthetic-confidence `48`.
  - Detection Engineer: Inconclusive, confidence `72`, synthetic-confidence `34`; deliberated to
    Inconclusive, confidence `74`, synthetic-confidence `43`.
  - Network Forensics: Inconclusive, confidence `68`, synthetic-confidence `42`; deliberated to
    Inconclusive, confidence `70`, synthetic-confidence `50`.
  - Host/EDR: Synthetic, confidence `72`, synthetic-confidence `67`; deliberated to Synthetic,
    confidence `74`, synthetic-confidence `68`.
- Panel consensus and prioritized findings:
  - The reboot lifecycle issue no longer dominated the panel. Host/EDR specifically reported no
    visible process/session lifecycle inversions and praised Linux SSH/SCP ordering.
  - The new strongest source-native contradiction is FILE-SRV-01/10.10.2.20 rendering HTTP
    health checks as `kube-probe/1.28` while endpoint eCAR and Windows WFP attribute the same
    tuples/source ports to Windows `svchost.exe -k netsvcs`, with no kubelet/container evidence.
  - Secondary targets include duplicated core/DMZ sensor timing offsets, endpoint/export window
    clustering, Linux sysstat/cron regularity, repeated sudo/admin command pool texture, and
    templated email prose.
- Selected loop 33 target:
  - P0/P1 health-check User-Agent/process ownership semantics. Owning abstraction:
    web-session/profile selection plus canonical HTTP/network process ownership, not a single
    web emitter. Invariant: source-native HTTP User-Agent families must match the source host and
    visible owner process. `kube-probe/*` health checks may originate only from modeled Linux
    Kubernetes/kubelet/container sources with corresponding endpoint evidence; Windows service
    health-check traffic must use Windows-service-appropriate User-Agents and endpoint process
    identity. Consumers include web_access, Zeek HTTP, proxy/access when applicable, eCAR FLOW,
    Windows Security 5156, Sysmon Event 3, and blind host/network probes.

## Loop 33

- Family contract:
  - Owning abstraction: data-driven inbound web visitor profiles and the shared
    `pick_web_user_agent` OS-aware selection helper consumed by baseline web traffic generation.
  - Invariant: generic health-check User-Agent pools must be host/software compatible. A
    Windows-originated health-check request must not draw a Kubernetes/kubelet User-Agent unless
    the source host has modeled Kubernetes/container ownership evidence; generic internal health
    checks should use OS-appropriate service/monitoring User-Agents.
  - Entry paths: inbound web baseline request profiles, profile source-type/role filtering,
    source-host OS resolution in `_emit_web_server_access`, sticky User-Agent selection, and any
    overlay-provided web visitor classes that use `user_agent_pool_by_os`.
  - Consumers: `web_access.log`, Zeek `http.json`, proxy access rows for routed HTTP activity,
    eCAR `FLOW`, Windows Security 5156, Sysmon Event 3, and rendered-output probes comparing HTTP
    User-Agent families with endpoint process ownership.
  - Sibling risk: true Kubernetes health checks still need a role/software-aware source family
    with visible kubelet/container evidence; this loop removes the generic cross-platform
    mismatch rather than adding a full Kubernetes node model.
- Implemented changes:
  - Split the generic health-check User-Agent profile into OS-specific pools:
    `health_check_windows` and `health_check_linux`.
  - Removed `kube-probe/1.28` from generic health-check selection so ordinary Windows and Linux
    server health checks cannot masquerade as Kubernetes/kubelet traffic by default.
  - Added a `validate-config` guard that rejects `kube-probe` in generic health-check pools unless
    the profile is explicitly scoped to Kubernetes/container roles.
  - Extended web-session profile and baseline web-access tests to assert OS-scoped health-check
    User-Agent selection and no Kubernetes User-Agent leakage from server-scoped health checks.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_web_session_profiles.py tests/unit/test_baseline_canonical.py -k "health_check"`
    (`4` passed).
  - `uv run pytest --no-cov tests/unit/test_validate_config.py -k "web_session_profile or kube_probe"`
    (`2` passed).
  - `uv run pytest --no-cov tests/unit/test_web_session_profiles.py tests/unit/test_validate_config.py`
    (`90` passed).
  - `uv run eforge validate-config`
  - `uv run ruff check src/evidenceforge/cli/validate_config.py tests/unit/test_web_session_profiles.py tests/unit/test_baseline_canonical.py tests/unit/test_validate_config.py`
  - `uv run ruff format --check src/evidenceforge/cli/validate_config.py tests/unit/test_web_session_profiles.py tests/unit/test_baseline_canonical.py tests/unit/test_validate_config.py`
- Generated loop 33 output successfully.
- Automated eval passed at `95.0425237961009` over 95,354 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.56367827855763`
  - Causality: `88.79128058921359`
  - Timing: `96.01892039579043`
- Guardrail note:
  - Causality stayed below 90 for the same existing event-presence/storyline-linkability issues
    observed in loop 32; causal ordering remained `100.0` and acceptance passed.
- Hard probe `hard_probe_health_check_user_agent_binding.json`:
  - Loop 32 Windows-source `kube-probe` HTTP rows: `15`.
  - Loop 33 Windows-source `kube-probe` HTTP rows: `0`.
  - Loop 33 total `kube-probe` HTTP rows: `0`.
  - Loop 33 Windows service-style health-check rows: `21`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-33/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-mike.vx_ypzgg`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement and synthetic-confidence spread over 30.
- Blind initial mean synthetic-confidence: `50.5`; deliberation mean: `59.25`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `64`, synthetic-confidence `42`; deliberated to
    Inconclusive/synthetic-leaning, confidence `68`, synthetic-confidence `55`.
  - Detection Engineer: Synthetic, confidence `62`, synthetic-confidence `64`; deliberated to
    Synthetic, confidence `68`, synthetic-confidence `70`.
  - Network Forensics: Real, confidence `72`, synthetic-confidence `28`; deliberated to Real
    with endpoint caveat, confidence `64`, synthetic-confidence `38`.
  - Host/EDR: Synthetic, confidence `70`, synthetic-confidence `68`; deliberated to Synthetic,
    confidence `76`, synthetic-confidence `74`.
- Panel consensus and prioritized findings:
  - The loop 32 Windows `svchost.exe`/`kube-probe` contradiction disappeared from the loop 33
    reports after the fix.
  - The strongest new concrete contract gap is MAIL-EDGE endpoint FLOW viewpoint handling:
    eCAR renders repeated internal SMTP flows to the public VIP `203.14.220.11` while host-local
    Postfix syslog shows MAIL-EDGE accepting those sessions locally from internal mail hosts.
  - A broad timing texture issue recurred across Detection and Host/EDR: MAIL-FIN and
    WS-EBROOKS Security 4688, Sysmon Event 1, and eCAR process-create timestamps align within
    sub-millisecond windows across most matched process creates.
  - Secondary targets: compact/repetitive Zeek SMB file name/size distribution, uneven endpoint
    collection texture/eCAR vocabulary coverage, templated email prose, Linux admin command pool
    repetition, and a lower-impact APP-INT SCP receiver PID/session split.
- Selected loop 34 target:
  - P0/P1 endpoint NAT/viewpoint contract for inbound MAIL-EDGE SMTP. Owning abstraction:
    canonical network connection/routing plus endpoint observation/rendering viewpoint, not the
    Zeek or eCAR renderer alone. Invariant: endpoint host telemetry for inbound flows must render
    the local socket tuple visible to the host after NAT/VIP translation, while firewall/perimeter
    and Zeek sensors may render pre-NAT or public-VIP tuples according to sensor viewpoint.
    Consumers include eCAR `FLOW`, host syslog/Postfix/Dovecot evidence, Zeek SMTP/conn/files,
    ASA NAT/teardown rows, and blind host/network tuple-correlation probes. Sibling risk:
    public VIP handling for web and other inbound services must be checked so the fix does not
    break legitimate perimeter/network viewpoints.

## Loop 34

- Family contract:
  - Owning abstraction: network visibility/NAT context computation before source observation and
    endpoint rendering.
  - Invariant: traffic aimed at a modeled static NAT VIP must carry DNAT context even when the VIP
    inherits the real host's segment for visibility. Endpoint telemetry may render the host-local
    post-NAT listener tuple, while firewall/perimeter/network sensors can retain their viewpoint.
  - Entry paths: `NetworkVisibilityEngine.compute_nat`, dispatcher NAT swaps, eCAR inbound FLOW
    rendering, and internal mail traffic that resolves MX hostnames to public VIPs.
  - Consumers: eCAR `FLOW`, Postfix/syslog tuple correlation, Zeek SMTP/conn, ASA NAT/teardown,
    and blind host/network endpoint-viewpoint probes.
- Implemented changes:
  - Added a static-VIP pre-pass in `compute_nat()` so known VIP destinations produce static DNAT
    context before the same-segment no-NAT guard and before dynamic PAT can win by rule order.
  - Added unit coverage for internal server-to-public-VIP hairpin SMTP with dynamic PAT listed
    before the static VIP rule, plus a guard that ordinary same-segment real-IP traffic remains
    un-NATed.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_network_visibility.py -k "NatComputation"`
    (`2` passed).
  - `uv run pytest --no-cov tests/unit/test_log_realism_fixes.py -k "EcarNatAwareIp"`
    (`1` passed).
  - `uv run pytest --no-cov tests/unit/test_network_visibility.py` (`30` passed).
  - `uv run ruff check src/evidenceforge/generation/network_visibility.py tests/unit/test_network_visibility.py`
  - `uv run ruff format --check src/evidenceforge/generation/network_visibility.py tests/unit/test_network_visibility.py`
- Generated loop 34 output successfully.
- Automated eval passed at `95.0425237961009` over 95,354 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.56367827855763`
  - Causality: `88.79128058921359`
  - Timing: `96.01892039579043`
- Hard probe `hard_probe_mail_edge_endpoint_nat_viewpoint.json`:
  - Loop 33 MAIL-EDGE endpoint inbound SMTP rows from internal sources to public VIP: `7`.
  - Loop 34 MAIL-EDGE endpoint inbound SMTP rows from internal sources to public VIP: `0`.
  - Loop 34 matching rows rendered to local real IP `10.10.2.25`: `7`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-34/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-mike.svnh_0_0`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement and synthetic-confidence spread over 30.
- Blind initial mean synthetic-confidence: `64.0`; deliberation mean: `67.5`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `76`, synthetic-confidence `78`; deliberated to
    Synthetic, confidence `76`, synthetic-confidence `74`.
  - Detection Engineer: Synthetic, confidence `72`, synthetic-confidence `68`; deliberated to
    Synthetic, confidence `75`, synthetic-confidence `72`.
  - Network Forensics: Inconclusive, confidence `68`, synthetic-confidence `42`; deliberated to
    Inconclusive/synthetic-leaning, confidence `64`, synthetic-confidence `52`.
  - Host/EDR: Synthetic, confidence `74`, synthetic-confidence `68`; deliberated to Synthetic,
    confidence `76`, synthetic-confidence `72`.
- Panel consensus and prioritized findings:
  - The loop 33 MAIL-EDGE public-VIP endpoint FLOW defect disappeared. Network Forensics
    specifically credited proxy/NAT viewpoint coherence and did not find a hard NAT contradiction.
  - The strongest remaining cross-source contradiction is external mail infrastructure identity:
    provider hostnames and EML `Received` chains do not cohere with Zeek SMTP peer IP/provider
    families or relay paths.
  - The second strongest source-native issue is daemon-owned Linux endpoint FILE activity:
    Postfix processes write/read browser caches, downloads, `.ssh/known_hosts`, and desktop
    metadata paths.
  - Secondary targets: intent-revealing artifact filenames and repeated EML boilerplate, proxy/web
    page-resource bundle repetition, overly complete shell-history breadcrumbs, and Windows WFP
    `\device\harddiskvolume1` uniformity.
- Selected loop 35 target:
  - P0/P1 external mail infrastructure identity modeling. Owning abstraction: mail identity
    planning/provider catalog and canonical SMTP/email contexts before Zeek/EML/syslog rendering,
    not a single emitter patch. Invariant: external mail provider identity must bind together
    HELO/EHLO, Received-chain hostnames, MX/relay hostnames, source IP family, Zeek SMTP peers,
    firewall source tuples, and artifact headers. Google/Mimecast/Zoho/etc. hostnames must not be
    paired with unrelated provider IP ranges unless the model explicitly represents an upstream
    relay/forwarding hop. Consumers include EML artifacts, Zeek SMTP/conn, Postfix syslog, ASA,
    DNS/MX evidence, and blind email-investigation pivots.

## Loop 35

- Family contract:
  - Owning abstraction: mail provider identity catalog plus external SMTP/source-mail planning
    before Zeek, EML, syslog, and firewall rendering.
  - Invariant: external mail provider hostnames must bind to provider-family public IPs across
    Zeek SMTP peers, EML `Received` headers, HELO/EHLO strings, relay hostnames, and firewall
    tuples. Google, Microsoft, Proofpoint, Mimecast, SendGrid, Zoho, Fastmail, Mailgun, Amazon
    SES, and generic hosted-mail identities must not be cross-paired unless an explicit relay hop
    models that relationship.
  - Entry paths: `_external_email_hop`, `_external_source_mail_system`,
    `_external_sender_public_hops`, public mail identity generation, EML header construction,
    Zeek SMTP/conn rendering, and ASA/firewall rendering.
  - Consumers: EML artifacts, Zeek SMTP/conn, Postfix syslog, firewall rows, DNS/MX evidence,
    and blind email-investigation pivots.
- Implemented changes:
  - Expanded `mail_public_identities.yaml` with provider hostname patterns, prefixes, PTR
    templates, and IP pools for Google Workspace, Microsoft 365, Proofpoint, SendGrid, Mimecast,
    Amazon SES, Fastmail, Mailgun, Zoho, and generic hosted-mail sources.
  - Added hostname-to-provider matching in `mail_public_identities.py` and made public mail IP
    generation prefer the provider implied by the forward hostname.
  - Routed external SMTP hop, source-mail-system, and sender-public-hop generation through the
    provider-aware public mail identity helper.
  - Added regression coverage for provider hostname/IP binding and source mail system generation.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_email_evidence.py -k "provider_hostname or source_mail_system or external_sender_received"`
    (`3` passed).
  - `uv run pytest --no-cov tests/unit/test_identity_pools.py -k "mail_public or identity"`
    (`6` passed).
  - `uv run pytest --no-cov tests/unit/test_email_evidence.py` (`35` passed).
  - `uv run pytest --no-cov tests/unit/test_identity_pools.py` (`6` passed).
  - `uv run eforge validate-config`
  - `uv run ruff check src/evidenceforge/generation/activity/mail_public_identities.py src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/mail_public_identities.py src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
- Generated loop 35 output successfully.
- Automated eval passed at `95.14267614748574` over 95,349 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.96450921770158`
  - Causality: `88.79128058921359`
  - Timing: `96.01864347878478`
- Hard probe `hard_probe_external_mail_provider_identity_binding.json`:
  - Loop 34 SMTP provider mismatches: `13`.
  - Loop 34 EML `Received` provider mismatches: `13`.
  - Loop 35 SMTP provider mismatches: `0`.
  - Loop 35 EML `Received` provider mismatches: `0`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-35/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-mike.bspbnp5l`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement and synthetic-confidence spread over 30.
- Blind initial mean synthetic-confidence: `70.0`; deliberation mean: `78.25`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `66`, synthetic-confidence `42`; deliberated to
    Synthetic, confidence `72`, synthetic-confidence `68`.
  - Detection Engineer: Synthetic, confidence `84`, synthetic-confidence `82`; deliberated to
    Synthetic, confidence `88`, synthetic-confidence `84`.
  - Network Forensics: Synthetic, confidence `64`, synthetic-confidence `70`; deliberated to
    Synthetic, confidence `70`, synthetic-confidence `74`.
  - Host/EDR: Synthetic, confidence `82`, synthetic-confidence `86`; deliberated to Synthetic,
    confidence `85`, synthetic-confidence `87`.
- Panel consensus and prioritized findings:
  - The external mail provider identity defect disappeared from the loop 35 bounded probe and did
    not recur as the dominant review finding.
  - The strongest remaining source-native contradiction is SSH identity correlation: Windows
    `ssh.exe` endpoint commands owned by one local actor often omit an alternate remote user while
    the same tuple is accepted by Linux `sshd` as a different user. Detection's bounded check found
    `23` mismatches among `44` matched flows.
  - Secondary targets include Linux eCAR package-manager helper parentage, NTP/source-view timing
    texture, multi-sensor byte mirroring, public-client IP and user-agent realism, and selective
    observation gaps around high-signal attack paths.
- Selected loop 36 target:
  - P0/P1 SSH remote-session identity correlation. Owning abstraction: SSH action bundle and
    canonical session/transport intent, with Windows client process command rendering adapting to
    that shared truth. Invariant: the source endpoint `ssh.exe` process owner, command-line remote
    user/host target, Linux `sshd` accepted user, bash-history owner, eCAR login/logout rows, and
    Zeek/ASA tuple must agree. If the remote authenticated user differs from the local source
    actor, the client command must explicitly specify the remote principal (for example
    `remote.user@host`) or the bundle must align the remote identity to the local actor; the target
    host must not silently authenticate a different user on the same tuple.

## Loop 36

- Family contract:
  - Owning abstraction: SSH action bundle, canonical network connection request, and source-side
    user connection owner process modeling.
  - Invariant: the source endpoint SSH command line must expose the authenticated remote principal
    when it differs from the local source actor. A tuple accepted by Linux `sshd` as `remote.user`
    must have source endpoint evidence such as `ssh.exe remote.user@target` or `/usr/bin/ssh
    remote.user@target`, not a bare target that implies same-user authentication.
  - Consumers: eCAR FLOW and PROCESS rows, Sysmon process/network rows, Linux syslog SSH auth,
    Zeek conn, ASA/firewall rows, shell history, and review pivots that join source endpoint
    process telemetry to target authentication.
- Implemented changes:
  - Propagated `ssh_attempted_username` from the SSH action bundle into the canonical connection
    generation path.
  - Updated high-confidence SSH client process command construction to include
    `remote.user@target` while keeping the local source process owner unchanged.
  - Added regression coverage for a Windows client owned by one actor authenticating to a Linux
    SSH server as a different remote user.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "ssh_session_windows_client_command_names_remote_user or workstation_ssh_owner_is_scoped_to_command_target or ssh_process_network_effect_passes_command_username or generic_ssh_preauth_syslog_uses_attempted_username"`
    (`4` passed).
  - `uv run pytest --no-cov tests/unit/test_activity.py` (`321` passed).
  - `uv run ruff check src/evidenceforge/generation/actions/ssh_session.py src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py`
  - `uv run ruff format --check src/evidenceforge/generation/actions/ssh_session.py src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py`
- Generated loop 36 output successfully.
- Automated eval passed at `95.60105317639982` over 93,590 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `96.00427236022101`
  - Causality: `89.6969696969697`
  - Timing: `95.8787133105107`
- Hard probe `hard_probe_ssh_remote_identity_correlation.json`:
  - Loop 35 matched Windows SSH flows: `44`.
  - Loop 35 remote-user command mismatches: `23`.
  - Loop 36 matched Windows SSH flows: `49`.
  - Loop 36 remote-user command mismatches: `0`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-36/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-nova.JuGonM`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement.
- Blind initial mean synthetic-confidence: `60.0`; deliberation mean: `66.0`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `82`, synthetic-confidence `72`; deliberated to
    Synthetic, confidence `84`, synthetic-confidence `75`.
  - Detection Engineer: Synthetic, confidence `61`, synthetic-confidence `58`; deliberated to
    Synthetic, confidence `66`, synthetic-confidence `62`.
  - Network Forensics: Inconclusive, confidence `58`, synthetic-confidence `42`; deliberated to
    Synthetic, confidence `60`, synthetic-confidence `55`.
  - Host/EDR: Synthetic, confidence `74`, synthetic-confidence `68`; deliberated to Synthetic,
    confidence `78`, synthetic-confidence `72`.
- Panel consensus and prioritized findings:
  - The loop 35 SSH remote-user identity mismatch disappeared from the bounded probe.
  - The strongest remaining cross-source contradiction is SSH source-process lifecycle: source
    eCAR shows `ssh.exe` PIDs terminating well before Zeek and target Linux syslog keep the same
    SSH tuple/session alive.
  - The second strongest issue is Linux endpoint session ownership, where `systemd --user`, shell,
    and terminal trees appear for a user before visible successful session establishment for that
    same user.
  - Secondary targets include successful Zeek DNS connection rows without DNS companions and
    unstable byte accounting for repeated static/hash-named web assets.
- Selected loop 37 target:
  - P0 SSH client process lifecycle. Owning abstraction: SSH action bundle plus canonical
    network-connection/source-process lifecycle path. Invariant: for an SSH/RDP-like interactive
    session, source endpoint client process termination must not precede the correlated network
    transport close or target session close. If source process identity would otherwise force an
    impossible lifetime, the lifecycle owner should extend/protect the process through close or
    omit process identity rather than emitting an early termination.

## Loop 37

- Family contract:
  - Owning abstraction: canonical network connection and process lifecycle ownership.
  - Invariant: any process-attributed transport with a concrete close interval should keep the
    source endpoint process alive through that interval. Process termination may be delayed beyond
    session logoff clamping if the process already owns a visible transport that closes later.
  - Consumers: eCAR PROCESS/TERMINATE and FLOW rows, Windows Security/Sysmon process lifecycle and
    network rows, Zeek connection durations, and target-side SSH/syslog session close evidence.
- Implemented changes:
  - Added process connection-hold state keyed by source host/PID.
  - Recorded process holds from process-attributed network connections with known close times.
  - Made process termination honor the latest held transport close even after existing
    session-end clamping.
  - Added regression coverage for a Windows SSH client whose transport remains open for 30
    minutes while an early termination request is issued.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_process_lifetimes.py` (`34` passed).
  - `uv run pytest --no-cov tests/unit/test_zeek_activity_contexts.py` (`85` passed).
  - `uv run pytest --no-cov tests/unit/test_activity.py` (`321` passed).
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_process_lifetimes.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_process_lifetimes.py`
- Generated loop 37 output successfully.
- Automated eval passed at `95.60121230950934` over 93,597 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `96.00490889265907`
  - Causality: `89.6969696969697`
  - Timing: `95.8787133105107`
- Hard probe `hard_probe_ssh_source_process_lifecycle.json`:
  - Loop 36 matched SSH source endpoint flows: `70`.
  - Loop 36 premature source process terminations: `2`.
  - Loop 37 matched SSH source endpoint flows: `77`.
  - Loop 37 premature source process terminations: `0`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-37/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-nova.2cWtRJ`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement and synthetic-confidence spread over 30.
- Blind initial mean synthetic-confidence: `49.5`; deliberation mean: `67.75`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `78`, synthetic-confidence `70`; deliberated to
    Synthetic, confidence `82`, synthetic-confidence `76`.
  - Detection Engineer: Realistic, confidence `76`, synthetic-confidence `32`; deliberated to
    Synthetic, confidence `68`, synthetic-confidence `62`.
  - Network Forensics: Realistic, confidence `74`, synthetic-confidence `28`; deliberated to
    Synthetic, confidence `64`, synthetic-confidence `58`.
  - Host/EDR: Synthetic, confidence `72`, synthetic-confidence `68`; deliberated to Synthetic,
    confidence `80`, synthetic-confidence `75`.
- Panel consensus and prioritized findings:
  - The SSH client process lifecycle contradiction disappeared from the bounded probe and was not a
    panel-leading finding.
  - The strongest remaining hard contradiction is DHCP renewal timing: Linux `dhclient` syslog
    advertises one renewal interval while the next Zeek/syslog REQUEST appears at a substantially
    different time.
  - The next strongest hard host contradiction remains Linux eCAR session ownership: local session
    login rows can name one user while adjacent `systemd --user`, terminal, and shell processes
    belong to another.
  - Secondary targets include Zeek `missed_bytes` history markers, DNS/cache TTL texture, root SSH
    policy, and thin NTP recurrence.
- Selected loop 38 target:
  - P0 DHCP renewal lifecycle. Owning abstraction: DHCP lease action bundle plus baseline DHCP
    renewal scheduler. Invariant: Linux `dhclient` "renewal in N seconds" messages must match the
    actual next scheduled DHCP REQUEST/ACK transaction for that host, or the model must represent
    an explicit link/reset/observation gap explaining an early renewal. Zeek DHCP rows, syslog
    dhclient lines, lease state, and registry side effects must share one schedule.

## Loop 38

- Family contract:
  - Owning abstraction: DHCP lease action bundle, DHCP setup/storyline lease state, and baseline
    DHCP renewal scheduler.
  - Invariant: every visible `dhclient` "bound -- renewal in N seconds" message must point to the
    next visible DHCPREQUEST for the same host/IP when that next transaction falls inside the
    collection window. Explicit storyline DHCP leases own their host's DHCP transaction for that
    hour and suppress conflicting ambient renewals.
  - Consumers: Linux syslog `dhclient`, Zeek DHCP, Zeek conn, DHCP lease state, registry lease side
    effects, and blind-review pivots joining syslog to Zeek DHCP rows.
- Implemented changes:
  - Added `renewal_interval` to the DHCP lease action request and source-native syslog rendering.
  - Added a shared `dhcp_renewal_interval_seconds()` helper and stored `next_renewal` in setup,
    storyline, and baseline lease state.
  - Made baseline DHCP scheduling advertise the next visible/cross-hour renewal rather than a
    generic T1 interval.
  - Made baseline DHCP renewals defer to explicit storyline DHCP events in the same host/hour.
  - Adjusted dhclient syslog renewal display to count from the visible `bound` message timestamp,
    not the request timestamp.
  - Added focused tests for DHCP renewal scheduling, bundle rendering, setup lease state, and
    explicit storyline DHCP lease state.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_baseline_canonical.py -k dhcp` (`12` passed).
  - `uv run pytest --no-cov tests/unit/test_dhcp_setup.py tests/unit/test_storyline_command_networks.py -k dhcp` (`6` passed).
  - `uv run ruff check src/evidenceforge/generation/actions/__init__.py src/evidenceforge/generation/actions/dhcp_lease.py src/evidenceforge/generation/activity/generator.py src/evidenceforge/generation/engine/baseline.py src/evidenceforge/generation/engine/emitter_setup.py src/evidenceforge/generation/engine/storyline.py tests/unit/test_baseline_canonical.py tests/unit/test_dhcp_setup.py tests/unit/test_storyline_command_networks.py`
  - `uv run ruff format --check src/evidenceforge/generation/actions/__init__.py src/evidenceforge/generation/actions/dhcp_lease.py src/evidenceforge/generation/activity/generator.py src/evidenceforge/generation/engine/baseline.py src/evidenceforge/generation/engine/emitter_setup.py src/evidenceforge/generation/engine/storyline.py tests/unit/test_baseline_canonical.py tests/unit/test_dhcp_setup.py tests/unit/test_storyline_command_networks.py`
  - Full `tests/unit/test_baseline_canonical.py` still has an unrelated pre-existing failure in
    `TestWebAccessCorrelation::test_server_like_auto_http_uses_service_user_agent`.
- Generated loop 38 output successfully after the sibling-path correction.
- Automated eval passed at `95.34043175969583` over 95,141 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.96486993652913`
  - Causality: `89.3091433426466`
  - Timing: `95.10964219950945`
- Hard probe `hard_probe_dhcp_renewal_schedule.json`:
  - Loop 37 renewal mismatches: `16`.
  - Loop 38 checked bound messages with visible next request: `33`.
  - Loop 38 renewal mismatches: `0`.
  - Loop 38 Zeek request rows unmatched to syslog: `0`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-38/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-nova.KEtACA`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement.
- Blind initial mean synthetic-confidence: `49.75`; deliberation mean: `54.75`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `62`, synthetic-confidence `57`; deliberated to
    Synthetic, confidence `68`, synthetic-confidence `64`.
  - Detection Engineer: Inconclusive, confidence `68`, synthetic-confidence `34`; deliberated to
    Inconclusive, confidence `70`, synthetic-confidence `40`.
  - Network Forensics: Inconclusive, confidence `63`, synthetic-confidence `46`; deliberated to
    Inconclusive, confidence `66`, synthetic-confidence `50`.
  - Host/EDR: Synthetic, confidence `66`, synthetic-confidence `62`; deliberated to Synthetic,
    confidence `70`, synthetic-confidence `65`.
- Panel consensus and prioritized findings:
  - The DHCP renewal timing contradiction disappeared from the bounded probe and Detection called
    DHCP renewal alignment production-like.
  - The strongest remaining concrete synthetic indicator is eCAR FILE ownership for protected
    Windows event logs: repeated `C:\Windows\System32\winevt\Logs\Security.evtx` CREATE/WRITE/READ
    rows attributed to unrelated processes such as `explorer.exe`, `dns.exe`, `userinit.exe`,
    `SearchIndexer.exe`, and `service-healthcheck.exe`.
  - Other recurring targets include RDP target eCAR FLOW timing after Type 10 authentication,
    proxy cache/origin timing texture, Zeek TLS/OCSP source shape, and smooth endpoint collection
    texture.
- Selected loop 39 target:
  - P0 eCAR protected event-log FILE ownership. Owning abstraction: data-driven EDR file path
    pools and ambient eCAR FILE churn selection. Invariant: generic ambient Windows FILE churn must
    not emit `C:\Windows\System32\winevt\Logs\*.evtx` rows under arbitrary process ownership.
    Protected event-log activity, if modeled, should be owned by source-native Windows Event Log
    service semantics, not browsers, explorers, DNS service, userinit, search indexers, or generic
    service-health jobs.

## Loop 39

- Family contract:
  - Owning abstraction: data-driven EDR file path pools and ambient eCAR FILE churn selection.
  - Invariant: generic ambient Windows FILE churn must not emit
    `C:\Windows\System32\winevt\Logs\*.evtx` rows under arbitrary process ownership. Protected
    event-log activity, if modeled later, should be owned by Windows Event Log service semantics.
- Implemented changes:
  - Removed `Security.evtx` from the default Windows ambient eCAR file path pool.
  - Added a Windows protected-event-log filter in ambient FILE churn selection so overlays or
    future pools cannot reintroduce `winevt\Logs\*.evtx` as generic churn.
  - Added focused tests for default pools and ambient selection filtering.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_edr_pools.py -k "protected_event_logs or default_windows_file_paths or ambient_file_churn_filters_windows"`
  - `uv run eforge validate-config`
  - `uv run pytest --no-cov tests/unit/test_edr_pools.py`
  - `uv run ruff check src/evidenceforge/generation/activity/edr_pools.py tests/unit/test_edr_pools.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/edr_pools.py tests/unit/test_edr_pools.py`
- Generated loop 39 output successfully.
- Automated eval passed at `95.2619512034567` over 91,972 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.80454827032506`
  - Causality: `88.63321129007949`
  - Timing: `95.76255656677782`
- Hard probe `hard_probe_ecar_protected_event_log_file_ownership.json`:
  - Loop 38 protected event-log eCAR FILE rows: `61`.
  - Loop 39 protected event-log eCAR FILE rows: `0`.
  - Overall probe result: `passed`.
- Additional reviewer-finding probe `hard_probe_windows_process_before_logon.json`:
  - Loop 38 Security process-before-logon rows: `0`; Sysmon process-before-security-logon rows:
    `0`.
  - Loop 39 Security process-before-logon rows: `1`; Sysmon process-before-security-logon rows:
    `1`.
  - The defect matches the Host/EDR FILE-SRV-01 sample for LogonId `0xf88578c`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-39/review-data`.
  - Neutral read-only copy: `/private/tmp/review-dataset-nova.QdQAOK`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement.
- Blind initial mean synthetic-confidence: `42.0`; deliberation mean: `48.75`.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `64`, synthetic-confidence `39`; deliberated to
    Inconclusive, confidence `68`, synthetic-confidence `50`.
  - Detection Engineer: Real, confidence `62`, synthetic-confidence `31`; deliberated to
    Inconclusive, confidence `64`, synthetic-confidence `43`.
  - Network Forensics: Inconclusive, confidence `66`, synthetic-confidence `42`; deliberated to
    Inconclusive, confidence `65`, synthetic-confidence `44`.
  - Host/EDR: Synthetic, confidence `68`, synthetic-confidence `56`; deliberated to Synthetic,
    confidence `72`, synthetic-confidence `58`.
- Panel consensus and prioritized findings:
  - The loop 38 protected event-log FILE ownership issue disappeared from the bounded probe and
    did not recur as a panel-leading finding.
  - The strongest remaining issue is a hard same-session causality contradiction on FILE-SRV-01:
    Windows Security 4688, Sysmon Event 1, and eCAR process evidence for `svc_mhsync` and LogonId
    `0xf88578c` visibly precede the same LogonId's 4624/eCAR session login.
  - Secondary targets include DNS TTL/cache texture, tidy dual-sensor Zeek overlap, unsupported
    high rsyslog queue-backlog messages, endpoint volume symmetry, SearchIndexer token semantics,
    and one SSH publickey format outlier.
- Selected loop 40 target:
  - P0 same-session causality for Windows remote-admin dependent evidence. Owning abstraction:
    Windows remote-admin/storyline command action bundles plus canonical session/bootstrap timing
    and source timing planning. Invariant: for a host and concrete LogonId, Security/Sysmon/eCAR
    process, file, module, and EDR activity must not appear before visible logon/session creation
    for that same LogonId. When remote-execution process materialization needs the session
    identity, the bundle/planner must place or delay the logon before dependent process evidence
    rather than relying on renderer order.

## Loop 40

- Family contract:
  - Owning abstraction: Windows remote logon/session source readiness, shared process source-time
    pre-planning, Windows Security flush ordering, and eCAR final lifecycle normalization.
  - Invariant: for a host and concrete non-service LogonId, Security 4688, Sysmon Event 1, and
    eCAR process/file/module/registry/service evidence must not render before the same session's
    visible 4624 or `USER_SESSION LOGIN`.
- Implemented changes:
  - Added a data-driven `windows.remote_logon_source_ready` timing profile.
  - Marked Windows Type 3 sessions with a deterministic source-ready floor after remote logon.
  - Made process source pre-planning clamp Windows Sysmon, Security, and eCAR process-create
    source times after a session's source-ready floor when a process carries that LogonId.
  - Reordered Windows Security final flush fixups so remote 4624-after-transport repair happens
    before same-session 4688/special-privilege/dependent/logoff repairs.
  - Added eCAR `logon_id` propagation to process-owned endpoint rows and a final eCAR
    same-session dependent-after-login normalizer.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_emitters.py -k "transport_shifted_logon_before_process_create or network_logon_shifted_after_matching_wfp_transport or process_create_shifted_after_visible_logon"`
  - `uv run pytest --no-cov tests/unit/test_source_timing.py -k "ecar_session_dependents_shift_after_visible_login or ecar_dependent_timestamp_follows_process_create or windows_security_process_create_tracks_sysmon_source_time"`
  - `uv run pytest --no-cov tests/unit/test_storyline_command_networks.py -k "process_preplan_waits_for_session_source_ready_time or activity_generator_preplans_process_create_time_before_threaded_dispatch"`
  - `uv run pytest --no-cov tests/unit/test_timing_profiles.py -k "timing_profiles_load_default_relationship"`
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py src/evidenceforge/generation/emitters/windows.py src/evidenceforge/generation/emitters/ecar.py tests/unit/test_emitters.py tests/unit/test_storyline_command_networks.py tests/unit/test_source_timing.py tests/unit/test_timing_profiles.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py src/evidenceforge/generation/emitters/windows.py src/evidenceforge/generation/emitters/ecar.py tests/unit/test_emitters.py tests/unit/test_storyline_command_networks.py tests/unit/test_source_timing.py tests/unit/test_timing_profiles.py`
  - `uv run eforge validate-config`
- Generated loop 40 output successfully.
- Automated eval passed at `95.21246194955461` over 91,972 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.60454827032505`
  - Causality: `88.6352542744711`
  - Timing: `95.76255656677782`
- Hard probe `hard_probe_windows_same_session_causality.json`:
  - Loop 39 Security process-before-logon rows: `1`; Sysmon process-before-security-logon rows:
    `1`; eCAR strict same-session dependent-before-login rows: `0` because loop 39 eCAR
    dependent rows did not carry source-native LogonIds.
  - Loop 40 Security process-before-logon rows: `0`; Sysmon process-before-security-logon rows:
    `0`; eCAR same-session dependent-before-login rows: `0`.
  - Loop 40 eCAR now includes `1,830` session-keyed dependent rows in the probe scope, making the
    invariant directly checkable.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-40/review-data`.
  - Neutral copy: `/private/tmp/review-dataset-nova.RoeXao`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
- Blind initial mean synthetic-confidence: `43.75`; deliberation was not triggered.
- Reviewer scores:
  - Threat Hunter: Inconclusive, confidence `68`, synthetic-confidence `52`.
  - Detection Engineer: Inconclusive, confidence `76`, synthetic-confidence `42`.
  - Network Forensics: Inconclusive, confidence `70`, synthetic-confidence `43`.
  - Host/EDR: Inconclusive, confidence `72`, synthetic-confidence `38`.
- Panel consensus and prioritized findings:
  - The Windows same-session causality contradiction disappeared from the bounded probe and was
    no longer a panel-leading issue.
  - The strongest remaining concrete issue is host-role/persona blur in ordinary SSH/admin
    activity: successful SSH sessions include broad user/source combinations, `root`/`admin`
    fallbacks, repeated service-health maintenance texture, and workstation/server source choices
    that make routine Linux administration look generator-selected rather than environment-owned.
  - Secondary targets include dual-sensor Zeek timestamp texture, eCAR FLOW actor/close semantics,
    proxy/web response-size texture, templated email text, and bash-history command texture.
- Selected loop 41 target:
  - P1 host-role/persona binding for baseline SSH/admin activity. Owning abstraction: world-model
    remote-admin user eligibility plus baseline SSH source selection. Invariant: successful
    ordinary baseline SSH sessions use scenario users whose persona, effective groups, and target
    role plausibly grant Linux admin access, and source from that user's own remote source host.
    Explicit storyline SSH and suspicious attacker activity remain out of scope for this baseline
    contract.

## Loop 41 Fix Target

- Selected family: host-role/persona binding for baseline SSH/admin activity.
- Owning abstraction: `WorldModel` SSH-admin roster plus the baseline SSH identity adapter.
- Invariant: ordinary baseline SSH sessions should not invent successful `root`/`admin` users or
  pair named admin users with unrelated sales/finance/executive workstations. The selected
  username and source host must come from one scenario user whose persona/groups and target role
  make Linux SSH administration plausible.
- Entry paths: baseline Linux remote-admin shell sessions and ambient baseline SSH session noise
  (`source="baseline_ssh_noise"`). Persona traffic already skips bare SSH/RDP and explicit
  storyline SSH remains owned by scenario intent and the SSH action bundle.
- Consumers: Linux `sshd` syslog, eCAR source-host `PROCESS`/`FLOW`, Zeek SSH connections,
  bash-history/session evidence, threat-hunting pivots, and host-role/source-family blind review.
- Layer rationale: the world model owns host roles, persona/group placement, and remote source
  systems before the SSH bundle renders source-native evidence. Emitter-side filtering would only
  hide symptoms and could leave syslog, eCAR, and Zeek disagreeing.
- Residual sibling risks: routine Linux administration still needs richer bastion/sudo/service
  automation modeling and maintenance command-palette diversity; this loop narrows successful
  baseline SSH identity/source selection first.
- Implemented changes:
  - Added `WorldModel.get_ssh_admin_users()` with persona, target-role, and effective group
    scoping for ordinary Linux SSH administration.
  - Added a baseline SSH identity adapter that returns a matched `(user, source_system)` pair and
    rejects unrelated workstation fallbacks.
  - Routed both modeled Linux remote-admin sessions and ambient `baseline_ssh_noise` through the
    shared identity adapter.
  - Removed successful ambient SSH `root`/`admin` fallback users from baseline noise.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_world_model.py tests/unit/test_baseline_canonical.py -k "ssh_admin_roster or plan_session_selects or baseline_ssh_identity or syslog_ssh_noise_is_server_scoped or disconnect_uses_same_duration"`
  - `uv run ruff check src/evidenceforge/generation/world_model.py src/evidenceforge/generation/engine/baseline.py tests/unit/test_world_model.py tests/unit/test_baseline_canonical.py`
  - `uv run ruff format --check src/evidenceforge/generation/world_model.py src/evidenceforge/generation/engine/baseline.py tests/unit/test_world_model.py tests/unit/test_baseline_canonical.py`
- Generated loop 41 output successfully.
- Automated eval passed at `95.33415700770531` over 89,132 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.99732224519799`
  - Causality: `89.49234376024657`
  - Timing: `96.05870253172087`
- Hard probe `hard_probe_baseline_ssh_role_source_binding.json`:
  - Loop 40 accepted SSH sessions: `121`; generic privileged users: `15`; ordinary named
    successful users: `4`; named-user unowned workstation sources: `25`.
  - Loop 41 accepted SSH sessions: `102`; generic privileged users: `6`; ordinary named
    successful users: `0`; named-user unowned workstation sources: `0`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-41/review-data`.
  - Neutral copy: `/private/tmp/review-dataset-nova.6KwWMh`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement.
- Blind initial mean synthetic-confidence: `61.5`; deliberation mean: `70.0`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `82`, synthetic-confidence `72`; deliberated to
    Synthetic, confidence `86`, synthetic-confidence `76`.
  - Detection Engineer: Inconclusive, confidence `62`, synthetic-confidence `44`; deliberated to
    Synthetic, confidence `70`, synthetic-confidence `64`.
  - Network Forensics: Synthetic, confidence `72`, synthetic-confidence `68`; deliberated to
    Synthetic, confidence `76`, synthetic-confidence `70`.
  - Host/EDR: Synthetic, confidence `64`, synthetic-confidence `62`; deliberated to Synthetic,
    confidence `72`, synthetic-confidence `70`.
- Panel consensus and prioritized findings:
  - The loop 40 SSH identity/source issue improved in the bounded probe and did not recur as the
    leading host-role finding.
  - The strongest remaining hard contradiction is Linux eCAR process/session lifecycle: apt and
    service-health helper processes can inherit stale SSH `logon_id`/`session_id` or `sshd` parent
    state after the visible SSH logout.
  - Network also found a proxy CONNECT contract gap: successful CONNECT rows for an internal mail
    host can lack the corresponding proxy-origin flow and have DNS ordering after the 200 response.
- Selected loop 42 target:
  - P0 Linux eCAR post-logout process/session parentage. Owning abstraction: canonical Linux
    process/session ownership and explicit-proxy package/server helper process selection.
    Invariant: Linux endpoint PROCESS/FLOW rows for background package-manager or service-health
    helper activity must not carry a human SSH session after that session's visible logout, and
    must not use a stale session-bound `sshd`/shell process as parent. Workstation browser/proxy
    traffic remains user-session-owned.

## Loop 42 Fix Target

- Selected family: Linux eCAR post-logout process/session parentage for package-manager and
  service-health proxy helpers.
- Owning abstraction: process execution bundle compatibility path plus explicit proxy client
  owner selection and Linux parent repair.
- Invariant: Linux background proxy/package helper processes must be system/service-owned when
  they run outside a live human session. If a caller passes a stale SSH session ID or parent PID,
  process state must drop the ended human session and choose a live system/service parent before
  eCAR PROCESS/FLOW contexts are built.
- Entry paths: explicit proxy client-to-proxy attribution for apt/dnf/server service-health user
  agents; direct `generate_process()` callers for apt method helpers; parent selection/history and
  Linux fallback parent repair.
- Consumers: eCAR PROCESS and FLOW rows, syslog SSH session timelines, Zeek/proxy correlation,
  Host/EDR and Network blind review.
- Layer rationale: the generator owns the canonical process owner, logon ID, parent PID, and
  source process context before renderers see the event. Fixing only eCAR output would still leave
  connection attribution and sibling process state inconsistent.
- Implemented changes:
  - Routed Linux apt/dnf package-manager helpers and server-like service-health/integration-worker
    proxy helpers through the existing system-owned connection process path before selecting a
    user session.
  - Added Linux background-helper identity coercion for direct process creation after a session
    has ended, mapping apt/service-health helpers to `root` or service ownership.
  - Hardened Linux parent repair/history/fallback so ended-session `sshd`/shell PIDs are not
    reused as child parents after visible logout; system fallbacks now prefer `systemd`/`init`
    rather than stale `sshd` or `bash`.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_explicit_proxy.py -k "linux_package_proxy or background_helper_process"`
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_explicit_proxy.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_explicit_proxy.py`
- First loop 42 generation attempt exposed a Linux fallback bug introduced by this loop:
  `_select_parent_pid()` referenced `effective_time` from the Windows-only branch. Fixed by
  hoisting `effective_time` before OS-specific parent selection and reran focused verification.
- Generated loop 42 output successfully after the fallback fix.
- Automated eval passed at `95.18501294378603` over 91,495 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `94.23485831323002`
  - Causality: `89.83907909805315`
  - Timing: `95.83264295482621`
- Hard probe `hard_probe_linux_ecar_post_logout_process_ownership.json`:
  - Loop 41 Linux helper PROCESS rows: `62`; human-session-bound helpers: `62`; post-logout
    helpers: `30`; stale `sshd`/shell parent helpers: `44`.
  - Loop 42 Linux helper PROCESS rows: `94`; human-session-bound helpers: `0`; post-logout
    helpers: `0`; stale `sshd`/shell parent helpers: `0`.
  - Overall probe result: `passed`.
- Blind review:
  - Review bundle: `scenarios/iteration-test-expanded/blind-test/loop-42/review-data`.
  - Neutral copy: `/private/tmp/review-dataset-nova.ldYEPk`.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
  - Deliberation was triggered by verdict disagreement.
- Blind initial mean synthetic-confidence: `42.0`; deliberation mean: `43.5`.
- Reviewer scores:
  - Threat Hunter: Synthetic, confidence `62`, synthetic-confidence `52`; deliberated to
    Synthetic, confidence `60`, synthetic-confidence `50`.
  - Detection Engineer: Inconclusive, confidence `64`, synthetic-confidence `44`; deliberated to
    Inconclusive, confidence `66`, synthetic-confidence `46`.
  - Network Forensics: Inconclusive, confidence `68`, synthetic-confidence `38`; deliberated to
    Inconclusive, confidence `69`, synthetic-confidence `40`.
  - Host/EDR: Inconclusive, confidence `62`, synthetic-confidence `34`; deliberated to
    Inconclusive, confidence `64`, synthetic-confidence `38`.
- Panel consensus and prioritized findings:
  - The Linux eCAR helper post-logout/session-parent defect disappeared from the bounded probe
    and from the panel-leading findings.
  - The strongest remaining hard contract gap is Kerberos lifecycle completeness for newly-created
    account `svc_mhsync`: visible account creation and Domain Admins membership precede a later
    CIFS `4769`, but no visible `4768` AS/TGT event or matching client-to-DC Kerberos flow
    supports the service ticket.
  - Secondary targets include eCAR/Sysmon Windows session ID mismatches, eCAR FLOW `tid` without
    `pid`, one RDP endpoint correlation gap, external IP distribution texture, sparse NTP, and
    parser companion texture.
- Selected loop 43 target:
  - P0 Kerberos lifecycle completeness for newly-created domain accounts. Owning abstraction:
    account lifecycle action bundles plus Kerberos authentication/ticket causal expansion and
    network-connection evidence. Invariant: when a domain account is created during the visible
    window and later receives a visible service ticket, generation must emit source-native TGT/AS
    evidence and matching Kerberos transport evidence before the TGS event, using the same
    client/DC tuple where visibility implies it should exist.

### Loop 43 implementation notes

- Root cause: `_should_emit_visible_kerberos_tgt()` allowed probabilistic "pre-window cached TGT"
  suppression for principals that had been visibly created by an `account_created` bundle earlier
  in the dataset. Direct service-ticket paths could therefore emit a 4769 for a newly-created
  account without a visible 4768 or matching KDC transport flow.
- Implemented changes:
  - Track visible account creation times by normalized Kerberos principal in
    `ActivityGenerator`.
  - Invalidate any impossible pre-create TGT cache entries when an account is visibly created.
  - Force a visible fresh TGT decision when a no-cache principal was created inside the visible
    window.
  - Teach the Kerberos service-ticket bundle to create the first matching client-to-DC KDC flow
    for visible-created accounts, reusing the same source IP/DC/source-port tuple as the 4769 and
    suppressing duplicate connection-driven machine-account audit repair via the existing recent
    audit cache.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "newly_created_account_service_ticket or generate_connection_can_use_cached_tgt or generate_connection_reuses_recent_kdc_audit"`
  - `uv run pytest --no-cov tests/unit/test_dc_kerberos_logon.py tests/unit/test_phase5_system_traffic.py -k "kerberos"`
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py`
- Generated loop 43 output successfully.
- Automated eval passed at `95.38307498053253` over 91,467 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.03540940150783`
  - Causality: `89.83907909805315`
  - Timing: `95.8222642782114`
- Hard probe `hard_probe_new_account_kerberos_lifecycle.json`:
  - Loop 42: account creation count `1`, TGT count `0`, TGS count `1`, matching
    client-to-DC KDC flow before TGS count `0`; result `failed` as expected.
  - Loop 43: account creation count `1`, TGT count `1`, TGS count `1`, matching
    client-to-DC KDC flow before TGS count `1`; result `passed`.
  - Evidence: loop 43 has `svc_mhsync` 4768 at `2024-03-18T17:01:29.2107747Z`
    and 4769 at `2024-03-18T17:01:29.3354210Z`, both from `10.10.1.35:55466`;
    Zeek `conn.json` includes `10.10.1.35:55466 -> 10.10.2.10:88` at
    `1710781288.405664`, before the 4769.
- Blind review bundle:
  - Durable bundle: `scenarios/iteration-test-expanded/blind-test/loop-43/review-data`
    with 116 files.
  - Neutral copy: `/private/tmp/review-dataset-aurora.qBAdAp` with 116 files.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.

## Loop 44 Fix Target

- Selected family: eCAR session lifecycle timing for visible workstation sessions.
- Owning abstraction: eCAR source-observation lifecycle normalization, after process/file/flow
  source-native timestamp repair has produced the final visible endpoint rows.
- Invariant: after an eCAR `USER_SESSION LOGOUT` for a host/logon ID, no later eCAR endpoint row
  should carry that same visible session identity. The logout row is the source-visible boundary
  for the endpoint session, so it must clear same-logon `PROCESS`, `FILE`, `MODULE`, `REGISTRY`,
  `SERVICE`, `THREAD`, and `FLOW` observations that remain visible for that session.
- Entry paths: interactive workstation logoffs, source-timed process/file/module/process-terminate
  evidence, and final eCAR writer flush normalization.
- Consumers: eCAR `USER_SESSION` lifecycle, Windows Security/Sysmon correlation pivots, blind
  Host/EDR and Threat Hunter review, and temporal/casual eval checks.
- Layer rationale: Windows Security already performs a final render-time 4634 delay after
  same-session rendered dependents. eCAR needs the equivalent source-local lifecycle contract
  because its own source timing and process termination repair can move dependent rows after the
  canonical logoff request. Fixing only one generating call path would leave other visible eCAR
  dependents able to cross the logout boundary.
- Implemented changes:
  - Added final eCAR writer normalization that shifts `USER_SESSION/LOGOUT` after same-logon
    visible endpoint dependents (`PROCESS`, `FILE`, `MODULE`, `REGISTRY`, `SERVICE`, `THREAD`,
    and `FLOW`) after the existing process/reference/termination ordering repairs.
  - Split eCAR logout timing from generic eCAR session timing via `source.ecar_session_logout`
    and `source.ecar_session_logout_after_dependents` timing profiles so endpoint logout
    observations trail Windows Security's rendered 4634 jitter instead of racing it.
  - Added a focused eCAR chronology regression covering a logout before same-session
    process/file/flow dependents.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_ecar_spec_compliance.py -k "logout_shifted_after"`
  - `uv run pytest --no-cov tests/unit/test_ecar_spec_compliance.py tests/unit/test_source_timing.py -k "ecar or USER_SESSION or user_session or logout or logoff"`
  - `uv run pytest --no-cov tests/unit/test_timing_profiles.py tests/unit/test_validate_config.py -k "timing_profiles or timing"`
  - `uv run ruff check src/evidenceforge/generation/emitters/ecar.py tests/unit/test_ecar_spec_compliance.py`
  - `uv run ruff format --check src/evidenceforge/generation/emitters/ecar.py tests/unit/test_ecar_spec_compliance.py`
- Generated loop 44 output successfully.
- Automated eval passed at `95.38307498053253` over 91,467 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `95.03540940150783`
  - Causality: `89.83907909805315`
  - Timing: `95.8222642782114`
- Hard probe `hard_probe_ecar_logout_before_windows_session_activity.json`:
  - Loop 43: failed for two sampled workstation sessions (`WS-AJOHNSON-01` and `WS-MCHEN-01`)
    with later eCAR and Windows Security activity after eCAR logout.
  - Loop 44 before the widened logout timing: same-logon eCAR crossings were eliminated, but
    thirteen narrow Windows-4634-only crossings remained (27-355 ms after eCAR logout).
  - Final loop 44: `passed` with zero later eCAR, Windows Security, or Sysmon records after the
    first eCAR logout for the same host/logon ID.
- Blind review bundle:
  - Durable bundle: `scenarios/iteration-test-expanded/blind-test/loop-44/review-data`
    with 116 files.
  - Neutral copy: `/private/tmp/review-dataset-aurora.o5203X` with 116 files.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
- Blind review:
  - Deliberation was triggered by verdict disagreement and synthetic-confidence spread.
  - Initial mean synthetic-confidence: `44.25`; deliberated mean: `51.75`.
  - Reviewer scores:
    - Threat Hunter: Inconclusive, confidence `64`, synthetic-confidence `34`; deliberated to
      Inconclusive, confidence `66`, synthetic-confidence `44`.
    - Detection Engineer: Inconclusive, confidence `66`, synthetic-confidence `32`; deliberated
      to Inconclusive, confidence `70`, synthetic-confidence `48`.
    - Network Forensics: Inconclusive, confidence `64`, synthetic-confidence `43`; deliberated
      to Inconclusive, confidence `64`, synthetic-confidence `45`.
    - Host/EDR: Synthetic, confidence `72`, synthetic-confidence `68`; deliberated to Synthetic,
      confidence `76`, synthetic-confidence `70`.
  - Panel consensus and prioritized findings:
    - The eCAR logout/session-lifecycle contradiction from loop 43 disappeared from the hard
      probe and did not recur as a leading finding.
    - The strongest remaining hard contract gap is eCAR remote-thread prerequisite ordering:
      `WS-AJOHNSON-01` renders `THREAD/REMOTE_CREATE` into `lsass.exe` before the same actor's
      `PROCESS/OPEN` of that same target, while Sysmon orders process-open before remote-thread
      creation.
    - Secondary targets include Windows source-side SSH process identity reuse across many TCP/22
      transports, tight dual-sensor Zeek timestamp deltas, narrow IDS variety, sparse NTP, and
      repeated web/proxy asset texture.
- Hard probe `hard_probe_ecar_remote_thread_before_process_open.json`:
  - Loop 44: failed with one result. eCAR on `WS-AJOHNSON-01` records
    `THREAD/REMOTE_CREATE` at `2024-03-18T15:45:34.363Z` before `PROCESS/OPEN` of the same
    `lsass.exe` target at `2024-03-18T15:45:35.004Z`.
- Selected loop 45 target:
  - P0 eCAR remote-thread prerequisite ordering. Owning abstraction: eCAR endpoint source-order
    normalization / canonical process-access and remote-thread rendering. Invariant: for the same
    source process and target process, eCAR `PROCESS/OPEN` must render before
    `THREAD/REMOTE_CREATE`, and final eCAR normalization must preserve the order.

## Loop 45 Fix Target

- Selected family: eCAR remote-thread prerequisite ordering.
- Owning abstraction: final eCAR endpoint source-order normalization for process-access and
  remote-thread evidence, with canonical process-access/remote-thread contexts as the source of
  target identity.
- Invariant: for a same source process and target process, eCAR `PROCESS/OPEN` must render before
  `THREAD/REMOTE_CREATE`. If source-native timestamp jitter or final writer repairs would invert
  the relationship, eCAR must move the remote-thread row after the matching process-open row, not
  leave the prerequisite inverted.
- Entry paths: remote thread injection/LSASS access storyline activity, eCAR `PROCESS/OPEN`,
  eCAR `THREAD/REMOTE_CREATE`, and final writer ordering repairs.
- Consumers: Host/EDR blind review, eCAR source-native process graph, Sysmon/eCAR cross-source
  correlation, and attack-path reconstruction.
- Layer rationale: Sysmon already shows the canonical prerequisite order correctly. The defect is
  introduced by eCAR source timing/final ordering, so patching a single attack generator call would
  leave other remote-thread rows vulnerable to the same inversion.

### Loop 45 implementation notes

- Initial root cause: eCAR final sort priority placed `THREAD/REMOTE_CREATE` ahead of
  `PROCESS/OPEN`, and the existing final normalizer only ensured both rows occurred after
  `PROCESS/CREATE`. Source-native eCAR jitter could therefore invert the process-open prerequisite
  even when Sysmon rendered Event ID 10 before Event ID 8.
- Sibling root cause discovered by hard probe: baseline CreateRemoteThread noise bypassed the
  storyline-only LSASS causal expansion path, so one Defender-style `THREAD/REMOTE_CREATE` had no
  matching eCAR `PROCESS/OPEN` at all.
- Implemented changes:
  - Added final eCAR normalization that matches `PROCESS/OPEN` and `THREAD/REMOTE_CREATE` by
    host, source actor/process, and target process UUID/PID, then shifts the remote-thread row
    after the matching process-open prerequisite when final eCAR timing is inverted.
  - Changed eCAR sort priority so same-timestamp `PROCESS/OPEN` rows order before
    `THREAD/REMOTE_CREATE`.
  - Added `source.ecar_remote_thread_after_process_open` timing profile for deterministic repair
    gaps.
  - Generalized `ProcessAccessAfterRemoteThread` causal expansion from LSASS-only to all
    remote-thread activity with known source/target PID and target image. LSASS keeps the stronger
    `0x1FFFFF` access mask; non-LSASS targets use lower-friction `0x1010`.
  - Moved CreateRemoteThread prerequisite expansion to the public
    `ActivityGenerator.generate_create_remote_thread()` entrypoint so storyline and baseline
    callers share the same process-open prerequisite contract.
  - Removed the old storyline-only post-remote-thread LSASS expansion to avoid duplicate
    process-access companions.
  - Added `process.remote_thread_process_access` timing profile and gave remote-thread creation a
    slightly later near-start process clamp than its process-access prerequisite.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_ecar_spec_compliance.py -k "remote_thread or process_open"`
  - `uv run pytest --no-cov tests/unit/test_ecar_thread_process_access.py`
  - `uv run pytest --no-cov tests/unit/test_causal_engine.py::TestProcessAccessAfterRemoteThread`
  - `uv run pytest --no-cov tests/unit/test_activity.py -k "create_remote_thread or process_access"`
  - `uv run pytest --no-cov tests/unit/test_logonid_scoping.py -k "create_remote_thread"`
  - `uv run pytest --no-cov tests/unit/test_timing_profiles.py tests/unit/test_validate_config.py -k "timing_profiles or timing"`
  - `uv run ruff check src/evidenceforge/generation/emitters/ecar.py src/evidenceforge/generation/causal/rules.py src/evidenceforge/generation/activity/generator.py src/evidenceforge/generation/engine/storyline.py tests/unit/test_ecar_spec_compliance.py tests/unit/test_timing_profiles.py tests/unit/test_causal_engine.py tests/unit/test_activity.py tests/unit/test_logonid_scoping.py`
  - `uv run ruff format --check src/evidenceforge/generation/emitters/ecar.py src/evidenceforge/generation/causal/rules.py src/evidenceforge/generation/activity/generator.py src/evidenceforge/generation/engine/storyline.py tests/unit/test_ecar_spec_compliance.py tests/unit/test_timing_profiles.py tests/unit/test_causal_engine.py tests/unit/test_activity.py tests/unit/test_logonid_scoping.py`
- Generated loop 45 output successfully.
- Automated eval passed at `95.12991448713123` over 94,588 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `93.76561452875072`
  - Causality: `90.58055274688238`
  - Timing: `95.21686334111476`
- Hard probe `hard_probe_ecar_remote_thread_before_process_open.json`:
  - Loop 44: failed with one eCAR inversion for the `lsass.exe` target.
  - Loop 45 pre-generalized-prerequisite check exposed one sibling missing process-open companion
    for Defender-style remote-thread activity targeting `RuntimeBroker.exe`.
  - Final loop 45: `passed` with `7` `THREAD/REMOTE_CREATE` rows, `577` `PROCESS/OPEN` rows,
    and zero missing or inverted same-source/same-target process-open prerequisites.
- Blind review bundle:
  - Durable bundle: `scenarios/iteration-test-expanded/blind-test/loop-45/review-data`
    with 116 files.
  - Neutral copy: `/private/tmp/review-dataset-cypress.UzE4v4` with 116 files.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
- Blind review:
  - Deliberation was triggered by verdict disagreement and synthetic-confidence spread.
  - Initial mean synthetic-confidence: `54.75`; deliberated mean: `65.75`.
  - Reviewer scores:
    - Threat Hunter: Inconclusive, confidence `64`, synthetic-confidence `43`; deliberated to
      Synthetic, confidence `70`, synthetic-confidence `62`.
    - Detection Engineer: Inconclusive, confidence `60`, synthetic-confidence `40`; deliberated
      to Synthetic, confidence `68`, synthetic-confidence `60`.
    - Network Forensics: Synthetic, confidence `76`, synthetic-confidence `72`; deliberated to
      Synthetic, confidence `78`, synthetic-confidence `74`.
    - Host/EDR: Synthetic, confidence `68`, synthetic-confidence `64`; deliberated to Synthetic,
      confidence `72`, synthetic-confidence `67`.
  - Panel consensus and prioritized findings:
    - The loop 44 eCAR remote-thread issue was fixed by hard probe and did not recur.
    - Highest-impact next target: large proxied-flow byte accounting. ASA and Zeek core agree
      closely, while Zeek DMZ diverges from the same 5-tuples by hundreds of KB to nearly 5 MB
      beyond `missed_bytes`.
    - Secondary targets include Sysmon Event ID 7 module metadata version mismatches, one missing
      Zeek NTP companion row, tight SSH auth timing, Linux local desktop session companion gaps,
      proxy host/path texture, and email/DNS tunnel texture.
- Hard probe `hard_probe_large_proxy_flow_byte_accounting.json`:
  - Loop 45: failed with `3` large inside-to-proxy byte-accounting mismatches.
  - Sibling examples:
    - `10.10.2.10:51008 -> 10.10.3.20:8080`: ASA `155898680`, Zeek core IP bytes
      `155898598`, Zeek DMZ IP bytes `156689946`, allowed delta `70092`.
    - `10.10.2.10:53062 -> 10.10.3.20:8080`: ASA `112177742`, Zeek core IP bytes
      `112177677`, Zeek DMZ IP bytes `112298201`, allowed delta `65536`.
    - `10.10.1.35:50872 -> 10.10.3.20:8080`: ASA `328858087`, Zeek core IP bytes
      `328858022`, Zeek DMZ IP bytes `333832406`, allowed delta `65536`.

## Loop 46 Fix Target

- Selected family: large proxy flow byte accounting across ASA, Zeek core, Zeek DMZ, and proxy.
- Owning abstraction: canonical network/proxy connection accounting and sensor-specific
  observation rendering.
- Invariant: for the same visible client-to-proxy 5-tuple, ASA teardown bytes, Zeek core IP-byte
  totals, Zeek DMZ IP-byte totals, and proxy payload byte fields must derive from one accounting
  model. Any sensor differences must be explained by modeled `missed_bytes`, packet counts, or
  source-specific framing.
- Entry paths: explicit-proxy transaction bundle, network-connection action bundle, large HTTP
  downloads/uploads, Zeek core and DMZ sensor rendering, ASA teardown rendering, and proxy access
  logging.
- Consumers: Network Forensics review, large-transfer hard probes, proxy/Zeek/ASA pivots, and
  future ingestion validation.
- Layer rationale: the contradiction appears across multiple rendered sources for the same
  connection tuple. Fixing one emitter would leave sibling sources disagreeing; the shared
  canonical accounting or observation metadata must own the payload/IP/packet relationship before
  renderers serialize it.

### Loop 46 implementation notes

- Root cause: Zeek multi-sensor rendering applied percentage-based lossy observation jitter to
  secondary sensor `orig_bytes`, `resp_bytes`, `orig_ip_bytes`, and `resp_ip_bytes`. For small
  rows this looked like plausible tap texture, but for 100 MB+ client-to-proxy transfers it scaled
  into hundreds of KB or MB while `missed_bytes` only claimed tens of KB or less.
- Implemented changes:
  - Added bounded bulk-TCP accounting detection in `zeek_base.py` for TCP flows with at least
    10 MB of payload/IP-byte accounting and no more than 65,536 declared missed bytes.
  - Routed those rows through bounded sensor texture: preserve canonical payload bytes, apply only
    tiny packetization/IP-byte deltas plus bounded duration jitter, then re-enforce HTTP body and
    IP-byte invariants.
  - Left ordinary small lossy rows on the existing per-sensor jitter path so low-volume capture
    texture still varies across taps.
  - Added a regression test that models a large inside-to-proxy TCP transfer and asserts secondary
    Zeek sensor totals remain within the same missed-byte/framing budget used by the hard probe.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_zeek_multiplex.py -k "bulk_proxy_flow or lossy_conn_observation or lossless_conn_observation or sensor_conn_metrics"`
  - `uv run pytest --no-cov tests/unit/test_zeek_multiplex.py`
  - `uv run ruff check src/evidenceforge/generation/emitters/zeek_base.py tests/unit/test_zeek_multiplex.py`
  - `uv run ruff format --check src/evidenceforge/generation/emitters/zeek_base.py tests/unit/test_zeek_multiplex.py`
- Generated loop 46 output successfully.
- Automated eval passed at `95.12991448713123` over 94,588 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `93.76561452875072`
  - Causality: `90.58055274688238`
  - Timing: `95.21686334111476`
- Hard probe `hard_probe_large_proxy_flow_byte_accounting.json`:
  - Loop 45: failed with `3` large inside-to-proxy byte-accounting mismatches.
  - Loop 46: `passed` with `854` inside-to-proxy teardowns checked, `3` large transfers checked,
    and zero ASA/Zeek core/Zeek DMZ byte-accounting mismatches.
- Blind review bundle:
  - Durable bundle: `scenarios/iteration-test-expanded/blind-test/loop-46/review-data`
    with 116 files.
  - Neutral copy: `/private/tmp/review-dataset-cypress.JoAlV1` with 116 files.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
- Blind review:
  - Deliberation was triggered by verdict disagreement and synthetic-confidence spread.
  - Initial mean synthetic-confidence: `50.25`; deliberated mean: `58.0`.
  - Reviewer scores:
    - Threat Hunter: Inconclusive, confidence `63`, synthetic-confidence `34`; deliberated to
      Inconclusive, confidence `64`, synthetic-confidence `45`.
    - Detection Engineer: Inconclusive, confidence `61`, synthetic-confidence `43`; deliberated to
      Inconclusive, confidence `63`, synthetic-confidence `52`.
    - Network Forensics: Inconclusive, confidence `60`, synthetic-confidence `56`; deliberated to
      Synthetic, confidence `66`, synthetic-confidence `65`.
    - Host/EDR: Synthetic, confidence `73`, synthetic-confidence `68`; deliberated to Synthetic,
      confidence `75`, synthetic-confidence `70`.
  - Panel consensus and prioritized findings:
    - The loop 45 large proxy flow byte-accounting issue was fixed; the 17:24 large transfer now
      pivots consistently across proxy, Zeek, and ASA.
    - Highest-impact next target: Linux SSH `systemd-logind` removal lifecycle. Host/EDR found 106
      SSH sessions where PAM opened, `systemd-logind` created a session ID, and PAM closed, but no
      matching `Removed session <same_id>` appeared.
    - Secondary targets include proxy DNS/SNI/origin consistency for `mail-fin.meridianhcs.com`,
      Zeek NTP conn-to-parser fan-out and stratum/ref_id semantics, email/SSH-noise texture, and
      eCAR field texture.

## Loop 47 Fix Target

- Selected family: Linux SSH `systemd-logind` removal lifecycle.
- Owning abstraction: SSH action bundle source-native session lifecycle.
- Invariant: every modeled in-window SSH session that emits `systemd-logind New session <id>` and
  later emits `pam_unix(sshd:session): session closed` must also emit
  `systemd-logind Removed session <same_id>` after the PAM close. If source observation drops the
  lifecycle, it should drop the same-source lifecycle coherently rather than orphaning the removal.
- Entry paths: storyline SSH sessions, baseline remote-admin SSH sessions, SCP-backed receiver SSH
  sessions routed through the SSH bundle, Linux syslog rendering, and final syslog logind ID
  normalization.
- Consumers: Host/EDR blind review, Linux syslog session reconstruction, bash-history/session
  correlation, eCAR login/logout pairing, and SSH hard probes.
- Layer rationale: the SSH bundle already owns connection, accepted auth, PAM open, logind New
  session, PAM close, and session close timing. Emitting removal in a renderer or broad syslog
  repair would infer lifecycle facts from strings after the source of truth was available.

### Loop 47 implementation notes

- Root cause: `SshSessionActionBundle._dispatch_linux_session_close_lifecycle()` emitted the SSH
  PAM close and endpoint logout, then terminated the tuple-scoped `sshd` process, but never emitted
  the matching `systemd-logind Removed session <same_id>` row. Ambient baseline logind noise did
  emit unrelated remove rows, making the modeled SSH session IDs look orphaned. After the bundle
  fix, a hard-probe run found the compatibility `generate_logoff()` path still orphaned some
  Linux SSH session IDs, and one regenerated row had the removal rendered 81 ms before the PAM
  close because `sshd` and `systemd-logind` syslog rows had independent observation-delay
  identities.
- Implemented changes:
  - Added a deterministic source-native logind removal timestamp after PAM close.
  - Emitted a separate `systemd-logind` syslog row using the same logind PID lookup and the same
    `auth_state.logind_session_id` allocated for the New-session row.
  - Added the same removal emission to the compatibility `ActivityGenerator.generate_logoff()`
    path for Linux SSH sessions.
  - Added a syslog observation-group key for SSH PAM/logind rows carrying the same auth/session
    identity, then attached that auth context to logind New/Removed rows so collection delay cannot
    invert source-local session lifecycle order.
  - Extended the SSH action-bundle close regression test to require `Removed session <same_id>`
    after the PAM close.
  - Added an observation-policy regression test proving SSH PAM close and logind removal rows for
    the same session receive the same syslog delay decision.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_dispatcher.py -k "ssh_success_syslog_lifecycle_rows_share_observation_delay"`
  - `uv run pytest --no-cov tests/unit/test_zeek_activity_contexts.py -k "ssh_session_bundle_renders_publickey_and_optional_close or records_logind_session_id or logind_uses_seeded"`
  - `uv run pytest --no-cov tests/unit/test_phase5_logoff.py -k "ssh_logoff or linux_type10"`
  - `uv run ruff check src/evidenceforge/events/observation.py src/evidenceforge/generation/actions/ssh_session.py src/evidenceforge/generation/activity/generator.py tests/unit/test_dispatcher.py tests/unit/test_zeek_activity_contexts.py tests/unit/test_phase5_logoff.py`
  - `uv run ruff format --check src/evidenceforge/events/observation.py src/evidenceforge/generation/actions/ssh_session.py src/evidenceforge/generation/activity/generator.py tests/unit/test_dispatcher.py tests/unit/test_zeek_activity_contexts.py tests/unit/test_phase5_logoff.py`

## Loop 49 Fix Target

- Selected family: canonical endpoint lifecycle/session ownership for process termination.
- Owning abstraction: canonical process/session state plus Linux parent validity.
- Invariant: process termination evidence must preserve the original process principal/logon
  identity from `RunningProcess`; it must not inherit a newer active session at termination time.
  Linux SSH login shell creation must treat a tuple-scoped privileged `sshd: <user> [priv]`
  process as a valid native parent even when that parent is root/system-owned.
- Entry paths: baseline system processes, connection-owned foreground terminations, stale
  process cleanup, storyline process termination, SSH session bootstrap, eCAR rendering, and
  process/source timing repair.
- Consumers: eCAR process lifecycle rows, host/EDR review, threat-hunter process/session pivots,
  process object graph tests, and process lifecycle hard probes.
- Layer rationale: the loop 48 finding came from a state/rendering mismatch. Linux system process
  create rows rendered `0x3e7`, but the stored `RunningProcess` lacked that logon ID. Later generic
  termination resolved `root` against the current SSH session and rendered a different logon/session.

### Loop 49 implementation notes

- Root cause: `generate_system_process()` rendered system logon IDs but called
  `StateManager.create_process()` without `logon_id`, leaving root-owned Linux system processes
  with empty canonical process ownership. Generic termination then used the caller/current session
  context. A first regeneration also exposed a sibling parent-selection issue: a root-owned
  privileged SSH child process was rejected as the parent of the user login shell, causing recursive
  `ensure_linux_session_shell()` calls during SSH bootstrap.
- Implemented changes:
  - Passed the system logon ID into canonical process state for system-generated processes.
  - Allowed live `/usr/sbin/sshd` privileged children with `sshd: <user> [priv]` command lines to
    parent Linux SSH user shells despite the root/system logon ID.
  - Added regression coverage for Linux root system process termination during a later root SSH
    session and for SSH login-shell parent selection.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_edr_object_graph.py -k "linux_system_process_termination_preserves_original_logon or process_create_terminate_share_object_id or late_termination"`
  - `uv run pytest --no-cov tests/unit/test_spawn_rules.py -k "ssh_login_shell_keeps_privileged_sshd_parent or ssh_user_process_prefers_matching_session_shell or linux_generate_process_replaces_untracked_parent_pid"`
  - `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_edr_object_graph.py tests/unit/test_spawn_rules.py`
  - `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_edr_object_graph.py tests/unit/test_spawn_rules.py`
- Generated loop 49 output successfully after the SSH parent-validity fix.
- Automated eval passed at `95.17991535282289` over 94,702 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `93.9656145287507`
  - Causality: `90.58055274688238`
  - Timing: `95.21686766957305`
- Hard probe `hard_probe_process_termination_ownership.json`:
  - Loop 48 comparison: failed with `257` process termination ownership mismatches across `1,324`
    matched terminations.
  - Loop 49: `passed` with `1,324` matched terminations checked and `0` ownership mismatches.
  - Probe semantics: principal/logon ID drift always fails; session ID conflicts fail when both
    create and terminate rows carry non-empty session IDs. Termination-side session ID enrichment
    is not counted as ownership drift when the create row lacks `session_id` and both rows share
    the same logon ID.
- Blind review bundle:
  - Durable bundle: `scenarios/iteration-test-expanded/blind-test/loop-49/review-data`
    with 86 log evidence files.
  - Neutral copy: `/private/tmp/review-dataset-cypress.eNJQ6J` with 86 log evidence files.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`, `ARTIFACTS_MANIFEST.json`, and
    `OUTPUT_TARGET.txt`.
- Blind review:
  - Deliberation was triggered by verdict disagreement and a synthetic-confidence spread above 30.
  - Initial mean synthetic-confidence: `43.5`; deliberated mean: `49.5`
    (`Mixed/Inconclusive`).
  - Reviewer scores:
    - Threat Hunter: Real, confidence `68`, synthetic-confidence `28`; deliberated to
      Inconclusive, confidence `66`, synthetic-confidence `38`.
    - Detection Engineer: Inconclusive, confidence `76`, synthetic-confidence `44`; deliberated
      to Inconclusive, confidence `78`, synthetic-confidence `52`.
    - Network Forensics: Inconclusive, confidence `64`, synthetic-confidence `34`; deliberated
      to Inconclusive, confidence `66`, synthetic-confidence `38`.
    - Host/EDR: Synthetic, confidence `74`, synthetic-confidence `68`; deliberated to Synthetic,
      confidence `76`, synthetic-confidence `70`.
  - Panel consensus and prioritized findings:
    - Loop 48's process-termination ownership defect is fixed by hard probe; the blind panel did
      not re-identify that family as the top issue.
    - Highest-impact future target: singleton lifecycle constraints for long-running Windows
      service agents such as `PanGPS.exe` and `ZSAService.exe`, which overlapped on multiple hosts
      without prior visible termination.
    - Secondary targets: stable Sysmon `LogonGuid` per `(host, LogonId)`, source-native Windows
      4672 privilege lists, Linux local session-open anchoring, static web/proxy object byte
      stability, proxy CONNECT visibility contracts, and host-specific WFP device-volume mappings.
- Generated loop 48 output successfully.
- Automated eval passed at `95.17991488181465` over 94,702 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `93.9656145287507`
  - Causality: `90.58055274688238`
  - Timing: `95.21686531453192`
- Hard probe `hard_probe_ssh_auth_lifecycle_order.json`:
  - Loop 47 comparison: failed with `19` ordering inversions across `116` complete successful
    SSH sessions.
  - Loop 48: `passed` with `116` attempts containing Accepted+PAM checked, `116` complete
    successful SSH sessions checked, and zero source-native ordering inversions.
- Regression hard probe `hard_probe_ssh_logind_removed_session.json`:
  - Loop 48: `passed` with `109` closed SSH sessions checked, `116` sessions with logind New
    rows checked, and zero missing or inverted `Removed session <same_id>` rows.
- Blind review bundle:
  - Durable bundle: `scenarios/iteration-test-expanded/blind-test/loop-48/review-data`
    with 116 files.
  - Neutral copy: `/private/tmp/review-dataset-cypress.XviGSg` with 116 files.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
- Blind review:
  - Deliberation was triggered by verdict disagreement and cross-review endpoint/session lifecycle
    overlap.
  - Initial mean synthetic-confidence: `57.5`; deliberated mean: `59.0`.
  - Reviewer scores:
    - Threat Hunter: Inconclusive, confidence `74`, synthetic-confidence `62`; deliberated to
      Inconclusive, confidence `76`, synthetic-confidence `64`.
    - Detection Engineer: Inconclusive, confidence `72`, synthetic-confidence `42`; deliberated to
      Inconclusive, confidence `73`, synthetic-confidence `46`.
    - Network Forensics: Inconclusive, confidence `72`, synthetic-confidence `58`; deliberated to
      Inconclusive, confidence `72`, synthetic-confidence `56`.
    - Host/EDR: Synthetic, confidence `62`, synthetic-confidence `68`; deliberated to Synthetic,
      confidence `65`, synthetic-confidence `70`.
  - Panel consensus and prioritized findings:
    - The loop 47 SSH Accepted-before-PAM ordering issue was fixed; reviewers described SSH syslog
      ordering as plausible/believable.
    - Highest-impact future target: canonical endpoint lifecycle/session ownership for process
      termination. Threat Hunter and Host/EDR independently found DB-PROD `wget` processes created
      under system/service context but terminated under a later root SSH logon/session.
    - Secondary targets include Windows/eCAR USER_SESSION normalization, proxy-origin DNS/SNI
      consistency, NTP protocol fan-out, duplicate shell creation, repeated root SSH/password
      texture, benign command-palette diversity, and IDS alert texture.
- Generated loop 47 output successfully after the final observation-grouping fix.
- Automated eval passed at `95.17991448713123` over 94,702 records.
- Pillars:
  - Parseability: `100.0`
  - Plausibility: `93.9656145287507`
  - Causality: `90.58055274688238`
  - Timing: `95.21686334111476`
- Hard probe `hard_probe_ssh_logind_removed_session.json`:
  - Loop 47: `passed` with `109` closed SSH sessions checked, `116` sessions with logind New
    rows checked, and zero missing or inverted `Removed session <same_id>` rows.
- Blind review bundle:
  - Durable bundle: `scenarios/iteration-test-expanded/blind-test/loop-47/review-data`
    with 116 files.
  - Neutral copy: `/private/tmp/review-dataset-cypress.jOw4kS` with 116 files.
  - Verified both bundles excluded `GROUND_TRUTH.md`, `GROUND_TRUTH.json`,
    `data/COLLECTION_PROFILE.json`, `OBSERVATION_MANIFEST.json`,
    `ARTIFACTS_MANIFEST.json`, and `OUTPUT_TARGET.txt`.
- Blind review:
  - Deliberation was triggered by verdict disagreement and synthetic-confidence spread.
  - Initial mean synthetic-confidence: `55.5`; deliberated mean: `63.5`.
  - Reviewer scores:
    - Threat Hunter: Realistic, confidence `78`, synthetic-confidence `22`; deliberated to
      Inconclusive, confidence `76`, synthetic-confidence `38`.
    - Detection Engineer: Inconclusive, confidence `76`, synthetic-confidence `46`; deliberated
      to Synthetic, confidence `78`, synthetic-confidence `62`.
    - Network Forensics: Synthetic, confidence `76`, synthetic-confidence `78`; deliberated to
      Synthetic, confidence `76`, synthetic-confidence `76`.
    - Host/EDR: Synthetic, confidence `78`, synthetic-confidence `76`; deliberated to Synthetic,
      confidence `79`, synthetic-confidence `78`.
  - Panel consensus and prioritized findings:
    - The loop 46/47 SSH logind-removal issue was fixed by hard probe and reviewers observed many
      richer SSH session chains.
    - Highest-impact next target: successful SSH syslog source-native ordering. Detection and
      Host/EDR independently found repeated cases where PAM session-open rows render before
      `Accepted password/publickey` for the same `sshd` PID/source tuple.
    - Secondary targets include `mail-fin.meridianhcs.com` DNS/SNI/origin ownership,
      eCAR session ownership/reuse around logout and unlock, proxy/file transfer
      missed-byte consistency, Linux command-line rendering, email text texture, and sparse NTP.

## Loop 48 Fix Target

- Selected family: Linux SSH successful-auth syslog lifecycle ordering.
- Owning abstraction: SSH action bundle plus source-observation grouping for successful SSH
  session syslog rows.
- Invariant: every complete successful SSH session must render source-native syslog order for one
  PID/source tuple:
  `Connection from` -> `Accepted password/publickey` -> `pam_unix session opened` ->
  `systemd-logind New session`, with close/removal after session activity. Source-observation
  delay must be coherent across the successful-auth lifecycle so it cannot invert the already
  planned canonical order.
- Entry paths: storyline SSH sessions, baseline remote-admin SSH sessions, SCP-backed receiver SSH
  sessions routed through the SSH bundle, Linux syslog rendering, source-observation delay, and
  compatibility Linux type-10 logon syslog.
- Consumers: Detection Engineering, Host/EDR review, Linux syslog session reconstruction, eCAR
  session correlation, SSH hard probes, and downstream SIEM auth-session rules.
- Layer rationale: the SSH bundle owns successful SSH auth lifecycle timing, but source-observation
  delay is applied after canonical events are built. Fixing only the rendered timestamps or one
  syslog emitter would leave source-local rows vulnerable to observation-delay inversions.

### Loop 48 implementation notes

- Root cause: loop 47 grouped PAM/logind rows to prevent close/removal inversion, but successful
  `Connection from` and `Accepted password/publickey` rows still used a different syslog
  observation identity from PAM/logind. The canonical gap between Accepted and PAM open is often
  tens to hundreds of milliseconds, while messy syslog collection delay can be up to 1000 ms, so
  independent delays could render PAM open before Accepted.
- Implemented changes:
  - Extended the syslog SSH session observation group to include successful `Connection from` and
    `Accepted` rows when they carry the same auth/session identity.
  - Attached the SSH session `AuthContext` to the SSH bundle's pre-auth connection and accepted
    authentication syslog rows, matching the auth context already attached to PAM/logind rows.
  - Broadened the observation-policy regression test to require one shared delay decision across
    `Connection`, `Accepted`, PAM open, logind New, PAM close, and logind Removed.
- Focused verification passed:
  - `uv run pytest --no-cov tests/unit/test_dispatcher.py -k "ssh_success_syslog_lifecycle_rows_share_observation_delay"`
  - `uv run pytest --no-cov tests/unit/test_zeek_activity_contexts.py -k "ssh_session_bundle_renders_publickey_and_optional_close or records_logind_session_id or logind_uses_seeded"`
  - `uv run pytest --no-cov tests/unit/test_phase5_logoff.py -k "ssh_logoff or linux_type10"`
  - `uv run ruff check src/evidenceforge/events/observation.py src/evidenceforge/generation/actions/ssh_session.py src/evidenceforge/generation/activity/generator.py tests/unit/test_dispatcher.py tests/unit/test_zeek_activity_contexts.py tests/unit/test_phase5_logoff.py`
  - `uv run ruff format --check src/evidenceforge/events/observation.py src/evidenceforge/generation/actions/ssh_session.py src/evidenceforge/generation/activity/generator.py tests/unit/test_dispatcher.py tests/unit/test_zeek_activity_contexts.py tests/unit/test_phase5_logoff.py`
