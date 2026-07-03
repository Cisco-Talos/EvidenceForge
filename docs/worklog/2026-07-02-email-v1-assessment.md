# Email V1 Assessment Worklog

Branch: `codex/email-evidence-design`

Scenario: `scenarios/email-v1-assessment/scenario.yaml`

Purpose: run repeated blind realism assessment loops against a purpose-built
scenario that stresses Email Evidence V1: explicit topology, multiple SMTP
servers, inbound/internal/outbound delivery, ISP relay routing, distribution
groups, Bcc, corpus-backed content, MIME `.eml` artifacts, Zeek SMTP/files
linkage, mixed STARTTLS visibility, explicit mailbox reads, and automatic reads.

## Loop 1

Generation and validation succeeded. Automated eval initially failed the
causality event-presence gate because email storyline events were not recognized
as traces by the evaluator. After adding email trace matching, eval passed:

- Overall score: 96.28
- Records: 68,104
- Event presence: 8/8

Blind panel result: synthetic-leaning, average deliberated synthetic-confidence
66.75. Highest-leverage email-owned findings:

- External third-party MX hosts received host-scoped eCAR endpoint files.
- The blind package exposed `EMAIL_ARTIFACTS.json`, including storyline and
  verdict metadata.
- Message-IDs exposed artifact/storyline slugs and a zero-prefixed deterministic
  shape.
- SMTP `user_agent` rotated by message for the same sender/workstation.

Fixes applied before loop 2:

- Evaluator now recognizes `email_message` and `email_read` storyline traces via
  email artifacts, Zeek SMTP, Zeek conn, and Zeek SSL evidence.
- External SMTP peers no longer get source-host endpoint attribution when
  delegated into the network connection bundle.
- Email Message-IDs now use deterministic opaque components without artifact
  slugs or the global zero prefix.
- Background corpus entries no longer rotate `user_agent` for the same
  sender/workstation; mail client identity is stable per host/user/OS unless
  explicitly overridden.
- Loop 2 blind package excludes `EMAIL_ARTIFACTS.json` and uses a neutral
  temporary review path.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py -q` passed.
- `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`
  passed.
- `uv run ruff check src/evidenceforge/evaluation/pillars/causality.py tests/unit/test_email_evidence.py`
  passed after import ordering cleanup.

## Loop 2

Generation succeeded with the expected informational storyline pivot warnings.
Automated eval passed:

- Overall score: 96.28
- Records: 68,093
- Event presence: 8/8

Pre-panel probes confirmed:

- No `EMAIL_ARTIFACTS.json` in the review package.
- No external MX host directories in the review package.
- Message-IDs in SMTP and `.eml` artifacts no longer include artifact slugs or
  the loop-1 zero-prefix pattern.

Loop 2 blind reviewers are running against `/private/tmp/eforge-review-2b9a/review-data`.

Panel result: two Synthetic, two Inconclusive, average synthetic-confidence
57.0. The original loop-1 package leaks and external MX endpoint files were
resolved. New highest-leverage findings:

- External `198.51.100.x` SMTP peers queried internal `10.55.20.10` DNS for AD
  `_kerberos`/`_ldap` SRV records and private mail answers.
- Zeek `local_orig`/`local_resp` used private-address heuristics, so RFC 5737
  internet peers and ISP relay addresses were marked local.
- SMTP MIME part FUIDs were reused across plaintext relay hops. Content hashes
  were stable, which is good, but Zeek file-analysis IDs should be per observed
  transfer.
- STARTTLS SMTP rows still lack same-UID TLS/SSL sidecar evidence; deferred
  behind the more direct DNS/locality/FUID contradictions.

## Loop 3

Family contract for the loop-3 fix:

- Owning abstraction: network connection bundle for locality and DNS
  prerequisite eligibility; email delivery bundle for mail-route DNS and MIME
  file-transfer context.
- Invariant: only modeled local systems/VIPs/internal segments query the
  organization's resolver as connection prerequisites; external SMTP peers do
  not emit victim-internal AD DNS. Zeek `local_orig`/`local_resp` reflects
  modeled local topology, not Python/IP documentation/private-address
  classification. Every observed plaintext SMTP hop gets fresh FUIDs while
  preserving content continuity through hashes/message metadata.
- Entry paths: storyline email, baseline email, generic network connections,
  causal DNS expansion, and SMTP file fan-out.
- Consumers: Zeek conn/dns/smtp/files, eCAR endpoint flow attribution, Windows
  WFP DNS/service rows, evaluator parsers, and blind-review package artifacts.
- Residual sibling risk: explicit public/VIP/NAT semantics may need broader
  realism review; STARTTLS TLS sidecar evidence remains a separate follow-up.

Implemented fixes:

- Added a modeled-local-IP helper based on systems, internal/both network
  segments, NAT mappings, and visibility VIP mappings.
- `NetworkContext.local_orig/local_resp` now use modeled local membership.
- DNS prerequisites in the network bundle now require a modeled local source.
- Email route DNS now emits from each local hop source and skips external-origin
  hops.
- SMTP MIME file-transfer FUIDs now include hop observation identity; hashes
  remain content-stable.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py -q` passed.
- `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`
  passed.
- `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
  passed.
- Rendered-output probe after regeneration found zero external DNS-to-DC rows,
  zero inbound/outbound locality mismatches for the sampled external SMTP
  families, and zero duplicate SMTP FUID groups.

Automated eval passed:

- Overall score: 96.73
- Records: 68,562

Loop 3 blind reviewers are running against `/private/tmp/eforge-review-3c4d/review-data`.

Panel result: all four reviewers returned Inconclusive, average
synthetic-confidence 43.5. External DNS/locality and SMTP FUID findings did not
recur. Highest-leverage new finding was Windows Security 4769 field shape:
`TargetUserName` used `account@REALM` while `TargetDomainName` also carried the
realm/domain.

## Loop 4

Family contract for the loop-4 fix:

- Owning abstraction: Kerberos service-ticket generation context plus Windows
  Security 4769 renderer.
- Invariant: Windows 4769 renders account and domain in source-native separated
  fields; `TargetUserName` is account-name-only and `TargetDomainName` carries
  the domain/realm.
- Entry paths: explicit Kerberos service-ticket generation, DC logon audit
  bundles, machine-account Kerberos flows, cached-ticket companions, and any
  direct emitter tests.
- Consumers: Windows Security XML, Snare sidecar rendering, evaluator Kerberos
  timing/causality checks, and blind-review schema analysis.
- Residual sibling risk: 4768 TGT and 4771 failure fields may have different
  native account-name conventions and were not broadened beyond the 4769 finding.

Implemented fixes:

- Kerberos service-ticket generation now stores account-name-only
  `target_username`.
- Windows 4769 rendering normalizes any legacy/context UPN-style value to the
  account-name portion before output.
- Focused generator and emitter tests cover the new 4769 invariant.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_emitters.py::TestWindowsEventEmitter::test_kerberos_service_ticket_target_username_is_account_name tests/unit/test_activity.py::TestActivityGenerator::test_kerberos_krbtgt_service_ticket_uses_domain_rid_502 -q`
  passed.
- `uv run pytest --no-cov tests/unit/test_emitters.py::TestWindowsEventEmitter tests/unit/test_activity.py::TestActivityGenerator::test_kerberos_krbtgt_service_ticket_uses_domain_rid_502 tests/unit/test_dc_kerberos_logon.py -q`
  passed.
- Rendered-output probe after regeneration found 1,673 Windows 4769 rows and
  zero `TargetUserName` values containing `@`.

Automated eval passed:

- Overall score: 96.71
- Records: 68,562

Loop 4 panel result after deliberation:

- Threat Hunter: Inconclusive, final synthetic-confidence 52.
- Detection Engineer: Synthetic, final synthetic-confidence 72.
- Network Forensics: Synthetic, final synthetic-confidence 75.
- Host/EDR Forensics: Inconclusive, final synthetic-confidence 55.
- Final average synthetic-confidence: 63.5.

Highest-leverage concrete finding: Zeek `files.json.local_orig` contradicted the
referenced parent `conn.json` locality for inbound SMTP MIME parts and some OCSP
certificate transfers.

## Loop 5

Family contract for the loop-5 fix:

- Owning abstraction: canonical `NetworkContext` plus `FileTransferContext`, as
  rendered by the Zeek files emitter.
- Invariant: `files.log.local_orig` must reflect the transmitting side's
  canonical locality from the referenced connection, not private-address
  heuristics. For originator-sent files use `network.local_orig`; for
  responder-sent files use `network.local_resp`.
- Entry paths: SMTP MIME body/attachments, HTTP response file transfers,
  TLS/X.509 certificate file rows, SMB file metadata, and direct file-transfer
  tests.
- Consumers: Zeek `conn.log`/`files.log` correlation, SMTP `fuids`,
  evaluator cross-source checks, and blind-review network analysis.
- Residual sibling risk: Zeek SMTP `path`, RFC 5737 external email peer IPs,
  and fixed SSH/Kerberos timing are separate follow-up families.

Implemented fixes:

- Zeek files rendering now uses the parent `NetworkContext` locality instead of
  recomputing from `tx_hosts` with private-IP tests.
- TLS certificate file rows now inherit responder locality from the parent
  connection.
- Unit coverage now exercises inbound and outbound SMTP-like file parts through
  full `SecurityEvent` rendering.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_zeek_files.py -q` passed.
- `uv run ruff check src/evidenceforge/generation/emitters/zeek_files.py tests/unit/test_zeek_files.py`
  passed.
- Rendered-output probe after regeneration found 1,037 Zeek file rows and zero
  `files.log.local_orig` mismatches against referenced `conn.log` locality.

Automated eval passed:

- Overall score: 96.71
- Records: 68,562

Loop 5 panel result:

- Threat Hunter: Synthetic, synthetic-confidence 72.
- Detection Engineer: Synthetic, synthetic-confidence 70.
- Network Forensics: Synthetic, synthetic-confidence 68.
- Host/EDR Forensics: Synthetic, synthetic-confidence 74.
- Average synthetic-confidence: 71.0.

The loop-4 file-locality contradiction did not recur. The panel converged on
documentation-range external email IPs, missing STARTTLS SSL sidecars,
generated-looking Message-ID/MIME/header texture, and mail endpoint attribution
gaps.

## Loop 6

Family contract for the loop-6 fix:

- Owning abstraction: email route planning for external MX and external source
  mail systems.
- Invariant: generated live external email peers must use deterministic
  global-looking addresses from the shared external-IP sampler, not RFC 5737
  documentation ranges.
- Entry paths: inbound Internet-to-internal email, outbound direct MX delivery,
  outbound ISP relay delivery, background inbound/outbound email, storyline
  email, `.eml` Received headers, Zeek SMTP/conn/files, and firewall/endpoint
  companion evidence.
- Consumers: Zeek SMTP/conn/files, `.eml` artifacts, DNS/route evidence,
  evaluator parsers, and blind-review attribution.
- Residual sibling risk: STARTTLS SSL sidecars, SMTP `path`, message-ID/MIME
  texture, and endpoint mail-client attribution are separate follow-up families.

Implemented fixes:

- External email MX hops now use `_generate_random_external_ip()` with a stable
  per-host seed.
- External source mail systems now use the same shared sampler.
- Email tests now assert global non-TEST-NET external email peers instead of
  hardcoded documentation ranges.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py -q` passed.
- `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
  passed.

- Rendered-output probe after regeneration showed first-hop SMTP rows preserving
  `finance@alderridge.example` / `it-help@alderridge.example` aliases while later
  relay rows expanded them.

Automated eval passed:

- Overall score: 96.716
- Records: 68,584

Loop 9 panel result:

- Threat Hunter: Synthetic, synthetic-confidence 72.
- Detection Engineer: Synthetic, synthetic-confidence 68.
- Network Forensics: Synthetic, synthetic-confidence 72.
- Host/EDR Forensics: Synthetic, synthetic-confidence 74.
- Average synthetic-confidence: 71.5.

The first-hop alias recipient change was insufficient. Reviewers still saw
recipient/header drift because Bcc/list expansion is visible without enough
directory/list/transport-rule evidence. Treat this as a partial fix; future work
should add explicit distribution-list/transport artifacts or richer manifest
visibility.

## Loop 10

Family contract for the loop-10 fix:

- Owning abstraction: Sysmon Event 3 destination hostname rendering.
- Invariant: endpoint network telemetry should not pair POP/IMAP hostnames with
  SMTP port semantics. When rendering port 25 and reverse DNS points at common
  Gmail POP/IMAP names, normalize to the SMTP sibling hostname.
- Entry paths: Sysmon Event 3 rendering for mail-host/background email
  connections and any endpoint-visible SMTP flow where reverse DNS chooses a
  provider mail host.
- Consumers: Windows Sysmon XML, endpoint detection parsers, and blind-review
  source-native protocol/hostname checks.
- Residual sibling risk: broader DNS-registry role/port binding, SMTP `path`,
  client-submission STARTTLS policy, distribution-list evidence, and eCAR flow
  attribution are separate follow-up families.

Implemented fixes:

- Sysmon destination hostname resolver now accepts destination port.
- Port 25 events with reverse-DNS `imap.gmail.com` or `pop.gmail.com` normalize
  to `smtp.gmail.com`.
- Regression test covers a port-25 event whose reverse DNS initially returns
  `pop.gmail.com`.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_sysmon_new_events.py::TestRenderEvent3::test_event3_normalizes_mail_hostname_to_port_family -q`
  passed.
- `uv run ruff check src/evidenceforge/generation/emitters/sysmon.py tests/unit/test_sysmon_new_events.py`
  passed.
- Rendered-output probe after regeneration decoded every artifact-backed `.eml`
  attachment and found zero MD5/SHA1/SHA256 or byte-count mismatches against
  matching Zeek SMTP `files.json` rows.

Automated eval passed:

- Overall score: 96.716
- Records: 68,584

Loop 8 panel result:

- Threat Hunter: Synthetic, synthetic-confidence 68.
- Detection Engineer: Inconclusive, synthetic-confidence 52.
- Network Forensics: Synthetic, synthetic-confidence 68.
- Host/EDR Forensics: Synthetic, synthetic-confidence 78.
- Average synthetic-confidence: 66.5.

The attachment-hash finding did not recur; Detection Engineering moved to
Inconclusive. Remaining email findings focus on recipient/list semantics,
client-submission TLS policy, header/MIME/content texture, and background
subject repetition. Host/EDR concern is now dominated by endpoint workflow and
server-role texture outside the email artifact layer.

## Loop 9

Family contract for the loop-9 fix:

- Owning abstraction: SMTP envelope recipient selection inside email delivery.
- Invariant: first-hop SMTP submission/delivery preserves authored envelope
  aliases and Bcc recipients, while later relay/delivery hops may expand
  distribution lists to mailbox recipients. Header `To`/`Cc` remains the visible
  authored header view; `Bcc` remains envelope/manifest only.
- Entry paths: distribution groups, Bcc, inbound Internet delivery, internal
  client submission, internal relay, artifacts, Zeek SMTP, and manifest
  expanded-recipient metadata.
- Consumers: Zeek `smtp.log`, `.eml` artifacts, `EMAIL_ARTIFACTS.json`, ground
  truth, and blind-review recipient pivots.
- Residual sibling risk: visible directory/list metadata, mail-host endpoint
  protocol coherence, richer enterprise headers, and content-pool repetition
  are separate follow-up families.

Implemented fixes:

- Email delivery now computes original envelope recipients separately from
  expanded mailbox recipients.
- First SMTP hop uses original envelope recipients; later hops use expanded
  recipients.
- Distribution-group tests now assert first-hop alias preservation and later-hop
  expansion.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py -q` passed.
- `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
  passed.
- Rendered-output probe after regeneration found zero TEST-NET hits in visible
  SMTP peers and `.eml` artifacts.

Automated eval passed:

- Overall score: 96.71
- Records: 68,562

Loop 6 panel result:

- Threat Hunter: Synthetic, synthetic-confidence 68.
- Detection Engineer: Synthetic, synthetic-confidence 72.
- Network Forensics: Synthetic, synthetic-confidence 68.
- Host/EDR Forensics: Synthetic, synthetic-confidence 74.
- Average synthetic-confidence: 70.5.

The documentation-IP issue did not recur. The panel shifted to SMTP STARTTLS
SSL sidecars, `.eml` attachment hash ownership, SMTP envelope/header/path
semantics, repeated DNS transaction IDs, and endpoint telemetry texture.

## Loop 7

Family contract for the loop-7 fix:

- Owning abstraction: canonical network connection context for SMTP STARTTLS
  delivery hops.
- Invariant: if an SMTP hop has `smtp.tls=true`, the same canonical connection
  should carry an `SslContext` so Zeek emits a same-UID `ssl.json` row. Encrypted
  SMTP message metadata remains protected in `smtp.json`, and MIME file rows are
  still omitted for that hop.
- Entry paths: internal server-to-server relay, outbound direct MX delivery,
  outbound ISP relay delivery, background/storyline SMTP, and Zeek format group
  fan-out.
- Consumers: Zeek `smtp.log`, `ssl.log`, `conn.log`, evaluator parsers, and
  blind-review network/detection joins.
- Residual sibling risk: certificate/x509 sidecars for STARTTLS, client
  submission STARTTLS, `.eml` attachment hash ownership, SMTP path/envelope
  semantics, and MIME/header texture are separate follow-up families.

Implemented fixes:

- `NetworkConnectionRequest` and `ActivityGenerator.generate_connection()` now
  accept an explicit `SslContext`.
- Email delivery attaches deterministic STARTTLS `SslContext` metadata to
  successful encrypted SMTP relay hops.
- Focused email tests assert encrypted SMTP UIDs appear in Zeek `ssl.json` and
  still omit protected SMTP `fuids`.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py -q` passed.
- `uv run ruff check src/evidenceforge/generation/actions/network_connection.py src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
  passed.
- Rendered-output probe after regeneration found 22 SMTP `tls=true` rows, all
  with same-UID Zeek `ssl.json` rows, and zero encrypted SMTP rows with `fuids`.

Automated eval passed:

- Overall score: 96.716
- Records: 68,584

Loop 7 panel result:

- Threat Hunter: Synthetic, synthetic-confidence 66.
- Detection Engineer: Synthetic, synthetic-confidence 66.
- Network Forensics: Synthetic, synthetic-confidence 72.
- Host/EDR Forensics: Synthetic, synthetic-confidence 66.
- Average synthetic-confidence: 67.5.

The hard missing STARTTLS SSL sidecar finding did not recur. Reviewers shifted
to recipient/header semantics, repeated content pools, MIME/header profiles,
DNS/MX prerequisites, and endpoint/eCAR texture.

## Loop 8

Family contract for the loop-8 fix:

- Owning abstraction: canonical email attachment payload materialization.
- Invariant: decoded attachment bytes in `.eml` artifacts and Zeek
  `files.json` hashes/byte counts must come from the same canonical payload.
- Entry paths: corpus-backed storyline attachments, deterministic size-only
  attachments, MIME rendering, Zeek SMTP file metadata, and artifact parser
  workflows.
- Consumers: `.eml` artifacts, Zeek `files.log`, evaluator parsers, SIEM
  attachment-hash pivots, and blind-review detection workflows.
- Residual sibling risk: SMTP recipient/header semantics, Message-ID/MIME
  texture, endpoint attachment-open evidence, and content-pool repetition are
  separate follow-up families.

Implemented fixes:

- Added a shared `_email_attachment_payload_bytes()` helper.
- Zeek SMTP MIME file metadata and `.eml` rendering now use the same attachment
  payload bytes.
- Regression coverage decodes a generated `.eml` attachment and compares its
  MD5/SHA1/SHA256 to the matching Zeek `files.json` row.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py -q` passed.
- `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
  passed.

## Final Loop 10 Closure

Loop 10 completed after the Sysmon mail hostname/port coherence fix.

Automated eval passed:

- Overall score: 96.716
- Records: 68,584
- Parseability: 100.0
- Plausibility: 95.184
- Causality: 95.714
- Timing: 94.957

Panel result:

- Threat Hunter: Synthetic, synthetic-confidence 66.
- Detection Engineer: Inconclusive, synthetic-confidence 57.
- Network Forensics: Synthetic, synthetic-confidence 64.
- Host/EDR Forensics: Synthetic, synthetic-confidence 69.
- Average synthetic-confidence: 64.0.

The port/hostname issue did not recur as a named finding. Remaining V1 realism
work is now concentrated in richer mail endpoint attribution, sender-specific
mail content/header texture, SMTP envelope/path semantics, DNS/TLS policy
texture, and optional mail-daemon host evidence. The authoritative loop-10
synthesis is saved at `scenarios/email-v1-assessment/blind-test/loop-10/REPORT.md`;
machine-readable scores are saved at
`scenarios/email-v1-assessment/blind-test/loop-10/scores.json`.

## Loop 11

Priority item: email content/artifact realism.

Family contract:

- Owning abstraction: email artifact rendering and shared mailer-profile
  helpers inside the email delivery path.
- Invariant: materialized `.eml` artifacts should not all look like one generic
  Python email serializer. Header order, Message-ID morphology, visible mailer
  header, MIME boundary style, and service-vs-human mailer fingerprints should
  be deterministic but profile-specific.
- Entry paths: storyline email, corpus-backed email, selected/background
  artifact email, MIME rendering, Zeek SMTP Message-ID metadata, and manifest
  references.
- Consumers: `.eml` artifacts, Zeek `smtp.json`, Zeek `files.json`, email
  artifact parser, ground truth artifact references, and blind reviewer
  workflows.
- Residual sibling risk: repeated background subject/body pools remain in scope
  for this priority. Endpoint mail process ownership, Zeek SMTP `path`, To/Cc
  schema shape, and background SMTP conn/protocol coverage are separate priority
  families or sibling contract gaps.

Implemented fixes:

- Added deterministic mailer-profile classification for Outlook, Thunderbird,
  Apple Mail, and service mail.
- Varied Message-ID morphology by profile.
- Replaced generic stdlib `.eml` serialization output with deterministic
  source-native-ish header ordering and MIME boundary generation.
- Preserved custom header insertion before MIME headers.
- Normalized service-origin corpus/default mail that carried human
  Outlook-like fingerprints into service mailer fingerprints, while preserving
  explicit event-level `user_agent` overrides.

Focused verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_zeek_files.py tests/unit/test_sysmon_new_events.py::TestRenderEvent3::test_event3_normalizes_mail_hostname_to_port_family tests/unit/test_emitters.py::TestWindowsEventEmitter::test_kerberos_service_ticket_target_username_is_account_name tests/unit/test_activity.py::TestActivityGenerator::test_kerberos_krbtgt_service_ticket_uses_domain_rid_502 -q`
  passed: 43 tests.
- `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
  passed.
- `uv run ruff format --check src/evidenceforge/generation/activity/generator.py tests/unit/test_email_evidence.py`
  passed.
- Rendered `.eml` probe confirmed Received-first headers, profile-specific
  Message-IDs, service `X-Mailer` values, custom headers before MIME headers,
  and non-stdlib MIME boundary shapes.

Automated eval passed:

- Overall score: 96.716
- Records: 68,584

Panel result:

- Threat Hunter: Inconclusive, synthetic-confidence 49.
- Detection Engineer: Inconclusive, synthetic-confidence 53.
- Network Forensics: Inconclusive, synthetic-confidence 56.
- Host/EDR Forensics: Synthetic, synthetic-confidence 66.
- Average synthetic-confidence: 56.0.

The average did not meet the user-defined `<=45` temporary-solve threshold, so
email content/artifact realism remains active for loop 12. The next target is
background corpus entropy: diversify deterministic subjects/bodies and restrict
exact repeats to plausible threads, list/newsletter traffic, repeated
transactional notices, or true duplicate/relay artifacts.

## Loop 12

Priority category: email content/artifact realism.

Family contract:

- Owning abstraction: email content selection and deterministic built-in
  metadata/body helpers.
- Invariant: background email should not overuse a small corpus/content pool
  when a scenario provides reusable background corpus entries; template-backed
  messages must maintain varied senders, subjects, body text, and visible SMTP
  metadata.
- Entry paths: baseline internal, inbound, outbound, SMTP delivery,
  artifact-backed messages, metadata-only messages, Zeek SMTP rendering, and
  `.eml` artifact rendering.
- Consumers: Zeek `smtp.json`, `files.json`, `.eml` artifacts,
  `EMAIL_ARTIFACTS.json`, ground truth references, and blind review packages.
- Residual sibling risk: conversation-thread state is still shallow, so a
  single sender can repeat subjects more than ideal.

Implemented fixes:

- Baseline background mail now samples scenario corpus entries opportunistically
  instead of always using the small corpus whenever one is present.
- Built-in deterministic background subjects and bodies now use larger,
  structured pools and more subject forms.
- Added focused subject-diversity coverage for generated background SMTP.

Verification:

- Rendered-output probe: 39 visible SMTP subjects, 28 unique subjects.
- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Automated eval passed with score 97.14 over 70,169 records.

Blind panel:

- Threat Hunter: Real, synthetic-confidence 34.
- Detection Engineer: Inconclusive, synthetic-confidence 38.
- Network Forensics: Real, synthetic-confidence 34.
- Host/EDR: Inconclusive, synthetic-confidence 43.
- Average: 37.25.

Result: average blind synthetic-confidence is `<=45`, so email
content/artifact realism is temporarily solved under the user's special rule.
Loop 13 should move to endpoint/host mail and process realism. Highest-priority
next finding: sub-second post-logon desktop bursts that mix autostart
applications with typed shell commands, especially bare PowerShell spawning a
build command one millisecond later.

## Loop 13

Priority category: endpoint/host mail and process realism.

Family contract:

- Owning abstraction: Windows process execution timing in the process action
  bundle path.
- Invariant: children of bare interactive Windows shells should not appear with
  machine-speed timing. Sub-second children remain valid for explicit inline
  command wrappers, scripts, automation, or storyline-authored timing.
- Entry paths: baseline process launches, application-catalog CLI tools,
  spawn-rule parent materialization, shell parent reuse, Sysmon/Security/eCAR
  process rendering, and endpoint-owned network side effects.
- Consumers: Windows Security 4688/4689, Sysmon Event 1/5/3/22, eCAR
  PROCESS/FLOW rows, source timing checks, and blind endpoint review.
- Residual sibling risk: workstation assignment and server interactive-session
  texture are a separate world-model/activity-profile family.

Implemented fixes:

- Added an interactive-shell child spacing helper after parent repair, so both
  existing bare shell parents and auto-created shell parents get human-scale
  dwell time before child commands.
- Preserved explicit storyline process timing.
- Added focused tests for background bare-shell child spacing and storyline
  timing preservation.

Verification:

- Rendered-output probe: the reviewed Linh Tran PowerShell-to-`kubectl.exe`
  startup example now has roughly 17 seconds of dwell time rather than a
  sub-second gap.
- Focused tests passed: `uv run pytest --no-cov tests/unit/test_activity.py::TestActivityGenerator::test_generate_process_spaces_bare_shell_child_commands tests/unit/test_activity.py::TestActivityGenerator::test_storyline_process_preserves_bare_shell_child_timing tests/unit/test_activity.py::TestActivityGenerator::test_generate_process_rejects_one_shot_shell_parent tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Automated eval passed with score 96.93 over 69,437 records.

Blind panel:

- Threat Hunter: Real, synthetic-confidence 32.
- Detection Engineer: Inconclusive, synthetic-confidence 34.
- Network Forensics: Real, synthetic-confidence 28.
- Host/EDR: Real, synthetic-confidence 32.
- Average: 31.5.

Result: average blind synthetic-confidence is `<=45`, so endpoint/host mail and
process realism is temporarily solved under the user's special rule. Loop 14
should move to email routing and recipient semantics. Good candidate: avoid
mixed internal/external recipient envelopes on outbound external relay hops.

## Loop 14

Priority category: email routing and recipient semantics.

Family contract:

- Owning abstraction: email route planning plus SMTP hop context.
- Invariant: each SMTP hop carries the envelope recipients appropriate to that
  route segment. Submission preserves original visible aliases and Bcc envelope
  addresses; internal relay hops carry only recipients delivered through that
  internal server; outbound external relay/MX hops carry only external
  recipients.
- Entry paths: storyline email, baseline internal/outbound/inbound mail,
  distribution groups, sender-group outbound overrides, ISP relay mode,
  same-server collapse, and Zeek SMTP rendering.
- Consumers: Zeek `smtp.json`, SMTP `rcptto`, artifacts/manifest route
  summaries, evaluator cross-source checks, and blind network/detection review.
- Residual sibling risk: DNS TTL/cache semantics and generic Zeek
  failed-connection texture are separate Zeek contract families.

Implemented fixes:

- Added hop-scoped recipient lists in the email route planner.
- SMTP rendering now uses the hop recipient scope instead of every expanded
  recipient on every relay.
- Submission hops restore original envelope aliases so distribution-list and
  Bcc semantics remain realistic at the client submission boundary.
- Added mixed internal/external recipient coverage and updated
  distribution-group assertions for same-server collapse.

Verification:

- Rendered-output probe: 10 outbound external SMTP hops and 0 mixed
  internal-recipient violations.
- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_activity.py::TestActivityGenerator::test_generate_process_spaces_bare_shell_child_commands tests/unit/test_activity.py::TestActivityGenerator::test_storyline_process_preserves_bare_shell_child_timing tests/unit/test_eval_cross_source.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Automated eval passed with score 96.93 over 69,437 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 37.
- Detection Engineer: Real, synthetic-confidence 29.
- Network Forensics: Inconclusive, synthetic-confidence 47.
- Host/EDR: Inconclusive, synthetic-confidence 55.
- Average: 42.0.

Result: average blind synthetic-confidence is `<=45`, so email routing and
recipient semantics is temporarily solved under the user's special rule. Loop
15 should move to Zeek cross-source contracts. Best next candidate: DNS answer
TTL/cache consistency into later TLS/HTTP connections.

## Loop 15

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: DNS lookup action bundle plus client/resolver cache state.
- Invariant: local hostname-backed TCP activity should not depend on visibly
  expired DNS answers, and DNS cache suppression must be evaluated against the
  event timestamp, not generation order.
- Entry paths: causal DNS-before-TCP expansion, explicit hostname-backed local
  TCP connections, proxy-origin connections, email access/read sessions,
  internal service lookups, and direct DNS connection compatibility paths.
- Consumers: Zeek `dns.json`, `conn.json`, `ssl.json`, `http.json`, proxy
  evidence, endpoint flow rows, and evaluator/blind-review cross-source checks.
- Residual sibling risk: DNS still repeats internal service answers inside TTL
  through non-forced/background DNS paths; generic failed-connection scan
  texture, SMTP submission TLS posture, and RDP endpoint ordering remain
  separate families.

Implemented fixes:

- Client DNS cache now stores validity windows `(cached_at, cached_until)` based
  on the TTL returned in visible `dns.json` rather than only a last-query
  timestamp or authoritative TTL.
- Cache suppression now requires the current event timestamp to fall inside the
  cached window, making generation-order inversions safe.
- Local hostname-backed TCP flows now route through DNS prerequisite evidence
  even when the caller did not explicitly set `emit_dns`.
- Connection-prerequisite external A/AAAA lookups avoid near-expired returned
  TTLs that could expire before the dependent TCP row.
- Added focused tests for returned-TTL cache suppression, TTL refresh,
  hostname-backed TCP without `emit_dns`, and future-generated lookups not
  suppressing earlier timestamped DNS evidence.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_dns_realism.py tests/unit/test_activity.py::test_emit_dns_lookup_prunes_and_bounds_dns_cache tests/unit/test_causal_engine.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after final regeneration found 0 expired DNS
  dependencies for 1,335 SSL rows with SNI and 62 direct HTTP rows with Host.
- Automated eval passed with score 96.44 over 86,247 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 42.
- Detection Engineer: Inconclusive, synthetic-confidence 46.
- Network Forensics: Synthetic, synthetic-confidence 68.
- Host/EDR: Synthetic, synthetic-confidence 64.
- Average: 55.0.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 16. The expired-DNS reuse finding was resolved, but Network found the
sibling DNS-cache defect: repeated same-client/same-query/same-answer internal
DNS lookups inside advertised TTL windows. Loop 16 should target DNS
repeat-inside-TTL behavior across internal service/background DNS paths while
preserving the loop-15 expired-answer fix.

## Loop 16

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: canonical DNS context handling in the network connection
  bundle path.
- Invariant: successful A/AAAA/MX/SRV DNS observations with the same
  client/resolver/query/type/answer set should not repeat inside their visible
  TTL window, regardless of whether the row came from a caller-supplied
  `DnsContext`, forced connection-prerequisite DNS, or hostname-only DNS
  fallback.
- Entry paths: causal DNS-before-TCP expansion, direct/background DNS
  connections, hostname-only DNS fallback, email route DNS, proxy-origin DNS,
  internal service DNS, and out-of-order generation.
- Consumers: Zeek `dns.json`, `conn.json`, `ssl.json`, `http.json`, proxy and
  endpoint flow evidence, evaluator checks, and blind network review.
- Residual sibling risk: source-native SMTP reply/status texture, generic
  failed-connection scan texture, eCAR endpoint flow timing, and environment
  DNS/DHCP registry consistency remain separate families.

Implemented fixes:

- Added a shared DNS observation cache keyed by
  client/resolver/query/type/answers.
- Cache windows are overlap-aware so out-of-order generation does not create
  duplicate visible DNS observations inside TTL.
- Applied the shared cache to caller-supplied `DnsContext` rows and the
  hostname-only DNS fallback path.
- Added focused tests for direct DNS suppression, hostname fallback
  suppression, and out-of-order duplicate suppression.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_dns_realism.py tests/unit/test_activity.py::test_emit_dns_lookup_prunes_and_bounds_dns_cache tests/unit/test_causal_engine.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after final regeneration found 0 repeat-inside-TTL DNS
  pairs across 1,657 eligible A/AAAA/MX/SRV DNS rows.
- Automated eval passed with score 96.36 over 70,905 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 64.
- Detection Engineer: Synthetic, synthetic-confidence 68.
- Network Forensics: Synthetic, synthetic-confidence 63.
- Host/EDR: Inconclusive, synthetic-confidence 44.
- Average: 59.75.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 17. The DNS repeat-inside-TTL finding did not recur. Loop 17 should target
SMTP source-native texture, especially the uniform `last_reply` value across
all SMTP rows.

## Loop 17

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: email delivery bundle and canonical SMTP context
  creation.
- Invariant: SMTP delivery rows should carry plausible server/profile-specific
  completion replies and route hops should render in delivery order; response
  texture must not be one fixed `250` string across the dataset.
- Entry paths: storyline email, background email, internal submission,
  internal relay, outbound relay/MX, inbound mail, same-server collapse, and
  TLS/plaintext SMTP hops.
- Consumers: Zeek `smtp.json`, Zeek `conn.json`, Zeek `files.json`, email
  artifacts, EMAIL_ARTIFACTS.json, ground truth SMTP UID references, and blind
  network/detection review.
- Residual sibling risk: manifest route UID namespace, SMTP submission TLS and
  endpoint process attribution, external SMTP peer IP role realism, and
  non-source-native manifest fields remain separate families.

Implemented fixes:

- Replaced the single delivered-hop reply string with deterministic
  source-native SMTP completion replies using server role/OS/message/hop
  context.
- Added plausible Postfix/Exchange-like and external MTA-style queue IDs while
  preserving successful `250` semantics and varied 5xx rejection replies.
- Made email route hop times monotonic by accumulating relay offsets instead
  of multiplying each hop by an independently sampled delay.
- Added a regression assertion that delivered background SMTP replies vary
  across multi-message output.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 42.
- Detection Engineer: Real, synthetic-confidence 30.
- Network Forensics: Inconclusive, synthetic-confidence 52.
- Host/EDR: Real, synthetic-confidence 32.
- Average: 39.0.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears email artifact/content texture. The next priority
category for loop 36 is failed sensitive-port probe distribution: Network
Forensics repeatedly found SYN-only probes to RDP/VNC/Telnet/MSSQL/Redis-style
ports spread too evenly across nearly every internal host and hour.

## Loop 36

Priority category: failed sensitive-port probe distribution.

Family contract:

- Owning abstraction: firewall deny baseline generation.
- Invariant: external scanner/firewall deny noise remains the dominant blocked
  traffic family. Internal denied scan-like traffic should come from a small,
  stable, role-plausible source set and each source should use a narrow
  source-sticky port vocabulary, not a broad shared blocked-port pool spread
  across all workstations, mail servers, proxy, and DCs.
- Entry paths: hourly firewall deny baseline, cross-segment denied TCP
  attempts, outbound denied TCP attempts, external scanner denies, Cisco ASA
  deny rendering, Zeek `conn.json`, and eCAR/network visibility companions.
- Consumers: Zeek `conn.json`, Cisco ASA 106023 rows, evaluator distribution
  checks, and blind Network/Threat Hunter review.
- Residual sibling risk: explicit storyline/nmap scanner events, Linux UFW
  block noise on DMZ hosts, DNS answer texture, proxy HTTP diversity, and
  endpoint command/process-pool texture remain separate families.

Implemented fixes feeding loop 36:

- Firewall deny baseline now selects a small stable internal denied-probe source
  set per firewall sensor, preferring explicit scanner/monitoring roles, then
  workstations, then non-DC servers.
- Internal cross-segment and outbound denied probe attempts now use a
  source-sticky port profile instead of every source drawing from the same broad
  blocked-port list.
- External scanner and ICMP deny families now account for more of the generated
  firewall deny texture, reducing all-host internal sensitive-port spray.

Verification:

- Focused tests passed:
  `uv run pytest --no-cov tests/unit/test_firewall_baseline.py tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 60 SMTP rows with 60 unique
  `last_reply` values.
- Automated eval passed with score 96 over 71,212 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 82.
- Detection Engineer: Synthetic, synthetic-confidence 70.
- Network Forensics: Synthetic, synthetic-confidence 72.
- Host/EDR: Synthetic, synthetic-confidence 74.
- Average: 74.5.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 18. The uniform `last_reply` finding did not recur, but Detection and
Network both found a hard cross-source contradiction: route UIDs in
`EMAIL_ARTIFACTS.json` used canonical pre-sensor UIDs while rendered Zeek
`smtp.json`/`conn.json` used sensor-derived UIDs. Loop 18 should make email
manifest and ground-truth SMTP UID references use the same sensor-visible UID
namespace as rendered Zeek evidence.

## Loop 18

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: email delivery route summary and ground-truth SMTP UID
  reporting.
- Invariant: email manifest route UIDs and ground-truth `smtp_uids` must be in
  the same sensor-visible UID namespace as rendered Zeek `smtp.json` and
  `conn.json`.
- Entry paths: storyline email, background email, internal submission,
  internal relay, inbound SMTP, outbound direct/ISP relay, and sensor
  multiplexing.
- Consumers: `EMAIL_ARTIFACTS.json`, `GROUND_TRUTH.json`,
  `GROUND_TRUTH.md`, Zeek `smtp.json`, Zeek `conn.json`, evaluator parsers,
  and blind detection/network review.
- Residual sibling risk: STARTTLS SMTP visibility, Zeek SMTP `path`
  semantics, port-587 TLS posture, external SMTP peer role realism, manifest
  label leakage, and endpoint mail-client attribution remain separate families.

Implemented fixes:

- Added sensor-visible UID derivation for email route summaries.
- Updated `EmailDeliveryResult.smtp_uids` so ground truth references rendered
  Zeek sensor UIDs instead of canonical pre-sensor UIDs.
- Added regression assertions that manifest route UIDs and ground-truth SMTP
  UIDs exist in rendered Zeek SMTP rows.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 60 manifest route UIDs and
  10 ground-truth SMTP UIDs, with zero missing from Zeek `smtp.json` or
  `conn.json`.
- Automated eval passed with score 96 over 71,212 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 72.
- Detection Engineer: Synthetic, synthetic-confidence 72.
- Network Forensics: Synthetic, synthetic-confidence 68.
- Host/EDR: Synthetic, synthetic-confidence 68.
- Average: 70.0.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 19. The manifest UID contradiction did not recur. The highest-priority
remaining cross-source issue is STARTTLS visibility: encrypted SMTP rows still
expose post-STARTTLS envelope/reply/path fields. Loop 19 should suppress those
protected fields in Zeek SMTP output while preserving plaintext SMTP metadata
and Zeek files linkage.

## Loop 19

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: Zeek SMTP emitter visibility rules for protected SMTP
  transfer.
- Invariant: STARTTLS-protected SMTP hops should not expose post-STARTTLS
  envelope, header, reply, path, body, or file metadata in Zeek SMTP/files
  evidence; plaintext hops should still expose SMTP metadata and MIME fuids.
- Entry paths: internal relay STARTTLS, outbound relay STARTTLS, inbound relay
  STARTTLS, plaintext client submission, plaintext inbound/outbound hops, and
  MIME file extraction.
- Consumers: Zeek `smtp.json`, Zeek `ssl.json`, Zeek `files.json`, email
  artifacts, evaluator checks, and blind network/detection review.
- Residual sibling risk: SMTP `path` semantics on plaintext rows, DNS NS/PTR
  cache repeats, port-587 plaintext posture, external SMTP peer role realism,
  endpoint mail-client attribution, and manifest label leakage remain separate
  families.

Implemented fixes:

- Suppressed `mailfrom`, `rcptto`, `last_reply`, `path`, headers, message IDs,
  subjects, user agents, and fuids from protected SMTP rows.
- Preserved plaintext SMTP envelope/reply/header/fuid visibility.
- Added regression coverage for encrypted internal relays, mixed-recipient
  routes, and plaintext SMTP metadata preservation.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 21 protected SMTP rows with
  zero protected-field leaks and 39 plaintext rows with retained envelope/reply
  metadata.
- Automated eval passed with score 96 over 71,212 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 74.
- Detection Engineer: Inconclusive, synthetic-confidence 54.
- Network Forensics: Synthetic, synthetic-confidence 82.
- Host/EDR: Synthetic, synthetic-confidence 76.
- Average: 71.5.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 20. The STARTTLS hard contradiction improved the Detection Engineer score
but did not solve the category. The next highest-signal Zeek SMTP issue is
plaintext `path` rendering: all visible `path` values still look mechanically
derived as `[destination, source]`. Loop 20 should derive SMTP paths from
prior route/Received-chain context or omit them when no prior path is visible.

## Loop 20

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: email delivery route context and Zeek SMTP `path`
  rendering.
- Invariant: Zeek SMTP `path` must not be mechanically derived from the
  current network tuple as `[id.resp_h, id.orig_h]`; it should use prior
  route/Received-chain context when visible, or be omitted when no prior path
  is available.
- Entry paths: client submission, inbound SMTP, internal relay, outbound relay,
  ISP relay, STARTTLS-protected hops, and plaintext multi-hop delivery.
- Consumers: Zeek `smtp.json`, email artifacts/Received headers, evaluator
  checks, and blind network/detection review.
- Residual sibling risk: MIME body hash reuse, MIME file timestamp ordering,
  SMTP byte/duration texture, DNS cache repeats, port-587 plaintext posture,
  external SMTP peer role realism, endpoint mail-client attribution, and
  manifest label leakage remain separate families.

Implemented fixes:

- Added Received-chain-like SMTP path selection from prior route hops.
- Removed the Zeek SMTP emitter fallback that rendered missing paths as the
  reversed current tuple.
- Added regression coverage that visible SMTP `path` values are not the
  reversed current tuple.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 60 SMTP rows, 5 rows with
  `path`, and 0 paths equal to `[id.resp_h, id.orig_h]`.
- Automated eval passed with score 96 over 71,212 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 72.
- Detection Engineer: Synthetic, synthetic-confidence 74.
- Network Forensics: Synthetic, synthetic-confidence 68.
- Host/EDR: Synthetic, synthetic-confidence 72.
- Average: 71.5.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 21. The SMTP `path` finding improved the Network score but did not solve
the category. The next highest-signal cross-source issue is MIME/files
realism: one report found MIME part timestamps out of source order, and another
found identical tiny body hashes reused across unrelated message IDs. Loop 21
should preserve MIME part observation order and diversify generated body
content at the owning email body/MIME file-transfer layer.

## Loop 21

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: canonical email body/MIME rendering and Zeek file
  sibling observation for SMTP transfers.
- Invariant: generated `.eml` body parts and Zeek `files.json` body/attachment
  rows should vary by message context and render in plausible source order
  within the parent SMTP connection.
- Entry paths: storyline artifact-backed mail, corpus-backed background mail,
  template-backed background mail, plaintext SMTP MIME extraction, encrypted
  SMTP visibility reduction, and multi-part attachment rendering.
- Consumers: `.eml` artifacts, `EMAIL_ARTIFACTS.json`, Zeek `smtp.json`,
  Zeek `files.json`, evaluator consistency checks, and blind
  detection/network review.
- Residual sibling risk: mail-route DNS transaction texture, fixed
  Received-header timing, SMTP byte/duration texture, external SMTP peer role
  realism, port-587 plaintext posture, endpoint mail-client attribution, and
  manifest label leakage remain separate families.

Implemented fixes:

- Added deterministic message-context lines to generated body content so
  template-backed messages no longer produce identical small body hashes across
  unrelated message IDs.
- Contextualized corpus-backed background message bodies without changing
  storyline-authored artifact content.
- Made sibling Zeek MIME file observations monotonic within the parent SMTP
  connection instead of allowing later MIME parts to render before earlier
  parts.
- Added regression coverage for cross-message body hash reuse and MIME file
  timestamp ordering.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found zero MIME order inversions and
  zero cross-message body hash reuse.
- Automated eval passed with score 96 over 72,829 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 67.
- Detection Engineer: Inconclusive, synthetic-confidence 46.
- Network Forensics: Synthetic, synthetic-confidence 82.
- Host/EDR: Synthetic, synthetic-confidence 84.
- Average: 69.75.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 22. The MIME/body findings did not recur in the local probe, but the
Network and Detection reviews both pointed at mail-route DNS texture and
mechanical Received/header timing. Loop 22 should vary email DNS transaction
IDs, TTLs, and RTTs, and avoid fixed relay gaps in generated Received headers.

## Loop 22

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: explicit email topology and generic baseline traffic
  profile boundary.
- Invariant: when `environment.email` is configured, SMTP-looking traffic must
  be generated through the email delivery bundle, not through generic
  role-profile network noise. Every visible port 25/587 mail connection should
  have the expected SMTP parser companion unless modeled as a different
  protocol outcome with corresponding evidence.
- Entry paths: mail-server role outbound traffic, mail-server role inbound
  traffic, typed storyline email, background email, STARTTLS relay, plaintext
  submission, and explicit/automatic mailbox reads.
- Consumers: Zeek `conn.json`, `smtp.json`, `ssl.json`, `files.json`,
  `EMAIL_ARTIFACTS.json`, evaluator cross-source checks, and blind
  network/detection review.
- Residual sibling risk: client-submission TLS posture, endpoint mail-client
  attribution, external SMTP peer IP role realism, MIME payload scale,
  DNS-cache personality, STARTTLS imperfection, and manifest label leakage
  remain separate families.

Implemented fixes feeding loop 22:

- Varied email-route DNS transaction IDs, TTLs, and RTTs for explicit mail
  route lookups.
- Replaced fixed four-second Received-header relay spacing with deterministic
  per-hop timing variation.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 320 mail-related DNS rows,
  zero `trans_id: 0` rows, 311 unique DNS RTT values, and zero exact
  four-second Received-header gaps.
- Automated eval passed with score 96 over 72,829 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 74.
- Detection Engineer: Inconclusive, synthetic-confidence 52.
- Network Forensics: Synthetic, synthetic-confidence 76.
- Host/EDR: Synthetic, synthetic-confidence 74.
- Average: 69.0.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 23. The DNS transaction-ID and fixed Received-gap findings were reduced,
but the Network review found a larger cross-source contract violation: 297
visible SMTP-port connections but only 60 SMTP parser rows, with the orphan
flows coming from generic mail-server role-profile traffic. Loop 23 should
suppress profile-generated SMTP when explicit email topology exists so mail
traffic is owned by the email bundle.

## Loop 23

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: SMTP route transfer sizing and DNS route semantics in
  the email delivery bundle.
- Invariant: visible SMTP relay connections, including STARTTLS-protected hops,
  should carry byte, packet, and duration weight consistent with the message
  they transport. Configured ISP smart hosts should be resolved as smart-host
  A/AAAA targets, not as self-referential recipient-domain MX lookups.
- Entry paths: outbound ISP relay delivery, internal STARTTLS relay, inbound
  mail relay, plaintext submission, background mail, storyline artifact-backed
  mail, and route DNS prerequisite generation.
- Consumers: Zeek `conn.json`, `dns.json`, `smtp.json`, `ssl.json`,
  `files.json`, evaluator checks, and blind network/detection review.
- Residual sibling risk: endpoint mail-client attribution, source-native MTA
  logs, public SMTP peer IP role realism, client-submission TLS posture,
  DNS-cache personality, MIME payload scale, STARTTLS imperfection, and
  manifest label leakage remain separate families.

Implemented fixes feeding loop 23:

- Suppressed generic traffic-profile SMTP when explicit `environment.email`
  topology exists, so mail-shaped port 25/587 traffic is generated through the
  email bundle.
- Added regression coverage requiring explicit-email mail-port connections to
  have matching Zeek SMTP rows.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 60 mail-port connections, 60
  SMTP rows, and zero missing SMTP parser UIDs, down from 237 orphan
  mail-port connections in loop 22.
- Automated eval passed with score 96 over 77,151 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 76.
- Detection Engineer: Synthetic, synthetic-confidence 82.
- Network Forensics: Synthetic, synthetic-confidence 86.
- Host/EDR: Synthetic, synthetic-confidence 72.
- Average: 79.0.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 24. The orphan SMTP connection finding did not recur, but Network found
two high-signal SMTP route realism issues: STARTTLS relay connections carried
only handshake-scale byte counts, and configured ISP relay DNS was modeled as
self-referential MX lookups. Loop 24 should size relay connections from the
message body/attachment weight and treat ISP relays as smart-host A/AAAA
resolution targets.

## Loop 24

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: SMTP STARTTLS evidence attached to canonical network
  connection events.
- Invariant: SMTP STARTTLS hops should preserve the existing
  `conn`/`smtp`/`ssl` UID contract while rendering source-native TLS
  certificate artifacts where passive Zeek could observe them. TLS 1.2
  STARTTLS rows should link `ssl.cert_chain_fuids` to Zeek `files.json` and
  `x509.json`; TLS 1.3 rows remain opaque without passive cert extraction.
- Entry paths: internal relay STARTTLS, outbound smart-host STARTTLS, inbound
  relay STARTTLS, storyline email, background email, and Zeek files/x509
  fanout.
- Consumers: Zeek `smtp.json`, `conn.json`, `ssl.json`, `files.json`,
  `x509.json`, evaluator cross-source checks, and blind network/detection
  review.
- Residual sibling risk: client-submission TLS posture, endpoint mail-client
  attribution, source-native MTA logs, public SMTP peer IP role realism,
  DNS-cache personality, MIME payload scale, STARTTLS imperfection, and
  manifest label leakage remain separate families.

Implemented fixes feeding loop 24:

- Sized SMTP relay connections from deterministic body/attachment/recipient
  weight so encrypted relays no longer look like handshake-only flows.
- Modeled configured ISP relay routing as smart-host A-record resolution rather
  than self-referential MX lookup.
- Added regression coverage for smart-host DNS and STARTTLS relay byte scale.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 11 `smtp.metroline.example`
  DNS rows, all A records and zero MX rows; 21 STARTTLS SMTP rows with
  minimum `orig_bytes` 2,228 and mean `orig_bytes` 3,247.95.
- Automated eval passed with score 96 over 75,327 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 78.
- Detection Engineer: Synthetic, synthetic-confidence 78.
- Network Forensics: Synthetic, synthetic-confidence 78.
- Host/EDR: Inconclusive, synthetic-confidence 42.
- Average: 69.0.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 25. Host/EDR dropped below the threshold individually, but Network still
found missing certificate-chain evidence for SMTP STARTTLS rows. Loop 25 should
attach TLS 1.2 SMTP STARTTLS certificate chains through canonical x509/files
contexts while preserving TLS 1.3 opacity.

## Loop 25

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: Zeek SMTP row shape and STARTTLS visibility semantics in
  the SMTP emitter, backed by canonical SMTP/file contexts.
- Invariant: every Zeek SMTP row should keep a stable parser-compatible field
  shape, while STARTTLS-protected transfers expose only unprotected connection
  and TLS facts. Protected rows should not leak message headers, envelope
  values, body/file metadata, or MIME FUIds.
- Entry paths: plaintext submission, plaintext relay, internal STARTTLS relay,
  outbound smart-host STARTTLS, inbound relay STARTTLS, storyline messages,
  background messages, artifact-backed MIME messages, and corpus-backed mail.
- Consumers: Zeek `smtp.json`, `conn.json`, `ssl.json`, `files.json`,
  `x509.json`, `EMAIL_ARTIFACTS.json`, evaluator schema checks, evaluator
  cross-source checks, and blind network/detection review.
- Residual sibling risk: client-submission TLS posture, endpoint mail-client
  attribution, source-native MTA logs, public SMTP peer IP role realism,
  DNS-cache personality, MIME payload scale, STARTTLS imperfection, and
  manifest label leakage remain separate families.

Implemented fixes feeding loop 25:

- Added SMTP STARTTLS certificate evidence for TLS 1.2 protected hops.
- Routed SMTP STARTTLS certificate chains through canonical network connection,
  Zeek `ssl`, Zeek `files`, and Zeek `x509` contexts.
- Preserved TLS 1.3 opacity so TLS 1.3 SMTP STARTTLS rows do not fabricate
  passive certificate artifacts.
- Added regression coverage forcing TLS 1.2 on the ISP relay path to verify
  `ssl.cert_chain_fuids` link to both `files.json` and `x509.json`.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 21 SMTP STARTTLS rows, 17 TLS
  1.2 SMTP STARTTLS rows, certificate chains on all 17 TLS 1.2 rows, 41
  certificate FUIds, and zero missing `files.json` or `x509.json` references.
- Automated eval passed with score 97 over 75,409 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 60.
- Detection Engineer: Inconclusive, synthetic-confidence 42.
- Network Forensics: Synthetic, synthetic-confidence 28.
- Host/EDR: Synthetic, synthetic-confidence 72.
- Average: 50.5.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 26. STARTTLS certificate linkage improved, but Detection and Network both
flagged Zeek SMTP field-shape/schema gaps. Loop 26 should stabilize Zeek SMTP
optional fields across plaintext and protected rows without leaking protected
headers, envelope values, or MIME file metadata.

## Loop 26

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: SMTP route planning and Zeek-visible DNS/SMTP route
  causality.
- Invariant: outbound SMTP route decisions should remain explicit and
  deterministic without collapsing multi-domain delivery into one synthetic
  destination. Direct MX routing should emit recipient-domain MX lookups,
  selected-MX A lookups, and SMTP connections to the selected hosts. ISP relay
  mode should make smart-host routing evident and should not hide route policy
  behind one sender-only choice when multiple relays are configured.
- Entry paths: storyline outbound messages, background outbound messages,
  sender-group route overrides, direct MX routing, global ISP relays,
  route-specific ISP relay lists, Zeek DNS, Zeek SMTP, Zeek conn, STARTTLS
  relay evidence, and `EMAIL_ARTIFACTS.json`.
- Consumers: Zeek `dns.json`, `conn.json`, `smtp.json`, `ssl.json`,
  `files.json`, `x509.json`, `EMAIL_ARTIFACTS.json`, evaluator consistency
  checks, and blind network/detection review.
- Residual sibling risk: client-submission TLS posture, endpoint mail-client
  attribution, source-native MTA logs, public SMTP peer IP role realism,
  fleet-wide mailbox-read topology, DNS companion-query behavior, SMTP failure
  and retry texture, and manifest label leakage remain separate families.

Implemented fixes feeding loop 26:

- Stabilized Zeek SMTP row shape so plaintext and protected SMTP rows include
  the same parser-compatible optional fields.
- Preserved STARTTLS opacity by rendering protected envelope/header/body/file
  fields as empty strings or arrays instead of missing keys, nulls, or leaked
  values.
- Updated regression coverage for protected SMTP rows to require stable empty
  values rather than absent keys.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 60 SMTP rows, 39 plaintext
  rows, 21 protected rows, zero missing required SMTP fields, and protected
  rows with blank strings/empty arrays for protected values.
- Automated eval passed with score 97 over 75,409 records.

Blind panel:

- Threat Hunter: Inconclusive leaning realistic, synthetic-confidence 34.
- Detection Engineer: Mostly realistic and detection-useful,
  synthetic-confidence 38.
- Network Forensics: Synthetic-leaning, synthetic-confidence 70.
- Host/EDR: Fail for host/EDR realism, synthetic-confidence 84.
- Average: 56.5.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 27. Detection explicitly called the SMTP field shape parser-compatible,
and Threat Hunter dropped below the threshold, but Network still flagged
outbound SMTP route collapse and MX-to-A causality while Host/EDR highlighted
endpoint ownership as the largest remaining non-Zeek sibling family. Loop 27
should split outbound external routing by recipient domain, choose ISP relays
with sender-plus-domain scope when a relay pool exists, fix direct-MX owner
queries, and enrich manifest route metadata with FQDN/routing-mode/domain
fields.

## Loop 27

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: authoritative DNS identity for configured email topology.
- Invariant: configured mail server FQDNs from `environment.email` should be
  answered by the systems that own those mail server objects, even when the mail
  accepted domain differs from the AD domain. Generic DNS/background helpers
  must not answer a mail FQDN with unrelated DC, file-server, workstation, web,
  or random internal IPs.
- Entry paths: explicit email route DNS, automatic connection-prerequisite DNS,
  baseline DNS companion/background rows, smart-host A lookups, direct MX
  lookups, and caller-provided `DnsContext` normalization.
- Consumers: Zeek `dns.json`, `conn.json`, `smtp.json`, `ssl.json`,
  `EMAIL_ARTIFACTS.json`, evaluator consistency checks, and blind
  network/detection review.
- Residual sibling risk: client-submission TLS posture, endpoint mail-client
  attribution, source-native MTA logs, public SMTP peer IP role realism,
  fleet-wide mailbox-read topology, SMTP failure/retry texture, and answer-key
  fields in blind-facing artifacts remain separate families.

Implemented fixes feeding loop 27:

- Split outbound external delivery by recipient domain so one message with
  multiple external domains creates separate domain-scoped SMTP route hops.
- Selected configured ISP relays with sender-plus-recipient-domain scope when a
  relay pool exists, instead of choosing only by sender.
- Fixed direct-MX route DNS so MX owner queries use the recipient domain and A
  lookups resolve the selected MX host.
- Added selected-host A lookups after generic companion MX answers, leaving
  unselected alternate MX hosts unresolved.
- Enriched `EMAIL_ARTIFACTS.json` route entries with source/destination FQDN,
  routing mode, and recipient-domain metadata.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 10 outbound smart-host SMTP
  sessions spread across three relay IPs and smart-host/domain route metadata
  for the external recipient domains.
- Companion MX unresolved selected hosts dropped substantially; remaining
  unresolved MX names were unselected alternate targets from multi-answer MX
  responses.
- Automated eval passed with score 96 over 72,575 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 52.
- Detection Engineer: Synthetic but detection-useful, synthetic-confidence 68.
- Network Forensics: Revise before analyst-facing use, synthetic-confidence 82.
- Host/EDR: Synthetic, synthetic-confidence 74.
- Average: 69.0.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 28. The route-collapse finding improved, but Network found a stronger DNS
identity failure: `mail.alderridge.example` answered with unrelated internal
hosts because generic DNS paths did not treat configured email FQDNs as
authoritative internal names. Loop 28 should make `environment.email` mail
server hostnames authoritative for both automatic DNS lookups and normalized
caller-provided DNS contexts.

## Loop 28

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: public identity pools for SMTP senders, external MX
  targets, and configured smart hosts.
- Invariant: public SMTP peers should use mail-role IP, PTR, DNS, SNI, and
  certificate identities rather than borrowing generic web/CDN/SaaS address
  pools. Port 25 senders and relays should look like MTAs or relay providers,
  while generic browser/CDN activity keeps its separate public identity model.
- Entry paths: inbound external SMTP senders, outbound smart-host hops, direct
  external MX hops, public PTR companion lookups, STARTTLS SNI/cert generation,
  Zeek DNS, Zeek SMTP, Zeek SSL/X.509, and route manifests.
- Consumers: Zeek `dns.json`, `conn.json`, `smtp.json`, `ssl.json`,
  `x509.json`, `EMAIL_ARTIFACTS.json`, evaluator consistency checks, and blind
  network/detection review.
- Residual sibling risk: client-submission TLS posture, endpoint mail-client
  attribution, source-native MTA logs, SMTP failure/retry texture, STARTTLS
  pre-encryption reply semantics, and answer-key fields in blind-facing
  artifacts remain separate families.

Implemented fixes feeding loop 28:

- Made configured `environment.email` mail server hostnames authoritative for
  automatic DNS lookups and normalized caller-provided `DnsContext` rows.
- Treated configured mail FQDNs as internal even when the accepted mail domain
  differs from the AD domain.
- Rewrote A/AAAA answers for configured mail hostnames to the owning mail
  server system IP and deterministic IPv6 mapping.
- Added regression coverage for a mail accepted domain outside the AD DNS
  namespace.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found `mail.alderridge.example`
  answering only `10.55.20.25` for A and `fd00:3714:0019::1` for AAAA, instead
  of unrelated DC, file-server, mailbox-server, or workstation IPs.
- Automated eval passed with score 97 over 69,446 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 76.
- Detection Engineer: Pass with reservations, synthetic-confidence 58.
- Network Forensics: Synthetic, synthetic-confidence 78.
- Host/EDR: Synthetic, synthetic-confidence 82.
- Average: 73.5.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 29. The internal mail DNS drift finding did not recur, but Network and
Detection both called out public SMTP peer identity: inbound senders and
outbound smart hosts were still drawn from web/CDN-looking IP families with PTR
and provider identities that did not look like mail infrastructure. Loop 29
should add mail-specific public identity pools and use them for external SMTP
senders, smart hosts, direct MX targets, and PTR answers.

## Loop 29

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: source-native STARTTLS visibility in Zeek SMTP rows.
- Invariant: STARTTLS-protected SMTP rows should expose only pre-encryption SMTP
  negotiation facts such as EHLO/STARTTLS replies while keeping post-STARTTLS
  envelope, headers, body, and file metadata opaque. TLS rows should not look
  like perfectly blank parser placeholders when Zeek would normally see the
  `220` reply that begins TLS negotiation.
- Entry paths: internal STARTTLS relay, outbound smart-host STARTTLS, inbound
  STARTTLS when modeled, Zeek SMTP rendering, Zeek SSL/X.509 linkage, and
  evaluator parser/schema checks.
- Consumers: Zeek `smtp.json`, `conn.json`, `ssl.json`, `files.json`,
  `x509.json`, `EMAIL_ARTIFACTS.json`, evaluator consistency checks, and blind
  network/detection review.
- Residual sibling risk: client-submission TLS posture, endpoint mail-client
  attribution, source-native MTA logs, SMTP failure/retry texture, DNS
  causality for cached/internal first-use routes, and answer-key fields in
  blind-facing artifacts remain separate families.

Implemented fixes feeding loop 29:

- Added data-driven mail-specific public SMTP identity pools under
  `config/activity/mail_public_identities.yaml`.
- Routed external SMTP senders, smart hosts, and direct MX targets through the
  mail-specific public IP helper instead of generic web/CDN public IP pools.
- Added mail-style PTR answers for mail-specific public IP ranges.
- Added regression coverage that inbound and outbound external SMTP peers come
  from the mail identity pool and have mail-style PTR support.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 12 unique external SMTP IPs,
  all in the mail-specific identity pool, with mail-style PTR evidence for the
  observed relay PTR lookup.
- Automated eval passed with score 97 over 69,379 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 48.
- Detection Engineer: Pass with targeted fixes, synthetic-confidence 38.
- Network Forensics: Synthetic, synthetic-confidence 74.
- Host/EDR: Host/EDR realism rejection, synthetic-confidence 88.
- Average: 62.0.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 30. Detection dropped below the threshold and Threat Hunter nearly did,
but Network still flagged STARTTLS source semantics and SMTP transaction
texture. Loop 30 should preserve pre-STARTTLS reply metadata on encrypted SMTP
rows while continuing to suppress post-STARTTLS envelope, header, body, and
file metadata.

## Loop 30

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: SMTP MIME/file and source-native transfer texture in the
  email action bundle before Zeek rendering.
- Invariant: plaintext SMTP should expose body and attachment file evidence
  whose sizes and timestamps come from the canonical rendered message, not
  post-hoc emitter sizing. STARTTLS-protected hops remain opaque after the TLS
  upgrade, while pre-STARTTLS negotiation metadata can remain visible.
- Entry paths: storyline email, background email, corpus-backed content,
  artifact-backed MIME messages, inbound external SMTP, internal relays,
  outbound smart-host relays, Zeek SMTP, Zeek files, and email artifacts.
- Consumers: Zeek `smtp.json`, `files.json`, `conn.json`, `ssl.json`,
  `x509.json`, `.eml` artifacts, `EMAIL_ARTIFACTS.json`, evaluator checks, and
  blind network/detection review.
- Residual sibling risk: V1 plaintext client submission, endpoint mail-client
  attribution, source-native MTA logs, DNS cache/causality texture, and
  mailbox-read semantics remain separate families.

Implemented fixes feeding loop 30:

- Preserved source-native STARTTLS negotiation replies on encrypted SMTP rows
  instead of rendering protected rows as empty parser placeholders.
- Kept post-STARTTLS envelope, header, recipient, body, and file metadata
  suppressed for encrypted hops.
- Added focused coverage that encrypted SMTP rows retain pre-TLS reply metadata
  while omitting protected SMTP details and `files.log` linkage.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 21 TLS SMTP rows with visible
  `220` STARTTLS replies and no leaked subject, recipients, message IDs, or
  file identifiers.
- Automated eval passed with score 97 over 69,379 records.

Blind panel:

- Threat Hunter: Realistic, synthetic-confidence 26.
- Detection Engineer: Synthetic-leaning but detection-useful,
  synthetic-confidence 78.
- Network Forensics: Marginal pass for hunt usability, synthetic-confidence 72.
- Host/EDR: Conditional fail, synthetic-confidence 78.
- Average: 63.5.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 31. STARTTLS opacity improved, but Detection and Network both continued
to flag SMTP/MIME transfer texture, especially very tidy body/file sizes and
thin transfer realism. Loop 31 should improve body-size texture at the
canonical rendered-message layer so Zeek file rows naturally reflect more
realistic content without falsifying emitter-side byte counts.

## Loop 31

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: external SMTP public identity planning for DNS, PTR,
  STARTTLS SNI/certificates, Received headers, and route manifests.
- Invariant: public SMTP infrastructure rendered as Internet-facing DNS/TLS/PTR
  evidence should not use bare reserved TLD hostnames such as `.example`,
  `.test`, `.invalid`, or `.localhost`, even when scenario authors use those
  domains as safe shorthand. Internal accepted domains remain exactly as
  authored.
- Entry paths: inbound external SMTP sender MX hosts, outbound direct-MX
  targets, configured ISP smart hosts, mail public PTR generation, SMTP
  STARTTLS SSL/X.509, route DNS evidence, Received headers, and baseline
  background email domains.
- Consumers: Zeek `dns.json`, `smtp.json`, `ssl.json`, `x509.json`,
  `conn.json`, `.eml` artifacts, `EMAIL_ARTIFACTS.json`, evaluator checks, and
  blind network/detection/threat review.
- Residual sibling risk: V1 plaintext client submission, answer-key-like
  manifest fields in blind packets, endpoint mail-client attribution, and
  non-email proxy/firewall texture remain separate families.

Implemented fixes feeding loop 31:

- Added deterministic mail-client/gateway footer material at the canonical
  rendered-body layer before MIME and Zeek file rendering.
- Preserved emitter-side byte truth by allowing `files.json` sizes to derive
  from the rendered MIME body and attachments instead of post-hoc size edits.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found SMTP body part sizes ranging
  from 404 to 574 bytes with a median of 515 bytes, while attachment rows
  remained tied to their actual small test payloads.
- Automated eval passed with score 97 over 69,379 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 64.
- Detection Engineer: Synthetic, synthetic-confidence 66.
- Network Forensics: Synthetic, synthetic-confidence 64.
- Host/EDR: Real, synthetic-confidence 32.
- Average: 56.5.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so Zeek cross-source contracts remain active for
loop 32. The SMTP file/body texture issue softened and Host review dropped
below threshold, but the panel clustered on public external mail identities
using reserved `.example` TLDs in DNS, STARTTLS certificates, Received headers,
SMTP HELOs, and artifacts. Loop 32 should keep internal safe domains intact
while rendering external public SMTP infrastructure under less glaring
reserved-domain forms such as `*.example.net` and update the assessment
scenario's explicit external partner names accordingly.

## Loop 32

Priority category: Zeek cross-source contracts.

Family contract:

- Owning abstraction: external SMTP public identity planning for DNS, PTR,
  STARTTLS SNI/certificates, Received headers, and route manifests.
- Invariant: Internet-facing SMTP identities should not render as bare reserved
  TLDs when the same names are presented as public DNS/TLS/PTR infrastructure.
  Internal accepted domains remain scenario-authored safe domains.
- Entry paths: inbound external senders, outbound direct MX targets, ISP smart
  hosts, baseline background external email domains, public mail PTR, route DNS,
  SMTP `helo`, STARTTLS SSL/X.509, Received headers, `.eml` artifacts, and
  `EMAIL_ARTIFACTS.json`.
- Consumers: Zeek `dns.json`, `smtp.json`, `ssl.json`, `x509.json`,
  `files.json`, `.eml`, `EMAIL_ARTIFACTS.json`, blind network/detection/threat
  review, and evaluator consistency checks.
- Residual sibling risk: V1 plaintext client submission, endpoint mail-client
  attribution, manifest semantics in blind packets, proxy/firewall distribution
  texture, and collection-window documentation remain separate families.

Implemented fixes feeding loop 32:

- Added `public_safe_mail_hostname()` for external public SMTP infrastructure,
  mapping bare reserved suffixes such as `.example` to safe
  `*.example.net`-style public identities while preserving authored labels.
- Applied the helper to external source MX hosts and outbound external hops so
  route DNS, STARTTLS SNI/certificates, Received headers, and route metadata use
  the same public-safe hostname.
- Shifted built-in background external mail domains from bare `.example` names
  to `*.example.net`.
- Updated focused tests to assert `smtp.isp.example` author input renders as
  public-safe `smtp.isp.example.net` for public mail infrastructure.
- Updated the assessment scenario's explicit Internet counterparties and ISP
  relays to use `example.net`/`example.com` safe public forms.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found zero external SMTP/DNS/X.509
  bare `.example` public identities outside internal `alderridge.example`.
- Automated eval passed with score 97 over 69,365 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 36.
- Detection Engineer: Inconclusive, synthetic-confidence 38.
- Network Forensics: Inconclusive, synthetic-confidence 36.
- Host/EDR: Inconclusive, synthetic-confidence 45.
- Average: 38.75.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears the Zeek cross-source contracts priority. The next
priority category for loop 33 should be endpoint mail attribution: Host/EDR
continues to find systematic missing eCAR process/user ownership for all
workstation SMTP/587 submissions, all mail-server mail-port flows, and overly
regular `svchost.exe` ownership for IMAPS/993 reads.

## Loop 33

Priority category: endpoint mail attribution.

Family contract:

- Owning abstraction: email delivery/access action bundles as adapters into the
  canonical network-connection bundle's endpoint process ownership contract.
- Invariant: modeled mail submission, server relay, and mailbox-read network
  flows should either carry a compatible source process/principal or explicitly
  suppress endpoint process inference when no modeled client PID is available;
  opaque mailbox reads must not fall back to unrelated `svchost.exe` ownership.
- Entry paths: storyline email delivery, baseline background mail, automatic
  recipient reads, explicit `email_read` events, generic mail-server baseline
  traffic, and canonical network connection PID inference.
- Consumers: eCAR `FLOW`, Zeek `conn/smtp/ssl`, endpoint process lineage,
  evaluator cross-source checks, and blind Host/EDR review.
- Residual sibling risk: answer-key-like manifest fields, SMTP timestamp
  anchoring, DHCP/DNS endpoint configuration drift, source-native MTA logs, and
  full mailbox/client process modeling remain separate families.

Implemented fixes feeding loop 33:

- Added source PID inference suppression to canonical network connection
  requests for cases where endpoint process ownership is intentionally unknown.
- Attached modeled mail-client processes to SMTP/587 submission and mailbox-read
  flows when host/user context is available.
- Attached modeled MTA/IMAP/OWA server processes to mail-server relay and
  server-side mail access flows.
- Suppressed generic mail profile SMTP/OWA/IMAPS baseline traffic when explicit
  `environment.email` topology exists.

Verification:

- Focused tests passed:
  `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_edr_flow_pid.py::TestConnectionPidPropagation::test_connection_can_suppress_source_pid_inference -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found mail submission flows owned
  mostly by Outlook/Thunderbird, mailbox reads owned by Outlook/Thunderbird or
  browser processes when attributable, no read flows owned by `svchost.exe`, and
  all sampled server relay/access flows owned by compatible mail services.
- Automated eval passed with score 97 over 65,285 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 48.
- Detection Engineer: Inconclusive, synthetic-confidence 36.
- Network Forensics: Inconclusive, synthetic-confidence 52.
- Host/EDR: Inconclusive, synthetic-confidence 38.
- Average: 43.5.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears endpoint mail attribution. The next priority category
for loop 34 is blind-facing manifest semantics: Threat Hunter again identified
`EMAIL_ARTIFACTS.json` fields such as `storyline_id`, `verdict`, `artifact_id`,
and local artifact paths as exercise/generator metadata rather than
production-facing evidence.

## Loop 34

Priority category: blind-facing manifest semantics.

Family contract:

- Owning abstraction: email artifact manifest schema plus evaluator
  ground-truth matching.
- Invariant: `EMAIL_ARTIFACTS.json` is a production-facing message manifest and
  must not expose storyline IDs, exercise verdict labels, generator artifact
  IDs, or local filesystem paths. Scenario/storyline correlation belongs in
  `GROUND_TRUTH.json`, and evaluator causality matching should use that
  ground-truth-only linkage.
- Entry paths: storyline email artifacts, background artifact-backed messages,
  metadata-only background messages, `EMAIL_ARTIFACTS.json` rendering, email
  docs/skill references, and causality event-presence matching.
- Consumers: blind review packages, email artifact browsers, evaluator
  causality checks, `GROUND_TRUTH.json`, `GROUND_TRUTH.md`, docs, and
  development skill references.
- Residual sibling risk: `.eml` header ordering and content texture, SMTP row
  timestamp anchoring, DHCP/DNS endpoint configuration drift, and reviewer
  packaging choices remain separate families.

Implemented fixes feeding loop 34:

- Removed `storyline_id`, `verdict`, `artifact_id`, and local `artifact_path`
  from `EMAIL_ARTIFACTS.json`.
- Replaced manifest `mail_action` with production-facing `delivery_action` and
  exposed only a relative `eml_path` basename for materialized messages.
- Loaded email storyline identifiers from `GROUND_TRUTH.json` inside the
  evaluator so email artifact event-presence checks no longer depend on leaking
  storyline labels into the artifact manifest.
- Updated user-facing docs and repo-local development skill references to
  describe the manifest as production-facing metadata.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe after regeneration found 34 manifest messages, zero
  leaked exercise fields, and no broken `eml_path` references.
- Automated eval passed with score 97 over 65,285 records and event presence
  remained 8/8.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 46.
- Detection Engineer: Real, synthetic-confidence 28.
- Network Forensics: Synthetic, synthetic-confidence 62.
- Host/EDR: Inconclusive, synthetic-confidence 43.
- Average: 44.75.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears blind-facing manifest semantics. The next priority
category for loop 35 is email artifact/content texture: the user observed
source-native but odd `.eml` header ordering, and loop-34 Threat Hunter still
found repeated background email subjects across unrelated senders/recipients.

## Loop 35

Priority category: email artifact/content texture.

Family contract:

- Owning abstraction: email delivery bundle corpus adaptation plus `.eml`
  source-native renderer.
- Invariant: storyline/corpus-authored message content remains authoritative,
  but background reuse of a corpus entry gets deterministic per-message subject
  context so unrelated messages do not expose a tiny phrase pool. Materialized
  `.eml` headers should use profile-appropriate ordering that resembles common
  received Outlook, Thunderbird, Apple Mail, and automated-service messages
  rather than technically valid but odd generic ordering.
- Entry paths: storyline `.eml` artifacts, background corpus-backed messages,
  metadata-only background SMTP rows, corpus custom headers, MIME artifacts,
  Zeek SMTP subject metadata, and `EMAIL_ARTIFACTS.json`.
- Consumers: `.eml` artifacts, Zeek `smtp.json`, Zeek `files.json`,
  `EMAIL_ARTIFACTS.json`, evaluator consistency checks, and blind
  threat-hunter/detection review.
- Residual sibling risk: broader mail body semantic variety, background corpus
  size authored by scenario creators, SMTP timestamp anchoring, non-email proxy
  and scanner texture, and full mailbox client modeling remain separate
  families.

Implemented fixes feeding loop 35:

- Background corpus-backed messages now get deterministic subject variants
  based on sender, recipients, and event time, while explicit storyline/event
  subjects remain unchanged.
- `.eml` profile header order was adjusted so common original headers and
  custom headers land in more source-native positions before `Message-ID` and
  MIME structure where appropriate.
- Focused tests now cover contextualized background corpus subjects and the
  updated header-order invariants for Outlook-like and automated service
  messages.

Verification:

- Focused tests passed: `uv run pytest --no-cov tests/unit/test_email_evidence.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 42.
- Detection Engineer: Inconclusive, synthetic-confidence 30.
- Network Forensics: Inconclusive, synthetic-confidence 52.
- Host/EDR: Real, synthetic-confidence 32.
- Average: 39.0.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears email artifact/content texture. The next priority
category for loop 36 is failed sensitive-port probe distribution.

## Loop 36

Priority category: failed sensitive-port probe distribution.

Implemented fixes feeding loop 36:

- Concentrated internal firewall false-positive probe traffic into a smaller,
  more plausible set of hosts and reduced broad sensitive-port spray behavior.
- Reduced internal firewall probe volume so low-value denied connections no
  longer dominated the visible network/security texture.

Verification:

- Focused probe showed fewer internal denied sensitive-port connection
  families, with less workstation-wide fan-out.
- `uv run ruff check .` and `uv run ruff format --check .` passed before the
  related commits.

Blind panel:

- Threat Hunter: Real, synthetic-confidence 34.
- Detection Engineer: Inconclusive, synthetic-confidence 34.
- Network Forensics: Real, synthetic-confidence 28.
- Host/EDR: Real, synthetic-confidence 29.
- Average: 31.25.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears failed sensitive-port probe distribution. The next
priority category for loop 37 is DHCP/DNS endpoint configuration consistency.

## Loop 37

Priority category: DHCP/DNS endpoint configuration consistency.

Family contract:

- Owning abstraction: baseline DHCP registry side-effect materialization and
  endpoint configuration template expansion.
- Invariant: endpoint registry evidence for DHCP-provided DNS servers must
  render the actual modeled DHCP/DNS server for the environment, not a static
  address from a generic template.
- Entry paths: DHCP baseline lease evidence, Windows registry side effects,
  eCAR registry rendering, DNS resolver evidence, and endpoint configuration
  probes.
- Consumers: eCAR registry rows, Zeek DHCP/DNS, evaluator consistency checks,
  and blind host/detection review.

Implemented fixes feeding loop 37:

- Replaced the hardcoded `10.10.2.10` DHCP DNS registry template value with a
  `{dns_server_ip}` placeholder.
- Passed the modeled DHCP lease DNS server into EDR registry template
  materialization.
- Added focused unit tests for EDR template substitution and baseline DHCP
  registry side effects.

Verification:

- Focused tests passed:
  `uv run pytest --no-cov tests/unit/test_edr_pools.py tests/unit/test_baseline_canonical.py -q`.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe found DHCP servers `10.55.20.10`, DNS servers
  `10.55.20.10`, and all 13 `DhcpNameServer` registry writes using
  `10.55.20.10`.
- Automated eval passed with score 95.699 over 65,037 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 42.
- Detection Engineer: Inconclusive, synthetic-confidence 28.
- Network Forensics: Inconclusive, synthetic-confidence 38.
- Host/EDR: Inconclusive, synthetic-confidence 45.
- Average: 38.25.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears DHCP/DNS endpoint configuration consistency. The next
priority category for loop 38 is eCAR flow attribution coherence.

## Loop 38

Priority category: eCAR flow attribution coherence.

Family contract:

- Owning abstraction: eCAR source-native flow attribution renderer, consuming
  canonical process/principal ownership from endpoint/process state.
- Invariant: for the same host/PID/image flow group, eCAR `FLOW` rows should
  not alternate between populated and missing principal or actor identity unless
  the canonical source intentionally lacks attribution.
- Entry paths: client outbound connections, server inbound listener flows,
  paired endpoint flow rows, failed/no-duration flows, and process-owned
  network bundle requests.
- Consumers: eCAR `FLOW`, Zeek/eCAR tuple probes, blind host/detection review,
  and endpoint process ownership tests.

Implemented fixes feeding loop 38:

- Stabilized eCAR `FLOW` principal attribution across inbound/outbound
  directions for the same host/PID/username/image identity.
- Coupled `actorID` population to principal attribution so service flows do not
  produce actor-only mixed-attribution groups.
- Allowed inbound listener `FLOW` rows to use the listener process object ID
  when principal attribution is available.

Verification:

- Focused eCAR tests passed after each attribution fix.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe found zero mixed-principal groups and zero mixed-actor
  groups after regeneration.
- Automated eval passed with score 95.790 over 65,037 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 38.
- Detection Engineer: Inconclusive, synthetic-confidence 34.
- Network Forensics: Synthetic, synthetic-confidence 68.
- Host/EDR: Inconclusive, synthetic-confidence 34.
- Average: 43.5.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears eCAR flow attribution coherence. Network review surfaced
the next priority category: source/cross-source timing texture, especially
eCAR `FLOW` timestamps landing too close to Zeek `conn` timestamps at scale.

## Loop 39

Priority category: source/cross-source timing texture.

Family contract:

- Owning abstraction: source timing and endpoint flow timestamp planning for
  eCAR `FLOW` rows relative to canonical network connection intervals.
- Invariant: endpoint flow observations should preserve lifecycle causality
  while avoiding dataset-wide near-identical timestamps to Zeek `conn` rows,
  especially for failed/no-duration and very short flows.
- Entry paths: successful short connections, failed connections, paired endpoint
  flow companions, DNS/Kerberos/NTP flows, and source-visible process-owned
  network evidence.
- Consumers: eCAR `FLOW`, Zeek `conn`, evaluator timing checks, rendered-output
  timing probes, and blind network/detection/host review.

Implemented fixes feeding loop 39:

- Added endpoint timing texture for failed/no-duration eCAR `FLOW` rows instead
  of anchoring them exactly to the canonical event timestamp.
- Spread very short completed endpoint `FLOW` observations after close with
  deterministic small-source latency instead of forcing them inside
  sub-100 ms Zeek intervals.
- Added focused tests for failed, no-duration, and short-flow endpoint timing
  behavior.

Verification:

- Focused eCAR timing tests passed.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe improved eCAR/Zeek tuple timing matches from 717 to 34
  within 1 ms, from 4,008 to 198 within 10 ms, and median delta from about
  48.6 ms to about 184.8 ms.
- Automated eval passed with score 95.740 over 65,039 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 46.
- Detection Engineer: Synthetic, synthetic-confidence 78.
- Network Forensics: Real, synthetic-confidence 35.
- Host/EDR: Inconclusive, synthetic-confidence 34.
- Average: 48.25.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold. The specific eCAR/Zeek timing issue was downgraded:
Network review called it a weak signal, Host review found endpoint/file timing
coherent, and Threat review found no hard cross-source timing contradictions.
The remaining timing-family concrete finding is exact 11 ms ICMP burst spacing,
so loop 40 targets ICMP observation cadence before moving on.

## Loop 40

Priority category: source/cross-source timing texture, narrowed to ICMP
observation cadence.

Implemented fixes feeding loop 40:

- Replaced fixed 11 ms duplicate-ICMP observation spacing with deterministic
  tuple-local variable gaps while preserving monotonic observation times and
  constant-time duplicate handling.
- Updated the focused ICMP disambiguation test to assert monotonic varied
  spacing instead of the old fixed cadence.

Verification:

- Focused test passed:
  `uv run pytest --no-cov tests/unit/test_activity.py::test_disambiguate_icmp_observation_time_uses_monotonic_varied_sequence -q`.
- `uv run ruff check src/evidenceforge/generation/activity/generator.py tests/unit/test_activity.py`
  and matching format check passed.
- Rendered-output probe after regeneration found 145 ICMP rows, 117 adjacent
  same-tuple gaps, zero exact 11 ms gaps, and 117 unique adjacent gaps.
- Automated eval passed with score 95.790 over 65,038 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 34.
- Detection Engineer: Real, synthetic-confidence 34.
- Network Forensics: Inconclusive, synthetic-confidence 43.
- Host/EDR: Inconclusive, synthetic-confidence 43.
- Average: 38.5.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears source/cross-source timing texture. The next priority
category for loop 41 is DHCP lease lifecycle continuity: Network review found
visible one-hour DHCP renewals followed by later client activity without
subsequent visible renewals.

## Loop 41

Priority category: DHCP lease lifecycle continuity.

Family contract:

- Owning abstraction: DHCP lease baseline scheduler plus DHCP lease action
  bundle.
- Invariant: DHCP-managed hosts with visible one-hour leases and later visible
  network activity should have visible renewal evidence before expiry, unless
  DHCP collection is explicitly out of scope for that host. The baseline
  scheduler must catch up from warm-up state and emit every renewal that falls
  inside the visible hour.
- Entry paths: warm-up lease acquisition, hourly baseline system traffic,
  DHCP renewal transactions, DHCP registry side effects, Zeek DHCP/conn rows,
  Linux dhclient syslog companions, and evaluator/blind network review.
- Consumers: Zeek `dhcp.json`, Zeek `conn.json`, eCAR registry side effects,
  Linux syslog, source timing checks, and blind Network/Detection review.

Implemented fixes feeding loop 41:

- Added a DHCP renewal scheduler helper that skips hidden catch-up renewals,
  emits every renewal due inside the current hour, and updates the schedule
  anchor even when no visible renewal falls in that hour.
- Replaced the old one-renewal-per-hour baseline block with iteration over the
  helper's due renewal epochs.
- Added focused tests for catch-up from warm-up and multiple visible renewals
  for one-hour leases.

Verification so far:

- Focused tests passed:
  `uv run pytest --no-cov tests/unit/test_baseline_canonical.py::TestDhcpLease::test_dhcp_renewal_schedule_catches_up_from_warmup tests/unit/test_baseline_canonical.py::TestDhcpLease::test_dhcp_renewal_schedule_emits_multiple_due_renewals tests/unit/test_activity.py::test_disambiguate_icmp_observation_time_uses_monotonic_varied_sequence -q`.
- `uv run ruff check src/evidenceforge/generation/engine/baseline.py tests/unit/test_baseline_canonical.py`
  and matching format check passed.

## Loop 42

Priority category: workstation startup and proxy/browser burst texture.

Family contract:

- Owning abstraction: baseline interactive-session activity scheduling and
  persona/profile traffic timing before browser/proxy expansion.
- Invariant: routine baseline desktop activity should not collapse unrelated
  app launches and web/proxy sessions into the first few seconds after an
  interactive logon. Startup-adjacent activity should have deterministic but
  human/OS-scale pacing, and persona web sessions should inherit that pacing
  before fan-out into proxy requests.
- Entry paths: baseline user activity, baseline persona profile traffic,
  world-planner session reuse, browser-session action bundles, proxy
  transaction evidence, Windows process telemetry, and eCAR flow/process rows.
- Consumers: Windows Security/Sysmon, eCAR, proxy access logs, Zeek
  HTTP/SSL/conn rows, and blind threat-hunter/detection review.

Implemented fixes feeding loop 42:

- Added deterministic per-session startup pacing for baseline interactive
  activity inside the first five minutes after logon.
- Applied the same pacing to profile/persona traffic before it creates or reuses
  a process and before browser-session fan-out reaches proxy/network evidence.
- Added focused tests for early event staggering and hour/logoff boundary
  handling.

Verification so far:

- Focused tests passed:
  `uv run pytest --no-cov tests/unit/test_baseline_canonical.py::test_interactive_startup_activity_pacing_spreads_early_baseline_events tests/unit/test_baseline_canonical.py::test_interactive_startup_activity_pacing_respects_hour_and_logoff_boundaries -q`.
- `uv run ruff check src/evidenceforge/generation/engine/baseline.py tests/unit/test_baseline_canonical.py`
  and matching format check passed.
- Automated eval passed with overall score 95.726 over 62,326 records.
- Rendered-output startup/proxy probe found 11 interactive logins, zero proxy
  requests within 5 or 30 seconds after those logins, 60 proxy requests within
  180 seconds, median first user-process gap of 70.471 seconds, and one
  user-process gap under five seconds.
- Fix committed and pushed as `6d6a950f`.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 68.
- Detection Engineer: Inconclusive, synthetic-confidence 48.
- Network Forensics: Synthetic, synthetic-confidence 70.
- Host/EDR: Synthetic, synthetic-confidence 84.
- Average: 67.5.

Result: average blind synthetic-confidence is above the user's `<=45`
temporary-solve threshold, so this priority category is not cleared. The
startup/proxy compression probe improved, but reviewers shifted to adjacent
source-native texture problems: endpoint process lifecycle contradictions,
implausible process-to-file/registry ownership, overly tidy proxy/browser
process attribution, SMTP 587 plaintext semantics, and one public-service TLS
certificate mismatch. Loop 43 targets endpoint process lifecycle ownership
because it was the largest blind-score driver and affects the same workstation
process realism family.

## Loop 43

Priority category: endpoint process lifecycle ownership and delayed source
observation consistency.

Family contract:

- Owning abstraction: canonical process lifecycle/state plus dispatcher
  source-observation handling before source-native rendering.
- Invariant: source-native process, flow, and dependent rows must not create
  visible same-process contradictions across Windows Security, Sysmon, and eCAR.
  When a delayed source row carries process identity, the running process
  lifetime must extend to that visible source timestamp before later
  finalization can terminate it.
- Entry paths: process create/terminate bundles, network-connection action
  bundle, source-observation delays, Sysmon Event 3, Windows 5156, eCAR FLOW,
  and foreground-process finalizers.
- Consumers: Windows Security/Sysmon, eCAR, Zeek/proxy pivot review, and blind
  Host/EDR plus Detection review.

Implemented fixes feeding loop 43:

- Fixed eCAR process termination timing so the source terminate timestamp is
  anchored to the original process-create source timestamp instead of planning a
  new create timestamp from the terminate event.
- Dropped connection process attribution when the referenced process instance is
  already known to have emitted termination evidence.
- Updated dispatcher source-observation handling so delayed endpoint source rows
  with process identity extend `StateManager` process activity time before
  emission.

Verification:

- Focused tests passed:
  `uv run pytest --no-cov tests/unit/test_dispatcher.py::TestObservationProfiles::test_delayed_process_source_observation_extends_process_activity tests/unit/test_activity.py::TestActivityGenerator::test_generate_connection_drops_recorded_terminated_process_pid tests/unit/test_timing_profiles.py::test_process_source_terminate_time_preserves_visible_ecar_lifetime tests/unit/test_timing_profiles.py::test_process_source_terminate_time_uses_stored_visible_create_anchor -q`.
- `uv run ruff check src/evidenceforge/events/dispatcher.py src/evidenceforge/generation/activity/generator.py tests/unit/test_dispatcher.py tests/unit/test_activity.py tests/unit/test_timing_profiles.py`
  and matching format check passed.
- Automated eval passed with overall score 95.727 over 62,382 records.
- Strict lifecycle probe still found three large eCAR/Sysmon browser termination
  deltas, so the underlying endpoint observation asymmetry is not fully
  eliminated; however, the blind Host reviewer no longer treated that specific
  browser termination pattern as the dominant issue.
- Fixes committed and pushed as `1b9509b8`, `0fb6e6bf`, and `8953d4be`.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 52.
- Detection Engineer: Inconclusive, synthetic-confidence 36.
- Network Forensics: Inconclusive, synthetic-confidence 34.
- Host/EDR: Inconclusive, synthetic-confidence 56.
- Average: 44.5.

Result: average blind synthetic-confidence is `<=45`, so the user's special
rule temporarily clears this priority item. Per the user's explicit instruction,
the assessment stopped after loop 43 and did not proceed to loop 44.

Top remaining blind findings for the next resumed loop:

- Network `contract_gap`: one concurrent TCP source-port reuse by
  `10.55.10.21:61712` for a long SSH session and a Kerberos TCP connection.
- Host `hard_contradiction`: `PROXY-ARD-01` bash history records `exit`, then
  later commands still parented to the same eCAR `/bin/bash` process.
- Detection `schema_or_format`: `EMAIL_ARTIFACTS.json` looks like an
  analyst-ready manifest rather than a production-native source.
- Threat/Detection/Network `contract_gap` and `distribution_texture`: source-side
  SSH attribution gaps, exact same-millisecond paired eCAR FLOW observations,
  and uneven eCAR principal attribution remain visible.

## Loop 44

Priority category: blind-facing email artifact manifest semantics.

Implemented fixes feeding loop 44:

- Removed route/delivery internals from the blind-facing `EMAIL_ARTIFACTS.json`
  manifest. The manifest now acts as a message artifact index and no longer
  exposes `delivery_action`, `outcome`, `expanded_rcptto`, `route`, or
  `received_headers`.
- Preserved route metadata in internal ground truth/evaluator paths and updated
  email docs/tests to assert route behavior from SMTP/DNS evidence rather than
  the manifest.

Verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`
  passed: 84 tests.
- Focused ruff check/format passed for touched files.
- Rendered manifest probe found 34 messages and zero forbidden transport fields.
- Automated eval passed with score 95.915 over 62,778 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 48.
- Detection Engineer: Real, synthetic-confidence 32.
- Network Forensics: Inconclusive, synthetic-confidence 42.
- Host/EDR: Synthetic, synthetic-confidence 64.
- Average: 46.5.
- Deliberation triggered by verdict disagreement and ended with final scores
  56/43/47/66, average 53.0.

Result: the prior manifest finding did not recur. The next highest-leverage
email-owned family is SMTP client identity and submission policy: SMTP
`user_agent` values drift from endpoint mail-client binaries, all client
submission on TCP/587 is plaintext, and external `.eml` Date headers can land
after early external Received hops.

## Loop 45

Priority category: SMTP submission privacy, mailer identity, and external
`.eml` chronology.

Implemented fixes feeding loop 45:

- Moved port-587 client submission to STARTTLS by default, with Zeek SMTP rows
  showing TLS negotiation instead of cleartext envelope/message fields.
- Normalized scenario/corpus mailer identities so `.eml` headers and endpoint
  process attribution agree.
- Ensured external sender `Date` headers precede the first visible Received hop.

Verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`
  passed: 84 tests.
- Focused ruff check/format passed for touched files.
- Rendered-output probe found 23/23 submission rows using STARTTLS, 23/23 SSL
  sidecars, zero cleartext submission leaks, zero old Outlook user-agent leaks,
  and zero `.eml` Date inversions.
- Automated eval passed with score 95.090 over 62,320 records.

Blind panel:

- Threat Hunter: Inconclusive, synthetic-confidence 43.
- Detection Engineer: Real, synthetic-confidence 32.
- Network Forensics: Inconclusive, synthetic-confidence 55.
- Host/EDR: Synthetic, synthetic-confidence 66.
- Initial average: 49.0; deliberated average: 49.25.

Result: the STARTTLS, mailer identity, and Date-header fixes held. The next
highest-leverage email root cause was missing Linux/Postfix MTA-native syslog
lifecycle evidence for SMTP handling on MAIL-ENG.

## Loop 46

Priority category: Linux/Postfix MTA-native syslog lifecycle for SMTP hops.

Implemented fixes feeding loop 46:

- Added Postfix-style `smtpd`, `cleanup`, `qmgr`, delivery, and `removed`
  syslog lifecycle rows for Linux mail-server SMTP hops.
- Preserved loop-45 STARTTLS, manifest, mailer identity, and `.eml` chronology
  improvements.
- Added unit coverage for the new Postfix syslog lifecycle behavior.

Verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`
  passed: 85 tests.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe found 96 Postfix rows, 16 queue IDs, zero missing
  receive chains, zero missing removed rows, and one stable qmgr PID.
- Automated eval passed with score 95.040 over 62,416 records.

Blind panel:

- Threat Hunter: Synthetic, synthetic-confidence 72.
- Detection Engineer: Synthetic, synthetic-confidence 76.
- Network Forensics: Real, synthetic-confidence 24.
- Host/EDR: Real, synthetic-confidence 32.
- Average: 51.0.

Result: adding Postfix lifecycle improved source coverage but exposed
source-native contradictions. The next loop targeted root-cause queue state:
`delay=` values shorter than visible queue elapsed time, `nrcpt=2` queues
removed after one delivery row, and outbound MAIL-ENG SMTP flows owned by the
inbound `postfix/smtpd` listener.

## Loop 47

Priority category: Linux MTA queue lifecycle consistency and outbound process
ownership.

Implemented fixes feeding loop 47:

- Added per-queue lifecycle state so Postfix delays derive from queue active,
  cleanup, and delivery timestamps rather than independent short jitter.
- Tracked expected local and relayed recipients and emitted `removed` only after
  all visible delivery rows land.
- Changed Linux server-to-server outbound SMTP source ownership from
  `/usr/lib/postfix/sbin/smtpd` to `/usr/lib/postfix/sbin/smtp`.

Verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`
  passed: 85 tests.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe found zero Postfix delay shortfalls, zero queues removed
  before all deliveries, zero under-delivered queues, zero eCAR SMTP PID/syslog
  mismatches, and 7/7 MAIL-ENG outbound SMTP eCAR FLOW rows owned by
  `/usr/lib/postfix/sbin/smtp`.
- Automated eval passed with score 95.040 over 62,418 records.

Blind panel:

- Threat Hunter: Real, synthetic-confidence 32.
- Detection Engineer: Real, synthetic-confidence 28.
- Network Forensics: Synthetic, synthetic-confidence 67.
- Host/EDR: Inconclusive, synthetic-confidence 36.
- Average: 40.75.

Result: the Postfix lifecycle contradictions and outbound-process ownership
findings did not recur. Network found a new email-owned byte-accounting issue:
Postfix `size=` values matched Zeek `conn.orig_bytes` on MAIL-ENG SMTP hops,
collapsing queued message size and wire-level transfer accounting.

## Loop 48

Priority category: SMTP queued message size versus transport wire byte
accounting.

Implemented fixes feeding loop 48:

- Split SMTP transfer sizing into queued message bytes and transport wire bytes.
- Kept Zeek `conn.orig_bytes` as the SMTP/TLS/relay wire observation.
- Passed the source-native queued message size into Postfix `size=` fields.
- Updated email tests to assert Postfix `size=` differs from matching STARTTLS
  submission and outbound relay `conn.orig_bytes`.
- Fixed a stale Zeek format-count assertion from 22 to 23 formats.

Verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`
  passed: 85 tests.
- `uv run pytest --no-cov tests/unit/test_zeek_format_accuracy.py::TestSampleDataFieldValidation::test_all_formats_load tests/unit/test_email_evidence.py tests/unit/test_eval_cross_source.py -q`
  passed: 86 tests.
- `uv run ruff check .` and `uv run ruff format --check .` passed.
- Rendered-output probe found 23 MAIL-ENG Postfix-size/Zeek-wire comparisons,
  zero Postfix size values equal to matching `conn.orig_bytes`, 23/23 STARTTLS
  submission rows with SSL sidecars, zero cleartext submission leaks, zero
  Postfix delay/recipient/removal gaps, and 7/7 outbound MAIL-ENG SMTP eCAR
  FLOW rows owned by `/usr/lib/postfix/sbin/smtp`.
- Automated eval passed with score 95.040 over 62,418 records.
- A full default `uv run pytest --no-cov` was run before the stale format-count
  assertion fix and failed only that 22-vs-23 expectation; the targeted failing
  test and email-focused suites passed afterward.

Blind panel:

- Threat Hunter: Real, synthetic-confidence 34.
- Detection Engineer: Real, synthetic-confidence 34.
- Network Forensics: Real, synthetic-confidence 31.
- Host/EDR: Inconclusive, synthetic-confidence 46.
- Average: 36.25.

Result: the loop-47 byte-accounting finding did not recur, and the panel
shifted from SMTP transport/lifecycle correctness to higher-order texture. The
top email-owned next priorities are Message-ID/queue-ID/Received-token
diversity, Dovecot/IMAP auth and session syslog companions for observed IMAPS
mailbox access, and tighter Received timestamp/protocol alignment for STARTTLS
hops. A separate non-email finding remains around early MAIL-ENG SSH eCAR
process trees without matching syslog/Zeek session evidence.

## Loops 49-58

Priority category: new email functionality introduced on the branch, with
root-cause fixes at the canonical email/SMTP/TLS context layer where possible.

Implemented fixes across this batch:

- Added Cc ownership to `SmtpContext`, Zeek SMTP rendering, and the Zeek SMTP
  schema so visible SMTP rows preserve Cc without folding it into To.
- Added endpoint mail-cache and named attachment file artifacts for rendered
  email attachments.
- Improved Message-ID, Received-header, Exchange version, queue-ID, and Postfix
  source-native texture.
- Added Dovecot IMAPS syslog companions and Linux MTA Postfix process ownership
  for outbound relay flows.
- Changed STARTTLS replies to server-family-specific palettes so TLS rows no
  longer render generic non-TLS replies.
- Consolidated external inbound SMTP Received-path and Zeek `path` construction
  through one public-hop model with provider/PTR-like relays.
- Added SMTP STARTTLS SNI policy: port 587 client submissions keep SNI, while a
  realistic subset of port 25 MTA-to-MTA STARTTLS sessions omit SNI.

Verification:

- `uv run pytest --no-cov tests/unit/test_email_evidence.py -q` passed with 26
  tests after the final SNI-policy fix.
- `uv run pytest --no-cov tests/unit/test_zeek_format_accuracy.py -q` passed
  with 27 tests.
- Loop 58 probe found `16` port-25 STARTTLS rows with SNI and `12` without SNI,
  while port 587 had `23` with SNI and `0` without.
- Loop 58 probe found zero non-STARTTLS TLS replies, zero invalid Exchange
  Received versions, zero generic ESMTPS version-like IDs, zero leading-zero or
  UUID-like Message-ID issues, zero TLS 1.2 cert/cipher mismatches, and three
  endpoint named-attachment file events.

Blind panel summary:

| Loop | Automated | Threat | Detection | Network | Host/EDR | Blind avg | Notes |
|---|---:|---:|---:|---:|---:|---:|---|
| 49 | 94.668 PASS | 72 | 24 | 76 | 63 | 58.75 | Identifier/IMAPS fixes held; STARTTLS opacity and non-email gaps dominated. |
| 50 | 91.985 FAIL | 59 | 38 | 28 | 65 | 47.50 | Automated event-presence gate failed; later loops restored coverage. |
| 51 | 94.996 PASS | 34 | 48 | 90 | 72 | 61.00 | Network flagged SMTP STARTTLS TLS/cert mismatch. |
| 52 | 94.965 PASS | 56 | 38 | 86 | 78 | 64.50 | Zeek SMTP correlation improved; endpoint/artifact gaps remained. |
| 53 | 94.965 PASS | 68 | 34 | 68 | 68 | 59.50 | STARTTLS replies and Exchange Received syntax improved but ID/artifact texture remained. |
| 54 | 94.465 PASS | 38 | 34 | 34 | 55 | 40.25 | Most email correctness defects cleared; broader host-role texture remained. |
| 55 | 94.465 PASS | 30 | 46 | 44 | 34 | 38.50 | Exchange Received version morphology fixed; STARTTLS reply texture became next target. |
| 56 | 94.465 PASS | 30 | 38 | 38 | 49 | 38.75 | STARTTLS replies fixed; MTA-to-MTA all-SNI behavior became next target. |
| 57 | 94.465 PASS | 36 | 42 | 36 | 38 | 38.00 | External public-hop model held; universal SMTP STARTTLS SNI remained. |
| 58 | 94.465 PASS | 48 | 33 | 43 | 66 | 47.50 | SMTP STARTTLS SNI fixed; host/SSH/endpoint issues drove regression. |

Result: the new batch improved the email-specific defects reviewers were
calling out: Message-ID/Received morphology, Cc/path separation, attachment
artifacts, Postfix/Dovecot lifecycle, STARTTLS replies, external hop paths, and
MTA-to-MTA no-SNI policy all now have focused probe coverage. The late loop-58
regression is primarily non-email endpoint realism: Group Policy extension data,
SSH shell/session ordering, Linux package-manager process ancestry, and Windows
service/network logon closure.

Chart artifact:

- `scenarios/email-v1-assessment/blind-test/assessment-effectiveness-dashboard-last-20-email-loops.svg`
  shows loops 39-58, including reviewer score lines, trailing five-loop blind
  average, loop-to-loop deltas, and reviewer disagreement band (#6).
