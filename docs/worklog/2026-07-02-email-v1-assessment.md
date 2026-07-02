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
