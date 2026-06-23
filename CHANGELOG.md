# EvidenceForge Development Changelog

Detailed development history for the EvidenceForge project. Transferred from TODO.md during release preparation. For active and planned work, see [TODO.md](TODO.md).

---

## Unreleased

## v1.4.2 (2026-06-23)

This patch release fixes authored HTTP response-size realism for web access
records generated from storyline `connection` and `beacon` events.

**Authored HTTP error sizing**

- Routed authored HTTP response body sizing through status-aware logic so
  4xx/5xx responses, including download-like paths such as `.zip`, render small
  error-page bodies instead of served-file-sized payloads (`e329cb43`).
- Honored `response_body_len` and, when that dedicated HTTP override is absent,
  explicit `resp_bytes` for access-log body bytes, and documented the authoring
  contract with focused regression coverage (`e329cb43`).

## v1.4.1 (2026-06-18)

This patch release captures the accepted assessment-loop realism fixes queued on
`dev` after `v1.4.0`. The work improves blind-review realism signals while
preserving the public generation interface.

**Assessment-loop realism improvements**

- Added coherent collection-imperfection handling across Zeek sibling rows:
  source-observation format missingness now promotes required same-sensor parent
  rows and prunes HTTP/SSL reference vectors when dependent files or X.509 rows
  are absent (`14dccc2f`).
- Improved source-native web, proxy, eCAR, Linux, Zeek file-analysis, and NTP
  texture, including cache-buster entropy, host-specific root response sizing,
  actor-linked eCAR FLOW principals, realistic polkit process start ticks,
  incomplete Zeek file-analysis rows, NTP precision/poll/cadence/metric
  semantics, and Linux compound-command process rendering (`14dccc2f`).
- Added focused regression coverage for the new observation, rendering,
  lifecycle, and configuration contracts, and recorded the assessment-loop
  handoff in the tracked worklog (`14dccc2f`).

## v1.4.0 (2026-06-17)

This release integrates the accepted Codex hardening fixes queued on `dev`, the
accepted `adversarial_payload` feature, a local SOF-ELK harness fixture cleanup
found during slow-suite validation, a spillage validation fix, and dependency
maintenance. Because this release now includes the non-breaking
`adversarial_payload` feature before landing on `main`, the project moves from
`1.3.2` to `1.4.0`.

**Adversarial payload testing**

- Added the typed `adversarial_payload` storyline event for deterministic
  log-pipeline weakness testing across syslog, process command line, HTTP
  user-agent, URL, and referrer surfaces, with data-driven payload families,
  surface-aware encoding, canonical ground-truth records, evaluation support,
  and on-wire IDS alert modeling when cleartext HTTP traffic is sensor-visible
  (`fe4bc439`, `fd40a2b4`, `ca46a3e4`).
- Added supported payload families for ANSI escape, CRLF log forging, CSV
  formula injection, Log4Shell/JNDI, reflected XSS, SQL injection,
  structured-log injection, and oversized-field testing, then removed the
  temporary proposed-family mechanism so shipped families are first-class
  supported behavior (`2ea19b4e`, `86ba2e86`).
- Added explicit live-callback OOB support via `--oob-host`, removed the
  separate acknowledgement flag, added `eforge validate --oob-host` parity, and
  enforced concrete registrable-domain/IP validation at the payload safety
  boundary and carrier-rendering boundary so broad values cannot widen the host
  allowlist (`cca749e3`, `0daa726d`, `47a1fa58`).
- Tightened adversarial-payload docs, skill guidance, IDS sensor-model
  documentation, public-suffix handling, Linux-only surface validation, and
  `expected_sources` so ground truth names only sources that actually land in the
  generated dataset (`68d77afe`, `55bb3d62`, `3eede9b8`, `03e92fea`,
  `9aee3b19`, `4cd64cac`, `ef59cd9a`).

**External parser and output-target hardening**

- Hardened Splunk app archive extraction, output-target marker reads, raw
  Windows Event ID normalization, deep X.509 parser originals, SOF-ELK DNS tag
  validation, and symlink handling for external parser source logs
  (`fe267171`, `228fbaca`, `e79f2e6e`, `094afa79`, `ba34aae4`, `f64a7447`,
  `5fcb7da5`, `a96e505d`, `7d8e49c1`, `ec6f88c3`, `8d6c3c58`, `4aaf2df2`).
- Preserved accepted integration behavior by replacing unsafe tar extraction
  with safe regular-file extraction and keeping explicit eCAR pipeline group
  stage order stable after parser hardening (`c4405a8e`).
- Updated the combined SOF-ELK harness DNS fixture to include normalized
  `dns.answers.ip` for address answers, matching the stricter parser validation
  contract (`f9b5e2f2`).

**Malformed input tolerance and source-specific rendering**

- Tolerated malformed explicit proxy URIs, HTTP file URIs, and Splunk request
  URLs without crashing parser or emitter paths (`950fa2cd`, `655227de`,
  `719770f6`, `f58a9d58`, `9e4ea592`, `2478c63f`).
- Preserved IPv6 Cisco ASA ICMP `faddr` parsing and aligned web-emitter role
  matching with normalized web-server roles (`bca1481b`, `2461e744`,
  `a2d362a8`, `75a416c3`).

**eCAR, shell, and logon realism guards**

- Bounded eCAR file churn counts, required explicit eCAR shell concurrency
  groups, hardened storyline shell friction templates, and avoided orphan Linux
  logons when dropped bash commands no longer have visible session evidence
  (`2fad4a9f`, `28c12917`, `19222895`, `d261c57e`, `241d756b`, `ada23d3e`,
  `ec00e3d7`, `104c457f`).
- Added a regression guard for file side-effect event mappings so read-style
  side effects remain covered (`4cf50430`).
- Rejected Linux-only spillage surfaces such as `shell_history` and
  `syslog_message` on any non-Linux host, preventing ground-truthed credential
  labels from being created for evidence that no Linux-modeled emitter can write
  (`de6fc246`).

**Release documentation**

- Hardened the manual release fallback docs so maintainers have clearer release
  guard and tagging instructions when automation is unavailable (`f292f0ec`,
  `39c8d87a`).

**Dependency maintenance**

- Updated development dependencies to pytest 9.1.0 and Ruff 0.15.17, with
  slow-inclusive no-coverage validation passing on the upgraded toolchain
  (`f9db94b3`, `65387363`).

## v1.3.2 (2026-06-06)

This patch release fixes a long-window Windows process lifecycle regression
found after v1.3.1. The branch contains only a `fix:` commit since v1.3.1, so
the project moves from `1.3.1` to `1.3.2`.

**Windows process lifecycle stability**

- Cleared stale active-session process pointers when referenced processes end,
  repaired stale user and system parent PIDs before strict process allocation,
  and added regression coverage for multi-week Windows parent churn
  (`60594ee4`).

## v1.3.1 (2026-06-06)

This patch release fixes several generation edge cases reported from class
exercise authoring and preserves a durable service-process state regression.
The branch contains only `fix:` commits since v1.3.0, so the project moves from
`1.3.0` to `1.3.1`.

**Generation edge cases and backward-compatible controls**

- Moved Windows Security event spool SQLite state out of final output
  directories, optimized SOF-ELK syslog close-time normalization, allowed
  concrete Zeek formats in output and sensor configuration, added opt-in
  per-tick beacon DNS resolution, optimized high-volume DGA state handling,
  preserved compatible explicit TCP payload byte overrides, and added explicit
  storyline process lineage refs (`949faa26`).

**Durable service process state**

- Preserved durable service process state across activity generation paths and
  added regression coverage for service process and spawn-rule behavior
  (`7e3a3a52`).

## v1.3.0 (2026-06-05)

This minor release adds the Splunk output target, Splunk parser validation
pipeline, optional caller-supplied CIM app validation, and output-target ingest
guides. The branch contains non-breaking `feat:` commits since v1.2.1, so the
project moves from `1.2.1` to `1.3.0`.

**Splunk output target and parser validation**

- Added `--target splunk`, target marker handling, Splunk-specific Windows XML
  event streams, RFC5424 Linux syslog retention, native Cisco ASA syslog
  staging, and Splunk parser harness orchestration with generated
  EvidenceForge-owned configs and reports (`7b8aabca`, `aa53c84f`).
- Stabilized Splunk live ingest and normalized source metadata handling so the
  base parser harness can validate counts, source/sourcetype metadata, fields,
  and ingest/parser warnings without vendoring Splunk assets (`aa53c84f`,
  `5795b6dc`).

**CIM validation**

- Added optional CIM validation for caller-supplied Splunk apps/TAs, including
  dataset searches for Windows authentication, Sysmon process lifecycle, Zeek
  network/web records, Cisco ASA firewall records, web access, and proxy access
  logs (`6e886ff2`, `047da1a0`).
- Refined CIM query builders and app namespace handling so validation can
  distinguish indexed-but-unnormalized data from missing parser coverage
  (`047da1a0`).

**Output-target guidance and regression coverage**

- Added user-facing ingest guides for the default, SOF-ELK, and Splunk output
  targets, documenting format differences, validation tiers, ingest steps, and
  current compatibility expectations (`feede499`).
- Updated slow and renderer-level Zeek tests to use explicit sensor topology or
  direct-file mode, matching the no-root-Zeek-output policy when no sensors are
  configured (`2094f3f5`).

## v1.2.1 (2026-06-04)

This patch release promotes the current-dev realism assessment fixes from loops
268-277. The branch contains only fixes, documentation handoffs, and dependency
maintenance since v1.2.0, so the project moves from `1.2.0` to `1.2.1`.

**Linux session and process realism**

- Stabilized Linux shell, SSH, and package-manager evidence so workstation shell
  sessions bootstrap correctly, bash-history commands correlate to process
  telemetry, package-manager activity renders through a more coherent pipeline,
  logind session identity is preserved, and SSH auth logs no longer create
  synthetic file-write churn (`ececd460`, `e1896675`, `67470420`,
  `91893cb0`, `146e12ae`, `77a169fe`, `cd073fef`).

**Proxy, HTTP, and endpoint telemetry**

- Improved cache revalidation, static web asset sizing, proxy package-manager
  behavior, paired eCAR flow timing, and eCAR session logout identifiers so
  proxy and endpoint records stay more source-native and internally consistent
  across the final assessment loops (`3628d636`, `8e669384`, `42bb09ab`,
  `8f22356a`).

**Assessment handoff**

- Recorded loop-by-loop blind-review and automated-score handoff notes for
  loops 268-277 in the current-dev assessment worklog (`2ea6c6d6`,
  `a57f1a99`, `0920f70d`, `97c828ac`, `0074292e`, `2bbcfd27`,
  `1f1e36bf`, `0c223d24`, `3a0c3464`, `fb17b5d2`).

## v1.2.0 (2026-06-03)

This minor release promotes the new spillage feature family, the canonical
ground-truth JSON contract, and the final maintainer follow-up fixes from `dev`
 to `main`. The branch contains non-breaking `feat:` commits since v1.1.1, so
the project moves from `1.1.1` to `1.2.0`.

**Spillage modeling and ground truth**

- Added the typed `spillage` storyline event for deterministic synthetic
  credential leakage across shell history, process command line, syslog, and
  HTTP surfaces, with data-driven secret families, family/literal validation,
  carrier rendering, URL/syslog/shell-safe encoding, and safety guardrails
  against real credentials or unsafe hosts (`1a465b27`).
- Integrated `process_command_line` spillage back into canonical actor
  session/logon ownership so standalone process evidence still uses the shared
  auth/session/process architecture (`6e4090b9`).
- Added scheme-aware HTTP/HTTPS web spillage so `http_request_url` and
  `http_referrer` surfaces can model explicit cleartext or TLS-backed requests,
  with validator/runtime support and causality matching for cleartext HTTP
  observations (`d6d69f3d`).
- Added the spillage full-matrix scenario and broader coverage for supported
  surfaces, OS constraints, and source behavior (`190f16d3`).

**Canonical machine-readable ground truth**

- Replaced the spillage-only `GROUND_TRUTH.jsonl` sidecar with canonical
  `GROUND_TRUTH.json`, backed by strict Pydantic schema models, and made
  `GROUND_TRUTH.md` a renderer over that validated JSON document rather than a
  parallel generator path (`e1c9dfc7`).
- Updated `eforge eval`, CLI output staging/swap logic, docs, and regression
  tests to consume the canonical ground-truth JSON contract directly
  (`e1c9dfc7`).

**Generator realism and release automation**

- Improved iteration-test realism fidelity on `dev`, carrying forward the latest
  generator hardening before this release (`651a11a0`).
- Added GitHub release-tag automation so `main` merges verify version/tag
  consistency and publish the annotated release tag automatically (`0e97f738`).

---

## v1.1.1 (2026-05-29)

This patch release promotes the post-1.1.0 current-dev assessment fixes. The
branch contains only fixes and documentation updates since v1.1.0, so the
project moves from `1.1.0` to `1.1.1`.

**Blind realism assessment hardening**

- Tightened DNS realism, SSH/eCAR tuple ownership, proxy identity, firewall path
  ownership, paired FLOW timing, Windows Security port rendering, and related
  regression coverage from the latest blind-review loops (`d1ee3d79`,
  `3864057b`).

**Parser and workflow documentation**

- Hardened external parser output target marker reads, defaulted eforge skill
  command docs to installed command usage, and added Claude instructions as a
  reference to the existing AGENTS.md workflow (`9d59a887`, `617932f1`,
  `11dee4b3`).

---

## v1.1.0 (2026-05-28)

This minor release promotes the external-parser validation work and the latest
current-dev realism hardening from `dev` to `main`. The branch contains public
`feat:` commits since v1.0.1, so the project moves from `1.0.1` to `1.1.0`.

**External parser validation and source rendering**

- Added SOF-ELK harness support for Zeek, Cisco ASA, web access, syslog-family,
  Windows Snare sidecars, parser tag policy, target-aware output rendering, and
  coverage summaries, with runner/script documentation and parser smoke coverage
  (`3e6bccb8`, `b40c7bd5`, `a932ab56`, `544d877c`, `b1267bb6`, `c4374af6`,
  `461d8e5b`, `931cbe46`, `6ee64c21`, `fb03b056`, `5ea85fbe`, `c7235660`,
  `b46a9c5f`, `388421cb`, `fd83d83a`, `d8edbceb`, `a909693c`, `9873f0d0`,
  `37979eee`, `9507f69e`, `ad1d1b81`, `23c7ba94`, `103fb895`).
- Clarified external-parser validation workflow, parser progress phases, ignored
  parser tags, and dev-sync follow-up notes (`d90c9f67`, `2174b1c0`,
  `aa7195df`, `9af38656`).

**Current-dev realism assessment and generator hardening**

- Landed the loop 203-217 fix family for endpoint/eCAR coherence, proxy and HTTP
  file identity, Windows audit ordering, DNS hostname canonicalization, SMB
  transport binding, Linux shell/session texture, Zeek timing variation,
  explicit credential endpoints, PsExec lifecycle, Windows record IDs, source
  timing, Linux session reuse, eCAR concurrency, remote-session ordering, SSH
  source-port reuse, and the current-dev blind-review findings (`3a0647e1`,
  `8f2881c2`, `2e9462a4`, `af62abd0`, `74fd68a3`, `2e86c4aa`, `f6189674`,
  `c95bd588`, `786e7b88`, `b7a9c0fa`, `199d1f78`, `ca6ebca6`, `01f6954b`,
  `67bec768`, `d2688faf`, `f2b1c34b`, `ce79bc82`, `c2c6a344`, `1f95b0e3`,
  `0ad5983c`, `b725f912`, `e3fc1fc2`, `9ce3ad27`, `ecde3b4a`, `9895f149`,
  `607f4749`, `e8ea4deb`, `354eda17`, `fd786afc`, `70351fe7`, `057db70b`,
  `907678c1`).
- Added the final root-cause fixes for scanner probe isolation and explicit proxy
  HTTP outcome preservation, plus regression coverage for those contracts
  (`97d79a0a`).
- Recorded loop assessment handoff history and follow-up issues in the current
  dev worklog/TODO flow (`55d9afb3`, `d2688faf`, `ce79bc82`, `e3fc1fc2`,
  `607f4749`, `41b0569e`, `4f80e4a4`).

**Validation, model, and configuration fixes**

- Tightened ConnectionEventSpec response-body bounds, NTP schedule carryover,
  IDS numeric validation, SCP target username sanitization, proxy duration
  floors, SSH auth datetime normalization, bash-history and Sysmon PR review
  findings, and SOF-ELK smoke-log harvesting (`2b2bca5f`, `a1776317`,
  `43fc5454`, `cfa6b8d8`, `17a6c272`, `8e9e9cc2`, `199b6865`, `9507f69e`).
- Improved parser/runtime policy and related unit coverage so optional external
  parser failures surface as controlled validation outcomes (`103fb895`,
  `ad1d1b81`).

**Documentation, CI, and dependency maintenance**

- Updated the blog-post title and carried forward roadmap/worklog documentation
  for the assessment and parser-validation efforts (`787308aa`, `9af38656`,
  `41b0569e`, `4f80e4a4`).
- Refreshed CI and dependency pins for Python setup, uv setup, checkout,
  Ruff, pytest-asyncio, Codecov, and Typer (`4111a3dd`, `6ecd03e5`,
  `c00420e9`, `5ea0c7ac`, `b215608c`, `b9bf3ed2`, `5a46742e`).

## v1.0.1 (2026-05-27)

This patch release packages the final GitHub/source release-readiness cleanup
after v1.0.0. The branch contains only `fix:`, `docs:`, and `chore:` commits
since v1.0.0, so the project moves from `1.0.0` to `1.0.1`.

**CLI and ASA parser polish**

- Fixed Cisco ASA ICMP parsing/rendering so ICMP messages do not include
  TCP/UDP-style interface port suffixes, and added parser/emitter coverage for
  the corrected behavior (`05180a12`).
- Added `-h` as a short alias for `--help` on the root `eforge` command and all
  subcommands, with focused CLI regression coverage (`3134ed1a`).

**Documentation and onboarding**

- Added the `branch-office-example` beginner scenario, updated the README Quick
  Start to use it, fixed the public repo clone URL, and validated the scenario
  with validate/generate/eval smoke checks (`fe5d4785`).
- Aligned dev copies of the `/eforge` command docs with current CLI behavior,
  removed stale options, corrected scenario-authoring guidance, and updated
  source-checkout command examples (`73d47a39`).
- Clarified release test gates, including the no-coverage slow-suite guidance,
  refreshed the approximate test count, and added the Talos announcement link to
  the README (`0e69385d`, `a8e021d5`).

**Release metadata and public-source hygiene**

- Added project URL metadata, corrected stale repository links, refreshed
  evaluation wording, and Talos-branded the Code of Conduct report contact
  (`e31fd1ed`).
- Added MIT package license metadata, switched package author metadata to
  `Cisco Talos`, enabled Dependabot coverage for GitHub Actions, and recorded
  security/legal release checks (`f47563af`).
- Removed tracked iteration-test prompt/review artifacts while keeping the
  approved coverage prompts and public beginner scenario YAML (`fafc6f81`).
- Created and maintained the release-readiness worklog used to track the review
  decisions and handoff state (`72e210dc`).

## v1.0.0 (2026-05-26)

This major release promotes the architecture-reset work and post-reset hardening
from `dev` to `main`. The release includes public `feat:` commits for the action
bundle architecture, so the project moves from `0.9.1` to `1.0.0`.

**Action-bundle architecture reset**

- Added the action-bundle foundation and routed major correlated-evidence families
  through canonical bundle ownership: RDP, Windows remote admin, file transfer,
  Linux shell command, process execution, auth/session, network connection, DHCP,
  DNS lookup, scanner/probe, IDS alert, Kerberos/DC, Windows audit, and auxiliary
  auth/session bundles (`5d2d3245`, `edd968c4`, `89b83c81`, `afabe54c`,
  `81884ab1`, `c8364594`, `e88a33af`, `60461124`, `3b3ea66b`, `15e7f511`,
  `400de49b`, `3fc7c370`, `732f2fc4`, `96cf1d5b`, `4428ef2c`).
- Documented the reset requirements, A/B comparison, draft PR validation, blind
  review findings, contract-loop results, and final bundle audit (`417d241d`,
  `9fb11245`, `4897008b`, `eb00a7fc`, `f4766076`, `e5170757`, `2e809059`,
  `ebe41126`, `40431b39`).

**Cross-source timing, lifecycle, and source-native realism**

- Hardened SSH/RDP/remote-session ordering, endpoint flow timing, NTP scheduling,
  browser/proxy HTTP semantics, source observation groups, and eCAR/source timing
  contracts (`83037da5`, `70b40bdb`, `93d8e2df`, `7873c51b`, `0e0caf82`,
  `f3862eef`, `018440ba`, `e09d857d`, `6dceaede`, `7093eec5`, `ecb80405`,
  `7202e4b9`, `61b805f7`, `a49c0027`, `d72e3eae`, `b9d5b696`, `0d24cd8c`,
  `650d2f2f`, `3452d3d6`, `777c905d`, `644421d2`, `8c45320f`, `2603fa75`,
  `3bcdd8d4`, `13cb08ed`, `0c9f3209`, `85ea4f2f`, `30a897ef`, `df9988f1`).
- Stabilized generated-output repeatability while preserving realistic identity
  morphology, then tightened HTTP file/PE duration and analysis ordering, Zeek TCP
  byte/history semantics, TLS failure histories, HTTP transaction identity, NTP
  server-owned response fields, workstation unlock ordering, and HTTP downgrade
  behavior (`d8768a07`, `2bbe634a`, `6c526c54`, `5552af63`, `4e06e671`,
  `5f49c401`, `4d97ea66`, `5eb404c7`, `e90c5a55`, `05a77536`, `1d305a1c`,
  `7587cf57`, `3d49e31b`, `5ba27315`, `d7454333`).

**Security and robustness fix-family batch**

- Landed hardening for storyline slicing, syslog PAM backfill, Windows PID and
  Sysmon GUID normalization, eCAR timing/PID attribution, SQL target handling,
  placeholder expansion, Linux PID collision handling, Kerberos spool ordering,
  OCSP path bounds, external scanner weights, bash workflow config coercion,
  sshd PID normalization, runmru templating, TLS issuer selection, TCP packet
  accounting, Kerberos transport weights, cron/syslog config validation, transient
  PID scoping, proxy/browser URI handling, RDP source alignment, DNS TTL overrides,
  causal ordering after process visibility clamps, and warm-up quota accounting
  (`10191ec5`, `52b4037e`, `bc77f327`, `1f9ee143`, `fa15a10e`, `7cadbde8`,
  `ab6d12f6`, `0a386ae3`, `12937456`, `8334f0f4`, `a40e1fe9`, `8320f0f4`,
  `dc3e19f0`, `8546b41a`, `98de7cec`, `cad89ce8`, `544a4c0a`, `3514b968`,
  `31cf96ff`, `f3ba8e9c`, `1cfa066b`, `1bbc108e`, `74c0f081`, `0a64f8dc`,
  `f0c18942`, `7bfffac1`, `b33ca658`, `c1934477`, `0bb29e42`, `5061e57a`).
- Repaired the final dev-to-main release check failures by adding a default
  Kerberos connection audit state, preserving HTTPS semantics for malformed
  CONNECT browser hints, and restoring rich external scanner fallback profiles
  (`a7d3880d`).

**CI, roadmap, and release hygiene**

- Simplified GitHub Actions into stable required checks with release-only slow
  tests, recorded fix-family PR dispositions, and kept repeated TODO alignment
  commits out of the active roadmap surface (`ac811e4f`, `5feeeac0`, `9502eaaf`,
  `7963dac9`, `93ab3908`, `997c1768`, `9fd42caf`, `188b8126`, `f38b652a`,
  `23c18afe`, `046ca9fa`, `338b04d1`, `bf6998b1`, `f99803ab`, `81caf021`,
  `70fd5abf`, `4ed42909`, `df4784fc`, `d2cecc93`, `3501c1ed`, `b0a0d8d5`,
  `ee6046dd`, `ad9645e6`, `f23c37d5`, `6e242966`, `dfcbae68`, `416fa41a`,
  `b76841a4`).
- Reworked project memory so `TODO.md` is a durable roadmap and multi-session
  agent handoff state lives in tracked `docs/worklog/` files (`6a2ef81a`).

## v0.9.1 (2026-05-21)

This patch release packages the loop 189-199 realism follow-up work after v0.9.0.
The branch contains only `fix:`, `docs:`, and `chore:` commits since v0.9.0, so the
version moves from `0.9.0` to `0.9.1` under the pre-1.0 semver policy.

**Linux source timing and session lineage**

- Aligned Linux cron, shell, eCAR source timing, Zeek TCP packet accounting, and Windows/Linux
  session-lineage behavior across the loop 189-191 fixes (`b25412a3`, `b1fa742e`, `8477f079`,
  `ace69242`, `6e4136c5`).
- Materialized and guarded Linux shell parents for reused, local, loose, and visible session paths
  so endpoint process trees preserve source-native lineage (`b1c4ebe0`, `02b7ac1b`, `174a86fb`,
  `9c6c849e`, `21451a66`, `005766b1`).

**DNS, SSH, and explicit-credential realism**

- Rendered full Zeek SOA RDATA and carried SSH source-readiness, inbound-flow attribution,
  responder PID assignment, tuple-scoped PID reuse, syslog PID normalization, and source-tuple
  reservation through the Linux SSH family (`c6952e7e`, `2535ad69`, `252bac12`, `9b2a354c`,
  `1a5f31a5`, `473b7fba`, `3ae36035`).
- Ordered Windows explicit-credential audit events after their visible caller process evidence
  (`a1fdb87f`).

**Web, proxy, command, and eCAR timing texture**

- Varied web and auto-HTTP transfer bytes by client/profile, ordered explicit proxy tunnel legs,
  diversified Linux command/session texture, preserved Linux eCAR occurrence timing, aligned
  foreground source-visible termination timing, and preserved canonical sshd PIDs for visible
  syslog sessions (`a6a25651`, `559e7b69`, `3e208048`, `dcf26461`, `815f3827`, `226f1480`,
  `7568ba52`).

**Assessment records**

- Recorded loop 191-194 and loop 199 assessment summaries for the follow-up realism batch
  (`34f84a52`, `d96f238b`, `03e5fb7b`, `d132f43f`, `fe2bbf06`).

**Validation**

- `uv run ruff check .` passed.
- `uv run ruff format --check .` passed.
- `uv run pytest --no-cov` passed with `3592 passed`, `15 skipped`.

## v0.9.0 (2026-05-21)

This minor release packages the source-aware timing planner, expanded workstation-normal activity
defaults, and the loop-driven realism hardening work through loop 188. The branch includes `feat:`
commits since v0.8.1, so the version moves from `0.8.1` to `0.9.0` under the pre-1.0 semver
policy.

**Source-aware timing and activity expansion**

- Added the source-aware timing planner and expanded workstation-normal activity defaults, then
  carried that work through endpoint, Zeek, DNS, TLS, proxy, syslog, Kerberos, and shell-ordering
  fixes (`4accda90`, `e6aa9fd1`, `b4ee3d7`, `19b7d317`, `1bc5f0ad`, `949108ea`, `1aacf04d`,
  `7cfccdfc`, `8900bf5e`, `a4623f56`, `075a64cd`, `b7867189`, `a9d7fee5`, `249f3c09`,
  `92a0ee2b`, `0658ec96`, `e6952094`, `32d37f96`, `c578091a`, `6fb809ec`, `bd13f72c`,
  `c1330075`, `13b888b4`, `208694f9`, `d500c61a`, `b2168bc3`, `096d2141`, `d48c3877`,
  `f36f8000`, `b14cf417`, `7e4b5424`, `dd7291c9`, `cc480317`, `77adcba5`, `923aaf6f`,
  `635bdea4`, `ec3b409a`, `394f2c63`, `b286044f`, `7cb829d0`, `3aa98087`, `0f9c292f`,
  `b3ea6ab9`, `05a1205f`, `3fae9806`, `faf55ab7`).

**Loop-assessment realism fixes**

- Preserved source-native event ordering and lifetimes across browser, proxy, Linux SSH, OCSP,
  shell telemetry, eCAR, Kerberos, logind/PAM, source timing, DNS/TLS, Windows sessions, Bash
  workflow texture, web exploit provenance, Zeek sensor observations, OCSP request paths,
  infrastructure user agents, DNS tunnel morphology, scanner profiles, and proxy identities
  (`6886df61`, `49bc37bb`, `ea6133fd`, `d9ee7de7`, `d1494cec`, `9d523c3a`, `a3fa233e`,
  `84bb4126`, `73c3252c`, `6b95d76f`, `c613ac33`, `6e31ce16`, `75e4d5c5`, `b2e1e628`,
  `cb920b33`, `0eddcdd0`, `74ae3c85`, `8e65458d`, `fad4bc09`, `c1bc96be`, `3de3d26c`,
  `6a8b9b1b`, `b7b5009b`, `6e3c2241`, `0cf7f4b0`, `689e6e33`, `de0102db`, `e2ab1aa0`,
  `72b7236c`, `4a276c8e`, `87b359fc`, `165275e2`, `67144f31`, `2b72678c`, `7d405429`,
  `48d76342`, `9c3bf151`, `8a70d421`, `8f8d9987`, `3f4ced21`, `9601291f`, `898f8c68`,
  `85cc4fc0`, `3895f80f`, `3b86aa5a`, `67acff74`, `f700d3bf`, `ecd01eb6`).

**Assessment records and loop guidance**

- Recorded blind-panel and loop-assessment findings from loops 134-188, added messy-attacker and
  family-level iteration-loop guidance, strengthened the family-fix prompt, and tracked loop-178
  through loop-188 completion and blind-panel score summaries (`81522de6`, `80b274e2`,
  `edd38dec`, `1aff790a`, `4daf3e84`, `2d3fbd44`, `39f8495c`, `382cebf5`, `928643da`,
  `08843d32`, `67bebd75`, `8dfe97e0`, `b778c385`, `ed75fbdd`, `809e9160`, `07ddd477`,
  `c360e56a`, `385c500b`, `02ebb9f8`, `4ea58b96`, `6a2a620b`, `d57ce83f`, `be7d4a28`,
  `307907a1`, `9ec16b09`, `c6ed04f8`, `dbf77589`, `fe319860`, `c8a8f8de`, `1ae5a093`,
  `9cf2b14d`, `4d3fa6ef`, `0fd71ce6`, `d2b55174`, `9611bc2f`, `75447ca0`, `9dcb968d`,
  `d98dedea`, `178c1542`, `59418af1`, `95f75c7a`, `f34ec469`, `c71e0e78`, `936358be`,
  `333e31f8`, `418de425`, `905f4514`, `4c329877`).

**Validation**

- `uv run ruff check .` passed.
- `uv run ruff format --check .` passed.
- `uv run pytest --no-cov` passed with `3556 passed`, `15 skipped`.

## v0.8.1 (2026-05-19)

This patch release packages the post-v0.8.0 realism and skill-guidance fixes on `dev`.
The branch contains only `fix:` and `docs:` commits since v0.8.0, so the version moves
from `0.8.0` to `0.8.1` under the pre-1.0 semver policy.

**Source-native host and network realism**

- Improved Linux maintenance/syslog texture, RFC5424 eval compatibility, syslog kernel timing,
  anacron lifecycle behavior, Zeek HTTP accounting, Zeek sensor accounting, and SSH/Zeek
  observation timing (`8cd071b`, `74f6a29`, `db5d550`, `508cb3d`, `8a51954`, `c88a40a`,
  `72b144a`).
- Tightened Windows audit invariants, endpoint identifiers, browser launch URLs, session
  normalization, non-Windows eCAR failed-session typing, Linux SSH evidence, transient PID
  allocation, and Windows GUID rendering (`1862d37`, `15623a4`, `97969d0`, `698f921`,
  `bc43b8c`, `20e26ca`, `3322297`, `2713026`).

**Scenario and skill guidance**

- Added staged archive provenance, sensor realism, web/proxy response stability, UFW block-flow
  semantics, endpoint consistency, reduced high-signal realism fingerprints, assessment-loop
  records, and clarified the eforge scenario bundle layout for Codex/Claude skills (`5ec52ef`,
  `dc2cdc2`, `16114bc`, `56f6044`, `4064ba0`, `66e53c8`, `33c2624`).

**Validation**

- Full slow-enabled suite passed on current `dev`: `uv run pytest --include-slow --no-cov`
  completed with `3369 passed`, `2 skipped`.
- Skill installer/Codex skill validation passed for the scenario bundle layout update.
- Ruff checks and format checks passed before release preparation.

## v0.8.0 (2026-05-19)

This minor release adds target-aware output rendering so a single scenario can generate
SIEM-neutral default output or SOF-ELK-compatible file layouts without changing scenario YAML.
The branch includes `feat:` commits, so the version moves from `0.7.2` to `0.8.0` under the
pre-1.0 semver policy.

**Target-aware rendering**

- Added `eforge generate --target default|sof-elk`, `OUTPUT_TARGET.txt`, explicit per-format
  target policy, and evaluation support that reads target metadata while keeping missing markers
  compatible with legacy/default datasets (`5d5d25b`).
- Added shared syslog-family rendering helpers so default Linux syslog remains flat RFC5424,
  while the SOF-ELK target can render RFC3164 year-partitioned Linux syslog and Cisco ASA output
  through one source-native envelope path (`d6b859c`, `5d5d25b`).
- Added Windows Security and Sysmon Snare-over-RFC3164 rendering for the SOF-ELK target while
  preserving XML-only output for the default target (`69e053a`, `5d5d25b`).

**Source-native compatibility and validation**

- Tuned Linux SSH/syslog message realism for the target-aware syslog path without bringing in the
  external parser pipeline (`a6725f6`).
- Preserved additional source-native fixes from `dev` before release: ECDSA CA key metadata,
  eCAR login `LogonType`, Active Directory site SRV lookup handling, and proxy CONNECT status
  text diversification (`2c061b0`, `8d22cde`, `60cec0b`, `b04f293`).
- Documented the extraction boundary and recorded the full slow-enabled validation pass
  (`0731212`, `dadb742`).

**Validation**

- Focused target/rendering/eval checks passed: `242 passed`.
- Full normal suite passed: `uv run pytest --no-cov` completed with `3292 passed`, `37 skipped`.
- Slow release lane passed: `uv run pytest --include-slow -m slow --no-cov --durations=20`
  completed with `13 passed`, `1 skipped`, `3306 deselected`.
- Full slow-enabled suite passed: `uv run pytest --include-slow --no-cov` completed with
  `3296 passed`, `24 skipped`.
- Ruff checks passed with `uv run ruff check .` and `uv run ruff format --check .`.

## v0.7.2 (2026-05-18)

This patch release packages the final automated PR review integration batch after v0.7.1. The branch contains only `fix:`, `test:`, and `docs:` work since the prior version bump, so the version moves from `0.7.1` to `0.7.2` under the pre-1.0 semver policy.

**Automated PR review integrations**

- Hardened session offset allocation for far-future scenarios and merged the accepted Codex review fixes for bounded event handling, parser resilience, emitter accounting, and validation guards (`592d943`, `83d5e36`).
- Integrated the accepted after-rebase fixes for current `dev`, including Zeek and web/session realism hardening, safer config validation paths, and source-native rendering corrections (`944249d`).
- Reworked the real-but-not-ready PR fixes at the owning layers: sidecar-safe writes, bounded bash template expansion, Zeek OCSP optional-field defaults, and generation-safe extra syslog weights (`e707e1a`).
- Integrated the final approved PR set, covering site-map expansion bounds, observation-manifest trust binding, public DNS template validation, malformed URL handling, syslog/profile validation, non-finite Zeek timestamp guards, explicit-credential fallback validation, and PID-reuse process termination tracking (`4529265`).

**Automation records and validation**

- Recorded the full slow suite pass after final integration: `uv run pytest -v --include-slow --no-cov` completed with `3265 passed`, `24 skipped` (`c072849`).
- Preserved the PR #163 automated review notes in `TODO.md`, including the prior amended review state and remaining concerns that were later handled through the review workflow (`88af3a2`).

## v0.7.1 (2026-05-16)

This patch release packages the latest `dev` branch realism work since v0.7.0. The branch contains only `fix:` and `docs:` commits, so the version moves from `0.7.0` to `0.7.1` under the pre-1.0 semver policy.

**Source-native host and process realism**

- Improved observation coherence, TLS realism, baseline web/Kerberos texture, service-logon semantics, Linux telemetry, bash tool affinity, host-service command selection, CLI HTTP/analyzer timing, proxy-flow ownership, and session/web behavior across the early assessment loops (`7caf4b2`, `b476c16`, `7e6c7ea`, `02bd4bd`, `67ac00d`, `caf06a7`, `508501c`, `811b2f1`, `ac30094`).
- Tightened service and process lifecycle behavior by improving Loop 7 service/CLI realism, closing tracked foreground processes at finalization, correcting service-install start semantics, binding shell helpers to user sessions, repairing source-native host contradictions, preserving web response semantics, aligning command/DNS semantics, enforcing auth/network source semantics, and repairing source-native process and Zeek texture (`3f66d06`, `6374303`, `e768f4c`, `76bc107`, `b7c8a70`, `93463e4`, `7a82449`, `9c9dcef`, `21f3a79`).

**Network, web, DNS, and TLS realism**

- Reduced rare admin-tool noise, diversified web/proxy status outcomes, varied TLS duration floors, repaired network/session source semantics, fixed proxy HTTP response semantics and redirect MIME handling, modeled persistent Zeek HTTP transactions, aligned persistent HTTP parent-flow accounting, varied Zeek multi-sensor timing offsets, diversified public DNS/certificate profiles, loosened DNS tunnel/C2 cadence, and mixed eCAR FLOW principal attribution (`f0f5c3d`, `46bd9d2`, `bc738f2`, `eaf090a`, `dc4616c`, `b4c99b1`, `dd56f08`, `4f92a11`, `91546d7`, `999a20e`, `350b0f5`, `bc3772d`).

**Linux endpoint and blind-loop texture**

- Diversified Linux command texture, reduced Linux endpoint cadence fingerprints, diversified Linux syslog daemon noise, and varied Linux syslog timer texture to remove repeated blind-review fingerprints in bash histories, daemon pools, `phpsessionclean`, `irqbalance`, and related source-native messages (`e9ff69c`, `ecc45ef`, `38e431d`, `e37a5f3`).
- Recorded blind-review results and next-target decisions for loops 5 through 30, preserving automated eval scores, hard probes, reviewer synthetic-confidence scores, deliberation outcomes, and follow-up priorities in `TODO.md` (`380f38c`, `5702bbf`, `a477484`, `e21a25f`, `454edf0`, `34731ff`, `4993829`, `9ae822c`, `af301b9`, `16740cc`, `024db1a`, `aeb457b`, `4484c50`, `e98f744`, `6b207bd`, `f991a77`, `6b589ec`, `f8c19f0`, `a097f30`, `09076c1`, `ebc2d42`, `c13e429`, `3e78053`, `5994b26`, `73e123e`, `044b097`).

**Validation**

- Each fix loop was validated with focused regression tests, `uv run eforge validate-config`, Ruff checks, normal `uv run pytest --no-cov -q` runs, regenerated iteration-test data, quantitative eval, and blind expert review as recorded in `TODO.md`.
- Latest Loop 30 validation passed `uv run pytest --no-cov -q` (`3162 passed`, `37 skipped`), quantitative eval at `95.99/100` across `76,333` records, and a hard probe showing `4,579/13,240` eCAR FLOW records now carry mixed principals with zero `pid=-1` principal leaks.
- Release-prep validation passed `uv run eforge validate-config`, `uv run ruff check .`, `uv run ruff format --check .`, the explicit coverage gate (`3162 passed`, `37 skipped`, `80.58%` coverage), and the slow release lane (`13 passed`, `1 skipped`, `3185 deselected`).

## v0.7.0 (2026-05-15)

This minor release packages the latest `dev` branch realism, observation, and CI work since v0.6.3. The branch includes `feat:` commits, so the version moves from `0.6.3` to `0.7.0` under the pre-1.0 semver policy.

**Observation and evaluation realism**

- Added observation profiles and an observation-aware evaluation manifest so generated datasets can model source-specific coverage and missingness more explicitly (`0ed18df`, `599a40e`).
- Improved source identity metadata, endpoint baseline noise policy, and host activity distribution realism for more believable source-native evidence (`317decd`, `5931c8a`, `c8f6226`).
- Cleaned calibration evaluation warnings by tightening observation-aware causality matching, sensor-filtered observation-manifest accounting, OCSP optional-field rendering, and visible Windows logon-before-process ordering (`e771e77`).

**Source-native timing and log texture**

- Emitted syslog in RFC 5424 format and improved web sessions, sensor timing, auth noise, and Zeek timing realism (`0247cc7`, `90e96cf`, `30c8217`).
- Fixed generation sidecar emission so overwrite swaps preserve the expected matched output contract (`df2a446`).

**CI and developer workflow**

- Split slow comprehensive tests from coverage instrumentation, keeping normal coverage on fast/default tests while running slow workload tests separately with `--no-cov` (`a6d7583`).
- Stabilized the slow release gate by skipping the non-gating 500MB `tracemalloc` ceiling check and fixing observation manifests for scenarios that use explicit end times instead of durations (`6e6c9f3`).

**Validation**

- Release-prep validation passed `uv run ruff check .`, `uv run ruff format --check .`, `uv run pytest --cov-report=xml` (`3030 passed`, `37 skipped`, `79.82%` coverage), and `uv run pytest --include-slow -m slow --no-cov --durations=20` (`13 passed`, `1 skipped`, `1:08`).
- PR #162 cleanup validation passed `uv run eforge validate-config`, `uv run eforge validate scenarios/iteration-test/scenario.yaml`, `uv run eforge generate scenarios/iteration-test/scenario.yaml --verbose --force`, `uv run eforge eval scenarios/iteration-test/data --scenario scenarios/iteration-test/scenario.yaml --format json --verbose` (`94.64`, all hard gates passing), focused regressions (`164 passed`), and `uv run pytest -v` (`3075 passed`, `15 skipped`).

## v0.6.3 (2026-05-13)

This patch release packages the latest `dev` branch realism work since v0.6.2. The branch contains only `fix:` and `docs:` commits, so the version moves from `0.6.2` to `0.6.3` under the pre-1.0 semver policy.

**Loop 65-95 source-native realism fixes**

- Reduced recurring synthetic tells across network, proxy, TLS, ASA, DNS tunnel, shell, browser, Snort, Kerberos, Windows auth, and endpoint identity evidence (`aa82652`, `7975e3f`, `4751fc3`, `4313c6a`, `cd263e9`, `1bde596`, `a3a28af`, `84d8962`, `98a427c`, `bf36641`, `f7874a8`, `c74fae4`, `fa97120`, `a59c7b4`, `11f3e73`, `d4c0a1b`, `996f7c0`, `5a1751f`, `560c50f`, `2665cef`, `ba976a0`, `605c3aa`, `833e5eb`, `a690d9f`).
- Removed clock-derived and lifecycle-derived fingerprints by improving Windows LUID/logon ID behavior, Linux PID/session allocation, singleton Windows service lifecycle, syslog session monotonicity, and Sysmon module identity stability (`cc8d295`, `225f286`, `3dec4f6`, `9e6185f`, `9d71c0b`, `30bc103`, `6f5df29`, `96a4070`, `0454d64`, `ff5ce1c`, `6e37ef4`, `c0b08d5`, `74f33d7`, `c110e6f`, `28bbcda`, `92e99d0`).

**Post-loop 95 sprint stack**

- Addressed immediate realism defects, lifecycle/timing fingerprints, scan and DNS tunnel regularity, and Windows scheduled-task source-native XML rendering (`c568082`, `2f75757`, `5b03831`, `099665f`).
- Recorded the post-loop roadmap, Loop 95 and Loop 96 assessment results, slow-inclusive pytest verification, and follow-up TODOs for web session realism, well-synced Zeek sensor timing, endpoint/eCAR variance, and deferred observation coverage (`e7ff866`, `50204f5`, `3778e25`, `505f17a`).

**Scenario authoring guidance**

- Tightened attacker-controlled naming guidance so plausible domains, services, accounts, scheduled tasks, processes, and staging archives do not become semantic breadcrumbs that reveal the attack narrative (`505f17a`).

**Validation**

- The sprint stack was validated with focused tests, repo-wide Ruff checks, `eforge validate-config`, normal pytest runs, regenerated iteration-test data, quantitative eval, and a slow-inclusive pytest pass recorded in TODO.
- Release-prep validation ran `uv run ruff check .`, `uv run ruff format --check .`, and `uv run pytest tests/unit/test_install_skills.py -q --no-cov` before opening the dev-to-main PR.

## v0.6.2 (2026-05-12)

This patch release packages the `dev` branch hardening work since v0.6.1. The branch contains only `fix:` and `docs:` commits, so the version moves from `0.6.1` to `0.6.2` under the pre-1.0 semver policy.

**Lifecycle, identity, and endpoint realism**

- Tightened process/session lifecycle and network timing across endpoint sources, including storyline logoff ordering, singleton process reuse, eCAR listener flow correlation, endpoint/DNS tunnel tells, and renderer artifacts (`614bb75`, `843e860`, `e042dd5`, `8fa1ce5`, `0d21ea7`, `982b0ff`).
- Improved Linux process/syslog texture, dhclient ordering, workstation lock/unlock realism, web scan behavior, packet/process identity, and slow-suite proxy/logon contracts (`45e570a`, `4b23312`, `cf29343`, `68eb0de`, `fb95f13`).
- Addressed iterative endpoint and source-invariant review findings from loops 30-33, 35-40, 41-57, 61, and 63 (`bf4ff40`, `c3c8ced`, `84eec44`, `b7f3c30`, `b995e4e`, `e579236`, `9d1981e`, `804d54c`, `48fdfce`, `37e2ab9`, `254d129`, `38fc7be`, `245f55c`, `d02500a`, `7039592`, `2bdbb0e`, `24725fa`, `a79354b`, `d8d914b`, `63a26e9`, `c77bef7`, `9e87cb3`, `8f9c61a`, `25d2a20`, `2a1982f`, `52c3c0d`, `788364f`, `24cc06b`, `b3695c9`).

**Network, proxy, TLS, and analyzer correlation**

- Fixed protocol and source-native network evidence issues around loop 34 protocol correlation, proxy egress DNS, multisensor Zeek file timing, loop 62 analyzer/auth telemetry, TLS certificate chain ordering, and loop 65 parent/NAT visibility (`e5f4268`, `e8cb425`, `1f23689`, `ed5d34b`, `9aa20c9`, `6be55b3`, `762562b`).
- Closed loop 65 hard-probe gaps and recorded loop 40 and loop 65 assessment outcomes in the development history (`da81c78`, `9d6d8b2`, `495918f`).

**Security and evaluator hardening**

- Hardened Windows event spool decoding and final flush behavior with typed spool payloads and SQLite-backed streaming fixup passes that preserve process-create, process-termination, logoff, and lock/unlock ordering (`e04b49a`).
- Prevented ground truth from claiming skipped process-access/create-remote-thread evidence, hardened malformed beacon URL parsing, bounded cyclic Sysmon parent-process ordering, and preserved TCP header accounting for DNS SERVFAIL fallback rows (`13a6e19`, `bf901fb`, `791106e`, `4627326`).

**Validation**

- Focused verification during the branch included targeted unit coverage for DNS fallback accounting, Sysmon parent ordering, evaluator beacon matching, process-access/remote-thread skip propagation, and Windows emitter spool behavior.
- Release-prep validation ran `uv run ruff check .`, `uv run ruff format --check .`, and the focused tests listed in the dev-to-main PR description.

## v0.6.1 (2026-05-03)

This patch release packages the dependency refresh PRs merged into `dev` after v0.6.0. The branch contains only `chore(deps)` commits, so the version moves from `0.6.0` to `0.6.1` under the pre-1.0 semver policy.

**Dependency refresh**

- Updated Rich to 15.0.0 for the CLI rendering stack (`16901a2`).
- Updated pytest-cov to 7.1.0 for current coverage plugin behavior (`a9d7dae`).
- Updated Pydantic to 2.13.3 and pydantic-core to 2.46.3 for schema validation (`b242b2f`).
- Updated Ruff to 0.15.12 for linting and formatting (`86e6471`).
- Updated pre-commit to 4.6.0 for local hook execution (`6d87d36`).

**Validation**

- Dependency sync, linting, formatting, config validation, CLI smoke tests, scenario validation, pre-commit hooks, and the full pytest suite all passed with the refreshed dependency stack.
- Full suite with coverage passed before release prep: `uv run pytest --cov=evidenceforge --cov-report=term-missing` with 2656 passed, 37 skipped, and 78.00% coverage.

## v0.6.0 (2026-05-03)

This release packages the dev branch since `main` into a pre-MVP quality and Codex workflow release. Because the branch includes feature commits, the version moves from `0.5.0` to `0.6.0` under the pre-1.0 semver policy.

**Codex skill installation and assessment workflow**

- Added `eforge install-skills --agent codex` support alongside the existing Claude Code install path, with valid Codex `SKILL.md` frontmatter, conservative stale cleanup, and preservation of user-managed `eforge-*` skills such as `eforge-assess` (`9974b20`, `e63e6cb`).
- Imported and refined the independent `eforge-assess` Codex skill workflow for validate/generate/evaluate/blind-review loops, including bounded-window reviewer guidance, commit-before-next-loop discipline, and pytest-before-commit guidance (`aea8428`, `9df7349`).

**Evaluation and scenario guidance**

- Migrated evaluation to the four-pillar scoring model and fixed targeted evaluator issues around event presence, parseability, cross-source agreement, timing bounds, and short-scenario handling (`1a62403`, `5b138d7`, `891d9ba`).
- Tightened scenario and skill reference guidance so generated scenarios use source-native fields and current schema expectations without duplicating large reference content in command prompts (`124881c`, `f92d087`, `8a10345`).

**Endpoint, auth, and process causality**

- Fixed high-severity lifecycle and ordering defects across Windows Security, Sysmon, eCAR, Linux syslog, and storyline-derived process activity, including post-termination telemetry, process follow-on timing, singleton/system process handling, and log clear subject/token context (`cc00d6a`, `4d42461`, `3405c4d`, `b7fa175`, `5057517`, `605ebc5`, `6125e6d`, `bbb128a`, `37ffaef`, `0b5a676`, `946719c`, `101755c`).
- Improved endpoint identity realism for explicit credentials, SYSTEM/NT AUTHORITY rendering, LogonID/PID provenance, DNS Client process attribution, and cross-host eCAR actor ownership (`a1dc4e9`, `afcc63a`, `cfd16d7`, `028cca6`, `cc5eed2`).

**Network, proxy, TLS, and firewall realism**

- Preserved network timing invariants and source-native visibility across Zeek, Cisco ASA, proxy, web access, and storyline flows, including HTTP lifetime bounds, ASA connection IDs, DNS transaction accounting, denied CONNECT accounting, explicit proxy byte accounting, and NAT/source rendering (`442f41e`, `f13982d`, `7e2b829`, `3a382a0`, `5c995ba`, `fa1a7bd`, `a42ff57`, `e2714c5`).
- Improved TLS/certificate realism and scanner/DNS behavior by avoiding public-CA chains for raw IP TLS, keeping TLS success/failure state coherent across sources, reducing repeated certificate/hash artifacts, and diversifying DNS tunnel labels and web scan cadence (`36b0aa0`, `5aa3a7b`, `6b3a299`, `a5a8af2`).

**Validation**

- Fixed the CLI `eforge version` command to report the package `__version__` instead of the stale hardcoded `0.1.0`, and added unit coverage for the command.
- Full slow-inclusive suite passed before release prep: `uv run pytest -v --include-slow` with 2669 passed, 23 skipped, and 80.54% coverage.

## v0.5.3 (2026-04-30)

Five pre-existing evaluation false-positives eliminated. No generator behavior changes.

**Evaluator bug fixes**

- **Windows 4800/4801**: Added `workstation_locked` and `workstation_unlocked` entries to `WINDOWS_VARIANT_MAP` in `parseability.py`. Records for those EventIDs were evaluated against the base variant (missing required fields) rather than the correct variant, producing spurious "Unknown field" warnings and spec-conformance failures.
- **eCAR field declarations**: Declared six previously-emitted-but-undeclared optional base fields in `ecar.yaml`: `outcome`, `status_code`, `sub_status` (USER_SESSION/LOGIN) and `target_pid`, `target_process_uuid`, `target_image_path` (PROCESS/OPEN). Eliminated 6× "Unknown field in ecar" warnings per eval run.
- **eCAR rename**: THREAD/REMOTE_CREATE fields `tgt_pid` / `tgt_pid_uuid` renamed to `target_pid` / `target_process_uuid` to match the OpTC eCAR spec and the naming used by PROCESS events. Updated emitter, YAML, co_occurrence config, tests, and docs.
- **Host Log Profile deduplication**: `_build_host_log_profile` in `causality.py` now normalizes `VisibilityModel._os_map` keys via `resolve_hostname` before deduplication. Each host now appears exactly once (bare form) instead of appearing as both `WS-01` and `WS-01.corp.example.com`.
- **Diurnal pattern skip on short scenarios**: `_score_diurnal_pattern` returns a skipped `SubScore` (score=None) when the event span is <24 h or covers only one weekday — conditions under which JSD is not meaningful. The Timing pillar aggregator renormalizes weights across the remaining active sub-scores. Previously this produced a hard-zero score on typical single-day scenarios.
- **proxy_access ↔ zeek_http**: Added `condition_a/b: method_not: CONNECT` to exclude CONNECT tunnel rows from the pair. Proxy emits two rows per HTTPS request (CONNECT + inner); the pivot previously matched them against a single zeek_http row, causing status_code false-failures. Extended `_matches_condition` in `plausibility.py` to support `<field>_not` inequality checks.
- **zeek_ssl ↔ zeek_x509**: Added `condition_b: host_cert: true` to restrict the `server_name ∈ san.dns` agreement check to leaf certificates. Intermediate and root CA certs correctly have empty `san.dns` — the evaluator rule was incorrectly flagging them as failures.

**New / updated tests**

- `test_eval_record_fidelity.py`: `TestWindowsVariantMapCoverage` — all mapped variant names exist in the format YAML; 4800/4801 explicitly covered.
- `test_eval_cross_source_pairs.py`: `TestMatchesCondition` extended with three `_not` cases; `TestProxyZeekHttpConnectExclusion` (2 tests); `TestZeekSslX509IntermediateCAExclusion` (2 tests).
- `test_eval_timing_bounds.py`: `test_short_scenario_span_is_skipped` asserts `skipped=True, score=None` (was: `score=100`).
- `test_ecar_thread_process_access.py`, `test_ecar_spec_compliance.py`: updated assertions for `target_pid`/`target_process_uuid` rename.

---

## v0.5.2 (2026-04-30)

Completion of the 4-pillar evaluation restructure: rewritten field agreement scorer, strict-mode validators, two new timing sub-scores, Zeek schema fixes, and extended rule coverage.

**Signal integrity fixes (Phase A)**

- `event_presence` improved from 69.05 → 85.71 on apt-healthcare-breach dataset (acceptance_passed now True).
- Fixed FQDN hostname indexing: records with FQDN Computer fields (e.g., `WS-DEV-02.meridianhcs.com`) are now indexed under both FQDN and bare hostname keys. Eliminated the primary cause of missed storyline traces.
- Added `_DURATION_EVENT_TYPES` (beacon, dns_tunnel, dga_queries, web_scan): extended forward search window to `min(interval_seconds, 3600)` for duration-based events. Beacons with 10-minute intervals no longer require trace at exact `time:` offset.
- Added `logoff` and `raw` matchers in `_record_matches`. Both had fallthrough-to-False behavior; now logoff matches 4634/4647 on Windows, session-closed on syslog.
- Documented 6 remaining generator gaps (rogue DHCP, DC-01 C2 beacons without NAT, standalone DNS): categorized as (c) scenario topology gaps, not eval bugs.

**Cross-source field agreement (Phase C)**

- Replaced the no-op `_timestamps_agree` implementation with real pivot-key joins.
- New `src/evidenceforge/config/evaluation/cross_source_pairs.yaml` with 5 defined pairs: Windows 4688 ↔ eCAR PROCESS/CREATE (same PID+hostname+60s window), zeek_conn ↔ Cisco ASA flow (4-tuple match), web_access ↔ zeek_http and proxy_access ↔ zeek_http (client+URI+10s bucket), zeek_ssl ↔ zeek_x509 (cert_chain_fuids list → x509 id, server_name ∈ san.dns).
- Supports: multi-field pivots, `list_contains` pivot (ssl fuids), `require_hostname_match`, `time_window_seconds`, normalizers (`lower`, `path_basename_ci`, `cn_from_dn`), numeric tolerance, `b_is_list` for list-valued fields, nested properties access (`b_nested`).
- `field_agreement` score on apt-healthcare-breach: 93% (real disagreements: proxy vs Zeek HTTP status codes diverge because proxy records upstream status; these are genuine generator behavior differences).

**Parseability strict mode (Phase D)**

- New `validate_strict(format_name, raw, fields)` in `src/evidenceforge/formats/validator.py`. Dispatches to per-format checks when a format appears in `STRICT_FORMATS`.
- syslog: accepts BSD format (Mon DD HH:MM:SS HOSTNAME) and RFC 5424 with PRI (`<N>`); validates PRI ≤ 191 when present.
- zeek_*: each raw line must be valid JSON and a top-level object.
- windows_event_security / windows_event_sysmon: XML must be well-formed with root `<Event>` and `<System>` child.
- eCAR: JSON must be valid; `object` and `action` fields must be in the known enum sets.
- Strict mode runs only when `record.raw` is non-empty and the format is in `STRICT_FORMATS`; results merged into the Parsability sub-score.

**Zeek schema fixes (Phase B)**

- Fixed `zeek_files.yaml`: `tx_hosts`, `rx_hosts`, `conn_uids`, `analyzers` changed from `type: string` to `type: list`. These fields are emitted as JSON arrays; the validator was rejecting them with false positives, causing 15,395 spec_conformance failures.
- Fixed `zeek_http.yaml`: `tags` changed from `type: string` to `type: list`.
- Fixed `zeek_pe.yaml`: `section_names` changed from `type: string` to `type: list`.
- `spec_conformance` on apt-healthcare-breach: 99.22% → 100% after fixes.

**Evaluation rule extensions (Phase E)**

- `co_occurrence.yaml`: added impossible-combo rules — `zeek_conn` SF+TCP cannot have `duration=0`; `zeek_http` CONNECT must have `response_body_len=0`; `zeek_ssl` established connections must have `server_name`.
- `co_occurrence.yaml`: added new sections for `zeek_http` and `zeek_ssl`.
- `co_occurrence.yaml`: added `equals` check type (alongside existing `not_equal`, `in`, `present`, `min_length`). Fixed `min_value`/`max_value` to work as standalone checks (not just combined).
- `distributions.yaml`: added `zeek_http` (method, status_code) and `zeek_ssl` (version, established) reference distributions.

**New timing sub-scores (Phase F)**

- `diurnal_pattern` replaces `work_hours` as the active scoring sub-score (work_hours demoted to weight=0 informational). Scores 2D hour×weekday distribution via Jensen-Shannon divergence vs persona reference profile. Penalizes artificially uniform distributions (JSD < 0.01 treated as robotic). Requires ≥30 events per user.
- `attack_chain_timing`: checks elapsed time between consecutive storyline events against bounds from new `src/evidenceforge/config/evaluation/timing_bounds.yaml`. Default bounds 5s–2h; per-action-type overrides (lateral movement, exfiltration, recon, credential, persistence, C2, beacon, deploy, escalation). Activity matching: case-insensitive substring on step activity field.
- Temporal Realism sub-score weights updated: diurnal 0.20, burstiness 0.20, system_regularity 0.15, causal_ordering 0.20, timing_plausibility 0.15, attack_chain_timing 0.10 (sum=1.0).

**New tests (Phase G)**

- `tests/unit/test_eval_cross_source_pairs.py` (29 tests): pivot helpers, normalizers, values_agree, score_pair, integration with empty records.
- `tests/unit/test_eval_strict_parsers.py` (29 tests): all four format-specific strict validators, STRICT_FORMATS set.
- `tests/unit/test_eval_timing_bounds.py` (15 tests): attack_chain_timing (bounds loading, keyword matching, in/out-of-bounds), diurnal_pattern (work-hours clustering, uniform distribution penalty, insufficient-event fallback).
- Updated `test_eval_temporal.py` end-to-end test to expect 7 sub-scores.
- Total: 252 unit tests (was 173).

**Docs (Phase G.5)**

- `commands/eforge/references/config-evaluation.md`: removed "planned" markers from timing_bounds and cross_source_pairs sections; added full schema documentation for both.
- `commands/eforge/evaluate.md`: updated Cross-Source Field Agreement, Diurnal Pattern, and Attack-Chain Timing descriptions; added improvements-table rows for low field_agreement and low attack-chain timing.
- `docs/reference/CUSTOMIZING_CONFIG.md`: added eval config section documenting the six YAML files and how to tune them per-project.

**Score changes on apt-healthcare-breach (1.02M records, 14h, 17 users, 42 storyline events)**

| Sub-score | Before | After |
|-----------|--------|-------|
| event_presence | 69.05 (FAIL) | 85.71 (PASS) |
| spec_conformance | 99.22 | 100.00 |
| field_agreement | 100 (no-op) | 93.00 (real) |
| population_statistics | 78.58 | 81.14 |
| diurnal_pattern | — (new) | 100.00 |
| attack_chain_timing | — (new) | 90.24 |
| Overall | 87.63 | 94.13 |
| acceptance_passed | False | **True** |

---

## v0.5.1 (2026-04-30)

Evaluation framework restructure: 5 dimensions → 4 pillars (Parseability, Plausibility, Causality, Timing).

**Framework restructure**

- Replaced the 5-dimension / 23-sub-score model with 4 pillars (20 sub-scores). All existing sub-scores are re-homed, not dropped. Two baseline-coherence sub-scores (D2.4, D2.5) are demoted to a supplementary "Host Log Profile" diagnostic (informational, not scored). One old sub-score (`work_hours`) is replaced by the planned `diurnal_pattern`.
- Two-tier acceptance model: every sub-score now has a **minimum** (hard gate — dataset fails if missed) and an **aspirational** target (informational stretch goal). Thresholds stored in `src/evidenceforge/config/evaluation/thresholds.yaml` for tuning without code changes.
- Pillar weights: Parseability 0.30, Plausibility 0.25, Causality 0.25, Timing 0.20.
- Hard gates: `spec_conformance ≥ 95`, `value_plausibility ≥ 95`, `causal_ordering ≥ 90`, `event_presence ≥ 85`.

**Engine changes**

- `DimensionScore` renamed to `PillarScore`; `DimensionScore` kept as a backward-compat alias.
- `QualityReport.dimensions` kept as a property alias for `pillars`.
- `AcceptanceCriterion` gains `pillar` (string), `aspirational`, and `meets_aspirational` fields.
- `QualityReport` gains `aspirational_met` / `aspirational_total` counts.
- Engine reads thresholds from YAML; acceptance criteria are no longer hard-coded.
- Pillar-level `supplementary` dicts merged into `QualityReport.supplementary`.
- Transition-period machinery: `_LEGACY_SUB_SCORE_LOCATIONS` maps new sub-score keys to old dimension numbers/keys so thresholds.yaml can use new vocabulary while legacy scorers still run.

**Sub-score fixes**

- `CrossSourceScorer`: D2.4 (`baseline_sampled`) and D2.5 (`baseline_aggregate`) zeroed to `weight=0` (not scored); S1/S2/S3 re-weighted to 1/3 each. Emits `host_log_profile` diagnostic in `supplementary`.
- `NoiseRealismScorer` / `anomaly.py`: red herring events no longer inflate the organic anomaly rate. Red herrings are pre-declared storyline injections — they are not background anomalies.
- `TemporalScorer`: fixed pre-existing timezone-naive/aware comparison bug in causal ordering check.

**Report**

- Pillar-oriented text report replaces the old dimension table.
- Shows minimum (PASS/FAIL) and aspirational (met/missed) side-by-side for each gated sub-score.
- Summary line: "Aspirational targets: N/M (P%)".
- Host Log Profile supplementary section shows per-host expected vs. present formats (only when missing formats exist or `--verbose`).

**CLI**

- Added `--real-parsers` flag (no-op, reserved): prints "real parser backend not yet implemented" and exits cleanly. Reserves the interface for a future strict-parser evaluation backend.

---

## v0.5.0 (2026-04-29)

Version bump only; no code changes. Releases a known-good snapshot after the v0.4.3 correlated-timing review.

---

## v0.4.3 (2026-04-29)

Cross-source correlated timing hardening and Windows auth timing polish, driven by an adversarial timing-review cycle.

**Correlated timing** — introduced data-driven timing profiles (`src/evidenceforge/config/activity/timing_profiles.yaml`) as the source of truth for all inter-event offsets and stabilized cross-source timing correlation.

- Causal prerequisites (`network.dns_before_tcp`, `auth.kerberos_before_logon`, `process.remote_thread_lsass_access`) now consult a YAML profile instead of hard-coded constants; source-native latency, teardown margins, Zeek analyzer offsets, TLS duration floors, and Windows/Sysmon collision-spacing knobs are all configurable (47ec365, 7fb35c8).
- Stale evidence suppression: teardown events (SSH close, FLOW terminate) only emit for sessions/processes with a matching open event (f764425, 2ff89c4).
- Timing alignment across edges: EDR DNS↔SSH, SSH↔DNS↔proxy, IDS↔Zeek DNS alerts, process teardown↔Sysmon 5↔Security 4689↔eCAR PROCESS/TERMINATE (05e72a3, f831dc1, c2e7d7b, 7e1f9a1).
- Correlated lifecycle edge cases: source-offset margin before logoff, lifecycle guards for cross-source timing, cross-source network timestamp offsets (cc89170, 38266e4, e156d9b).
- Loop timing review follow-up findings resolved (ebe6bbf).
- Proxy context honors the canonical HTTP status code end-to-end rather than rewriting the origin response on the client-leg (3a887c3).

**Windows auth timing & rendering polish**

- Stabilized process parent chains during auth-adjacent activity (ac69865).
- Auth rendering/coherence fixes across 4624/4625/4634/4648 and pairing with target-host 4672 for elevated sessions (270eec3, 2467428, b467e6e).
- Timing realism for auth event sequences including DC machine-account logons (4b8779a).
- Windows logon token shape derived from auth context (d553709).

---

## v0.4.2 (2026-04-29)

Windows EDR and emitter field provenance hardening from a dedicated blind review.

- Field provenance alignment across emitters: WFP connection process image preserved, WFP/DNS provenance cleaned, emitter field consistency verified via blind review (ee32f4f, 980e500, c4203ee, 8432cc9).
- Windows process EDR cross-source realism polished across Sysmon 1/5/8/10, Security 4688/4689, and eCAR PROCESS/CREATE/TERMINATE/OPEN (d7bdf56, f794877, e4c5e5e).
- Consolidated approved open-PR updates (1b180a3).
- CI tuned: fast unit gate runs on dev; slow integration tests skipped on dev and re-enabled per PR (a976a44, b8409da).

---

## v0.4.1 (2026-04-28)

Windows authentication realism round 1.

- Data-driven Kerberos pre-auth realism: 4771/4776 validation paths, stale-account failure profiles (5fe6ca2).
- Improved Windows auth event realism across 4624/4625/4634/4648 rendering (df5a921).

---

## v0.4.0 (2026-04-28)

Web proxy path modeling and TLS/Zeek network realism — the biggest single feature release of the hardening campaign.

**Explicit proxy path modeling**

- `environment.proxy.mode` (transparent | explicit) controls whether proxy-routed HTTP/HTTPS keeps direct client→origin network evidence or splits into client→proxy and proxy→origin legs (9908cb6, 685bd81).
- DENIED proxy requests stop at the proxy leg and do not produce proxy→origin Zeek/IDS/firewall transactions (848de7d).
- Explicit proxy CONNECT tunnels reused across subsequent requests; explicit proxy DNS routed through the proxy; post-CONNECT TLS emits SSL evidence reliably (3d576db, 1e87a5b, 3e01f32, 1ddb932).
- External-hostname beacons correctly route through the proxy when explicit mode is in effect (c145b4a).
- Proxy user agents moved to data-driven YAML (`proxy_user_agents.yaml`) for diversity (c71d43e).
- Proxy/HTTP content realism: separated CONNECT timestamps, Apache-style response content, correlated web_access ↔ zeek_http ↔ zeek_conn (d6ec7cc, 8da9050, 62bb6cb, 3ac0d9c, edf7f9b).
- HTTP proxy NAT realism improved (685bd81).
- Prevent future session reuse on edge cases (bf4026f).
- Broader HTTP and proxy realism improvements (cd8f9f3).

**TLS & X.509 realism**

- Destination-aware certificate profiles (d0f433c).
- Issuer-matched validity periods and issuer overrides aligned (359ed67).
- OCSP evidence linked through zeek_files (a98f7b0, 20713f0).
- Chain-depth realism from `tls_realism.yaml` (a9fcf77, 575f3c0).

**Zeek network realism**

- Improved Zeek DNS support, SMB file observations, analyzer protocol semantics, and TLS-related conn records (6cb1f88, 00ed3c8, e0bcba3, e50d3c1, d988269, eff613f).
- Zeek outputs are sorted on close for deterministic ordering (757ddb9).
- Network blind-eval findings addressed (372c49a).

**Sysmon**

- Sysmon realism signals improved (e73cb85).

**Other**

- Warn on malformed overlay presets rather than silently ignoring (06e7839).
- Evidence formats reference inaccuracies fixed (3102cc4).

---

## v0.3.0 (2026-04-22)

The MVP-plus release. Introduced the bulk/periodic event framework, workstation lock/unlock, explicit credentials (4648), DC admin-only baseline with RSAT correlation, network segmentation hardening, CLI filtering, and broad web-log realism improvements.

**Bulk event framework**

- Phase A: shared `_PeriodicEventBase` timing engine, `beacon`, `dns_query` (59b856d).
- Phase B: `web_scan`, `credential_spray` (6696428).
- Phase C: `dga_queries`, `dns_tunnel` (eb18af4).
- `ProcessAccessEventSpec` added to the `EventSpec` discriminated union so `process_access` can be declared directly as well as auto-generated by `create_remote_thread` → lsass causal expansion (c9c6017).
- Per-event-type jitter defaults: `beacon` 0.15, `web_scan` 0.4, `credential_spray` 0.5, `dga_queries` 0.3, `dns_tunnel` 0.25.
- `credential_spray` success fires at exact attempt count (b287d62).
- `web_scan_presets` registered in `eforge info` and `validate-config` (eff2e1a).
- Multiple adversarial-review rounds for the bulk-event framework (bec232d, aa63ad9, 511b5ae, fb7faed).
- Security hardening: bounded `dns_tunnel` payload size, capped `traffic_rates` overrides, hardened `web_scan` preset overlay against malformed types, explicit credential process PID for 4648 (3323d85, 7559f8c, 65af981, b3c1e9c).

**Workstation lock/unlock & explicit credentials**

- `workstation_lock` / `workstation_unlock` (4800/4801) baseline + storyline with persona-variance lock frequency and cross-hour lock persistence (223959d, 4ca4268, e55b4c6).
- `explicit_credentials` (4648) storyline handler; broader baseline 4648 patterns for scheduled-task and RunAs activity (2ab8c9e, 1154520).
- Cluster 4 tests + docs for Windows auth enrichment (229c7fa).

**DC admin-only baseline & RSAT correlation**

- Domain controllers receive admin-only baseline activity: no user desktop artifacts, type 3 logons from RSAT sessions on admin workstations (mmc.exe runs on the workstation, not the DC), type 10 RDP for direct admin access (4382147, 9cdc464).
- Correlated RSAT sessions produce cross-host events: mmc.exe + DLL loads on the workstation, LDAP/RPC to DC, type 3 logon on DC — all within seconds (e1e08d9).
- OS-aware domain filtering prevents Linux hosts from visiting Windows-only domains (9e32911).

**Network segmentation & firewall**

- `NetworkSegment.exposure` required; `external_ratio` for segments with `exposure: both` (0e72bd7).
- Top-level `NetworkConfig.public_cidrs` for the org's own public address blocks (separate from NAT-inferred ranges).
- `NetworkSensor.drop_mode` (drop|reject) controls denied-connection conn_state (S0 vs REJ).
- `NetworkSensor.threat_detection_rate` drives ASA 733100 threat-detection alerts when deny bursts exceed the configured threshold.
- `intensity` scales all background traffic via configurable `traffic_rates.yaml` (46236c0).
- PAT port overflow, SF missing duration, and syslog None hostname fixes (75de469).

**CLI & config**

- `--formats` CLI filter for targeted log generation; individual format names accepted in `output.logs` (e71163d, c1ba151).
- EDR overlay pool validation with fallback to defaults (9535939).
- Transactional `--force` overwrite with rollback on failure; preserved rollback dir on failed restore for manual recovery (1e8647e, d96c721, 0c85126).
- Moved CallTrace patterns and EDR pools to YAML with overlay support (9396719, e835405).
- Document `sysmon_filters`, `edr_pools`, `calltrace_patterns` configs (1346563).
- Normalize naive datetimes in emitter sort and session bootstrap (2f4a856).
- Remove redundant runtime cap in `_resolve_traffic_rate` (05a8842).
- DNS multi-answer IPs use correct provider, IPv6 prefixes from YAML (980e24f).
- `dns_registry` + `proxy_uri_templates` for new curated `site_maps` domains (7f3656b).

**Web log realism improvements** — root-cause fixes for three structural realism gaps identified during adversarial evaluation of the `vdf-web-scanning` scenario (0f1e79b):

- *Referer header centralization* (root cause: 5 of 6 `HttpContext` construction sites dropped the field): extracted `pick_referrer()` and `pick_scan_referrer()` into `src/evidenceforge/generation/activity/referrer.py`. Baseline web-server traffic now generates realistic Referer distributions (~55% blank, ~20% search engine, ~20% same-origin, ~5% social/news; bot UAs always blank). Auto-generated HTTP connections and both storyline HTTP event types now populate Referer. Per-scanner Referer behavior is declarative in `web_scan_presets.yaml` via `send_referrer` field, grounded in verified upstream source behavior: Nikto sends same-origin Referer on ~30% of requests (partial-crawl mode); gobuster/sqlmap/dirb/nmap_http send none. Scenario authors can pin `referrer` on `connection` and `beacon` event specs for phishing-click and drive-by scenarios.
- *Scanner UA token substitution*: added `src/evidenceforge/utils/ua_template.py` with `render_ua()` supporting scanner-scoped tokens (`@NIKTO_TESTID@`, etc.). Nikto UA updated from static `(Test:map_codes)` to `(Test:@NIKTO_TESTID@)` — now generates a unique 6-digit test ID per request, matching real Nikto behavior.
- *Per-event-type jitter defaults*: each concrete `_PeriodicEventBase` subclass now carries an event-appropriate jitter default instead of the uniform 0.2 (see bulk event framework above). Scenario authors can still override per-event; existing YAML that omits `jitter` now gets a more realistic default.

**Data realism fixes from expert panel** (P0/P1 batches)

- P0 fixes: user-profile apps on DCs, formulaic HTTP, SF orig_bytes (727dbb8).
- P1 fixes: task XML, SSH fingerprints, IDS SIDs, journald, SSH ordering (8333dbf).
- Two additional iteration rounds (8c6bb87, 217490d).
- 6 more P0/P1 realism fixes (1486928).
- `test+docs` for realism fixes (33723dd).
- 4800/4801 and other missing EventIDs added to eval distribution allowlist (5e22243).

**Validation & security**

- JSON Logic truthiness for field constraints enforced (ddeb1ef).
- Windows eval XML parser hardened against entity expansion DoS (a92ebbe).
- Linux `process_query` placeholder expansion resolved (791c12c).
- `attacker` user renamed to a plausible contractor account (ce58db5).

**Test & CI**

- Repaired 4 broken tests (activity_gen fixture, thread safety assertions, Zeek DNS interface, inbound traffic role) (98d7813).
- Tests: `test_referrer.py`, `test_ua_template.py`, `test_scan_referrer.py` (185 new assertions) added for web log realism. Full suite at v0.3.0 release: 2083 passed.

---

## Pre-MVP Quality Fixes

### World Model Refactor (2026-04-08)

- Added a compiled `WorldModel` / `WorldPlanner` layer above the canonical event model to unify user placement, host capability inference, infrastructure discovery, proxy routing, and shared session bootstrap across baseline and storyline paths.
- Centralized interactive/network/SSH/RDP session planning so planner-owned sessions are allocated in `StateManager` before `ActivityGenerator` emits correlated host and network evidence, eliminating duplicated remote-session logic and brittle mock-only assumptions.
- Extended runtime ownership state to carry session/process/connection provenance (`logon_id`, `session_kind`, `source_port`, `transport_pid`, initiating PID, close time, source host metadata) and aligned process-first connection attribution with the new layer.
- Completed a realism cleanup sweep replacing remaining `hash()`-based derivation in critical generation paths with `_stable_seed(...)`.
- Added dedicated unit coverage in `tests/unit/test_world_model.py` and reran full verification with `uv run pytest -v --include-slow` (`1483 passed`).

---

## Phase 1: Core Generation (COMPLETE)

**Goal:** Prove the concept with basic functionality, simplified schema, 2-3 log formats, small datasets (<10K events).

### 1.1 Project Setup & Infrastructure
- [x] Initialize uv project with pyproject.toml
- [x] Set up src/evidenceforge/ package structure
- [x] Create tests/ directory structure (unit/, integration/, live/, fixtures/)
- [x] Set up pytest with coverage configuration
- [x] ~~Create .env.example with AWS_PROFILE, AWS_REGION placeholders~~ REMOVED (no Bedrock integration)
- [x] ~~Create config.example.yaml with documented parameters~~ REMOVED (no config.yaml needed)
- [x] Add LICENSE file (MIT)
- [x] Set up GitHub Actions for CI (unit + integration tests only)

### 1.2 Core Data Models (Pydantic)
- [x] ~~`models/config.py` - Config models (AWS, Bedrock, output, logging)~~ REMOVED
- [x] `models/scenario.py` - Simplified scenario schema (Phase 1 subset)
  - [x] Basic TimeWindow, Environment, User, System models
  - [x] Simple persona structure (no LLM expansion yet)
  - [x] Basic storyline structure
- [x] `models/state.py` - Runtime state dataclasses (ActiveSession, RunningProcess, OpenConnection)
- [x] Custom exception hierarchy (EvidenceForgeError, ValidationError, etc.)

### 1.3 Configuration & Utilities
- [x] ~~`utils/config.py` - Config loader with env var interpolation~~ REMOVED
- [x] `utils/logging.py` - Logging utilities (redact_secrets)
- [x] `utils/time.py` - Time parsing utilities (ISO 8601, duration strings)
- [x] `utils/files.py` - File I/O utilities, path validation

### 1.4 State Management
- [x] `generation/state_manager.py` - StateManager class
  - [x] Session creation and tracking (LogonID generation)
  - [x] Process creation and tracking (PID allocation per system)
  - [x] Connection tracking
  - [x] DNS cache
  - [x] Thread-safe reads, single-threaded writes
- [x] Test: Unique PID generation per system
- [x] Test: Session/process lifecycle

### 1.5 Format Definitions (2 formats)
- [x] `formats/format_def.py` - Pydantic models for format definitions
- [x] `formats/loader.py` - YAML format definition loader
- [x] `formats/validator.py` - JSON Logic validator integration
- [x] `formats/definitions/windows_event_security.yaml`
- [x] `formats/definitions/zeek_conn.yaml`
- [x] FLOAT field type for Zeek duration field
- [x] test_zeek_format_accuracy.py for real-world validation

### 1.6 Log Emitters (2 formats)
- [x] `generation/emitters/base.py` - LogEmitter ABC with buffering (10K events)
- [x] `generation/emitters/windows.py` - Windows Event Log emitter (XML)
- [x] `generation/emitters/zeek.py` - Zeek conn.log emitter (NDJSON)
- [x] `utils/ids.py` with generate_zeek_uid() for 18-character UIDs

### 1.7 Generation Engine
- [x] `generation/engine.py` - Main generation orchestrator
- [x] `generation/activity.py` - Activity execution logic
- [x] `generation/ground_truth.py` - Ground truth documentation generator
- [x] CLI entry point with Typer + Rich progress bars

### 1.8 Scenario Validation
- [x] `validation/schema.py` - Cross-reference validation
- [x] Pydantic model validation with clear error messages
- [x] 93 tests passing at Phase 1 completion

---

## Phase 2: Scalability (COMPLETE)

**Goal:** Handle real-world dataset sizes with parallel generation, 7 MVP formats, medium datasets (100K+ events).

### 2.1 Parallel Generation
- [x] Thread-safe StateManager with RLock
- [x] Emitter threading (one thread per log format)
- [x] Hour-level barriers for temporal consistency
- [x] Bounded queues with backpressure (50K events)

### 2.2 Additional Log Formats (5 new, 7 total)
- [x] eCAR (MITRE CAR-based EDR/XDR, NDJSON)
- [x] Syslog (Linux, RFC 5424/BSD format)
- [x] Bash history (per-user timestamped)
- [x] Snort/Suricata IDS alerts
- [x] Web access logs (Apache/Nginx combined)

### 2.3 Cross-Log Consistency
- [x] Windows Event IDs 4624, 4634, 4688, 4689
- [x] Zeek conn.log with consistent UIDs
- [x] eCAR PROCESS, FILE, FLOW, USER_SESSION
- [x] Syslog auth.info for SSH/PAM events

### 2.4 Persona-Based Temporal Distribution
- [x] Work hours parsing with ramp-up/ramp-down
- [x] Per-persona activity probability weights
- [x] Configurable work_hours string format

### 2.5 Network Visibility Modeling
- [x] NetworkSegment and NetworkSensor models
- [x] SPAN (all traffic) vs TAP (boundary only) placement
- [x] Directional sensors (inbound, outbound, bidirectional)
- [x] Format-aware emission (Zeek vs Snort per sensor)

### 2.6 Storyline Enhancements
- [x] Failed logon events (4625)
- [x] Account creation (4720)
- [x] Service installation (4697)
- [x] Log clearing (1102)
- [x] Supplementary event inference from command-line patterns

### 2.7 LLM Integration — OBSOLETE
- ~~Bedrock LLM client~~ → Replaced by Claude Code Skills architecture

### 2.8-2.9 Evaluation Framework (moved to Phase 4)

### 2.10 Multi-OS Support
- [x] OS detection from system OS string
- [x] Windows: Security Events + Sysmon + optional eCAR
- [x] Linux: syslog + bash_history + optional eCAR
- [x] OS-aware activity generation

**Phase 2 Milestone:** 7 formats in parallel, 100-user 8-hour scenarios in ~14 seconds. 526 tests passing.

---

## Phase 3: MVP Release (COMPLETE)

**Goal:** Ship skills for scenario creation, persona library, install command, and documentation.

### 3.1 Claude Code Skills + Install Command
- [x] `/eforge scenario` — Guided scenario creation with hybrid interview flow
- [x] `/eforge generate` — Generation workflow with pre-flight validation
- [x] `/eforge validate` — Schema and cross-reference validation
- [x] `eforge install-skills` CLI command (project + global scope)
- [x] Skills bundled as package data via importlib.resources + hatch force-include
- [x] 10-tactic MITRE ATT&CK kill chain template
- [x] ENVIRONMENT.md student context document generation

### 3.2 Pre-Built Persona Library
- [x] 15 personas: developer, executive, analyst, sysadmin, help_desk, hr, legal_counsel, marketing, sales, intern, receptionist, accountant, data_analyst, project_manager, security_analyst
- [x] Realistic work hours, activity patterns, risk profiles

### 3.3 Documentation
- [x] Scenario reference documentation (full YAML schema)
- [x] README with quick start and feature overview
- [x] Evidence formats reference
- [x] AGENTS.md coding conventions

---

## Phase 4: Data Quality Evaluation (COMPLETE)

**Goal:** Add `eforge eval` command scoring datasets across 5 quality dimensions with 23 sub-scores.

### 4.1 Report Framework & CLI
- [x] `evaluation/engine.py` — Orchestrator with progress callbacks
- [x] `evaluation/report.py` — Rich text + JSON report formatting
- [x] `evaluation/models.py` — QualityReport, DimensionScore, SubScore
- [x] `eforge eval` CLI command with Rich progress bars
- [x] 7 log parsers: XML, NDJSON, regex

### 4.2 Record-Level Fidelity (weight: 0.15)
- [x] Parsability, co-occurrence rules, population statistics (JSD)

### 4.3 Signal Integrity (weight: 0.20)
- [x] Event presence, indicator accuracy, pivot linkability, storyline temporal integrity

### 4.4 Cross-Source Consistency (weight: 0.20)
- [x] Source correctness, trace coverage, cross-format agreement

### 4.5 Temporal Realism (weight: 0.20)
- [x] Work-hour distribution, burstiness, causal ordering (YAML rule-based)

### 4.6 Noise Realism (weight: 0.25)
- [x] Volume adequacy, diversity, plausibility, statistical anomaly detection

---

## Phase 5: Data Realism Improvements (COMPLETE)

**Goal:** Fix generator-level tells to make data indistinguishable from real data at casual inspection.

### 5.1 Record Fidelity Quick Wins
- [x] Realistic SID generation (S-1-5-21-{domain}-{user_rid})
- [x] Logoff generation for baseline sessions
- [x] Varied Zeek conn_state/history strings
- [x] Expanded process template pools (OS-aware)

### 5.2 Failed Logons & Process Termination
- [x] Background failed logon noise (wrong password, expired account, lockout)
- [x] Process termination events (4689) matching 4688 lifecycle
- [x] eCAR PROCESS/TERMINATE events

### 5.3 Protocol & Destination Diversity
- [x] UDP traffic (DNS, NTP, SNMP, Syslog)
- [x] ICMP traffic (echo request/reply, unreachable)
- [x] 50+ destination IP pool with CDN/cloud diversity
- [x] Reverse DNS patterns per cloud provider

### 5.4 System Traffic Generation
- [x] Kerberos (port 88) to Domain Controllers
- [x] LDAP (port 389) to Domain Controllers
- [x] Database traffic (scenario-driven port/service detection)
- [x] NTP synchronization, SSH keepalive, ICMP health checks

### 5.5 Work-Hour Realism & Timing
- [x] Activity clustering (sub-second intra-cluster, non-uniform gaps)
- [x] Per-persona cluster templates
- [x] Work-hour ramp-up/ramp-down (not step function)
- [x] Human burstiness (CV > 1.0)

---

## Phase 6: Expert-Identified Realism Fixes (IN PROGRESS)

**Goal:** Address blind expert panel findings. 5 improvement loops completed, 60 resolved.

### 6.0 Pre-existing Fixes
- [x] LogonType diversity (Types 2,3,4,5,7,8,9,10,11)
- [x] PID multiples of 4 (Windows) / sequential (Linux)
- [x] UDP/TCP history separation
- [x] NXDOMAIN responses (~20% of DNS lookups)
- [x] Syslog volume and diversity (12-80 events/hr, 10 programs)
- [x] SYSTEM domain (NT AUTHORITY)
- [x] explorer.exe in process tree (winlogon → userinit → explorer)

### 6.1 P0: Critical Fixes
- [x] DNS query type semantics (AAAA→IPv6, PTR→in-addr.arpa, SRV for AD)
- [x] Realistic process trees with depth (_select_parent_pid)
- [x] Duplicate fields in 4624 XML template
- [x] Kerberos/LDAP/DB traffic in Zeek
- [x] Zeek UID correlation across all log types

### 6.2 P1: Major Fixes
- [x] Missing Windows Event IDs (4768/4769/4770/4771/4776, 4697/4698-4701, 4720-4738, 5156, 1102)
- [x] Sysmon Event 1 (process creation) and Event 8 (remote thread injection)
- [x] HTTP proxy log emitter (Squid/PAC3 format)
- [x] Zeek HTTP/SSL/files/x509 log emitters (13 log types total)

### 6.3-6.4 P2/P3: Moderate and Minor Fixes
- [x] Zeek DNS fan-out from connection events
- [x] DHCP lease events
- [x] NTP synchronization logs
- [x] Weird.log and packet_filter.log
- [x] Reporter.log and PE analysis logs

### 6.5 Improvement Loop 1 (2026-03-18)
- [x] Work-hour timezone conversion fix
- [x] Failed logon target_username fix
- [x] Proxy log emitter improvements
- [x] 16 new issues identified, multiple resolved

### 6.6 Phase 7 Eval Expert Panel (2026-03-19)
- [x] Multiple expert-identified issues resolved through canonical event model

### 6.7 Improvement Loop 2 (2026-03-20, arch-firm-ssh-bruteforce)
- [x] 11 new issues identified, evaluation score 75/100

### 6.8 Improvement Loop 3 (2026-03-20, healthcare-supply-chain)
- [x] Evaluation score improved to 78/100

### 6.9-6.10 Improvement Loops 4-5 (2026-03-23, healthcare-supply-chain)
- [x] 4-expert panel evaluations, score improved to 80/100
- ~30 remaining issues tracked in TODO.md

---

## Phase 7: Canonical Event Model (COMPLETE)

**Goal:** Replace manual per-emitter coordination with SecurityEvent intermediate representation.

### 7.1 Foundation
- [x] SecurityEvent and RawLogEntry dataclasses
- [x] 8+ composable context dataclasses (Host, Auth, Process, Network, DNS, File, Registry, IDS)
- [x] EventDispatcher with NetworkVisibilityEngine integration
- [x] StateManager.apply() for event-driven state changes
- [x] can_handle()/emit()/emit_raw() on LogEmitter base class

### 7.2 Activity Type Migration
- [x] generate_logon() — Windows + syslog + eCAR
- [x] generate_logoff() — Windows + syslog + eCAR
- [x] generate_failed_logon() — Windows + syslog + eCAR
- [x] generate_process() — Windows + eCAR
- [x] generate_process_termination() — Windows + eCAR
- [x] generate_system_process() — Windows + syslog + eCAR
- [x] generate_connection() — Zeek conn
- [x] generate_bash_command() — bash_history
- [x] generate_machine_account_logon() — Windows
- [x] generate_kerberos_tgt() — Windows (4768)
- [x] generate_kerberos_service_ticket() — Windows (4769)
- [x] generate_ntlm_validation() — Windows (4776)

### 7.3 Cleanup
- [x] Removed orphaned eCAR helpers
- [x] Converted remaining helpers to dispatch_raw()
- [x] Removed ActivityGenerator.emitters dict (all via dispatcher)

### 7.4 Remaining Emissions
- [x] Migrated DNS lookups to dispatch_raw
- [x] Migrated engine.py system traffic to dispatch_raw
- [x] Final eval: 82.3 → 83.7, expert panel 36 → 30 tells

**Phase 7 Milestone:** All event emission through EventDispatcher. 12 activity types use canonical dispatch; diversity helpers and system traffic use dispatch_raw. 761+ tests, zero regressions.

---

## Phase 8: Cross-Source Correlation (PLANNED)

Planned but not yet started. See TODO.md for details on eCAR FLOW migration, FILE/REGISTRY/MODULE migration, syslog system message migration, and typed event declarations.

### 8.4 Typed Event Declarations (COMPLETE)
- [x] Per-event-type Pydantic models for storyline events
- [x] `events` list field on storyline entries
- [x] `supplementary` field (auto/none)
- [x] Load-time validation via `eforge validate`
- [x] Existing scenarios migrated
- [x] Keyword matcher removed
