# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 31

## Executive Summary

The endpoint evidence is mostly production-like: Windows process identities and session ownership hold together, Linux authentication sequences have credible ordering, and the macOS records distinguish forks, successive executable images, and process exits. I found no demonstrated hard contradiction in the checks performed; the main remaining concern is repeated shell-based handling of Office/PDF documents on one Mac. The Real verdict is moderate confidence, not proof of provenance, and a capable synthetic dataset could reproduce these properties.

## Evidence For Synthetic

- [weak_signal] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` contains ten executions addressing `/Volumes/` paths: seven `/bin/cat`, two `/bin/ls`, and one `/usr/bin/tee`. The seven `cat` targets are PDF, DOCX, or XLSX documents, including `service-review.xlsx` at `16:05:48.676562Z`, `project-plan.docx` at `17:10:43.529782Z`, and `meeting-notes.docx` at `18:44:51.352962Z` on November 2. This repeated tool/file-type pairing resembles a generic document-read pattern more than ordinary application-driven document work, although deliberate inspection or byte extraction could explain it.
- [weak_signal] The same Mac executes `/usr/bin/tee /Volumes/Users/Downloads/draft.docx` at `18:42:09.887846Z` and exits successfully at `18:42:17.147013Z`. Together with the repeated `cat` operations, this adds a small amount of suspicion about generic read/write behavior being applied to binary document formats. The supplied rows do not expose stdin or document contents, so they cannot establish an invalid file or an impossible operation; this is not a hard contradiction or a missing-evidence finding.

## Evidence For Real

- Across all ten Windows Sysmon exports, all 919 visible Event 1 creations have a Security 4688 counterpart within two seconds for the same PID, with matching image and command line. Checks of visible parent GUIDs found matching parent image, command line, user, and PID; the tested source/target GUID references also retained their process identity.
- Windows session evidence includes realistic lock/unlock semantics. In `WS-MCHEN-01.meridianhcs.local/windows_event_security.xml`, Marcus's session `0x6c29844`, session ID `5`, locks at `14:06:00.9512538Z`, records a Type 7 unlock at `14:22:40.4679992Z`, and records 4801 at `14:22:41.0712096Z`; the same session identity survives the unlock.
- `APP-INT-01.meridianhcs.local/syslog.log` lines 1–4 show connection, public-key acceptance, PAM session opening, and logind session creation in that order for Aisha, source `10.10.1.35:59751`, sshd PID `3373783`, session `204`.
- The macOS native exports preserve successive exec images within one PID, rather than inventing a new process for every image. For example, on `MAC-MROSS-01`, PID `25527` progresses from launchd's fork image to `xpcproxy` and then Terminal, with changing `pidversion`, a stable process start time, and matching executable metadata.
- Windows binary hash sets remained stable for each image within the checked host exports. Grouping identical hash sets across the Windows sources did not reveal conflicting nonempty file-version, description, product, company, or original-filename metadata.
- Linux maintenance and user activity differ meaningfully: `WS-LNGUYEN-01` includes Git, editor, and build commands, while infrastructure hosts show service troubleshooting, mail operations, Samba, and administrative commands. System noise includes package management, name-resolution degradation, IRQ handling, logging queues, and scheduled collection.

## Detailed Analysis

### Scope and evidence standard

I examined only the supplied data directory. The endpoint population comprises ten hosts with Windows Security/Sysmon XML, eleven with Linux-style syslog, and two Macs with Endpoint Security and Unified Log NDJSON; all 23 also have normalized eCAR records. The visible window is approximately `2026-11-02 13:00–19:00 UTC`.

I parsed the native XML and structured endpoint records, inspected actual entries, and performed bounded consistency checks across their visible identifiers. No repository information, scenario narrative, ground truth, other analyst reports, or external context was used. I did not penalize missing Sysmon types, thin Unified Log coverage, pre-window state, absent post-window endings, sanitized domains, or high source alignment.

### Windows process identity and source correlation

The ten Sysmon sources contain 919 Event 1 process creations. Each has a same-PID Security 4688 creation within two seconds with the same image and command line. This is useful evidence that the representations agree; completeness itself is not an authenticity defect or proof that the data is real.

A concrete example is `WS-MCHEN-01`: Sysmon record `525191` at `13:17:14.8915183Z` creates `conhost.exe`, PID `6820`, GUID `{7b2a0e3f-8d5a-6ae8-0702-0010db3c1727}`, under `csrss.exe` PID `5860`, as SYSTEM with LogonId `0x3e7`. Security record `948762` at `13:17:15.0401283Z` gives `NewProcessId=0x1aa4` and creator `ProcessId=0x16e4`, which convert to those same PIDs, with the same command line and parent image.

At `13:00:25.4580847Z`, `WS-PPATEL-01` Sysmon record `739645` launches Firefox PID `6048` under Explorer PID `6024`, as `MERIDIANHCS\priya.patel`, medium integrity, LogonId `0xd84df9f`. Security record `358233` at `13:00:25.4962921Z` agrees, including the Jira URL command line and medium mandatory label. Source timestamps differ slightly in a plausible way.

For GUIDs whose creation was visible, checks found no mismatching parent image, parent command line, parent user, or parent PID. Checks of process/source/target GUID identity found no mismatching image or PID. Per-image hash sets were stable within the host exports, and identical hash sets did not carry inconsistent nonempty file metadata across hosts.

### Process and logon lifecycles

The eCAR exports contain 2,629 PROCESS/CREATE rows. A check using object and actor identities found no dependent process references more than one second before a visible creation or more than one second after a visible termination. This tolerance avoids presenting subsecond observation differences as impossible causality; it does not certify every event relationship.

A corresponding whole-second check of visible Sysmon process GUID creation/termination relationships found no violations. Windows Security checks also found no examined 4688/4689/4672 or file/share operations before a visible initial Type 2/3/9/10 logon or after the final visible logoff for the same non-system LogonId. Type 7 unlocks were excluded as initial session creation, and reserved service-session IDs were not treated as unique newly allocated user sessions.

There is a credible host-dependent logon mix: DC-01 has 136 Type 5, 134 Type 3, and three Type 10 logons, while WS-MCHEN has 19 Type 3, eight Type 5, two Type 7, one Type 2, and one Type 9. Counts alone cannot identify origin, but the roles and native fields do not create an obvious contradiction. The Marcus lock/unlock example above, and Priya's corresponding reuse of session `0xd9f9479`/session ID `2`, support session continuity.

### Linux host evidence

APP-INT-01's initial SSH sequence is specific and ordered: connection at `13:00:17.274260Z`, public-key acceptance at `13:00:18.225647Z`, PAM opening at `13:00:18.325445Z`, and logind creation at `13:00:18.856052Z`. The eCAR view retains the same source port and user, models the privileged sshd and user shell separately, and gives the shell session `204`.

Scheduled `debian-sa1` activity repeats predictably, which is appropriate for cron rather than a synthetic indicator by itself. Interactive histories include pipelines and shell builtins, while visible endpoint records include external pipeline components and separate sudo/privileged-command processes. I did not find the simple defect of every shell builtin being represented as a fictitious standalone executable.

The 741 WEB-EXT-01 kernel messages carrying bracketed uptime maintain a coherent relationship to wall time: inferred boot-time estimates span about 0.239 seconds across the window. This is compatible with collection delay and avoids the common contradiction of unrelated random kernel uptimes.

### macOS native and normalized evidence

The two native Endpoint Security exports contain 317 notifications total: 101 forks, 117 execs, and 99 exits. Their declared message version is 11. Per-type `seq_num` and `global_seq_num` advance consistently within each export. No checked `(pid,pidversion)` identity changes executable path, and no checked executable `(st_dev,st_ino)` identity changes its path/CDHash pairing.

The launch chains distinguish launchd, xpcproxy, Terminal/iTerm, login, and zsh. SSH evidence uses the visible sshd wrapper/session/auth process images, not Linux PAM or systemd assumptions imposed on a Mac. In MAC-MROSS-01's native stream, PID `44178` is forked at `16:02:05.625259Z`, becomes sshd and then sshd-session, and the Unified Log acceptance appears at `16:02:06.488664Z`; the user-side forks and zsh exec follow. This is a coherent visible order.

An apparent eCAR ordering concern did not survive inspection. In MAC-MROSS-01, child PID `44181` and its parent's exec into sshd-session both carry timestamp `1793635328060`; in MAC-MROSS-02, child `99706` and its parent's corresponding exec both carry `1793629475923`. Later audit-binding updates retain the same execution identity. File order within a millisecond and a later identity-preserving update do not demonstrate that a child preceded its parent's exec, so this was excluded from synthetic evidence and scoring.

MAC-MROSS-01's Unified Log policy message at `15:42:09.009673Z` says policy “would not allow” MeetingAssist process `42008`. I did not equate an Endpoint Security notification with an authorization result or infer successful child execution from this message.

The principal remaining concern is behavioral texture on MAC-MROSS-02: seven reads of Office/PDF files use `cat`, and a DOCX target uses `tee`, despite visible Office application launches. These are technically possible shell operations and lack content/stdin evidence, so they warrant only a weak penalty. They do not justify a claim of impossible document access.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | macOS Endpoint Security and eCAR | Seven shell reads of PDF/DOCX/XLSX targets on MAC-MROSS-02 | Small increase for repetitive tool/file-type pairing; deliberate byte inspection remains plausible. |
| weak_signal | macOS Endpoint Security and eCAR | One `tee` execution targeting `draft.docx` on MAC-MROSS-02 | Small additional concern when combined with the read pattern; no proof of bad file contents or invalid effects. |

No demonstrated hard contradiction, material lifecycle contract gap, or confirmed native schema defect was established. The two weak observations are related and were not treated as independent strong findings.

## Realism Score by Category

- **Field format accuracy:** 9 — Examined native fields, identities, executable metadata, and Windows numeric representations are coherent; this is not exhaustive native-schema certification.
- **Temporal patterns:** 9 — Visible process/session ordering, SSH phases, kernel uptime, and scheduled activity are credible.
- **Cross-source correlation:** 9 — Checked Windows creations, parent identities, session references, and Linux SSH details agree without a demonstrated contradiction.
- **Behavioral realism:** 7 — Role-dependent work and maintenance are convincing, with a limited concern about repetitive shell handling of binary documents.
- **Environmental consistency:** 9 — Platform-specific process/session behavior and host roles are broadly consistent with the supplied collection.

## Recommendations

- If this were synthetic, improve the tool/file-type distribution evidenced on MAC-MROSS-02: represent actual application-driven document work when that is the intended activity, and reserve repeated `cat`/`tee` operations on Office/PDF files for explicit shell-based handling.
- If the `tee` operation is intended to create a usable DOCX document, ensure its input and resulting bytes support that effect. The supplied logs do not reveal those bytes, so this is an improvement tied to the visible operation, not a finding that the document is invalid.
