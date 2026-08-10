# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 64

## Executive Summary

The endpoint telemetry is technically strong: representative Windows process, session, and RDP lifecycles preserve ownership and ordering, and Linux SSH sessions correlate cleanly among eCAR, sshd, PAM, and logind. The main synthetic tell is dataset-wide SSH identity texture—authentication methods switch repeatedly for the same client/user/target tuple, while the accepted client-key fingerprint is systematically destination-specific even though the visible client commands do not select per-host identities.

## Evidence For Synthetic

- `[distribution_texture]` The six Linux servers contain 96 successful SSH authentications in a six-hour window across 20 `(target, user, source IP)` groups; 13 of those 20 groups use both password and public-key authentication. For `aisha.johnson` from `10.10.1.35` to `WEB-EXT-01`, the nine successes form password, password, public key, public key, public key, password, password, public key, public key (12:38:17 through 17:37:43 UTC). `marcus.chen` from `10.10.1.31` to that same target changes method six times in 15 successes. A repeated, apparently stochastic switch pattern across most active tuples is less believable than a stable user/client policy with rare, causally visible fallback.
- `[contract_gap]` Public-key identity appears derived from the destination rather than the client key. The same `aisha.johnson` client at `10.10.1.35` presents six distinct accepted fingerprints to six servers: for example `SHA256:hQYJ...EIru` at `MAIL-CLIN-01` (2024-03-18 12:17:39 UTC), `SHA256:+UOM...gfPM` at `MAIL-EDGE-01` (12:18:33), `SHA256:51hH...ypyE` at `PROXY-01` (13:00:19), `SHA256:XGQe...Rr3S` at `WEB-EXT-01` (15:02:01), `SHA256:6vAc...NhQo` at `APP-INT-01` (16:11:26), and `SHA256:Xo/U...yJf` at `DB-PROD-01` (17:04:51). `marcus.chen` similarly has five target-specific fingerprints and `lina.nguyen` has three. The Windows client records show simple commands such as `ssh.exe aisha.johnson@DB-PROD-01.meridianhcs.local`, with no `-i` selection; per-host SSH config could explain an isolated case, but the systematic one-key-per-user-per-destination pattern across all three administrators is a strong modeling fingerprint.
- `[distribution_texture]` Administrative SSH is unusually dense and broad for three interactive client identities: `WS-AJOHNSON-01` records 38 `ssh.exe` creates and `WS-MCHEN-01` records 32 within six hours; the six Linux servers expose 93 matched SSH session lifecycles, with `WEB-EXT-01` alone receiving 33. This remains technically possible, but combined with the authentication randomization it looks like independently sampled baseline sessions rather than durable administrator habits.
- `[weak_signal]` Some repeated Linux command vocabulary crosses users and unrelated servers (`tail -20` ten times; `grep -i error /var/log/syslog` four times across three servers; `du -sh /home/*` three times across three servers). The counts are not high enough to establish a contradiction, but they reinforce the impression of a shared command pool.

## Evidence For Real

- The reviewed collection covers a coherent six-hour slice (approximately 12:00–18:00 UTC) across nine Windows and nine Linux endpoints. Volumes are plausible for the visible roles: 24,370 eCAR rows, 13,589 Security events, 4,063 Sysmon events, 4,109 syslog rows, and 396 timestamped bash-history lines in 20 files.
- Windows process correlation is excellent without impossible visible ordering. All 834 Sysmon Event 1 records found a same-PID, same-image Security 4688 partner within 200 ms; 1,285 of 1,400 eCAR terminations have visible creates, and none terminate before their matching create. The remaining terminations are consistent with processes that began before the slice.
- Across 3,335 eCAR records whose `actorID` resolves to a visible process create, no dependent record occurs before actor creation or after the actor's visible termination. Parent/child examples are source-appropriate: `services.exe` launches service binaries, `svchost.exe` launches `WmiPrvSE.exe`/`taskhostw.exe`, `explorer.exe` launches user applications, and Linux `sshd` launches `-bash` before shell commands.
- The RDP window on `WS-AJOHNSON-01` is causally plausible: endpoint transport is visible around 15:00:00 UTC, Type 10/eCAR session login follows, and Outlook launches at 15:00:05.776 under `explorer.exe`, principal `aisha.johnson`, logon ID `0x26d8b2b`, session 3.
- Linux SSH source-native sequencing is detailed and credible. At `APP-INT-01` on 2024-03-18 12:22:01–12:22:04 UTC, one PID (`948349`) carries connection, accepted-key, and PAM-open messages, followed by logind session creation; eCAR preserves the same privileged sshd/session ownership. Across 93 matched SSH sessions, duration ranges from 12.937 seconds to 15,384.395 seconds (median 1,165.33 seconds), avoiding a fixed-duration fingerprint.
- Linux identities are stable across hosts: PAM records consistently use UID 2528 for `aisha.johnson`, 4119 for `marcus.chen`, 5302 for `lina.nguyen`, and 3843 for `priya.patel`. Windows SID/domain/logon-ID formatting and Sysmon GUID/hash formats are likewise source-native in the sampled records.
- User behavior is differentiated. `aisha.johnson` and `marcus.chen` show remote administration, while `lina.nguyen` uses Git, npm, Docker, Emacs, and browser tools; `sophia.martinez` has Slack/Office/browser-heavy activity; Linux workstation activity includes desktop services rather than only server commands.

## Detailed Analysis

### Scope and bounded sampling

I inspected only the supplied data directory. I inventoried all endpoint source families, aggregated event/action counts, then sampled early, middle, and late windows from the largest Windows workstation, a domain controller, a Windows server, two Linux servers, and Linux/Windows workstations. I also ran bounded lifecycle checks over identifiers because those checks establish visible ordering without assuming boot-to-shutdown completeness.

### Windows process and session ownership

The Windows records are the strongest part of the collection. Security contains 839 Event 4688 records and Sysmon contains 834 Event 1 records. Every Sysmon create has a Security partner with matching PID/image and sub-200-ms timestamps; five Security creates lack a Sysmon partner, a modest and believable collection difference. Event 4689/Sysmon 5/eCAR termination coverage is similarly coherent, and no matched eCAR lifecycle reverses create and terminate.

Process trees have credible role texture. On `WS-AJOHNSON-01`, service/update children occur under `services.exe`, COM/WMI/task processes under `svchost.exe`, console hosts under `csrss.exe`, and browsers/Office/remote clients under `explorer.exe`, PowerShell, or cmd. The 15:00 UTC RDP sample preserves transport-before-login-before-user-process ordering and attaches the resulting Outlook process to the new Type 10 logon/session rather than to SYSTEM. On `DC-01`, the sampled PsExec path includes a 4697 service install, `services.exe` to `PSEXESVC.exe` to `cmd.exe`, and correlated endpoint records.

Repeated Type 7/unlock-style logins reuse an existing logon ID, which is expected for reconnection/unlock semantics; I did not count processes visible before a later unlock as causality defects. Likewise, source-local process terminations without a visible create at the beginning of the six-hour slice were treated neutrally.

### Linux SSH, syslog, and shell evidence

The SSH lifecycle itself is well constructed. A connection line precedes accepted authentication, PAM open, logind session creation, shell readiness, command processes, PAM close, and eCAR logout. PIDs and source tuples remain stable within a session, per-user UIDs remain stable across servers, and matched durations have a broad nonuniform distribution.

The authenticity issue is higher-level SSH identity state. Of 20 user/source/target groups with successful authentication, 13 alternate between password and public key. Within public-key successes, the fingerprint is stable for a given destination but changes when the same client/user reaches another destination. This behavior repeats for every administrator with multi-server key use. Per-destination keys are possible via SSH config, but the simple visible `ssh.exe user@host` commands, the systematic coverage, and the simultaneous random method changes make that explanation increasingly strained.

The bash histories are timestamped, user-specific, and mostly plausible. Commands seen in history are supported by eCAR child processes and appropriate shell ownership. The common diagnostic vocabulary is not by itself unrealistic for administrators, though the same small tail/head/grep idioms recur often enough across users and servers to be a weak pool-shaped signal.

### Distribution and environment

Endpoint source volumes fit the host roles: the domain controller has far more Security and flow activity, user workstations show user application/module/registry telemetry, and proxy/web hosts carry many more flows. Scheduled `sysstat` executions occur on cron-like half-hour boundaries with host-specific minute offsets and occasional missing observations; that is realistic scheduler behavior and was not scored as synthetic.

The unusually high remote-administration rate is not inherently impossible, especially for an active operations window. It affects the score because it co-occurs with destination-derived key identities and frequent method switching, making 96 SSH successes look independently sampled rather than governed by persistent client configuration.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---|---|
| `contract_gap` | Linux sshd + Windows/Linux eCAR client processes | Dataset-wide across three administrators and six targets | Client public-key identity changes systematically by destination despite simple client commands, suggesting key truth is owned per connection/target rather than per client identity. |
| `distribution_texture` | Linux sshd authentication | 13 of 20 active user/source/target groups | Password/public-key choices switch repeatedly within stable tuples, unlike durable client policy or a causally visible fallback. |
| `distribution_texture` | eCAR process/session telemetry | Repeated across admin clients and Linux servers | 70 SSH client creates on two Windows admin workstations and 93 matched target sessions in six hours amplify the sampled-authentication texture. |
| `weak_signal` | bash history + Linux eCAR process creates | Low-volume cross-host repetition | A small shared diagnostic-command vocabulary recurs across users/servers, but is not decisive alone. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, eCAR identifiers, RFC5424-style syslog, SIDs, GUIDs, hashes, UIDs, and PIDs are source-appropriate in sampled records.
- **Temporal patterns:** 8 — No visible process/actor lifecycle reversals were found, and session durations are varied; authentication-choice texture is the main temporal/distribution weakness.
- **Cross-source correlation:** 9 — Security/Sysmon/eCAR process records and sshd/PAM/logind/eCAR session records align without concrete contradictions.
- **Behavioral realism:** 6 — User/tool differentiation is good, but SSH method switching and broad destination-specific key identities look independently sampled rather than behaviorally persistent.
- **Environmental consistency:** 7 — Host roles and volumes are plausible, while the density and uniform breadth of interactive administration across all Linux servers remain somewhat artificial.

## Recommendations

- If this were synthetic, own SSH client-key identity at the client/user credential layer. Reuse the same fingerprint across destinations by default; allow per-host keys only when an explicit SSH-config/identity selection is modeled, and keep the selected algorithm/fingerprint consistent in all receiving sshd records.
- Make SSH authentication method sticky for a user/client/target policy. Rare method changes should follow visible causes such as key rejection, agent unavailability, account transition, or an explicit client option rather than an independent per-session draw.
- Couple administrative session frequency to persistent user routines and task bundles. Preserve the excellent lifecycle timing, but create bursts tied to an operational task and longer quiet intervals instead of broad independent SSH sampling across every server.
- Expand the long tail of user-specific Linux command habits and multi-command workflows while retaining role-appropriate overlap. This would reduce the cross-user reuse of short diagnostic fragments without adding arbitrary mistakes or narrative noise.
