# Detection Engineer — Authenticity Assessment
## Verdict
**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 76

## Executive Summary
The reviewed telemetry is likely synthetic. The decisive evidence is not the cleanliness or
completeness of the apparent activity. It is a repeated violation of Kerberos causal ordering on
both domain controllers: 120 of 214 tightly matched successful Kerberos network logons occur before
the same client and account obtain the immediately adjacent AS and service tickets. In a concrete
DC-01 example, LDAP transport and Event 4624 success for `WS-DRAMIREZ-01$` precede both the UDP/88
exchange and Events 4768/4769. That pattern recurs at subsecond scale across both DCs and looks like
independent timestamp jitter crossing a dependency boundary, not normal ticket caching.

Two secondary findings reinforce that conclusion. Sysmon Event 10 call stacks have unusually low
structural diversity: 713 records reduce to eight module-sequence templates and no stack exceeds
three frames. Separately, a DB-PROD command/file sequence refers to and hashes a gzip output before
the observed gzip process creates it. Source-format artifacts—literal `history:"-"` in all 712 Zeek
ICMP connections and inconsistent `src_ip:"-"` placeholders in normalized eCAR session records—add
lower-weight support.

There is also substantial evidence for realism. XML and JSON are parseable; Windows provider,
version, task, field, and direction/layer semantics are generally accurate; process and session
lifecycle identities are coherent; Windows 4688/4689, Sysmon 1/5, and eCAR process records correlate
without visible identity contradictions; and Zeek connection, protocol, file, certificate, SMB,
SSH, and RDP relationships are exceptionally consistent. Those strengths limit the score to the
“likely synthetic” band rather than “confidently synthetic,” but they do not repair the repeated
authentication-order contradiction.

## Evidence For Synthetic
- **[hard_contradiction] Kerberos logon succeeds before ticket acquisition.** On DC-01 and DC-02,
  214 Event 4624 records with Logon Type 3 and `AuthenticationPackageName=Kerberos` had a same-account,
  same-client-IP Event 4768 within ten seconds. In 120 cases (56%), the successful logon came first;
  only 94 had the expected order. The nearest 4768-minus-4624 delta ranged from -0.127445 to
  +1.195059 seconds, with a +0.235020-second median. The tight, bidirectional subsecond spread is
  characteristic of unconstrained timestamp perturbation across causally dependent events.

  - DC-01 Event 4624 at `2024-03-18T12:14:29.9307193Z`, Record ID `28245847`, authenticates
    `WS-DRAMIREZ-01$` from `::ffff:10.10.1.34:63532`. Event 4768 follows at
    `12:14:30.8198876Z` (Record ID `28245850`, client port `59677`, service `krbtgt`) and Event 4769
    follows at `12:14:30.8481534Z` (Record ID `28245851`, service `DC-01$`). Zeek strengthens the
    contradiction: LDAP UID `CjBB1b9M3JROXAYAKA1`, `10.10.1.34:63532` to `10.10.2.10:389`, starts
    at epoch `1710764069.702474`; the corresponding UDP/88 exchange UID
    `C369JOEWPkaVI93MpZ`, source port `59677`, does not start until `1710764070.610033`.
    The LDAP transport and successful domain logon therefore precede the visible ticket request.
  - DC-01 repeats the pattern for `FILE-SRV-01$`: Event 4624 at `12:09:11.7603035Z`, then 4768 at
    `12:09:12.3887848Z` and 4769 at `12:09:12.3894693Z`.
  - DC-02 repeats it for `WS-EBROOKS-01$`: Event 4624 at `12:08:33.185611Z`, then 4768 at
    `12:08:33.5929153Z` and 4769 at `12:08:33.6005481Z`.

  An isolated later KDC request could be unrelated renewal or cache behavior. Here, however, the
  same account/IP pairing, immediate AS-to-TGS sequence, matching service context, repeated
  subsecond placement, and confirming transport order make that explanation implausible at this
  frequency.

- **[distribution_texture] Sysmon Event 10 call traces are heavily templated.** Across 713
  `ProcessAccess` records on ten Windows hosts, 544 traces contain exactly three frames, 149 contain
  one, and 20 contain two; none has more than three. There are only eight module-sequence shapes.
  The two dominant forms—`ntdll.dll|KERNELBASE.dll|sechost.dll` (212) and
  `ntdll.dll|KERNELBASE.dll|ADVAPI32.dll` (190)—account for 56% of all records. Even varied
  source/target relationships such as `svchost.exe` to `lsass.exe`, `services.exe` to
  `MsMpEng.exe`, `csrss.exe` to `lsass.exe`, and `SearchIndexer.exe` to
  `SearchProtocolHost.exe` reuse this narrow stack grammar. Offsets vary, but the shallow and small
  module skeleton pool is atypical of broad native ProcessAccess telemetry.

- **[hard_contradiction] One shell/file lifecycle references an output before creation.** In
  `DB-PROD-01` root bash history, `sha256sum /tmp/rpt_0318.sql.gz` is timestamped at epoch
  `1710782100` and `du -h /tmp/rpt_0318.sql.gz` at `1710782111`; `gzip -9
  /tmp/rpt_0318.sql` is not issued until `1710782112`. eCAR independently places gzip process
  creation at `1710782112935` ms and FILE CREATE for `/tmp/rpt_0318.sql.gz` at
  `1710782116883` ms. The later `scp` then reads that file. A stale gzip file could make the early
  commands resolvable, but ordinary `gzip` without force would then refuse to overwrite it. This is
  a concrete contradiction, although isolated and therefore weighted below the Kerberos pattern.

- **[schema_or_format] Every ICMP Zeek connection carries a literal unset sentinel.** All 712 ICMP
  records across `zeek-core`, `zeek-dmz`, and `zeek-db` contain `history:"-"`; for example,
  core UID `CLo4M7991kacBTwhgw` at epoch `1710763893.435251` has `proto:"icmp"`,
  `conn_state:"SF"`, and `history:"-"`. The `history` alphabet is a sequence of Zeek state-history
  symbols; `-` is a text-log unset marker, not a history symbol. In this JSON corpus other absent
  optional connection fields are omitted, making literal retention of the text sentinel a
  source-native formatting inconsistency.

- **[schema_or_format] eCAR uses inconsistent non-IP missing values.** Of 1,450 `USER_SESSION`
  records, 466 place the string `"-"` in `properties.src_ip`, while 236 omit `src_ip`. Examples
  include DB-PROD-01 local login object `3f356042-8ccd-4520-96c3-06636be5e4c8` for
  `lina.nguyen` and DC-01 service login object `39cf501b-a107-4879-a5f0-6af5636aaf36` for
  `LOCAL SERVICE`. A normalized IP property should use one consistent missing-value representation;
  a text-log dash is not an IP address. This is lower-severity evidence because eCAR property bags
  may be weakly typed.

## Evidence For Real
- The corpus has substantial scale and source variety within its roughly six-hour visible interval:
  18,687 Windows Security events, 11,812 Sysmon events, 33,663 eCAR records, 33,507 Zeek records,
  and 308 timestamped shell-history commands. All inspected JSON lines and Windows XML documents
  parsed successfully.
- Windows event metadata is largely source-native. Security and Sysmon providers, event versions,
  tasks, keywords, and field sets match their event families. WFP Event 5156 uses inbound direction
  `%%14592` with receive-layer identifiers and outbound `%%14593` with connect-layer identifiers.
  Filter run-time IDs repeat stably by host rather than being invented uniquely per row.
- Windows process correlation is strong. Event 4688/4689 activity aligns with Sysmon Event 1/5 and
  eCAR process create/terminate records by host, PID, image, parent, command line, and time. The
  inspected matches showed no parent-PID, parent-image, or command-line disagreements. Sysmon
  `TimeCreated` to payload `UtcTime` offsets are small but varied rather than identical.
- Process identities obey visible lifecycles. Across Sysmon records there were no duplicate create
  or terminate events for a ProcessGuid and no visible parent created after its child or terminated
  before the child. Paired eCAR process objects showed no create/terminate inversion or PID,
  principal, or image mutation. Paired eCAR `USER_SESSION` objects likewise preserved principal,
  logon ID, session ID, and source identity from login to logout.
- Zeek protocol contracts are unusually well maintained. Every inspected DNS, HTTP, TLS, SMTP, SMB,
  DHCP, and file companion UID resolves to a connection on the same sensor, with no tuple mismatch
  and no companion record outside the connection interval under a 0.5-second allowance. File
  direction agrees with `local_orig`; transmitter/receiver hosts agree with the connection tuple.
- TLS/X.509 relationships are credible. Certificate-chain FUIDs resolve, certificates are valid at
  observation time, issuer/subject chaining is consistent, and SNI matches certificate SANs.
  Missing X.509 rows are overwhelmingly explained by corresponding file records with missing bytes,
  rather than arbitrary correlation loss.
- Remote-session ordering is strong outside the Kerberos defect. All 19 RDP Type 10 logons matched
  successful TCP/3389 transport that began 5.595–7.298 seconds before authentication. Thirty-four
  matched SSH logins followed target-side TCP/22 transport by 5.975–9.882 seconds. Forty-eight
  successful eCAR SMB logins followed their matched transports by 11–178 milliseconds.
- The single Security Event 1102 is represented with the Eventlog provider, task 104, SYSTEM subject,
  and a Security record-ID reset. Nearby process telemetry shows the `cmd.exe`/`wevtutil.exe` action,
  preserving realistic source-local behavior rather than merely inserting a generic “log cleared”
  label.
- Additional fine-grained details support authenticity: Sysmon Event 13 contains ROT13-encoded
  UserAssist paths; image hashes remain stable per host and image; DHCP renewal timing is jittered;
  cross-sensor representations of the same traffic use independent UIDs while preserving tuple,
  state, and service semantics.

## Detailed Analysis
The review treated each source as evidence with its own contract, then joined records only on
log-visible keys: hostname, IP/port tuple, account, process/session identity, Zeek UID/FUID, record
time, and lifecycle state. No inference relies on filenames beyond identifying the source host or
sensor, and no synthetic penalty is assigned merely because many sources correlate.

**Windows Security and Sysmon semantics.** The Security corpus covers authentication, privilege,
process, object-access, account-management, share, filtering-platform, and log-clear events. The
field layouts and value encodings are generally convincing: 4624/4625 logon fields and versions,
4768/4769 Kerberos fields, 5140/5145 share semantics, and 5156 direction/layer pairs are coherent.
Sysmon covers Events 1, 3, 5, 7, 8, 10, 11, 13, and 22. ProcessGuid continuity, parent-child
ordering, process termination, image/hash consistency, DNS/network linkage, and object identities
were checked across representative and bulk records. No broad lifecycle break was found.

The authentication timing check exposed the decisive exception. A successful Kerberos network
logon can legitimately consume a previously cached service ticket, so the analysis did not flag
every 4624 lacking a nearby 4768. It specifically matched same-account, same-client-IP 4768 records
within ten seconds and examined the adjacent 4769 and network flow. In 120 instances the supposed
prerequisite AS/TGS exchange is shifted just after the resulting logon, usually by less than one
second. The mixed sign and narrow delta distribution suggest per-record jitter was applied without
preserving the causal edge. The exact LDAP-versus-Kerberos transport ordering in the
`WS-DRAMIREZ-01$` example rules out a mere collector display-order issue for that case.

The Sysmon Event 10 review grouped every call trace by frame count and module sequence. Native
addresses and offsets alone do not establish realism if the stack grammar is repeatedly drawn from
a very small template set. Eight shapes across 713 accesses, with a hard three-frame ceiling across
ten hosts and heterogeneous process pairs, is a visible distributional artifact rather than an
argument from missing telemetry.

**eCAR lifecycle semantics.** Process and user-session object IDs are stable through their visible
lifecycles. Actor references did not visibly precede actor creation or follow termination; paired
process records did not change PID, image, or principal. FLOW, FILE, MODULE, REGISTRY, PROCESS, and
USER_SESSION records generally agree with their Windows or network counterparts. The `src_ip:"-"`
finding is consequently treated as a normalization/format problem, not evidence that session
correlation itself is broken. The DB-PROD gzip sequence is different: two timestamped shell commands
consume a named output before the process/file evidence says that output was produced, and normal
gzip overwrite behavior prevents the simplest stale-file reconciliation.

**Zeek schema and protocol semantics.** Connection state, duration, byte counts, ports, and protocol
companions were checked across all three sensors. There were no duplicate connection UIDs, negative
durations, invalid ports, or companion tuple contradictions. UDP accounting matched payload plus
packet overhead. TLS certificate reuse, chains, validity intervals, and hostname binding were
coherent. Multiple sensors used different UIDs/FUIDs for their observations, while independently
matching flows retained state and service agreement—behavior compatible with separate sensors.

The literal ICMP `history:"-"` value is narrower than those strengths: it indicates that a
text-format missing-value sentinel was serialized into a JSON field whose native domain is a set of
history symbols. It appears in all 712 ICMP rows, so it is systematic, but it does not compromise
tuple or timing correlation and receives only moderate weight.

**Collection and environmental plausibility.** Host roles, address ranges, services, user placement,
process images, and Windows/Linux path conventions are mutually consistent. DC traffic, file-share
activity, database access, proxy flows, user workstations, and exposed services appear where the
surrounding records imply they should. The bounded window explains partial lifecycles and renewal-
only DHCP visibility; neither was counted as a defect. No penalty was assigned for absent optional
Sysmon families, sanitized naming, attack-path completeness, or unusually good cross-source
coverage.

## Synthetic Indicator Summary
| Indicator | Label | Scope | Weight | Log-visible basis |
|---|---|---:|---|---|
| Successful Kerberos logon precedes same-client AS/TGS exchange | `hard_contradiction` | 120 of 214 tightly matched DC logons | Very high | 4624 before 4768/4769; one case also has LDAP flow before UDP/88 flow |
| Sysmon ProcessAccess stacks reduce to shallow templates | `distribution_texture` | 713 Event 10 records, 10 hosts | Medium-high | Eight module sequences; zero traces over three frames |
| gzip output consumed before observed creation | `hard_contradiction` | One DB-PROD sequence | Medium | bash timestamps precede gzip process and eCAR FILE CREATE |
| Zeek JSON retains `history:"-"` for every ICMP row | `schema_or_format` | 712 ICMP connections, 3 sensors | Medium-low | Literal sentinel is systematic while other absent JSON fields are omitted |
| eCAR session `src_ip` mixes dash and omission | `schema_or_format` | 466 dash values; 236 omissions | Low | `"-"` appears in an IP-named normalized property |

No separate `environment_or_collection_plausibility`, `contract_gap`, or `weak_signal` finding was
scored: the observed coverage is not inherently implausible, and the stronger findings above can be
stated directly without inflating ambiguous absences into evidence.

## Realism Score by Category
| Category | Score | Justification |
|---|---:|---|
| Field format accuracy | 8/10 | Windows XML and most Zeek/eCAR fields are source-appropriate; ICMP `history:"-"` and eCAR `src_ip:"-"` are systematic exceptions. |
| Temporal patterns | 6/10 | Timing is generally varied and lifecycle-aware, but the repeated Kerberos dependency inversion and isolated gzip sequence are material causal defects. |
| Cross-source correlation | 8/10 | Process, session, connection, protocol, file, RDP, SSH, SMB, and TLS identities correlate strongly; the DC logon/KDC transport ordering prevents a higher score. |
| Behavioral realism | 7/10 | User, service, network, and administrative behavior is diverse and plausible, but Event 10 call-stack texture is too shallow and templated. |
| Environmental consistency | 8/10 | Host roles, users, services, address topology, OS paths, and sensor views are coherent, with no broad collection contradiction observed. |

## Recommendations
- Treat authentication dependencies as ordered constraints. Generate or preserve AS/TGS issuance and
  Kerberos transport before any 4624 success that consumes them, then apply timestamp variation to
  the bundle without allowing jitter to cross those boundaries.
- Add a validation invariant that joins 4624, 4768, 4769, and port-88/target-service transport by
  account, client address, service, and bounded time; fail generation when a newly acquired ticket
  appears after the dependent logon.
- Increase Sysmon Event 10 stack depth and module-sequence diversity using source-process,
  target-process, access-mask, OS-build, and loaded-module context. Validate distributions per
  process pair rather than only per event type.
- Enforce file dependency ordering across shell history, process telemetry, and file events. A file
  read/hash/size query should follow creation unless an explicit pre-existing-file state is present;
  overwrite behavior must then match the invoked command flags.
- Serialize missing normalized values consistently. Omit or null unavailable eCAR IP properties,
  and omit unavailable Zeek JSON history instead of carrying the text-log dash sentinel.
- Preserve the existing strengths: stable canonical identities, realistic source-local latency,
  lifecycle pairing, independent sensor identifiers, TLS chain consistency, and protocol companion
  linkage.
