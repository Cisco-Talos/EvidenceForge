# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 87  
**Synthetic-Confidence Score:** 68

## Executive Summary

The corpus is unusually strong at schema fidelity, lifecycle integrity, and cross-source timing: I found no impossible visible ordering among the identities tested. The decisive synthetic indicator is a repeated source-native timestamp fingerprint in DHCP syslog: every one of 34 three-message renewal sequences preserves the same randomized sub-millisecond suffix across independently emitted REQUEST, ACK, and bound messages.

## Evidence For Synthetic

- `[distribution_texture]` All 34 complete DHCP renewal triplets—102 messages across three Linux hosts—reuse the exact final three microsecond digits within each REQUEST/ACK/bound sequence. For example, `WS-OHADDAD-01.../syslog.log` records `12:01:43.637412Z`, `12:01:45.279412Z`, and `12:01:46.721412Z`; all end in `412`. Later triplets use different suffixes, such as `429`, `248`, and `478`, but again freeze that suffix across all three messages. This is characteristic of deriving child timestamps by adding integral milliseconds to one generated timestamp, not three independent syslog clock observations.
- `[distribution_texture]` The same fingerprint repeats independently on `LT-MRIVERA-02` (`12:45:03.914509Z`, `12:45:05.188509Z`, `12:45:06.815509Z`) and `WS-LNGUYEN-01` (`12:09:46.145141Z`, `12:09:47.577141Z`, `12:09:49.254141Z`). Repetition across 34 transactions and three hosts makes ordinary scheduler coincidence implausible.

## Evidence For Real

- The corpus contains 81,741 records over the six-hour window: 24,868 eCAR, 19,759 Zeek JSON, 13,884 Security, 3,988 Sysmon, 11,799 ASA, 4,550 syslog, 1,789 proxy, 918 web, and 186 Snort records. Source volumes and host-role differences are credible.
- Windows metadata is notably accurate. All 1,068 Event 4624 records declare Version 2, all 907 Event 4688 records declare Version 2, all 8,131 Event 5156 records declare Version 1, and Sysmon versions match their event families.
- Parsed fields are source-native: Event 5156 uses device paths, protocol numbers, `%%14592/%%14593` direction tokens, layer tokens, and integer filter IDs; Event 4688 uses hexadecimal process IDs and correct SID/integrity-label forms.
- Across 11,472 Zeek connections, every tested DNS, HTTP, SSL, SMTP, and file UID reference resolved to a connection in the same sensor, and no child timestamp fell outside its visible connection interval.
- eCAR lifecycle checks found no duplicate process creates, duplicate terminations, create/terminate inversions, dependent activity before create or after terminate, actor/source UUID disagreement, or login/logout inversion.
- Security-to-Sysmon process timing was credible: 901 matched creates had a median delta of approximately -0.85 ms and a range of -20.57 to +58.10 ms. For 892 Sysmon-to-eCAR matches, median endpoint delay was about 613 ms, with broad non-lattice variation.
- Process-command texture is reasonably diverse: 1,851 eCAR process creates contain 551 distinct command lines, including 351 singletons.

## Detailed Analysis

### Scope and parsing

The visible interval runs approximately 2024-03-18 12:00–18:00 UTC. The data covers nine Windows systems, nine Linux/eCAR systems with some overlap in the organizational host set, two Zeek sensors, perimeter firewall, IDS, proxy, and web sources. All JSON examined parsed successfully, and the Windows XML was structurally parseable.

### Windows schema and event semantics

The Windows source is SIEM-usable. Representative Event 4624 record `28245277` on `DC-01` at `2024-03-18T12:00:38.9076838Z` contains a coherent Type 3 Kerberos logon for `marcus.chen`, an IPv4-mapped source address, numeric source port, Logon GUID, and Version 2 field set. Across the corpus, successful logons comprise 742 Type 3, 296 Type 5, 14 Type 10, nine Type 7, and seven Type 2 events.

Event 4688 record `28245405` on `DC-01` at `12:05:05.0918500Z` correctly combines Version 2 fields, hexadecimal PIDs, `WmiPrvSE.exe`, SYSTEM integrity `S-1-16-16384`, and token-elevation token `%%1936`. All checked SID values had valid `S-1-...` morphology.

Sysmon uses appropriate field families and version numbers: Event 1 Version 5, Event 3 Version 5, Event 5 Version 3, Event 7 Version 3, Event 8 Version 2, Event 10 Version 3, Event 11 Version 2, Event 13 Version 2, and Event 22 Version 5. Source/target ProcessGUID audits for Events 8 and 10 found no reference occurring before a visible create or after a visible termination.

The DC’s Event 1102 at `17:42:26.3595316Z` is correctly represented through `UserData/LogFileCleared`, and the following Security record IDs restart at 2. That reset is consistent with the logged clear operation rather than an ordering defect.

### Endpoint lifecycle and correlation

Across 1,851 eCAR process creates and 1,567 terminations, there were zero same-object termination-before-create cases. Dependent FLOW, FILE, MODULE, REGISTRY, PROCESS OPEN, and THREAD records referencing visible actor UUIDs remained within the actor’s visible lifetime and agreed on PID, image, and principal.

Sysmon process-associated Events 3, 7, 11, 13, and 22 likewise produced no visible same-GUID lifecycle inversion. The same held for SourceProcessGUID and TargetProcessGUID references in ProcessAccess and CreateRemoteThread records.

Unmatched early terminations and session logouts were treated as neutral because the six-hour slice can begin after their initiators. Likewise, open sessions and live processes at 18:00 were not penalized.

### Network and protocol correlation

`zeek-core/conn.json` contains 6,189 unique UIDs and `zeek-dmz/conn.json` contains 5,283; neither contains duplicate UIDs. All 2,800 DNS, 2,156 HTTP, 1,780 SSL, 67 SMTP, and 880 file-to-connection references examined resolved in their local sensor and remained inside the corresponding connection interval.

Connection fields use correct Zeek shapes and types: numeric epochs, string UIDs, numeric ports, protocol strings, connection states, directional byte/packet counters, histories, and integer IP protocol values. The mix includes internal Kerberos/DNS/SMB, proxy and public web traffic, DHCP, SMTP, TLS, and scanner traffic rather than one narrow protocol family.

### Timestamp analysis

Windows `SystemTime` uses seven fractional digits, Sysmon `UtcTime` uses milliseconds, Zeek uses fractional Unix seconds, eCAR uses integer milliseconds, and Linux syslog uses RFC 5424 timestamps.

The DHCP source-native timestamp behavior is the exception. A real dhclient emits REQUEST, ACK, and bound messages on separate logging calls. Preserving an arbitrary nonzero final-three-digit suffix across all three messages in all 34 observed transactions strongly suggests arithmetic construction from a shared anchor. This is a distribution fingerprint rather than a causal inversion—the event ordering itself remains valid.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `distribution_texture` | Linux dhclient syslog | 34/34 complete triplets; 102 records; 3 hosts | Identical randomized microsecond residue across separately emitted lifecycle messages is a strong generated-timestamp fingerprint. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, Zeek, eCAR, ASA, and RFC 5424 shapes are consistently parseable and source-appropriate.
- **Temporal patterns:** 6 — Causal ordering is strong, but the repeated DHCP sub-millisecond timestamp fingerprint materially lowers realism.
- **Cross-source correlation:** 9 — UID, process, actor, session, and timing relationships showed no visible contradiction.
- **Behavioral realism:** 8 — Process, authentication, protocol, and role distributions are varied and generally credible.
- **Environmental consistency:** 8 — Source volumes and host-role differences are plausible for the bounded environment.

## Recommendations

- If this were synthetic, generate each DHCP syslog timestamp as a separate source-native observation rather than adding integral-millisecond offsets to one shared timestamp. Preserve causal ordering, but independently vary the full microsecond component.
- Add a regression probe that groups DHCPREQUEST/DHCPACK/bound triplets and flags repeated nonzero low-order timestamp residues across all members.
- Apply the same residue-collision audit to other multi-message syslog lifecycles such as SSH authentication, sudo session open/close, and systemd start/finish pairs while preserving their current ordering guarantees.
