# Threat Hunter — Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict Confidence: 89%
- Synthetic-Confidence Score: 78/100
- Rubric Result: Likely synthetic

## Executive Summary

The dataset has substantial source-native detail and credible protocol semantics, but repeated mechanical patterns across unrelated hosts outweigh those strengths. The strongest synthetic indicators are highly regular DHCP and cron timing, template-like Linux administrative activity, implausibly uniform Windows module-load telemetry, generic PID-1-spawned `wget` activity on production servers, and public-client addresses drawn from operationally unlikely address space.

## Evidence For Synthetic

- DHCP renewals on `WS-OHADDAD-01` recur approximately every 29 minutes 47 seconds, progressively advancing by about 12–13 seconds on every cycle. Each transaction uses the same PID, interface, server, and request/ack structure. This resembles a periodic generator with accumulated jitter more than an actual DHCP client timer.
- `APP-INT-01` emits the identical sysstat cron command at every exact half-hour, with only 105–292 ms of timestamp variation. The same two-process cron pattern appears broadly across Linux hosts.
- Linux administrative noise is assembled from a compact reusable grammar: assorted users run `systemctl`, `grep`, `find`, `iostat`, and `apt` through `sudo`, followed by nearly identical PAM open/close pairs. The randomized TTY, working directory, user, and command combinations often lack an operational reason.
- `DB-PROD-01` repeatedly shows PID 1 directly spawning root-owned `wget` commands to `pypi.org`, `api.snapcraft.io`, and Ubuntu repositories through a proxy. No service or timer identity explains these unrelated fetches. Similar PID-1-to-`wget` behavior occurs on `WEB-EXT-01`.
- Windows process telemetry repeatedly assigns the same short DLL set to many processes, usually within the first few milliseconds after creation. The `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `rpcrt4.dll`, and `bcryptprimitives.dll` sequences are highly standardized and far less diverse than typical module telemetry.
- Linux PIDs rise monotonically with elapsed time across each host and reach unusually large values—for example, roughly 946,000–984,000 on `APP-INT-01` and 3.77–3.81 million on `MAIL-EDGE-01`. The host-specific linear allocation behavior looks algorithmic.
- Public web clients include sustained ordinary browser sessions from operationally unlikely space such as `29.176.39.5` in 29/8. Other “Internet” traffic is spread broadly across seemingly sampled global prefixes, consistent with random address generation rather than observed client populations.
- Web browsing uses a limited collection of reusable page bundles: recurring asset names, browser versions, response-size patterns, and referrer progressions appear across external sessions.
- IDS background traffic repeatedly selects a compact set of conspicuous signatures—BitTorrent, suspicious TLDs, curl, and Basic Auth—with broad random-looking endpoints. This produces threat-noise variety but lacks the messier repetition, suppression, and sensor-specific artifacts normally seen in deployed IDS output.

## Evidence For Real

- Zeek connection records generally have internally credible TCP/UDP fields, including state diversity, packet and byte accounting, history strings, services, and sub-millisecond durations.
- TLS records use plausible protocol/cipher combinations, SNI values, certificate chains, key sizes, validity periods, and resumed/established flags.
- Proxy records distinguish CONNECT control bytes from tunnel bytes and include deny, authentication, cache, SSL-bump, and tunnel-duration semantics.
- Cisco ASA messages use credible build, teardown, deny, NAT, interface, connection-ID, byte-count, and termination-reason syntax.
- Linux syslog includes realistic RFC 5424 structure and recognizable messages from PAM, systemd, rsyslog, cron, SSH, sudo, and DHCP.
- Windows XML resembles native Event Log structure, including provider metadata, channel, record ID, process/thread IDs, and event-specific fields.
- The dataset includes varied ordinary activity such as software updates, browser traffic, monitoring checks, mail protocols, Kerberos, LDAP, SMB, DHCP, DNS, SSH, and administrative sessions.
- Lifecycle evidence is often plausible: short-lived commands terminate, sudo sessions close, network flows have outcomes, and SSH/PAM sessions include open and close behavior.

## Detailed Analysis

### Temporal Behavior

Short-lived activity has useful millisecond-level variation, but multiple recurring families are too mechanically scheduled. DHCP renewals on `WS-OHADDAD-01` form an especially recognizable arithmetic series. Cron events occur exactly on half-hour boundaries across hosts, while randomized background events are evenly dispersed through the review window. This combination resembles explicit periodic jobs overlaid with sampled noise.

### Endpoint Telemetry

The eCAR records use coherent object/action vocabulary and preserve parent, actor, PID, principal, session, and flow properties. However, Windows module loading is conspicuously abbreviated and repeatable. On Linux, parentage such as PID 1 directly spawning many unrelated `wget` invocations omits the timer, shell, package manager, or service context normally expected.

### Authentication and Administration

PAM and Windows authentication records are structurally convincing. The weakness is behavioral: many server-side administrative sessions appear to be permutations of a small command/user/TTY/PWD matrix. Examples include different routine users repeatedly performing isolated diagnostic commands with no associated incident, change, or prolonged shell activity.

### Network and Protocol Data

Zeek, ASA, proxy, and IDS syntax is strong. DNS, TLS, HTTP, mail, and connection metadata are richer than a simple fabricated CSV dataset. Nevertheless, the public address population and alert mix look sampled for diversity. Some client prefixes are operationally improbable for ordinary healthcare-site browsing, while alerts cycle through well-known training-friendly categories.

### Web Activity

Browser sessions include realistic asset bursts, referrers, status codes, partial content, and varying response sizes. The weakness is repeated use of compact page templates and a narrow set of current browser strings. The traffic resembles modeled browsing sessions more than raw server access logs accumulated from a naturally heterogeneous public population.

## Synthetic Indicator Summary

| Category | Indicator | Strength |
|---|---|---:|
| Timing | Arithmetic DHCP renewal drift and exact half-hour cron cadence | High |
| Endpoint | Repeated abbreviated DLL-load sequences | High |
| Process semantics | PID 1 directly spawning unrelated root `wget` fetches | High |
| Administration | Recombined command/user/TTY/PWD templates | Medium-high |
| Addressing | Ordinary clients drawn from unlikely public prefixes | Medium-high |
| IDS | Compact, conspicuous signature pool across random endpoints | Medium |
| Web | Reusable browsing bundles and narrow client fingerprints | Medium |
| Fidelity | Strong source-native formatting and protocol fields | Evidence against synthetic |

## Realism Score by Category

| Category | Score |
|---|---:|
| Temporal realism | 5/10 |
| Endpoint/process realism | 5/10 |
| Network/protocol realism | 8/10 |
| Authentication/user-behavior realism | 6/10 |
| Source-native formatting realism | 8/10 |

## Recommendations

- Model DHCP renewals from client-state transitions and lease timers without cumulative fixed-direction drift.
- Add explicit service, timer, shell, or package-manager ancestry for automated Linux downloads.
- Generate host- and application-specific module-load populations with realistic filtering and timing.
- Tie administrative commands to durable operator sessions, host roles, and maintenance objectives instead of recombining a generic command pool.
- Draw external clients from realistic regional/ASN-weighted populations and exclude operationally improbable allocations.
- Model IDS output from actual flow/application properties and sensor policy, including thresholding and suppression.
- Expand web-client diversity and reduce reuse of identical page-navigation bundles.
- Preserve the strong Zeek, TLS, proxy, ASA, Windows XML, and lifecycle semantics while adding more organic host-specific irregularity.
