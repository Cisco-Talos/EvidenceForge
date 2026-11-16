# Kestrel Ridge Engineering - macOS Persistence and DNS: instructor guide

Instructor-only material. Give analysts ENVIRONMENT.md and the generated evidence; this guide and scenario.yaml reveal the intended sequence.

Correlate native Mac process evidence and explicit persistence stages with a DNS channel despite a missing direct query-to-process join.

## Learning questions

1. Which Mac acquires a new system LaunchDaemon definition, and under what principal?
2. What executable and script does the retained definition launch, and what parent chain is visible?
3. Which DNS sequence differs from ordinary engineering traffic, and what synthetic content can be decoded?
4. What can host/time correlation establish, and what remains unproven without query-to-payload attribution?
5. Does deleting the plist unload the job? Which modeled stage ends its registration?

## Intended interpretation

KR-MAC-01 already has an elevated foothold; entry, elevation and script staging precede the exercise. The root working shell writes and bootstraps com.kestreltools.update-agent, then explicitly activates its loaded definition. Launchd forks, the child execs xpcproxy and then the installed Homebrew Python interpreter with /Library/Application Support/KestrelTools/agent.py as its script argument. A base32 TXT series to telemetry.kr-diagnostics.example follows on the same host. Its literal input is synthetic FieldKit release-review text. Removal at +3h deletes the definition file while the retained job remains loaded; explicit unload follows at +3h5m. Nadia's later ordinary HTTPS update check is on a different Mac. Host/time correlation supports the investigation; it does not independently prove a payload PID for each DNS query.

## Authored timeline

| Offset / time | Actor | System | Intended activity |
|---|---|---|---|
| +10m | root | KR-MAC-01 | An already elevated foothold starts a working shell; initial access and elevation precede the collected exercise. |
| +2h | root | KR-MAC-01 | The elevated foothold writes a software-updater-style system LaunchDaemon definition. |
| +2h2m | root | KR-MAC-01 | The system-domain definition is registered separately from its first activation. |
| +2h5m | root | KR-MAC-01 | An explicit activation starts the installed Python interpreter and previously staged script through launchd and xpcproxy, without an inferred shell or helper tree. |
| +2h7m | root | KR-MAC-01 | The host sends encoded synthetic engineering data in TXT-query labels; collection does not establish the originating payload PID. |
| +3h | root | KR-MAC-01 | The plist is removed while the loaded definition remains registered. |
| +3h5m | root | KR-MAC-01 | The loaded job is explicitly unloaded; removal alone did not stop its retained process group. |

## Benign comparisons

- approved-status-check (+4h): An ordinary update check on another assigned Mac uses short HTTPS traffic, with no new system job or sustained encoded TXT series.

## Capabilities demonstrated

Qualified macOS 27 arm64 deployments; native Endpoint Security process starts; explicit root/system LaunchDaemon stages; an installed Python interpreter with its own metadata; base32 TXT-query payloads; comparison with ordinary update traffic.

## Modeling and interpretation limits

This is a fictional Python agent, not a claim to reproduce a named malware family or supply a runnable payload. The script is represented by pre-existing modeled storage and exact invocation; DNS wire behavior is authored through dns_tunnel. RunAtLoad is false, activation is explicit, and no reboot, KeepAlive or timer behavior is asserted. Native plist artifacts and launchd Unified Log messages are unavailable; use eCAR file evidence and native process evidence for their respective observations. Complete native process-start coverage is requested; an unsupported launch must fail rather than silently omit its start. Unload does not fabricate a known successful exit result. The shared DNS event cannot explicitly bind a payload process; any inferred resolver transport owner must not be treated as proof of origin. Missing direct linkage is the accepted collection boundary and a separate P1 engine backlog item.

## Evidence acceptance

This guide describes authored intent, not a reviewed generated dataset. Input validation and publication do not prove that every intended observation appears. After generation, inspect the run-owned GROUND_TRUTH.md/JSON, collection/observation manifests, relevant artifacts and exact process/session/network relationships, then evaluate the bundle. Do not invent a missing source, relax an acceptance threshold or treat absent telemetry as proof of nonexecution.
