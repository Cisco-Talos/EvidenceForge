# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

The dataset is highly huntable and often source-native, with a coherent intrusion path across endpoint, Windows, proxy, Zeek, firewall, and IDS telemetry. The strongest authenticity failures are in proxy metadata: repeated vendor updater user-agent/domain mismatches and implausible content types for known API endpoints, which look like independently sampled field pools rather than production traffic.

## Evidence For Synthetic

- `PROXY-01.meridianhcs.local/proxy_access.log:87` logs `hpia.hpcloud.hp.com` with `Lenovo+System+Update`; `:120` logs the same HP endpoint with `Dell+Command+Update/5.1`; `:170` logs `dellupdater.dell.com` with `HP+Image+Assistant`; `:209` logs `download.lenovo.com` with `HP+Image+Assistant`; `:825` and `:1300` log Dell updater traffic with `Lenovo+System+Update`. Those vendor pairings are source-native incoherences.
- `PROXY-01.meridianhcs.local/proxy_access.log:35` logs `GET https://api.github.com/rate_limit` as HTTP 200 with `text/html`; `:183`, `:458`, `:818`, `:1015`, `:1313` log `api.snapcraft.io/v2/snaps/refresh` as `text/html`; `:737`, `:953`, `:1225`, `:1268` log `registry.npmjs.org/` as `text/html`. These API/registry-style endpoints have consistently wrong-looking content types.
- Linux bash histories show generated-feeling command pools and typo injection: examples include `taiil`, `ca`, `journactl`, `ddf`, `pps`, `pi`, `lls`, and `locle` across APP-INT-01 user histories.
- The attack path is plausible but didactic: PsExec service, `whoami && hostname`, domain-admin creation, scheduled-task/service persistence, encoded PowerShell, `wevtutil cl Security`, then account deletion.

## Evidence For Real

- The main intrusion chain has strong source-native layering: DB root history shows `mysqldump`, `gzip`, and `scp`; DB ECAR records `/tmp/rpt_0318.sql.gz` and `scp`; APP receives the file; Zeek records the SSH transfer.
- DC Windows telemetry is internally coherent: `PSEXESVC.exe` file/process/service evidence appears in Sysmon and Security.
- Account manipulation lines up with Windows semantics: `net user svc_mhsync ... /add /domain`, Domain Admins membership, and deletion appear in Sysmon/Security.
- The large upload is convincingly represented across layers: proxy logs `cs-bytes=314782795`; Zeek sees the client-to-proxy flow and the proxy-to-external TLS flow with plausible byte deltas.
- The Security log clear is realistic: `wevtutil cl Security` appears immediately before Event ID 1102, with record IDs resetting afterward.

## Detailed Analysis

The hunt chain is clear. Root on `DB-PROD-01` dumps database content, compresses it, and transfers it to `10.10.2.30`; endpoint and Zeek records support the same movement. The chain shifts to `DC-01` using PsExec-style execution, creates `svc_mhsync`, adds it to Domain Admins, establishes `DeviceSyncSvc` persistence, performs C2 check-ins through `api.westbridge-services.net`, stages a large upload from `10.10.1.35`, clears Security logs, and deletes the temporary account.

That story is hunt-feasible and mostly source-native. The strongest problem is not source correlation; it is that several proxy records contain field combinations a production proxy should not normally emit. HP/Lenovo/Dell updater user agents are repeatedly attached to the wrong vendors' domains, and known API endpoints are repeatedly logged with `text/html` as successful SSL-inspected responses.

## Realism Score by Category

- **Field format accuracy:** 7/10 — Most formats are well-shaped, but proxy user-agent/content-type semantics break realism.
- **Temporal patterns:** 8/10 — Beaconing, DHCP renewals, session activity, and log clearing timing are plausible.
- **Cross-source correlation:** 9/10 — Attack and network evidence align well without obvious impossible ordering.
- **Behavioral realism:** 7/10 — User/admin activity is plausible but feels template-driven in command histories and attack flow.
- **Environmental consistency:** 6/10 — Host roles and IPs are consistent; vendor updater/domain mismatches are the main weakness.

## Recommendations

If synthetic, improve proxy generation by binding domains, user agents, and response content types to the same application profile. Avoid mixing HP, Dell, and Lenovo updater identifiers, and model common API content types accurately. Add more uneven human workflow texture and a few benign dead ends, but keep the strong cross-source attack chain.
