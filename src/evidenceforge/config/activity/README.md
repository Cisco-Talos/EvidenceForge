# Activity Generation Data

YAML lookup tables used during log generation to produce realistic baseline
and storyline activity. Each file is a single source of truth for its domain.

## Loader Modules

Most files have a dedicated loader in `evidenceforge.generation.activity` that
caches data after first load. Two files (`network_params.yaml`,
`systemd_schedules.yaml`) are loaded inline by engine modules.

## Files

| File | Loader | Purpose |
|------|--------|---------|
| `dns_registry.yaml` | `dns_registry.py` | Domain-to-IP mappings with tags (web, saas, email, etc.). Builds forward/reverse DNS indexes. |
| `spawn_rules.yaml` | `spawn_rules.py` | Parent-child process relationships for Windows and Linux. Builds reverse child-to-parent index. |
| `bash_commands.yaml` | `bash_commands.py` | Per-role bash command pools (sysadmin, dba, developer, generic) with `{placeholder}` templates. |
| `system_processes.yaml` | `system_processes.py` | Baseline Windows scheduled tasks and system services (svchost, MpCmdRun, etc.). |
| `tls_issuers.yaml` | `tls_issuers.py` | Certificate issuer configs (Let's Encrypt, DigiCert, etc.) with validity periods and key types. RSA-named issuers should not include ECDSA key types under the current simplified x509 model. |
| `tls_realism.yaml` | `tls_realism.py` | TLS SAN, OCSP, certificate-chain, CA key/signature metadata, and destination-profile settings with overlay support. |
| `kerberos_realism.yaml` | `kerberos_realism.py` | Kerberos 4768 TGT PreAuthType, TicketOptions, encryption, and PKINIT certificate field distributions with overlay support. |
| `windows_auth_realism.yaml` | `windows_auth_realism.py` | Windows Security authentication realism knobs such as minimum 4800→4801 lock/unlock gap, failed-logon validation paths, companion network evidence, and 4672 privilege profiles. |
| `auth_noise.yaml` | `auth_noise.py` | Baseline authentication-noise profiles such as stale scheduled-credential account pools and irregular recurrence timing. |
| `endpoint_noise.yaml` | `endpoint_noise.py` | Endpoint background timing, registry-emission, and EDR attribution policies for Windows scheduled processes, DHCP interface registry writes, and eCAR FLOW principal context. |
| `host_activity_profiles.yaml` | `host_activity_profiles.py` | Coarse host/persona/role rate multipliers for baseline volume, endpoint noise, firewall deny bursts, and data-driven artifact variation. |
| `observation_profiles.yaml` | `config/observation_profiles.py` | Named source-observation profiles for optional source-level missingness and delays. Scenario `observation_profile` defaults to `complete`; generation records status in `OBSERVATION_MANIFEST.json` for eval. |
| `proxy_uri_templates.yaml` | `proxy_uri.py` | Per-domain URI path templates, plaintext HTTP policy, and referrer policy for proxy/HTTP logs (Windows Update, CRL, OCSP, Azure AD, etc.). |
| `network_params.yaml` | `network_params.py`, `engine/emitter_setup.py` | MAC address OUI prefixes, public NTP fallback servers, and DNS tunnel RTT bounds. |
| `systemd_schedules.yaml` | `engine/baseline.py` | Systemd timer and cron job schedules (logrotate, fstrim, apt-daily, etc.). |
| `extra_syslog_messages.yaml` | `extra_syslog.py` | Role/distro-tagged syslog program messages for baseline diversity. |
| `application_catalog.yaml` | `application_catalog.py` | Unified app definitions: image paths, PE metadata, command templates, persona filtering, child processes. |
| `traffic_profiles.yaml` | `traffic_profiles.py` | Role-based and persona-based network traffic profiles. See `docs/design/traffic-profiles-design.md`. |
| `web_session_profiles.yaml` | `web_session_profiles.py` | Inbound web server visitor classes, request profiles, and User-Agent pools. Human visitors use `site_maps.yaml`; top-level `web` traffic rates fan out into page assets. |
| `process_network_map.yaml` | `process_network.py` | Process-to-network service mappings for PID attribution and process-network correlation. |
| `process_access_patterns.yaml` | `process_access_patterns.py` | Sysmon Event 10 baseline source/target pairs and weighted GrantedAccess masks. |
| `create_remote_thread_patterns.yaml` | `create_remote_thread_patterns.py` | Sysmon Event 8/eCAR THREAD benign source/target pairs plus weighted start module/function locations. |
| `edr_pools.yaml` | `edr_pools.py` | File, registry, and DLL diversity pools with template placeholders for ambient EDR/Sysmon events. |

## Adding a New Data File

1. Create `{name}.yaml` in this directory.
2. Create a loader in `evidenceforge/generation/activity/{name}.py` (or load inline if simple).
3. Use `from evidenceforge.config import get_activity_directory` for path resolution.
4. Follow the cached-loader pattern: module-level `_CACHED_DATA`, load-on-first-call, return cached.
