# Network Identities and Traffic Affinities

## Summary

Implemented scenario-local `environment.network_identities` and baseline
`traffic_affinities` / `traffic_suppression` on branch
`codex/network-identities-traffic-affinities`.

Key decisions:

- Scenario identities are an in-memory overlay above package DNS; generation does
  not mutate `dns_registry.yaml`.
- Explicit authored storyline IPs remain authoritative. Scenario identities are
  used for declared identity lookups and hostname-first/generated paths, while
  stable fallback resolution does not silently replace an explicit destination IP.
- `dns_query` storyline events keep the existing schema contract: `NOERROR`
  requires an explicit `answer`.
- Web route profiles bind path, method, status, body-size, and content type so
  invalid method/status combinations are not generated independently.
- `traffic_affinities` generate baseline-only evidence and are not recorded as
  storyline or red-herring leads.

## Verification

- `UV_CACHE_DIR=/private/tmp/eforge-uv-cache uv run --no-sync ruff check .`
- `UV_CACHE_DIR=/private/tmp/eforge-uv-cache uv run --no-sync ruff format --check .`
- `UV_CACHE_DIR=/private/tmp/eforge-uv-cache uv run --no-sync pytest --no-cov tests/unit/test_models.py tests/unit/test_validation.py tests/unit/test_browser_session_contract.py tests/unit/test_network_identities_affinities.py`
- `UV_CACHE_DIR=/private/tmp/eforge-uv-cache uv run --no-sync pytest --no-cov -k 'not splunk_runtime_mounts_apps_without_overriding_splunk_etc'`

The excluded Splunk test attempts to bind a local TCP port and fails under the
managed sandbox with `PermissionError: [Errno 1] Operation not permitted`; it was
the only failure in an initial full default-suite run.
