# Bounded modeled workstation acceptance

Target: macOS 26 arm64 workstations in a mixed Windows/Linux fleet. This is
experimental synthetic evidence support, not complete native macOS fidelity.
The benchmark sources and UUIDs are frozen in `revisions/`; each run retains
implementation, input, manifest and per-file hashes in its loop provenance.

| Contract | Evidence | Status |
| --- | --- | --- |
| Separate supported and native-source revisions | `01-supported` and `02-native`, independently created Schema 3 drafts | Complete |
| Platform-aware assessment reviewers | Installed assessment skill, retained replacement copies and tracked reviewer patch | Complete |
| Supported-source baseline | Loop 1 and `checks/supported-after-328` | Complete; later supported-source acceptance passes |
| Nonempty native fork output | Loop 2; three strict fork/v10 records | Complete for the bounded SSH receiver |
| Source filtering does not change shared truth | Revision-328 supported/native shared data bytes match; CLI filter tests | Pass |
| Fresh-process deterministic native output | `tests/integration/test_macos_es_cli.py` | Pass |
| Exact native checkpoint suspend/resume | Same integration file; six retained fork rows | Pass |
| Mixed-fleet, SSH, system-job and SMB acceptance | 38 relevant extended tests | Pass |
| Existing lifecycle/session/TLS hard probe | `loop-2/family_probe.json` | Zero failures |
| Catalog completion within evidence bounds | All 67 original IDs assessed; 48 prefilled Mac variants; runtime module and actual-engine tests | Complete; unsupported entries stay unavailable |
| Assessment-driven owner fixes | Revision 329, focused tests, next fresh loop and review-family probe | Final validation in progress |
| Complete routine regression suite | Full run plus 108 passing affected-file/skill/manifest tests; exact results in worklog | Validated with focused fixture repairs |

The following boundaries remain explicit:

- **Deferred by user:** native ES exec/exit (ES-R1) and native Gatekeeper denial
  (GK-R1). Their source/version gates stay closed. The lab proposal is retained;
  no capture is authorized or pending.
- **Outside this modeled scope:** Intel/Rosetta, sleep/wake, roaming, Mac SMB
  serving, binary log containers, filesystem artifact generation, full GUI
  lifecycle and general external SIEM normalization.
- **Catalog boundaries:** 18 native service entries are catalog-only; this does
  not assert their automatic behavior. Zscaler's native arm64 variant stays
  unavailable without qualifying architecture evidence. A logical npm/pip/pytest
  entry names a module invocation through one loaded runtime, not a separate
  invented executable or an inferred private virtual environment.
- **Realism result:** independent review scores are diagnostic, not a native
  certification or a guarantee that analysts cannot recognize synthetic data.
  New qualified findings remain distinct from the original acceptance plan.

See `blind-test/REPORT.md` for current scores, confirmed findings and residual
quality work, and the focused assessment worklog for gate output and commits.
