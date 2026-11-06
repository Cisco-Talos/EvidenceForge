# Assessment Loop 16 — macOS directory metadata

## Result

The loop-16 root-cause fix is complete. `MacosExecutionMetadataProducer` now assigns deterministic host-scoped inode ranges and deterministic host/path-scoped directory ages within configured bounds. This replaces one repeated inode base and one fixed directory age for every modeled Mac directory. The profile schema and YAML now express ranges, with tests for repeatability, scoped variation, bounds, and uniqueness.

The source change is behavior revision 415 (`116ea7e6bc961b28d374fda558120a5b352c9ce225f291ef361f1529cec36a11`). Forty-one focused metadata producer tests passed. Config validation reported zero errors, with the existing Chrome Helper warning and the loop-15 derived-pool informational message. Ruff, formatting, and behavior-manifest validation passed.

## Fresh generation and verification

- Generated bundle: `/private/tmp/eforge-iteration-test-macos-loop-16`
- Automated evaluation: PASS, 96.349234/100, 132,201 records
- Blind data copy: 117 files, byte-identical to generated source
- MAC01 root/home inode values: 2061341048677 / 2061341048678; ages approximately 107 / 284 days
- MAC02 root/home inode values: 2176108086486 / 2176108086487; ages approximately 446 / 587 days
- All observed values fell within configured bounds; host/path-scoped behavior is also covered by deterministic unit tests.

## Blind review

Initial synthetic-confidence scores were Threat 61, Detection 74, Network 27, and Host/EDR 65 (mean 56.75; verdict-confidence mean 76). Three reviewers chose Synthetic and Network chose Inconclusive; the score spread was 47, so deliberation was performed. Modeled revised mean synthetic-confidence is 54.25 and verdict-confidence is 71.5.

The strongest next root-cause candidate is a Windows PowerShell `Test-Connection` process followed by a randomized temporary-file write, corroborated in Sysmon and eCAR. The reports also flag narrow macOS shell-command texture. Detection's claim that `pidversion` must remain unchanged across exec was checked against Apple's Endpoint Security documentation and is not a confirmed defect; no change was made for it.

## Artifacts

See `family-contract.md`, `root-cause-probe.md`, `automated-eval.json`, the four blind reports, and `deliberation.md` in this directory. Generated and blind-copy data is under `data/`.
