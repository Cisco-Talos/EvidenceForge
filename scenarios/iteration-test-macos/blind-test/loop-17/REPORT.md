# Assessment Loop 17 — PowerShell ambient file effects (partial)

## Result

The loop-17 change added command-output-aware filtering to baseline ambient file churn. Focused EDR-pool tests passed (82); config validation had zero errors; Ruff, formatting, and behavior-manifest validation passed at revision 416. However, the fresh rendered output still contained three PowerShell temp writes (two after `Test-Connection`, one after `Get-EventLog`) because process-execution preflight has a second entry path through `select_file_side_effect`. The loop is partial and the baseline-only fix is not claimed complete.

## Fresh generation and evaluation

Generation: `/private/tmp/eforge-iteration-test-macos-loop-17`. The authoritative bundle passed one automated evaluation at 96.349234/100 with 132,201 records. The 117-file blind data copy is byte-identical. A source-level direct selector test filtered the generic temp path for `Test-Connection`, but the rendered-output probe found the bypass described above.

## Blind review

Standalone synthetic-confidence scores were Threat 53, Detection 27, Network 63 and Host/EDR 67 (mean 52.5; verdict-confidence mean 76). The 40-point spread and verdict split triggered deliberation; modeled revised score mean was 52.0. Findings are preserved in the four reports and `deliberation.md`.

## Next root cause

Loop 18 extends command-aware admission into the shared process side-effect selector as well as baseline churn. Its probe must confirm zero generic PowerShell temp writes across all Windows hosts while preserving file-producing commands such as `Export-Csv`. Full artifacts are in this directory.
