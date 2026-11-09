# Loop 18 root-cause probe

The process-execution preflight and baseline ambient-churn selectors now share the PowerShell file-output predicate. Focused tests verify that a `Test-Connection` command cannot receive a generic temp artifact in either path, while `Export-Csv` remains eligible. The focused EDR-pool suite passes 83 tests.

Rendered-output probe parsed every eCAR row and found zero PowerShell `AppData\\Local\\Temp\\tmp*.tmp` writes on any Windows host. The loop-17 examples on WS-PPATEL-01 and DC-01 are absent. The generated dataset copy contains 117 files and is byte-identical. The remaining non-PowerShell temp artifacts were not part of this invariant.
