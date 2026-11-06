# Loop 17 root-cause probe

The source-level helper probe confirms that `select_ambient_file_churn_effect()` filters the generic `AppData\\Local\\Temp\\tmp*.tmp` path for PowerShell commands without file-output markers, while allowing a PowerShell `Export-Csv` command. The focused `tests/unit/test_edr_pools.py` suite passes 82 tests.

The fresh rendered bundle contradicts that expected family result: `WS-PPATEL-01` still has a PowerShell `Test-Connection` process followed 3.6 seconds later by a `FILE WRITE`/Sysmon Event 11 to `tmp91497.tmp`. Two additional PowerShell temp writes remain on `DC-01` (one `Test-Connection`, one `Get-EventLog`). Therefore the newly added selector guard does not own all paths that can create this evidence, or the events are being created through a distinct generation path. The loop is partial; do not claim the output family invariant is fixed. Loop 18 must trace the exact occurrence producer and move the guard to the common canonical event owner or adapt the caller into it.

The 117-file blind copy is byte-identical to the generated data. This report records the failure of the rendered-output invariant so the next loop can continue the source trace.
