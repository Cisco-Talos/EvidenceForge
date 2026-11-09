# Host / EDR Forensics Review — Loop 76

## Final assessment / verdict

**Verdict: Inconclusive.** The inspected host telemetry is internally plausible and contains strong process-level cross-source alignment. I found no hard contradiction in the reviewed Windows, Linux, or macOS records. These observations are insufficient to establish whether the data is real or synthetic.

## Verdict confidence

**70/100.** Confidence is moderate that “Inconclusive” is the right verdict for this host-only review.

## Synthetic-confidence score

**45/100.** The reviewed host records provide little affirmative evidence of synthetic origin; their cross-source agreement supports plausibility but does not establish provenance.

## Evidence

- **No hard contradictions observed.** Process create/terminate records did not show a visible termination preceding its corresponding creation. Unpaired events are expected at the boundaries of this six-hour slice and are not treated as defects.
- **Strong Windows process correlation — `environment_or_collection_plausibility`.** On `WS-AJOHNSON-01`, PID 5116 (`C:\Windows\System32\OpenSSH\ssh.exe`) has an eCAR `PROCESS/TERMINATE` at `2026-11-02 13:00:22.137Z` ([eCAR line 1](/private/tmp/log-study-loop76/dataset-ash/data/WS-AJOHNSON-01.meridianhcs.local/ecar.json:1)); Sysmon Event ID 5 records the same PID and image at `13:00:22.069Z` ([Sysmon line 23](/private/tmp/log-study-loop76/dataset-ash/data/WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml:23)), and Security Event ID 4689 records its termination at `13:00:22.3504973Z` ([Security line 14](/private/tmp/log-study-loop76/dataset-ash/data/WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml:14)). The sub-second timing and matching identity are coherent across three sources.
- **Linux shell history aligns with endpoint process activity — `environment_or_collection_plausibility`.** On `APP-INT-01`, the `hostnamectl` history entry ([history line 2](/private/tmp/log-study-loop76/dataset-ash/data/APP-INT-01.meridianhcs.local/bash_history/maya.ross.bash_history:2)) at `2026-11-02 13:35:28Z` has an eCAR process-create record for `/usr/bin/hostnamectl` 1.34 seconds later ([eCAR line 75](/private/tmp/log-study-loop76/dataset-ash/data/APP-INT-01.meridianhcs.local/ecar.json:75)). Other inspected history commands, including `ss -s`, `systemctl`, and `ip route`, also have nearby matching process starts.
- **Possible command-to-process coverage gap — `contract_gap` (low weight).** `APP-INT-01` bash history records `pip install -r requirements.txt` at `17:00:04Z`; nearby eCAR process events show a shell and `debian-sa1`, but I did not find an evident `pip` process start. This could reflect collection coverage, shell-history timestamp semantics, or a failed/short-lived command; the dataset does not define expected process coverage, so this is not a contradiction.
- **Unusual but plausible activity.** The application host’s history includes developer/admin commands (`git`, `make test`, `pip install`, Docker and Kubernetes commands). This is atypical for some production application hosts but can fit an operator session and is not independently suspicious.

## Limitations

Review was limited to host and endpoint records in the supplied data directory. I did not use scenario, ground truth, evaluation output, source code, or prior reports. No collection policy or guaranteed eCAR process coverage was available, so missing companions cannot be classified as defects. A six-hour slice also cannot establish complete process or session lifecycles.
