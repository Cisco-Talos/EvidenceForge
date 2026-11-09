# Loop 21 root-cause probe

The exact DC-02 eCAR tuple remains present: `USER_SESSION/LOGIN` line 1035 and inbound `FLOW/CONNECT` line 1036 both have `timestamp_ms=1793629313776`. The matching Windows Security 5156 record is earlier than the 4624 logon, so the eCAR millisecond tie is not evidence of an impossible chronology.

`CausalityScorer._score_ecar_remote_auth_ordering` now treats `flow_time <= login_time` as correctly ordered for the eCAR source timestamp comparison. A tie is therefore indeterminate at the source's millisecond precision; a later flow remains a failure. The focused temporal evaluator suite passes (29 tests), including an equal-timestamp case and the retained +25 ms inversion case.

Fresh generation passed its single JSON evaluation at 96.34950094006459 with 132,196 records. The causal-ordering failure no longer appears. The blind-copy data tree has 117 files and is byte-identical to the generated output.
