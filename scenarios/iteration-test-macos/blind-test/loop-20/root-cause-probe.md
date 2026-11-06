# Loop 20 root-cause probe

The standalone source-timing regression suite passes, and a machine-account bundle unit test with an eCAR emitter confirms the canonical target FLOW precedes the LOGIN for a forced TCP/445 case. However, the fresh full scenario still reproduces the prior eCAR observation on `DC-02.meridianhcs.local`: line 1035 is a successful type-3 LOGIN from `10.10.1.34:55083` to `10.10.2.11:445`, and line 1036 is the exact inbound FLOW, both at `timestamp_ms=1793629313776`.

The output contains only that one inbound flow for the tuple. The matching workstation outbound FLOW is earlier. The JSON evaluator continues to report `Rule 'eCAR remote FLOW before login'` at line 1035. Therefore the loop 20 source-timing change did not affect this full-generation path; do not mark this symptom fixed based only on the planner unit tests. The remaining investigation is to identify why the full scenario's machine-account publication does not use the admitted target-flow timestamp that the isolated bundle test uses, or establish that millisecond equality is a valid source-resolution tie and correct the owning evaluation contract with evidence.

Fresh generation passed one JSON evaluation at 96.349141 with 132,196 records. The blind-copy data was byte-identical (117 files).
