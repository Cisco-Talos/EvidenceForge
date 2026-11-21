# Unselected server process-mixture follow-up

Native loop20 census independently reproduces Host counts: DC01conhost32/dllhost32/
WMI32/taskhost29; DC02dllhost40/taskhost34/conhost31/WMI25; FILEtaskhost31/WMI22/
conhost21/dllhost13; MAILconhost14/taskhost14/WMI14/dllhost12. Samples and native
parent counts retained alongside these notes. These are a distribution hypothesis,
not impossible individual rows; source filtering and managed workload remain alternatives.

Owner inventory: BaselineMixin._generate_system_service_processes already samples
3–8scaledserviceintents/hour plus continuous per-occurrence times. Shared
pick_system_service_process samples a deployed role/service-filtered pool.
Persistent services may reuse their canonical singleton and produce no new birth,
whereas bounded WMI/dllhost/conhost lifetimes recur. Scheduled tasks have separate
weights/cooldowns/admission and their taskhost/helper chains also contribute.
Thus raw process-create proportions do not equal service-selection probabilities.
Equal counts in a fixed-seed sample do not establish a round-robin generator.

Do not randomize weights/counts only to defeat this one sample, add unsupported
server software, relaunch resident services, or inject rare failures. A family
change needs installed workload/arrival ownership and collection-aware native
calibration, including direct service and scheduled/task-derived helper entry
paths. No production change has been selected from this weak signal.
