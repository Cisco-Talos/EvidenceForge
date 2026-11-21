# Unselected irqbalance diagnostic follow-up

18Threat's small repeated four-message vocabulary is not by itself a defect:
real daemons have finite format strings. Current extra_syslog_messages.yaml IRQ
profile is host-coherent for IRQ/device/CPU but messages read as narrative summaries.
Read-only primary-source search did not corroborate exact current phrases; do not
claim universal impossibility or absence solely from a search result.

Official upstream irqbalance.c/classify.c/activate.c expose native diagnostics,
verbosity/log destinations and state transitions. Example activate.c has debug
"IRQ %i affinity is now unmanaged". A repair must model the relevant IRQ state /
logging mode and host hardware facts rather than simply replacing four strings
with more strings or repeating serious warning formats at existing high rate.
Parameter affinity masks must agree with any state/accounting semantics selected.
No23selection/contract/code yet; reassess actual latest panel after20.

Primary sources:
https://github.com/Irqbalance/irqbalance/blob/master/irqbalance.c
https://github.com/Irqbalance/irqbalance/blob/master/classify.c
https://github.com/Irqbalance/irqbalance/blob/master/activate.c
https://github.com/Irqbalance/irqbalance/blob/master/irqbalance.1
