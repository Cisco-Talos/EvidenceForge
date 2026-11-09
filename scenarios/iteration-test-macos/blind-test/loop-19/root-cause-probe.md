# Loop 19 root-cause probe

On MAC-MROSS-01, the native accepted-publickey Unified Log record now has wall time `2026-11-02 16:02:17.562108+0000` and `machTimestamp=25145701490592`. The matching `/bin/zsh` Endpoint Security exec is `16:02:17.723014Z` with `mach_time=25145705352336`. Using the configured 125/3 ns Mach timebase, the Mach delta is 0.160906 seconds; the wall timestamps give the same delta. Authentication therefore precedes the shell exec, and the wall/Mach clocks agree exactly at the serialized precision.

The loop-18 Unified Log wall timestamp was 16:02:18.539009 while retaining the same auth Mach timestamp, placing the wall time 0.976901 seconds later than its Mach clock. The host clock projection was the cause. Focused source timing tests cover a nonzero Mac endpoint clock profile and pass. The blind data copy is byte-identical.
