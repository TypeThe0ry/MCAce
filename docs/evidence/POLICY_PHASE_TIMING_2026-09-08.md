# Content-free policy preparation timing

The strict 26.1.2 Folia/Velocity failure at release source `028c44c` spent
9718 ms in the aggregate policy-preparation interval. Earlier sampling and
successful runs did not establish which internal stage dominated that failure.

`ClientHandshakeEngine.policyPreparationTimings()` now returns only five long
nanosecond counters: envelope parse/verification, challenge decoding, policy
cache acceptance, compatibility/state initialization, and total elapsed time.
Counters use `System.nanoTime()`, not the protocol clock. An unfinished stage
is -1; each attempt resets stage values and records total duration in `finally`.
No policy bytes, paths, keys, player identifiers or session identifiers are
included. Verification order, rejection behavior and deadlines are unchanged.

The raw runtime probe appends `POLICY_PHASE_NANOS` to both successful reports
and failure-progress reports when a client engine exists. The cache interval
still includes policy verification, previous-cache loading and persistence;
it must not be described as disk-write time alone.

Verification: all 30 `ClientHandshakeEngineBudgetTest` cases passed with no
failures, errors or skips; runtime test sources compiled. Gradle exited 0 in
22 seconds, using cached offline dependencies and one worker. The new regression
checks completed-stage counters, total accounting, resetting after malformed
input, and that the public diagnostic record contains only long values.
Log: `build/policy-phase-diagnostics-20260908.log`.

This is diagnostic instrumentation, not a performance fix or a new real-server
acceptance result. A new controlled runtime measurement remains required. The
existing release bundle predates this product change and does not contain it.

## Controlled runtime measurement (2026-09-08)

The previously pending run completed at source
`dbfa4f21f21df22a8b9c45d27fe91577b13c097d`. Folia 26.1.2 build 8 behind
Velocity 3.5.1-615 failed with `SocketTimeoutException`; Gradle exited 1
after 3 minutes 20 seconds. This is a raw protocol peer, not a Fabric GUI
client or evidence of actual mod/Xray collection.

Local report:
`build/runtime-player-probe/runs/velocity-folia-2026-09-08T14-36-06-089069800Z/report.json`

SHA-256:
`7d29aa176068eb240e871c8b621ff2c782b0094a3eb8e5d65825a48ab3401f6e`

| Measured interval | Milliseconds |
| --- | ---: |
| Envelope parse/verification | 631.6784 |
| Challenge decoding | 310.1153 |
| Policy cache acceptance | 2044.1474 |
| Compatibility/state initialization | 11.3190 |
| Policy total (internal counter) | 2997.2645 |
| Policy preparation (outer probe interval) | 2999 |
| Authentication inputs and frame preparation | 3442 |
| Complete authentication work, including send | 6591 |

TCP connection, login, configuration completion and SERVER_HELLO observation
succeeded. AUTH_RESULT was not observed; authentication acceptance and backend
admission were false. The proxy logged challenge dispatch at 22:37:15 and
timeout/LIMITED at 22:37:21 (local time). The report lists no remaining owned
run processes after cleanup.

The frame interval includes Java argument evaluation (`authenticationBundle`
and `probeLoadedModGraph`) as well as `createAuthenticationFrames`; it is not
a measurement of signing alone. Cache acceptance also includes verification
and persistence. These measurements do not establish a single CPU, disk, JIT
or cryptographic root cause. Compared with the previous 9718 ms policy interval,
this failure has substantial latency in multiple stages. No deadline was
extended and no verification step was removed.

Next diagnostic work should separate input preparation from frame creation
and profile the slow stages before selecting a performance change. A passing
warm retry alone will not establish that the cold-start failure is fixed.
The complete version matrix remains incomplete; this failed diagnostic is not
release acceptance or a claim of real cheat detection.

## Warm/cold comparison follow-up

A fresh rerun using source `20abf6f7c7274d8f2519c2bc3935b5613fcf159c`
completed the same Folia 26.1.2 / Velocity path successfully. Report:
`build/runtime-player-probe/runs/velocity-folia-2026-09-08T14-48-46-315858400Z/report.json`

Report SHA-256:
`b251c85a1f21338112274dbfed57e1a1fa7908ca91c615fc369662498624f0d1`

The run had TCP/login/configuration/SERVER_HELLO, `mcace_auth_accepted=true`,
`backend_admission=true`, and zero remaining run processes. Its phase trace was:

| Interval | Nanoseconds |
| --- | ---: |
| Authentication input construction | 6,757,700 |
| Authentication frame creation | 33,085,900 |
| Envelope parse/verification | 173,452,900 |
| Challenge decoding | 265,720 |
| Policy cache acceptance | 126,842,400 |
| Compatibility/state | 484,900 |
| Policy total | 327,355,800 |

This controlled success rules out authentication frame construction as the
cause of the earlier multi-second interval. It also shows that a warm passing
run does not by itself prove cold-start reliability. No timeout or verification
rule was changed; the strict version matrix still needs its remaining cases.

## Frame-input diagnostic follow-up

The runtime test peer now additionally records `AUTH_FRAME_PHASE_NANOS`, with
separate `inputs` and `creation` intervals. Inputs cover integrity-bundle and
loaded-mod fixture construction; creation covers `createAuthenticationFrames`.
Each entered interval records elapsed monotonic time in `finally`, including
exception paths; an unentered interval remains -1. The existing aggregate
`frames_ms` field is retained. Only the test peer changes: product protocol,
signatures, admission deadlines and collection behavior are unchanged.

Three focused report regressions passed (zero failures, errors or skips),
including both successful-trace and failed-report preservation of these
counters and absence of invented timing before work begins. Gradle exited 0
in 30 seconds. This static regression does not establish improved runtime
performance; a fresh controlled run is required to interpret the new counters.
