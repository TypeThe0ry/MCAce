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

## Matrix rerun result (2026-09-12)

The rebuilt current bundle used source commit
`b642f3b205bc5687add3dd326acaa345cb9aa158`. Cases 1 and 2 passed again:
Paper 1.21.11 behind Velocity and BungeeCord. Case 3, Folia 1.21.11 behind
Velocity, failed closed on a timeout and stopped the matrix; cases 4--12 were
not executed.

Failed raw report:
`build/runtime-player-probe/runs/velocity-folia-2026-09-12T08-51-38-787614200Z/report.json`

Report SHA-256:
`9ad3dcbdf7da9edeb8805374b842bfcacdc4e8c1349c2a7755eb936d09421d54`

The report observed TCP, login and SERVER_HELLO, but no accepted
authentication or backend admission. `AUTH_FRAME_PHASE_NANOS` measured input
construction 28.6 ms and frame creation 110.2 ms. Policy timing measured
envelope parse/verification 1.309 s, decode 0.040 ms, cache acceptance 239.2
ms, state 1.1 ms, total 1.590 s; outer authentication work was 3.643 s.
The report records zero remaining run processes after cleanup.

This is a current-source matrix failure, not release acceptance. It narrows the
next investigation to cold envelope parse/verification and surrounding server
startup scheduling; changing the deadline or skipping the case would invalidate
the release gate.

## Prewarm rerun result (2026-09-12)

The next rerun used source commit `2d3567f` (the full commit is recorded by the
matrix invocation) after adding Ed25519 provider prewarming to both the Fabric
client startup path and the runtime probe. The prewarm only initializes the JCA
provider; it does not create keys or alter the wire protocol.

Cases 1 and 2 passed again. Case 3, Folia 1.21.11 behind Velocity, reached the
backend and logged the player join plus signed admission states, but the probe
timed out before observing an accepted authentication result or backend
admission. Cases 4--12 were not executed because the matrix fails closed.

Failed raw report:
`build/runtime-player-probe/runs/velocity-folia-2026-09-12T09-10-33-301679900Z/report.json`

Report SHA-256:
`60932f7a61af93dcc3409f26e38b9d321228592d5ccd5252e15a5996001b63ab`

Observed fields: `tcp_connected=true`, `login_success=true`,
`mcace_server_hello=true`, `mcace_auth_result=false`,
`mcace_auth_accepted=false`, and `backend_admission=false`. The server log
shows `VERIFYING` followed by `LIMITED` admission states. The report records
`AUTH_FRAME_PHASE_NANOS inputs=1351.8 ms, creation=2076.5 ms` and
`POLICY_PHASE_NANOS envelope=1063.8 ms, decode=516.3 ms, cache=2593.1 ms,
state=559.3 ms, total=4732.5 ms`; outer authentication work was 8431 ms.
No run processes remained after cleanup.

This confirms that provider prewarming did not resolve the 1.21.11/Folia
timeout. The next engineering step is to profile the Folia-specific admission
state/cache path and frame construction under this exact frozen asset; changing
the timeout or excluding Folia would not satisfy the matrix gate.

## KeyFactory prewarm rerun result (2026-09-12)

Source commit `41de8782d5192f50c17622ef00b566bf224f2d2b` additionally prewarms
the JCA `Ed25519` `KeyFactory` alongside the `Signature` provider. The frozen
matrix was rebuilt from that commit and rerun without changing the handshake
deadline or excluding any case.

The first three cases all passed:

* Paper 1.21.11 behind Velocity
* Paper 1.21.11 behind BungeeCord
* Folia 1.21.11 behind Velocity

The Folia report is:
`build/runtime-player-probe/runs/velocity-folia-2026-09-12T09-26-37-880510400Z/report.json`

Its SHA-256 is
`319a742a9ccdb6d651af9876564f25a72d9779bcc91be0ab0385b1f2e8cfff78`.
It records `tcp_connected=true`, `login_success=true`,
`mcace_server_hello=true`, `mcace_auth_accepted=true`, and
`backend_admission=true`. The policy phase was
`envelope=442.3 ms`, `decode=8.8 ms`, `cache=160.2 ms`, `state=0.5 ms`,
`total=611.7 ms`; authentication completed successfully and cleanup left no
run processes. This is the first current-source Folia pass after the two-stage
Ed25519 prewarm.
