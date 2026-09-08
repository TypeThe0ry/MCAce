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
