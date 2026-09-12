# Proxy startup barrier correction and real rerun

The test harness now waits directly for a loopback listener while checking its
owned proxy process is alive before and after connection. Identity files and
buffered log markers are no longer startup barriers. The default listener
budget is 90 seconds (previously a separate 90-second file/log wait followed by
30 seconds for the listener). Existing inventory tests retain their explicit
120-second override. This is test orchestration only; handshake, backend
admission, context and cleanup assertions remain unchanged.

`LoopbackListenerBarrierTest`: four tests actually executed, zero skips,
failures or errors. Coverage: live listener, dead process despite a listening
port, process exit after connection, and timeout without a listener.

The first targeted runtime command supplied an empty prepared-tree digest due
to an incorrect result property name; input validation rejected it before
startup. The command was corrected to use the validated `tree_sha256` result.
No hash validation was bypassed.

The corrected real `1.21.11 / Paper 132 / Velocity 3.5.1-615` rerun passed:

- JUnit: one test, zero skips/failures/errors, 85.912 seconds.
- Gradle: exit 0, BUILD SUCCESSFUL in 1m 43s (one task executed,
  34 up-to-date; not a full compile/test rerun).
- Velocity observed startup: 42.55 seconds; listening occurred at 20:06:01
  UTC+08 on 2026-09-08.
- Login, MCAce auth acceptance, verified backend admission and backend shadow
  context audit all true; no remaining owned processes.

Raw report:
`build/runtime-player-probe/runs/velocity-2026-09-08T12-05-07-627543600Z/report.json`

SHA-256: `e23cf6ac5184c9f8c941b93dcfea12e00b7f9dbaae37454535722f7613f6e053`

Log: `build/listener-barrier-rerun2-20260908.log`. Earlier startup failure is
retained separately in `MATRIX_15302cc_2026-09-08.md`.

This was a targeted development-worktree test using the real proxy/backend and
test wire peer, not a real Fabric GUI client or the complete signed twelve-case
release matrix. It does not establish ModList honesty, cheat/Xray detection,
GUI consent, federation handoff or an external supervisor signature. The full
matrix must be rerun against the new exact-source candidate. No release/tag.
