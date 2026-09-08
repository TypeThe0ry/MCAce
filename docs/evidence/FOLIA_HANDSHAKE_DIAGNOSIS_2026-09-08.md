# Folia handshake failure: observed progress, not all-false fallback

The exact `f6e8a48` matrix passed its two Paper/1.21.11 cases, then failed
Folia/1.21.11/Velocity with a socket read timeout. Nine cases were unexecuted.
The matrix session terminated with exit 1 and its two checkpoints remain on disk.

The old exception path discarded all observed protocol progress. The test
harness now preserves connection/login/configuration/handshake observations,
channel names and bounded packet metadata, plus failure state. It still records
the exception as a limitation, leaves unverified backend acceptance false and
rethrows the original exception after cleanup. No timeout, acceptance assertion
or product behavior changed. Two focused regression tests passed, including
snapshot isolation and no invented pre-connection progress.

A real development-worktree diagnostic rerun used Folia 1.21.11 build 14 and
Velocity 3.5.1-615 with their frozen hashes and a freshly computed prepared-tree
digest. It failed again, exit 1, BUILD FAILED in 2m 55s. This time the report
established:

- TCP, login, compression and configuration completed.
- State reached PLAY and the game-join/channel-registration steps occurred.
- SERVER_HELLO arrived in PLAY; the peer sent CLIENT_HELLO and AUTH_REQUEST.
- AUTH_RESULT was not observed; authentication and verified backend admission
  did not complete.
- No owned processes remained after cleanup.

Proxy log: listening at 20:26:53 UTC+08 (40.74s startup); test player connected
at 20:27:34; MCAce session timed out to LIMITED at 20:27:45. These timestamps do
not establish exactly when authentication frames were sent. The next diagnostic
run should correlate client authentication preparation time with this deadline.
Existing timing counters have now been added to failure metadata; this final
timing addition passed the two focused tests but has not yet had a real rerun.

Raw report (retained locally, not copied here because it includes a test session
identifier in packet metadata):
`build/runtime-player-probe/runs/velocity-folia-2026-09-08T12-25-58-927780Z/report.json`

SHA-256: `6b2ae8283eaacd0e4c5dc67ce7a452148969377b2dd6c7baa3e9d479dc5852f2`

Log: `build/folia-failure-progress-20260908.log`.

This is a diagnostic improvement and a reproduced failure, not a product fix,
successful matrix, real Fabric GUI/cheat test or signed release evidence.
No merge, tag or release was performed.
