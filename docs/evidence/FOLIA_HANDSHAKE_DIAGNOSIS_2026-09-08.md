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

## Follow-up: timing attribution and an intermittent pass

The clean `fa7f1cd` diagnostic run at `2026-09-08T12-31-34-696427Z`
failed with authentication work of 6626 ms, the old `policy_ms` counter at
6328 ms and frame preparation at 220 ms. Its report SHA-256 is
`d478b6e9a84a08d40f2c0fe9e1a7c22b9d4be7608d70bc25bf9cfe6aee99523e`.
The fixture and Velocity's production default both use a 5-second handshake
deadline. This observed client work exceeds that deadline.

Source inspection found an attribution error: the old `policy_ms` counter
started before `new ClientHandshakeEngine`, so it included session key generation
and engine initialization. It did not isolate policy verification or cache I/O.
Do not interpret the 6328 ms value as policy verification alone.

The development-worktree diagnostic now separates `engine_ms` from `policy_ms`.
Its first real rerun passed without changing deadlines or product code:

- Run: `velocity-folia-2026-09-08T12-40-29-467420800Z`.
- Frozen Folia 1.21.11 build 14 and Velocity 3.5.1-615.
- Authentication result, backend admission and context shadow audit observed.
- Three tests, zero skipped, failures or errors; runtime case 110.139 seconds.
- No remaining owned processes and no report limitations.
- Report SHA-256: `20c665fcc052c89b7e608cd7e74c397fb466150abffa40a83cf5a4cab579f39c`.
- Log: `build/folia-engine-timing-20260908.log`.

This pass does not establish a fix or consistent reliability. That run still
only exported timings on failure, so it cannot establish successful timing
values. The harness now exports separate timing fields on both report paths;
the timing regression also checks the success-path snapshot. Product signatures,
cache persistence, replay protection and the 5-second deadline remain unchanged.

The second development-worktree rerun, with success-path timing enabled, also
passed (3 tests, zero skipped/failures/errors, runtime case 117.493 seconds):

- Run: `velocity-folia-2026-09-08T12-44-52-645300800Z`.
- Authentication total: 540 ms; engine initialization: 95 ms; policy preparation:
  304 ms; authentication frame preparation: 57 ms. Total also includes sending
  and the fixture's inter-frame delay, so component values need not sum to total.
- Authentication result, backend admission and context shadow audit all true;
  limitations and remaining owned processes both empty.
- Report SHA-256: `926809cac370cf5bf1efa27382a2ce38f5ec921aba9c45526764fad47581680b`.
- Log: `build/folia-auth-timing-both-paths-20260908.log`.

Two diagnostic passes do not replace the exact-commit 12-case matrix or establish
the cause of the earlier latency spike. Both used the existing 5-second deadline.
The next failure will now distinguish engine initialization from policy work;
no production timeout change is justified by the attribution data collected so far.
