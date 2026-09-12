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

## Exact f055c2c matrix: slow policy preparation reproduced

Source and artifact source:
`f055c2c828f3817ecdac21e1d89b164d62e87949`. Its V4 release bundle was built
successfully (6 deployables, 8 entries) and the three-version compatibility
contract executed successfully. The preceding f6e8a48 bundle was copied to
`build/release-history/f6e8a48-before-f055c2c-20260908/release-bundle` with all
8 file hashes compared. Fleet inspection found the registered Helio offline
with stale telemetry, so this run used local cached dependencies, serially.

The exact-source strict matrix terminated with exit 1:

| Case | Result | Authentication work |
| --- | --- | --- |
| Paper 1.21.11 / Velocity | PASS, backend admission/context confirmed, no residue | 323 ms |
| Paper 1.21.11 / BungeeCord | PASS, checkpoint accepted, no residue | 218 ms |
| Folia 1.21.11 / Velocity | FAIL, SocketTimeoutException, no residue | 11926 ms |
| Remaining 9 cases | Not executed | Not measured |

Folia's separate counters show engine initialization 252 ms, policy preparation
11456 ms and frame preparation 142 ms. The peer reached PLAY, sent authentication
frames, but observed no AUTH_RESULT. The proxy logged the challenge at 21:03:13
UTC+08 and timeout to LIMITED at 21:03:19. This narrows the slow operation to
`prepareServerHello`, including signature checks, policy cache handling and class
loading; it does not yet identify the sub-operation responsible.

Failure report:
`build/runtime-player-probe/runs/velocity-folia-2026-09-08T13-01-03-573243600Z/report.json`.
SHA-256: `ff332ec779b2b2b3fde9252f72a2b0f47b33c9e713a731dc3b03cc472063b9bb`.
Matrix log: `build/matrix-f055c2c-20260908.log`.
No external receipt was requested/produced at the failed third case.

### Incremental performance diagnostic

A separate JFR-instrumented test JVM run passed without modifying product code
or the timeout: `velocity-folia-2026-09-08T13-05-44-652109900Z`.
Total authentication 432 ms; engine 29 ms; policy 300 ms; frame preparation 46 ms.
Report SHA-256: `2ab5de5c7151e7ce80202915ccb1016fcb648113b20552e8eb56009c0804586d`.
Log: `build/folia-policy-profile-f055c2c-20260908.log`.

The 87-second recording includes eight sampled stacks containing handshake/cache
code. Samples show class loading/JAR reads, method-handle generation and EdDSA
signing. They are samples from a successful run, not measured attribution of the
11456 ms failure. A strict-recompilation profile is the next useful comparison;
do not call class loading, antivirus or cache I/O the established root cause.

JFR is retained locally at `build/folia-policy-f055c2c.jfr`, SHA-256
`e4be57a2dbc50c835710c3805405b1148e78ae9de929e8fbbfd03e3ddcf0cba8`.
It contains machine/environment metadata and must not be committed or uploaded
without sanitization. Only this diagnostic summary is tracked.

## Strict-recompilation JFR comparison

At clean documentation descendant `a48430ed647382d511aa3691a5f8f374f42dbe4b`,
the same Folia case was run with rerun-tasks, strict dependency verification,
no build/configuration cache, no parallelism and one worker, with JFR enabled
only for the test JVM. Product code and the 5-second deadline were unchanged.

The failure reproduced: exit 1, 35 tasks executed, 3m 50s build duration.
Run `velocity-folia-2026-09-08T13-11-39-351123800Z` reached PLAY and sent AUTH,
but received no AUTH_RESULT. Counters: total 8539 ms, engine 80 ms, policy
6878 ms, frames 1464 ms. Owned process residue was empty.
Report SHA-256: `82485404b4a15a3a3a1b2cdc7cf1e1b664b06eeae1af1cd799073e661e565c4e`.
Log: `build/folia-policy-strict-profile-a48430e-20260908.log`.

The local JFR file `build/folia-policy-strict-a48430e.jfr` has SHA-256
`da67388a22811f0d174a688116ffb6694869f8b4ff282b5d6e28342a6bbd278b`.
It remains untracked because recording defaults include environment metadata.
Streaming inspection through the JDK RecordingFile API avoided expanding the
whole recording into a large PowerShell JSON object.

Confirmed observations in the 13:13:15–13:13:26 UTC window:

- Stacks containing handshake/cache code include class loading, JAR reads,
  decompression, cryptography and deoptimization. These are sampled observations,
  not additive wall-time measurements or proof that any one dominates.
- A handshake-associated JAR FileRead event lasted 163 ms.
- SafepointBegin events lasted 1103.9078 ms and 200.3007 ms; these are time to
  reach safepoints, not proof all application threads paused for the full interval.
- A GCPhasePause near the end lasted 18.3203 ms, not a multi-second GC pause.
- Machine CPU samples were approximately 45–59%; aggregate CPU does not establish
  individual-thread scheduling availability or exclude contention.

A read-only D-volume check reported Healthy/OK and the selected recent System
event query returned no disk-class errors. This is not an exhaustive hardware
health or latency test. No antivirus exclusions, power settings, priorities,
credentials, user processes or production timeout settings were changed.

Next: examine the authentication-pending admission state and deadline design
alongside cold-start work. A deadline change must preserve unverified-client
restrictions and bounded resource use; a fixture-only timeout increase or
verification/cache bypass is not a demonstrated product fix.
