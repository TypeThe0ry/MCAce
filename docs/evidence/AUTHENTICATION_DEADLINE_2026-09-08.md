# Authentication completion deadline

The Folia cold-start investigation led to a review of pending admission and
deadline enforcement. This change addresses a server-side deadline boundary;
it does not resolve or reclassify the client-side latency measurements.

## Observed behavior and change

`ServerHandshakeCoordinator.receive` checked expiration before parsing and
verification. The final authentication method then granted VERIFIED without
checking whether processing had crossed the deadline. A deterministic clock
regression failed on the old implementation: expected LIMITED, observed VERIFIED.
The red result is retained locally at `build/handshake-deadline-red-20260908.xml`.

The coordinator now checks the same exclusive expiration boundary immediately
before authenticating. It uses the checked instant as the authentication time.
An expired request follows the existing timeout path: UNKNOWN/LIMITED, no success
frame, no authenticated session. Signature, replay, policy and manifest checks
remain in place. Direct, deferred and reassembled AUTH requests converge on this
final method. The configured timeout and its default are unchanged.

## Pending-state finding

Beginning a handshake publishes UNKNOWN/VERIFYING, not VERIFIED. The SDK's
verified predicate rejects that state. However, the Paper local session action
adapter does not itself isolate a VERIFYING carrier; the default monitor profile
is not a waiting-room guarantee. A longer deadline must not be described as
preserving enforced isolation without implementing and validating that behavior.

Do not solve the runtime failure by changing only the matrix fixture's timeout,
removing cache/signature checks, or treating installation as proof of a clean
client. Pending restrictions and cold-start latency remain follow-up work.

## Verification

- Red test before the fix: one executed, failed with expected LIMITED but actual
  VERIFIED. The clock advances during processing, without real sleeps or traffic
  timing assumptions.
- After the fix, full core and client-common suites exited 0 (4m 41s): core 285
  discovered / 8 skipped / 0 failures / 0 errors; client-common 103 discovered /
  3 skipped / 0 failures / 0 errors. Skips remain coverage gaps, not passes.
- Added a positive boundary test, then ran both boundary tests: 2 executed,
  0 skipped/failures/errors, exit 0 (19 seconds). Completion one millisecond before
  expiry remains accepted; completion at expiry remains UNKNOWN/LIMITED.
- Logs: `build/handshake-deadline-green-20260908.log` and
  `build/handshake-deadline-boundaries-20260908.log`.

This product change requires a fresh release candidate and current-source runtime
matrix. The previous f055c2c bundle and its partial matrix do not validate these
changed product bytes. No full runtime matrix, GUI, Vulcan or production authority
acceptance is claimed for this change.
