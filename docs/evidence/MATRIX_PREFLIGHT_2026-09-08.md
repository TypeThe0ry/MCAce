# Matrix execution input preflight

The V4 matrix previously validated its release bundle and external supervisor
inputs inside final evidence assembly, after the product build and all twelve
process cases. An invalid source-bound bundle or missing trust material could
therefore waste a complete runtime run.

`Assert-MatrixExecutionInputs` now calls the existing bundle, trust-root and
out-of-band exchange-directory validators before execution-directory creation,
lock acquisition, checkpoint clearing, building or process startup. It also
rejects a supervisor public root inside the exchange directory. Existing final
evidence checks remain unchanged; preflight is not proof of a live supervisor
or a future valid signature.

Verification: `scripts/test-server-version-process-matrix.ps1` passed under
PowerShell Core and Windows PowerShell on 2026-09-08. Added dependency-double
tests exercise the actual function with valid inputs, bundle rejection, trust
rejection, exchange rejection and overlapping paths; call-order assertions
verify fail-fast behavior. A top-level ordering assertion places preflight
before execution mutations. `git diff --check` passed.

No server or GUI was started for these regression tests. This change is test
orchestration only, not a new anti-cheat capability or a passed release matrix.
The earlier candidate remains bound to `5fc94a4`; because the matrix script
changed, current-source release evidence must use a freshly bound candidate,
not a manually edited manifest or a relabeled historical report.
