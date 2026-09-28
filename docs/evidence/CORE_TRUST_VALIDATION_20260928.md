# Core trust-boundary validation — 2026-09-28

This record captures a current-source validation of the MCAce core trust path.
It is separate from the extended GUI, Federation V5, licensed Vulcan, and
Production Authority gates.

## Source and runtime

| Field | Value |
| --- | --- |
| Repository | `D:\Projects\MCAce` |
| Branch | `main` |
| Source commit | `5e4ffab1a5ccb5fac606ce1d3605b127438bec37` |
| Java 21 | `D:\MCAceTools\jdk\jdk-21` |
| Gradle | `9.6.1` |
| Validation date | 2026-09-28 (Asia/Singapore) |

## Executable anti-cheat fixture

Command:

```powershell
.\scripts\anticheat-live-fixture-smoke.ps1 -Execute `
  -JavaHome 'D:\MCAceTools\jdk\jdk-21'
```

Result:

```text
ANTICHEAT_LIVE_FIXTURE_EXECUTE_PASS
versions=1.21.11,26.1.2,26.2
client_executable_code_loaded=true
client_modlist_reported=true
server_behavior_signal_independent=true
correlated_same_session=true
server_confirmed_count=3
clean_false_positive_count=0
server_confirmed_action=QUARANTINE
```

The sanitized report is retained at:

`build/anticheat-live-fixtures/evidence-runs/20260927T234600569Z/report.json`

Report SHA-256:

`6134742ac6058c58ca3cfda23e2d02bbf9ee91dd0817664df91a8bff9cbcb8ba`

The fixture proves that the executable MCAce-owned client/server harness can
load client code, report a ModList, correlate an independent server signal on
the same session, and produce the signed lab `SERVER_CONFIRMED / QUARANTINE`
state for all three targets. The clean control produced no confirmed event.

## Whole-repository test

Command:

```powershell
.\gradlew.bat test `
  --no-daemon --no-parallel --max-workers=1 `
  --no-configuration-cache --console=plain
```

Result: `BUILD SUCCESSFUL` in `11m 35s` (`71 actionable tasks: 30 executed,
41 up-to-date`). The online dependency resolution populated the missing Fabric
compile artifacts that made the earlier offline attempt fail before compiling
the client module. No test failure or error was observed. Platform/GUI process
tests that are intentionally gated by their runtime properties remained
skipped according to their existing contracts.

## Boundary

This is executable loopback evidence, not a public-server or third-party-cheat
claim. It does not prove kernel/DMA/debugger coverage, arbitrary external
process detection, GUI consent, Federation V5 handoff, a licensed Vulcan event,
or production `SERVER_CONFIRMED` authority. The released action ceiling remains
`MONITOR`; the fixture's `QUARANTINE` is signed-lab, current-connection-scoped
evidence only.
