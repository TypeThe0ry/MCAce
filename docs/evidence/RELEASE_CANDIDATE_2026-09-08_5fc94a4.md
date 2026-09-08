# Current-source candidate build (not a published release)

Built on the local Windows controller from clean commit
`5fc94a4aaa1ee632579eab31b9a6924fba1f61ee`. Both source and artifact-source
identities bind to that commit. No product code was changed in this run.

ClusterYourCodex controller health was OK, but its only registered worker,
Helio, was offline with stale telemetry. The last reported disk availability
was 1251 MiB, not a current free-space measurement. No remote build was started.
The local fallback used one Gradle worker and the existing offline cache.

## Build and verification

`releaseBundle` exited 0: BUILD SUCCESSFUL in 1m 58s, 37 root tasks
(17 executed, 20 up-to-date). The nested modern build executed 15 tasks,
including tests for 26.1.2 and 26.2. This was not a full root test-suite rerun.
Gradle reported deprecated features incompatible with Gradle 10.

Toolchain: JDK 21.0.12.1, modern JDK 25.0.4.1, Gradle 9.6.1.
Bundle schema V4, product version 0.0.1, six deployable JARs, eight entries.
`version-compatibility-contract-smoke.ps1 -Execute` with both expected commit
arguments set to the source above returned `MCACE_VERSION_COMPATIBILITY_EXECUTE_PASS`.

Local outputs:

- `build/release-bundle/`
- `build/release-candidate-5fc94a4-20260908.log`
- `build/compatibility-contract/report.json`
- Previous bundle preserved in
  `build/release-history/885e98d-before-5fc94a4-20260908/release-bundle/`;
  all eight copied files were hash-compared before building.

## SHA-256

```text
e9db113de5ef609ad13a8c9af7586160c088311dd8946bcec5e77b62613a6274  mcace-client-fabric-1.21.11.jar
c57ea0cd9210f271f4610107e7228a2c598b267cec86e2a7ad6ea6deab728791  mcace-client-fabric-26.1.2.jar
9438a0eb95efb2bbe14829944c82974ead3d1436e8228cb6f9973ebf82e8e8f8  mcace-client-fabric-26.2.jar
cb7f0ffc1c2dfcb502c0a8e14ec8b67d70b05885aca88ca1571a09b1380fbe33  mcace-server-velocity.jar
f05bc5097989e589d738756a488371de31e03cb213fe7ee855cc97ffcf2b6210  mcace-server-bungeecord.jar
1e341fc72b973e48f49a828ef600aa986671a406f691ec3688978d79948aa2c0  mcace-server-paper.jar
```

This clears the stale local candidate problem, not the external release gates.
No GUI consent, real inventory receipt, real cheat/Xray execution, federation
handoff, Vulcan callback, production disposition, protected main/tag CI, or
release publication was performed in this build. Continue with candidate-bound
runtime evidence; the remaining gate inventory is in
`RELEASE_AUDIT_2026-09-08_CURRENT.md`.
