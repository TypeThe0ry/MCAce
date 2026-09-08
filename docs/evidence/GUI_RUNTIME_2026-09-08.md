# Native Fabric runtime check — 2026-09-08

This is a diagnostic record, not a Federation V5 release attestation.

## Source and environment

- Checkout: `D:\Projects\MCAce`
- Tested source: `6baa7652d97ee70112403fd92213423b3ae7e45a`
- Artifact source: `2a6274a9200f2aa195e1238eaddf43650f549a0a`
- Fabric target: `26.2`, Java 25; root dependency staging: Java 21.
- Client JAR SHA-256: `0680a528c38d9f456363488e80ea390615b5ba289714790583a434e2c95b0fe9`
- Isolated run: `build/fabric-federation-gui-handoff/evidence-runs/20260908T013959279Z-26_2-VELOCITY-to-VELOCITY-1371f0ca92a474cf699f93ea6537c188`
- Source endpoint: `127.0.0.1:62737`; separate source/target Velocity and Paper processes.

GitHub push run 34142961977 and PR run 34142964242 both completed successfully
for the tested source. PR 17 remained open and draft. The existing readiness
report for this source passes the Matrix gate and remains release-blocked.

## Native GUI and runtime results

The Windows `@oai/sky` API successfully listed and captured the independent
Fabric window (window ID 34211558, application `D:\MCAceTools\jdk\jdk-25\bin\java.exe`).
The previous browser-only `apps=[]` observation is not a current limitation of
the native Windows API. The existing Ellan.TOP user client was left running.

At 09:45:19 local time, the client logged the signed-policy enablement request
and visible screen render. The operator-authorized Computer Use interaction
clicked **Enable MCAce** once at 09:47:04. At 09:47:05:

```text
CLIENT: MCAce explicit-file manifest prepared entries=1
CLIENT: MCAce answered signed policy phase2-v3 sequence 2 with 4 scoped manifests
CLIENT: MCAce session verified at trust level VERIFIED with risk score 0
VELOCITY: MCAce verified Player536 at trust=VERIFIED risk=0
VELOCITY: observations=53 actions={OBSERVE=53} advisoryBlocks=0 policyVersion=bootstrap-1 issues=0 status=ACTIVE truncated=false
VELOCITY: action=OBSERVE result=NO_VALID_POLICY authorization=none session-bound=true execution-context-bound=false
PAPER: admission=VERIFIED, trust=VERIFIED, risk=0
```

These excerpts are from the run's `fabric-client/logs/latest.log`,
`source-proxy/logs/latest.log`, and `source-paper/logs/latest.log`. They verify
the authenticated manifest upload, proxy observations and signed backend
admission synchronization. The aggregate count alone does not enumerate the
individual loaded mod IDs. No cheat mod or Xray pack was loaded in this run;
this run does not prove their detection or any kick/ban effect.

![Native Fabric window immediately after the Enable MCAce click](gui-runtime-20260908-enabled.png)

The screenshot is the actual post-click Computer Use observation. It shows
the game view after the consent screen closed; the log excerpts above provide
the authentication evidence.

## Findings and remaining work

The disclosure text extends below the viewport at both default and maximized
window sizes. Mouse scrolling successfully reveals the remaining paragraphs;
the initial impression of unreachable text was corrected by live scrolling.
A visible scroll affordance would make this clearer.

The release GUI signer requires `prompt_challenge_visible=true`. No challenge
value was visible in the inspected prompt, including its scrolled end. The
runner creates its GUI nonce in PowerShell, while the inspected enablement
paragraph renderer contains no matching challenge display. This needs a
source-to-render binding review before signing a release attestation. No such
assertion or signed attestation was produced in this diagnostic run.

The wrapper ended with exit code 1 and
`FABRIC_FEDERATION_GUI_EXTERNAL_SCREENSHOT_NOT_CREATED_IN_VISIBLE_WINDOW`.
The capture was kept as diagnostic output rather than submitted to the
release-signing exchange. The wrapper forcibly stopped its test client after
a graceful shutdown timeout and removed its failed run directory, including
the original logs and pre-click diagnostic capture. The log excerpts in this
record were read before cleanup; they are not a retained raw evidence package.
A final process inventory contained only the pre-existing user Java processes
44064 and 23900. The post-click image above was saved from the already observed
Computer Use result after cleanup.

Federation handoff, licensed Vulcan genuine callback, production authority
evidence and protected main/tag release CI remain pending. The final README
evidence edition and v0.0.1 publication remain gated on those results.
