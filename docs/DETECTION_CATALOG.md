# Public-market detection catalog

Status: research catalog, not an allowlist or a malware verdict.

## Publishing a catalog safely

`examples/disposition-catalog.textproto` uses the current `catalog_entries` and
`catalog_selections` schema. An entry is inert unless a matching selection sets
`enabled: true` and an explicit `final_action`; `default_enabled` is metadata, not
authorization. Use the publisher workflow: `preview` first, then `validate` and
`list` the selected entries, and only then `publish`. The Bungee command is
`/mcace disposition publish` (permission `mcace.admin.policy`); `/mcace disposition`
is read-only. Equivalent Velocity operations must follow the same preview/validate/
list/publish order.

Non-exact selectors may not exceed `WARN`. `QUARANTINE` can require an independently
reviewed exact SHA-256 or content-root selector and human review; connection `DENY`
requires an independently reviewed exact SHA-256 selector. Content roots identify a
bounded package manifest, not one independently verified artifact.
Client-reported IDs, versions, signers, and metadata are not unique evidence. MCAce
has no automatic permanent BAN action. Manual exact-player `ALLOW` exceptions remain
available for reviewed, time-bounded cases.

Retrieval date for the upstream sources below: **2026-08-09**. The catalog uses
only public upstream GitHub repositories and their checked-in manifests/README
files. No cheat binary was downloaded or executed, and no private player data was
used.

## Machine-readable starter catalog

The distributable [`disposition-catalog.textproto`](../examples/disposition-catalog.textproto)
contains only three upstream Fabric manifest identities: `wurst`, `liquidbounce`,
and `meteor-client`. Each is a `MOD_ID_VERSION`, `LOW`-confidence, `OBSERVE`
suggestion that additionally requires client-reported `loaded=true`, with
`default_enabled: false` and a matching disabled selection. Consequently, a dormant
JAR that is merely present in `mods/` does not match these starter identities. It
contains no artifact hash, content-root, binary, Baritone, or Freecam identity.
An administrator must make a separate, reviewed selection before any catalog rule
can be published. Its provenance is pinned to the official manifest revisions
`64dfabaea5fa0afa4e33bc38997917c4c0c17cce` (Wurst),
`97bf05cc272f397fe5b7a7a6abe00130460e84d0` (LiquidBounce), and
`9ffe8e4d6dcaa2d2a73c7fc09e37054f0a9dff7c` (Meteor), retrieved 2026-08-09.
Those revisions confirm public project identity only; no artifact binary or hash
has been reviewed. The starter records an HTTPS `raw.githubusercontent.com` URI,
full revision, manifest path, and retrieval instant (`1786204800000`, which is
2026-08-09 00:00 Asia/Singapore) for each entry. These fields are provenance for
an identity match, not evidence that an artifact at that URL was obtained or
reviewed.

## Offline and explicit live provenance review

Before selecting an entry, operators can validate its structured provenance without
changing the catalog, enabling a policy, or contacting any player:

```powershell
.\scripts\verify-catalog-provenance.ps1
```

This default mode is offline. It reads at most 1 MiB of textproto and at most 512
entries. Each reviewed entry must be a Fabric `MOD_ID_VERSION` selector with a
complete, HTTPS, query-free provenance tuple. The URI must be a
revision-pinned `raw.githubusercontent.com` path matching both
`source_revision` and `source_manifest_path`. Its JSON report is written to stdout
and contains only the entry ID, selector ID, sanitized origin/path, revision,
retrieval instant, status, and an error code—never manifest content, query strings,
local paths, or secrets.

An explicit operator-initiated network check is available with `-Live`:

```powershell
.\scripts\verify-catalog-provenance.ps1 -Live -TimeoutSeconds 10
```

Live mode permits only HTTPS `raw.githubusercontent.com` manifest requests. It
disables proxy use and redirects, reads no more than 256 KiB of text/JSON in memory,
does not save the response, and verifies that the declared Fabric manifest ID equals
the selector `artifact_id`. It never downloads a JAR/ZIP/executable, executes remote
content, edits the catalog, enables a rule, or produces a player disposition. A
failed network check is an operator review failure, not player evidence and never a
punishment signal. Repository manifest templates containing a build placeholder are
accepted only when exactly one quoted, valid Fabric `id` field can be extracted;
they are never evaluated.

Run the isolated parser and starter-catalog checks with:

```powershell
.\scripts\test-catalog-provenance.ps1
```

The test intentionally does not invoke `-Live`; source availability remains an
operator-owned opt-in check rather than a flaky build dependency.

## Safety boundary

This catalog separates three different claims:

1. **Project identity:** an upstream project publicly describes a client, mod, bot,
   camera tool, renderer, shader loader, overlay, or controller utility.
2. **Observed installation/runtime load:** the resolved client separately reports
   bounded installed-file identity and the `FabricLoader.getAllMods()` runtime
   graph. Direct `mods/` origins may be bound to a basename/size/SHA-256 tuple;
   nested origins expose only a parent Mod ID, a non-direct `PATH` origin is
   classified as `UNKNOWN`, and built-in/classpath or unknown origins expose no
   path. Default proxy policy requires the signed loaded-graph capability, but the
   entire claim remains client-controlled.
3. **Confirmed security finding:** the server independently verifies bytes and/or
   authoritative behavior, correlates the result with the authenticated session,
   and obtains the required human review.

A project name, mod ID, filename, version, `loaded=true`, or client-reported
manifest is not a confirmed malicious hash. A client can remove, rename, forge, or
selectively omit its report. Name/ID/version/load-state matches in this catalog
therefore recommend at most
`OBSERVE`, `NOTICE`, or a narrowly scoped `WARN`; they must never directly produce
`DENY`, `QUARANTINE`, or a ban. `DENY` is still current-connection-only in MCAce,
and requires an independently verified, exact artifact finding under the signed
policy and operator gates.

The exact Fabric target check (`1.21.11`, `26.1.2`, or `26.2`) is an input, not a
conclusion. The server must compare the resolved `fabric.mod.json` Minecraft and
loader constraints with the actual server-approved version. An upstream branch
moving to another Minecraft release is a compatibility mismatch, not evidence of
cheating.

## Evidence ladder and signal handling

| Signal | Minimum collection rule | Trust and use |
| --- | --- | --- |
| Installed Mod ID / version | Parse bounded `fabric.mod.json` from the policy-scoped installed manifest; retain exact resolved values and Minecraft/loader constraints. | `CLIENT_REPORTED`; installed identity only. A dormant JAR is not a runtime-loaded Mod. |
| Loaded ModList identity | Enumerate at most 256 entries from `FabricLoader.getAllMods()`; canonicalize unique ID/version/origin tuples; bind a direct `mods/` origin to the exact installed manifest entry; classify every other `PATH` origin as `UNKNOWN`; omit local paths for nested/built-in/classpath/unknown origins; require the signed loaded-graph capability and one-to-one installed-scope binding. | `CLIENT_REPORTED`; `loaded=true` may narrow an identity selector to the runtime graph, but still permits only advisory handling without independent evidence. |
| Jar SHA-256 | Hash the exact received jar bytes on the trusted collection path; bind hash to player, session, path, and capture time. A direct loaded-origin hash is an on-disk scan-time binding, not proof of the bytes already defined in the JVM. | Strong artifact identity only. A hash is “confirmed malicious” only when it is independently reviewed and the policy names that exact hash. |
| Content root | Canonicalize the approved manifest/file set, record the root and file-count/size bounds, and verify the signed policy binding. | Detects changed content or a missing file; it does not prove intent. |
| Signature / signer | Record the JAR signature chain or signer metadata only when present and independently parsed. | Missing or unknown signer is not automatically malicious; compare to an approved signer set. |
| Configuration | Hash or record bounded config keys and enabled modules, with path containment and version binding. | Useful corroboration; configuration is client-controlled and may be absent or forged. Do not collect unrelated files. |
| Server behavior | Use authoritative movement, block interaction, reach, visibility, rate, inventory, and state-transition telemetry. | `SERVER_CONFIRMED` or `INFERRED` only after deterministic validation and longitudinal correlation. |
| Human review | Preserve rule ID, policy version, evidence IDs, operator reason, false-positive notes, and appeal state. | Required before any high-impact disposition; never infer review from a client claim. |

For all rows, pair client integrity with server authority and behavior adapters such
as the typed Grim integration or the optional Vulcan bridge. The upstream projects
below document capabilities; they do not prove that a particular player used them.

## High-risk public categories

### 1. Explicit hacked clients / cheat clients

| Upstream identity | Official capability evidence | Expected observables | False-positive risk | Default action and review |
| --- | --- | --- | --- | --- |
| [Wurst Client v7](https://github.com/Wurst-Imperium/Wurst7), manifest ID `wurst` ([manifest](https://raw.githubusercontent.com/Wurst-Imperium/Wurst7/master/src/main/resources/fabric.mod.json)) | The upstream README calls it a Minecraft hacked client and the manifest declares a client Fabric mod with mixins/access widener. | ID/version, Minecraft constraint, exact jar SHA, content root, mixin/access-widener presence, bounded config/module state, and server behavior. | A name/ID hit can be a renamed build, an approved test installation, or an outdated branch; current upstream version drift must be checked separately. | `OBSERVE` by ID/version; `NOTICE` only when server rules prohibit the category. Require exact reviewed SHA plus behavior correlation and manual review before stronger action. |
| [LiquidBounce](https://github.com/CCBlueX/LiquidBounce), manifest ID `liquidbounce` ([manifest](https://raw.githubusercontent.com/CCBlueX/LiquidBounce/nextgen/src/main/resources/fabric.mod.json)) | The upstream README describes a free mixin-based injection hacked client for Fabric. | Same artifact ladder; additionally record mixin/access-widener metadata and the exact Minecraft/loader dependency resolution. | Public source identity does not establish the loaded build, enabled feature, or player intent; branch/version mismatch can be benign. | `OBSERVE` or `NOTICE`; never `DENY` from the ID. Require independently verified bytes and server-side behavior review. |
| [Meteor Client](https://github.com/MeteorDevelopment/meteor-client), manifest ID `meteor-client` ([manifest](https://raw.githubusercontent.com/MeteorDevelopment/meteor-client/master/src/main/resources/fabric.mod.json)) | The upstream project calls itself a utility mod; its manifest shows client entrypoints, mixins, access widening, and integrations. Treat it as a high-risk utility-client category for review, not as a verdict. | ID/version, build/commit metadata when available, exact SHA/content root, enabled config, mixin set, and server behavior. | “Utility mod” includes harmless modules; some users may run it in a permitted test environment. | `OBSERVE` by identity, optional `NOTICE` under server policy. Only an exact reviewed artifact plus behavior can justify `LIMITED_ROUTE`/`QUARANTINE`; no automatic ban. |

The three rows above are public project identities, not a list of confirmed
malicious hashes. The catalog intentionally contains no real cheat hash.

### 2. X-Ray, ore highlighting, and transparent-render content

| Upstream identity | Official capability evidence | Expected observables | False-positive risk | Default action and review |
| --- | --- | --- | --- | --- |
| [Advanced XRay](https://github.com/AdvancedXRay/XRay-Mod), Fabric manifest ID `xray` ([manifest](https://raw.githubusercontent.com/AdvancedXRay/XRay-Mod/main/fabric/src/main/resources/fabric.mod.json)) | The README explicitly describes an XRay mod and a configurable block-selection UI; the manifest declares client mixins. Its manifest range still does not prove byte or behavior compatibility with any MCAce target; resolve and review the exact 1.21.11/26.1.2/26.2 artifact independently. | ID/version, exact SHA/content root, block-list/config JSON, mixins, render changes, and server mining/visibility behavior. | Another upstream project can legitimately use the same ID `xray`; custom contrast/visibility packs and shader interactions can look similar. | `NOTICE` or `OBSERVE` on identity/config only. Use exact content root plus server-authoritative ore/mining correlation and manual review. |
| [ate47/Xray](https://github.com/ate47/Xray/tree/fabric-1.21.4), manifest ID `xray` ([manifest](https://raw.githubusercontent.com/ate47/Xray/fabric-1.21.4/src/main/resources/fabric.mod.json)) | The official README describes Xray, entity tracers, ESP, fullbright, and a Fabric 1.21.4 branch; the manifest declares ID `xray` and `minecraft >=1.21`. | Preserve repository/branch provenance, resolved version, exact SHA/content root, config/templates, mixins, and behavior telemetry. | Same-ID collision is a concrete reason not to match on ID alone. Different versions and forks can have materially different behavior. | `NOTICE`/`OBSERVE` only for the identity. Do not deny from `xray` alone. |
| Generic ore-highlight resource pack or shader | A resource pack has no Fabric mod ID; the observable is the bounded pack root (`pack.mcmeta`, texture/model files, and canonical content root). | Exact ZIP/content root, pack metadata, changed `assets/minecraft` paths, transparent/contrast textures, selected-pack state, shader ID/version, and server mining/visibility behavior. | Legitimate accessibility, color-blind, high-contrast, performance, or aesthetic packs can change textures and visibility. Resource-pack names are especially weak identifiers. | `OBSERVE`; at most `NOTICE` for a name/config pattern. Require exact content root, reproducible visual review, and server behavior before any restricted route. |

An X-Ray-like render signal is not the same as proof that hidden blocks were
actually used. Keep the `CLIENT_REPORTED` render/config observation separate from
server-side ore exposure, mining path, and interaction telemetry.

### 3. Baritone and automation/pathfinding

| Upstream identity | Official capability evidence | Expected observables | False-positive risk | Default action and review |
| --- | --- | --- | --- | --- |
| [Baritone](https://github.com/cabaletta/baritone), expected manifest ID `baritone` (verify from the resolved artifact) | The official README calls it a Minecraft pathfinder bot, documents Fabric 1.21.1 builds, and documents pathing/mining commands. | ID/version, exact SHA/content root, settings file, command/module state, input timing, rotations, path-following, block interactions, and server-side movement/mining invariants. | Pathfinding can be permitted for building, accessibility, testing, or event staff. Human players and controller users can produce regular paths; a settings file is not a behavior proof. | `NOTICE` in prohibited survival modes, otherwise `OBSERVE`. Provide an exact, reviewed per-player `ALLOW` exception for approved use. Use Grim/Vulcan or equivalent behavior correlation before restriction. |

The relevant behavior hypotheses are path-following with low reaction variance,
continuous target-directed movement, automated block interaction, and mining rates
that violate server state or human review expectations. These are hypotheses that
need longitudinal samples, not single-tick rules.

### 4. Freecam and camera separation

| Upstream identity | Official capability evidence | Expected observables | False-positive risk | Default action and review |
| --- | --- | --- | --- | --- |
| [Freecam](https://github.com/MinecraftFreecam/Freecam), expected manifest ID `freecam` (verify from the resolved artifact) | The official README says the camera can be controlled separately from the player, can travel through blocks within render distance, works in multiplayer, and may be considered cheating on some servers. | ID/version, exact SHA/content root, camera/config state if client-reported, framebuffer/evidence scope, and authoritative player movement/interactions while camera diverges. | Freecam may be used for building inspection, recording, moderation, or accessibility. Camera movement alone is not player movement. | `OBSERVE` or `NOTICE` under explicit server rules. Never deny from the ID; require server-authoritative interaction/movement evidence and manual review. |

Freecam is also a useful test of trust boundaries: a server must not infer player
position, block interaction, or visibility from a camera-only observation.

## Normal, accessibility, and utility controls

These rows are deliberately included as false-positive controls. Their presence
should be represented by explicit `ALLOW` or `OBSERVE` rules for approved exact
versions, not by a blanket claim that every future build is safe.

| Upstream identity | Official capability evidence | Expected observables | False-positive risk | Default action and review |
| --- | --- | --- | --- | --- |
| [Sodium](https://github.com/CaffeineMC/sodium), manifest ID `sodium` (resolve the branch-specific manifest) | The official README describes a rendering engine replacement and optimization mod for frame rate/micro-stutter. | ID/version, exact SHA/content root, renderer/mixin metadata, graphics config, and crash/performance telemetry. | Renderer compatibility or a custom shader may alter visuals without altering gameplay. | Explicit `ALLOW` for approved exact builds; otherwise `OBSERVE`. |
| [Iris](https://github.com/IrisShaders/Iris), manifest ID `iris` ([1.21.1 manifest](https://raw.githubusercontent.com/IrisShaders/Iris/1.21.1/fabric/src/main/resources/fabric.mod.json)) | The official README describes an open-source shader mod; the 1.21.1 manifest binds ID `iris` to Minecraft 1.21.1 and Sodium compatibility. | ID/version, exact SHA/content root, shader-pack root and metadata, renderer/mixin state, and server behavior. | Shader packs and render pipelines can make visibility look unusual; they are not automatically X-Ray. | Explicit `ALLOW`/`OBSERVE`; review only when exact content or server behavior independently indicates risk. |
| [Jade](https://github.com/Snownee/Jade), manifest ID `jade` ([manifest](https://raw.githubusercontent.com/Snownee/Jade/26.3-fabric/src/main/resources/fabric.mod.json)) | The official README describes a UI improvement mod that shows information about what the player is looking at; the manifest includes an accessibility plugin. | ID/version, exact SHA/content root, addon/config state, and server-side data exposure/interaction behavior. | Information overlays can be used for ordinary gameplay, debugging, or accessibility. | Explicit `ALLOW`/`OBSERVE`; no action from overlay identity. |
| [MidnightControls](https://github.com/TeamMidnightDust/MidnightControls), manifest ID `midnightcontrols` ([manifest](https://raw.githubusercontent.com/TeamMidnightDust/MidnightControls/multiversion/src/main/resources/fabric.mod.json)) | The official README describes controller and touchscreen support, enhanced controls, and accessibility-related use; the manifest declares client controls and input bindings. | ID/version, exact SHA/content root, controller mappings, keybind/config state, and input-device telemetry. | Controller, touchscreen, remapped keys, and assistive input can change timing and movement distributions without automation. | Explicit `ALLOW`/`OBSERVE`; behavior rules must account for input device and accessibility context. |
| Vanilla accessibility settings / approved accessibility packs | No mod ID is required; use the signed `options.txt`/resource-pack manifest and the server's approved accessibility profile. | Bounded option keys, selected pack content root, input device, and consented profile metadata. | Accessibility settings can affect camera, subtitles, text scale, controls, and timing. | `ALLOW`/`OBSERVE`; never penalize a setting by itself. |

## Correlation and escalation rules

1. Start with the signed client manifest and exact content identity. Keep each
   observation tagged `CLIENT_REPORTED` unless the server independently verifies it.
2. Prefer `OBSERVE` for unknown, missing, incompatible, or client-only signals.
   Use `NOTICE`/`WARN` for a clear rule reminder, never as a disguised ban.
3. Require server-authoritative behavior and a stable sample window before
   `LIMITED_ROUTE` or `QUARANTINE`. Use typed Grim behavior evidence and the
   optional Vulcan bridge where licensed and configured; neither adapter should
   silently convert a client report into a confirmed fact.
4. Require exact SHA-256 verification, a signed policy rule, operator reason, and
   appeal/reversal handling before a current-connection `DENY`.
5. A declined, unavailable, stale, or tampered client report is a missing or
   unreliable observation. It must not itself create risk or punishment.

The catalog intentionally does not define a permanent ban action, does not include
real malicious hashes, and does not prescribe bypass-resistant client collection.
It is a review aid for the existing signed disposition schema and server-authority
pipeline.
