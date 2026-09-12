# Current release material audit — 2026-09-08

Audited clean source: `1c9312e1b5c4fb6a1d23bc37b0a144e9b2799655`.
Canonical checkout: `D:\Projects\MCAce`.

## Readiness result

`pwsh -NoProfile -File scripts/release-readiness.ps1` exited 1 with
`release_ready=false`. Six gates failed; only `clean_worktree` passed.
Local report SHA-256:
`d16ffe7e1ca81c35889d8a8143f6e6752699f2b697bf44e61b87b75354b1ba33`.
The report is under `build/release-readiness/report.json` and can be overwritten.

| Gate | Current evidence |
| --- | --- |
| Matrix exact source | Tracked indexes rejected by the current V4 validator; no current accepted package |
| Visible GUI enablement | Current-source attempt rendered the prompt but timed out without acceptance |
| Federation handoff | Tracked historical index rejected; no accepted current V5 set |
| Vulcan genuine event | Required externally signed V3 package missing |
| Production authority | Required V4 index and complete signed raw package missing |
| Protected exact bundle | Local run is not protected main/tag CI; current-source bundle acceptance missing |
| Clean worktree | Passed at audited commit |

The default local invocation did not import GitHub release-environment pins.
This does not imply those pins are absent from GitHub: the separate read-only
comparison below confirmed them. No environment variables or GitHub settings
were changed to manufacture a passing context.

## Existing trust material is present and matches GitHub

The GitHub `release` environment exists. Its five relevant SHA-256 variables
were compared with files in `D:\MCAceReleaseAuthority\public`; all match:

- Matrix V4 trust root.
- Federation visible-GUI trust root.
- Federation post-run trust root.
- Vulcan V3 trust root.
- Production Authority V4 supervisor public descriptor.

Corresponding public-root secret names are also configured in that environment;
secret values were neither retrieved nor printed. Matching public files/pins is
not a signed runtime receipt, human consent, genuine anti-cheat event, or current
release evidence. There is no need to regenerate trust roots merely because
the local shell lacks imported process/user/machine pin variables.

## Bundle and provider status

The existing `build/release-bundle/release-manifest.properties` declares:

```text
source_commit=885e98dc4b0672147057955b5423b3bb3f7c0165
artifact_source_commit=81d5d09aabf73e5e63e0e83b4b072958336ed43e
```

It therefore cannot establish release eligibility for the audited current
source. Preserve it as historical evidence; prepare and verify a new exact-source
candidate before collecting new source-bound release receipts. Do not merely
rewrite its manifest or retain an old artifact-source marker across code changes.

The previously recorded Vulcan 2.9.0 location
`D:\.archive\GalaSRV\.Ellan-1.21-PurPur\plugins\Vulcan-2.9.0.jar`
was checked and is still absent. This check does not prove that no licensed copy
exists anywhere else. No download, license bypass, or synthetic provider callback
was attempted.

## Next execution order

1. Build a new exact-source release candidate, preserving the old bundle.
2. Validate its six deployable JARs and compatibility bindings.
3. Run candidate-bound server/process checks using the already pinned supervisor
   configuration, not newly invented trust material.
4. Complete a real visible human enablement and client inventory/handoff run
   when the user is present; do not repeat unattended consent-timeout loops.
5. Supply the actual licensed Vulcan input and collect genuine provider/production
   evidence. Fixtures do not substitute for these events.
6. Complete protected exact main/tag CI and final evidence/README publication.

No tag, merge, or release was performed by this audit. Earlier successful branch
CI is not protected current-release acceptance. The goal remains incomplete.
