# Project storage migration

The MCAce working tree was moved from the original controller path to the
dedicated D: volume before the original source directory was removed.

| Item | Verified value |
| --- | --- |
| Working tree | `D:\Projects\MCAce` |
| Original source | `C:\Users\admin\MCAce` (absent after migration) |
| Initial copy | `26,199` files / `18,951,743,988` bytes |
| Copy verification | RoboCopy `/E /L` dry-run reported `0` action lines |
| Git branch | `feature/active-pack-integrity` |
| Git HEAD at deletion | `a43591a50a5e62c6486f030520055b8536e350ea` |
| Deletion scope | Only the original `C:\Users\admin\MCAce` directory |

The controller-side evidence is retained outside the repository:

- `D:\Projects\MCAce-migration.log`
- `D:\Projects\MCAce-migration-verify.log`
- `D:\Projects\MCAce-migration-manifest.json`

The manifest records `source_exists=false`, `destination_exists=true`, and an
empty Git status at the time of deletion. Later build outputs may increase the
destination file count; that is expected and does not invalidate the initial
copy record. No other C: data was deleted or modified by this migration.

To re-check the current state without changing either volume:

```powershell
Test-Path -LiteralPath 'C:\Users\admin\MCAce'   # expected: False
Test-Path -LiteralPath 'D:\Projects\MCAce'      # expected: True
git -C 'D:\Projects\MCAce' status --short --branch
Get-Content -Raw 'D:\Projects\MCAce-migration-manifest.json'
```
