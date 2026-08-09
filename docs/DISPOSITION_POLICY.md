# Detection/disposition policy authoring

MCAce creates an editable `disposition-policy.textproto` only when the file is
absent. This text file is administrator input, not an authority object. The
publish command validates it, assigns sequence/time/predecessor fields, compiles
it through the same runtime model, signs it with the existing proxy identity,
and atomically replaces the active binary policy.

## Locations and commands

| Proxy | Configuration | Publish | Status |
| --- | --- | --- | --- |
| Velocity | `plugins/<MCAce data>/policy/disposition-policy.textproto` | `/mcacepolicy publish` | `/mcacepolicy status` |
| BungeeCord | `plugins/<MCAce data>/disposition-policy.textproto` | `/mcace disposition publish` | `/mcace disposition` |

Publishing requires `mcace.admin.policy`. Bungee status and player checks use
`mcace.admin.check`. Back up the proxy identity, active signed policy,
textproto, and `history/` directory together.

## Example

```textproto
schema_version: 1
version: "network-2026-08-08.1"
rollout_stage: "OBSERVE"
validity_seconds: 86400

# Approved performance Mod, globally allowed at one exact version.
rules {
  rule {
    rule_id: "allow-sodium-0-6-5"
    priority: 100
    revision: 1
    selector {
      artifact_type: DETECTION_ARTIFACT_MOD
      match_type: DETECTION_MATCH_MOD_ID_VERSION
      artifact_id: "sodium"
      version_constraint: "0.6.5"
    }
    confidence: DETECTION_CONFIDENCE_HIGH
    default_action: DISPOSITION_ALLOW
    operator_reason: "Approved performance Mod"
  }
}

# Known pathfinding helper: warn only in survival gameplay.
rules {
  rule {
    rule_id: "warn-pathfinding-survival"
    priority: 200
    revision: 1
    selector {
      artifact_type: DETECTION_ARTIFACT_MOD
      match_type: DETECTION_MATCH_MOD_ID_VERSION
      artifact_id: "baritone"
    }
    scope {
      backend_ids: "survival"
      game_modes: "survival"
    }
    confidence: DETECTION_CONFIDENCE_HIGH
    default_action: DISPOSITION_WARN
    player_message_key: "mcace.mod.pathfinding.not_allowed"
    false_positive_notes: "Confirm that the hash belongs to the expected build"
    operator_reason: "Automation is not allowed in survival"
  }
}

# Reviewed X-ray resource-pack hash. Replace this example hash before publishing.
rules {
  rule {
    rule_id: "quarantine-known-xray-pack"
    priority: 300
    revision: 1
    selector {
      artifact_type: DETECTION_ARTIFACT_RESOURCE_PACK
      match_type: DETECTION_MATCH_EXACT_SHA256
    }
    confidence: DETECTION_CONFIDENCE_CONFIRMED
    default_action: DISPOSITION_QUARANTINE
    operator_reason: "Hash reviewed as an ore-visibility resource pack"
  }
  sha256_hex: "1111111111111111111111111111111111111111111111111111111111111111"
}

# Auditable per-player exception. exception=true requires player_ids and ALLOW.
rules {
  rule {
    rule_id: "event-staff-pathfinding-exception"
    priority: 1000
    revision: 1
    selector {
      artifact_type: DETECTION_ARTIFACT_MOD
      match_type: DETECTION_MATCH_MOD_ID_VERSION
      artifact_id: "baritone"
    }
    scope {
      player_ids: "00000000-0000-0000-0000-000000000001"
    }
    confidence: DETECTION_CONFIDENCE_HIGH
    default_action: DISPOSITION_ALLOW
    exception: true
    operator_reason: "Temporary reviewed event-staff exception"
  }
}

# DENY rejects this session/transfer; it is never a permanent ban.
rules {
  rule {
    rule_id: "deny-reviewed-cheat-build"
    priority: 2000
    revision: 1
    selector {
      artifact_type: DETECTION_ARTIFACT_MOD
      match_type: DETECTION_MATCH_EXACT_SHA256
    }
    confidence: DETECTION_CONFIDENCE_CONFIRMED
    default_action: DISPOSITION_DENY
    operator_reason: "Exact artifact reviewed by two operators"
  }
  sha256_hex: "2222222222222222222222222222222222222222222222222222222222222222"
}
```

`sha256_hex` and `content_root_sha256_hex` must contain exactly 64 hexadecimal
characters. They are converted to canonical 32-byte fields before signing. Raw
protobuf byte escapes are rejected in administrator configuration.

## Publication safety

- Input is strict UTF-8 textproto and is limited to 256 KiB.
- Unknown fields, duplicate scalar values, absolute rule timestamps, invalid or
  duplicate UUIDs, unsupported enums, and scope expansion above 4096 are rejected.
- Version constraints are exact values; range/comparison expressions are rejected.
- Player exceptions must be non-foundation `ALLOW` rules with `player_ids`.
- Foundation rules cannot `ALLOW` and remain limited to protocol-integrity artifacts.
- For every other rule, exact SHA-256 may use the full action range; a bounded
  content root may reach `QUARANTINE` but never `DENY`; Mod IDs, signers,
  metadata, behavior IDs, and administrator classifications may not exceed `WARN`.
  The same matrix is enforced by administrator parsing, signed-document validation,
  and the core rule model so hand-written rules cannot bypass catalog safeguards.
- Publication preserves policy ID, increments sequence, binds the predecessor
  hash, passes Protocol and Core compilation gates, and is root-signed.
- Validation or pre-commit history failure leaves active bytes unchanged.
  Successful versions are retained under `history/`, capped at 128 entries.

Velocity and BungeeCord evaluate authenticated, server-derived observations and
execute the current-session disposition through bounded, idempotent adapters.
`MONITOR` remains the default. High-impact LIMIT/QUARANTINE routing requires the
explicit `LIMITED_ROUTE` mode and two distinct registered targets:
`disposition.limited.server` for LIMIT and `disposition.quarantine.server` for
QUARANTINE. A missing, unregistered, or shared target safely makes the effective
mode `MONITOR`; primary handshakes remain usable and LIMIT, QUARANTINE, and DENY
do not execute. With a valid route pair, DENY disconnects only the current
connection. No disposition bans, crosses a reconnect boundary, or automatically
collects evidence. Backend-local Paper/Folia action adapters remain a separate,
reversible release gate.
