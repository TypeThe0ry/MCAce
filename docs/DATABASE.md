# PostgreSQL audit storage

> **Frozen optional scope.** PostgreSQL is not part of the current six-deployable
> release bundle and cannot decide admission or compensate for a missing Fabric
> client. Database availability must not change player trust or enforcement.

## Scope

The Phase 2/3 storage module persists:

- mutable session snapshots keyed by session ID;
- append-only, provenance-labeled risk events;
- append-only evidence metadata with a global predecessor hash and Ed25519 signature;
- append-only ordered revocations with domain-separated Ed25519 signatures;
- append-only operator audit records, transactionally paired with revocation writes;
- versioned review/appeal snapshots with append-only transition histories;
- immutable risk-policy releases/weights, append-only rollout events, atomic
  per-event policy evaluations, and reviewed false-positive feedback;
- shared, atomically consumed Cloud authentication challenges;
- append-only signed audit anchors, leased delivery state, and append-only
  external publication receipts;
- atomically consumed Web handoffs, opaque hashed Web sessions, append-only player
  notifications, and append-only per-player read receipts;
- checksummed schema migration history.

Evidence payloads are not stored in PostgreSQL. `storage_uri`, `content_size`, and
`content_sha256` identify an externally retained object without expanding client
collection scope.

## Velocity configuration

Add to `plugins/mcace/mcace.properties`:

```properties
storage.enabled=true
storage.jdbc-url=jdbc:postgresql://db.example.net:5432/mcace?sslmode=verify-full
storage.username=mcace_writer
storage.password-env=MCACE_DB_PASSWORD
storage.migrate-on-start=false
```

Set the named password environment variable before starting Velocity. Passwords
must not be written into the properties file or command line. Production
connections should use certificate-verified TLS.

With `storage.migrate-on-start=true`, Velocity runs checksummed migrations at
startup and fails startup if the configured database is unavailable or a migration
checksum changed. For least privilege, run migrations separately as the schema
owner and use a restricted runtime account:

```powershell
$env:MCACE_DB_URL='jdbc:postgresql://db.example.net:5432/mcace?sslmode=verify-full'
$env:MCACE_DB_USER='mcace_owner'
$env:MCACE_DB_PASSWORD='<from secret manager>'
java -cp mcace-server-velocity-0.1.0-SNAPSHOT.jar com.ellan.mcace.storage.postgres.PostgresMigrationCli
```

The runtime role needs `SELECT/INSERT/UPDATE` on `mcace_sessions`, `SELECT/INSERT`
on `mcace_risk_events` and `mcace_evidence_metadata`, and `SELECT/UPDATE` on
`mcace_evidence_chain_head`. It does not need table ownership or trigger-management
privileges.

The Cloud role additionally needs `USAGE/SELECT` on
`mcace_revocation_sequence`, `SELECT/INSERT` on `mcace_revocations`, and
`INSERT` on `mcace_operator_audit`; `SELECT/INSERT/UPDATE` on
`mcace_review_cases` and `mcace_appeals`; and `SELECT/INSERT` on
`mcace_review_transitions` and `mcace_appeal_transitions`. Timeline readers need
`SELECT` on sessions, risk events, evidence metadata, cases, appeals, and both
transition tables. Cloud readiness also requires permission to
connect and execute `SELECT 1`. Keep the migration owner separate from both
Velocity and Cloud runtime roles.

Distributed authentication additionally requires `SELECT/INSERT/DELETE` on the
ephemeral `mcace_auth_challenges` table and `SELECT` on
`mcace_auth_challenge_guard`; `DELETE ... RETURNING` is the atomic one-time
consume operation, not deletion of audit history. Anchor workers require
`SELECT/INSERT` on `mcace_audit_anchors`, `SELECT/UPDATE` on
`mcace_audit_anchor_head`, `SELECT/INSERT/UPDATE/DELETE` on the operational
`mcace_audit_anchor_delivery` outbox, and `SELECT/INSERT` on
`mcace_audit_anchor_publications`. The anchor and publication tables remain
append-only; only temporary challenges and leased delivery state are deletable.

The Web portal runtime needs `SELECT/INSERT/DELETE` on the ephemeral
`mcace_web_handoffs` and `mcace_web_sessions` tables. Handoffs are consumed with
`DELETE ... RETURNING`; sessions are deleted only on logout or expiry cleanup.
It additionally needs `SELECT/INSERT` on `mcace_player_notifications` and
`mcace_player_notification_reads`. Both notification tables are append-only.
The database validates that a read receipt carries the same player UUID as its
notification, while API authorization always derives that UUID from the session.

Policy services additionally need `SELECT/INSERT` on
`mcace_risk_policy_releases`, `mcace_risk_policy_weights`, and
`mcace_policy_rollouts`, plus sequence usage. Risk ingestion needs `INSERT` on
`mcace_risk_policy_evaluations`; reviewers need `INSERT` on
`mcace_risk_feedback`; metrics readers need `SELECT` on those tables. None of
these policy/review roles needs `DELETE`, trigger-management, or table-ownership
privileges.

## Verification

The repository integration test uses the exact `postgres:17.6-alpine` image and
performs concurrent evidence appends, signed revocation/audit transactions,
review version races, appeal transitions, policy rollout/rollback ordering,
stable evaluation audit, false-positive aggregation, timeline reconstruction,
cross-instance authentication races, signed anchor chaining, outbox lease
recovery, atomic Web-handoff races, hashed session lookup, notification ownership,
workflow/notification atomicity, and mutation attempts:

```powershell
.\gradlew.bat :mcace-storage-postgres:test --rerun-tasks --no-daemon
```

When Docker is unavailable, the real-PostgreSQL test is reported as skipped rather
than silently substituted with H2. CI runners execute the same test against the
disposable PostgreSQL container.
