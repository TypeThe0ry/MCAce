# MCAce Cloud control-plane foundation

## Delivered boundary

`mcace-cloud` is the first deployable Phase 3 control-plane service. It provides:

- Ed25519 challenge-response authentication for explicitly registered network
  servers;
- five-minute, cloud-signed bearer tokens with narrow API scopes;
- risk-event ingestion with cloud-owned policy weights;
- signed append-only evidence metadata receipts;
- ordered, signed revocation publication;
- append-only operator audit records written transactionally with revocations;
- provenance-aware player timelines with current review/appeal snapshots;
- versioned review and appeal state machines with append-only transition history;
- immutable risk-policy releases and ordered SHADOW/CANARY/BROAD/FULL rollout;
- deterministic player cohorts, baseline/candidate dual evaluation, rollback,
  reviewed feedback, and false-positive metrics;
- liveness and PostgreSQL-backed readiness endpoints.
- authenticated Paper behavior-event delivery with bounded asynchronous queues,
  threshold/cooldown suppression, and independent-provider corroboration.
- PostgreSQL-coordinated one-time challenges that can be issued and exchanged by
  different Cloud instances without reopening replay windows;
- chained, domain-separated signed audit heads with leased multi-instance outbox
  delivery to an external HTTPS ledger.
- role-gated operator dashboard and UUID-bound player appeal portal;
- one-time service-issued Web handoffs, opaque hashed sessions, strict Origin and
  double-submit CSRF enforcement;
- transactional player notifications and append-only self-only read receipts.

It does not ban players. Risk ingestion always returns
`enforcement_action=NONE`. A revocation response says
`DISTRIBUTE_REVOCATION_ONLY`; each consumer remains responsible for an explicit,
reviewable policy decision.

## Build and run

Build the deployable shadow JAR with Java 21:

```powershell
.\gradlew.bat :mcace-cloud:shadowJar --no-daemon
```

Required environment:

| Variable | Meaning |
| --- | --- |
| `MCACE_DATABASE_URL` | PostgreSQL JDBC URL |
| `MCACE_DATABASE_USERNAME` | Least-privilege database role |
| `MCACE_DATABASE_PASSWORD_ENV` | Name of the environment variable containing the password; defaults to `MCACE_DATABASE_PASSWORD` |
| `MCACE_CLOUD_DATA` | Identity/data directory; defaults to `./data` |
| `MCACE_CLOUD_SERVER_REGISTRY` | Registered server public-key file; defaults to `<data>/servers.registry` |
| `MCACE_CLOUD_BIND` | Bind address; defaults to `127.0.0.1` |
| `MCACE_CLOUD_PORT` | HTTP port; defaults to `8088` |
| `MCACE_AUDIT_ANCHOR_URL` | Optional external HTTPS ledger endpoint; enables periodic anchoring |
| `MCACE_AUDIT_ANCHOR_BEARER_ENV` | Optional name of the environment variable holding the ledger bearer credential |
| `MCACE_AUDIT_ANCHOR_INTERVAL_SECONDS` | Anchor interval, 30–86400 seconds; defaults to 300 |
| `MCACE_AUDIT_ANCHOR_TIMEOUT_SECONDS` | Publication timeout, 1–30 seconds; defaults to 10 |
| `MCACE_AUDIT_ANCHOR_RETRY_SECONDS` | Failed-delivery retry delay, 1–3600 seconds; defaults to 60 |
| `MCACE_WEB_PUBLIC_ORIGIN` | Optional pathless HTTPS origin (for example `https://mcace.example.net`); enables Web routes |

Start it with:

```powershell
java -jar .\mcace-cloud\build\libs\mcace-cloud-0.1.0-SNAPSHOT.jar
```

Plain HTTP is loopback-only by default. Terminate TLS at a local reverse proxy,
apply request-rate limits there, and forward only from the same host or private
service mesh. A non-loopback plaintext bind requires the deliberately explicit
`MCACE_CLOUD_ALLOW_PLAINTEXT_REMOTE=true` override and is not the recommended
deployment.

## Server identity registry

Each non-comment line has three pipe-delimited fields:

```text
server_id|BASE64_X509_ED25519_PUBLIC_KEY|RISK_WRITE,EVIDENCE_WRITE,REVOCATION_READ
```

Available scopes are:

- `RISK_WRITE`
- `EVIDENCE_WRITE`
- `REVOCATION_READ`
- `REVOCATION_WRITE`
- `TIMELINE_READ`
- `REVIEW_WRITE`
- `APPEAL_WRITE`
- `POLICY_READ`
- `POLICY_WRITE`
- `FEEDBACK_WRITE`
- `METRICS_READ`
- `WEB_OPERATOR_SESSION_WRITE`
- `WEB_PLAYER_SESSION_WRITE`

Grant `REVOCATION_WRITE` and `REVIEW_WRITE` only to operator-controlled service
identities. `APPEAL_WRITE` is reserved for a trusted service-to-service legacy
integration; the browser portal uses UUID-bound Web sessions instead. Never grant
it directly to a Minecraft client. Policy authors, reviewers, and metrics readers should use
separate identities and least-privilege scopes. The registry rejects duplicate
IDs, invalid keys, unknown scopes, and an empty file.

Grant `WEB_OPERATOR_SESSION_WRITE` only to an identity-aware SSO bridge after it
has authenticated the operator. Grant `WEB_PLAYER_SESSION_WRITE` only to
Velocity or another component that has already authenticated the Minecraft
player. These scopes issue one-time handoffs; they do not grant browser data
access and must never be embedded in JavaScript.

## Authentication flow

1. `POST /v1/auth/challenges` with `{"server_id":"..."}`.
2. Base64url-decode `signing_payload` and sign those exact bytes with the
   registered Ed25519 private key.
3. `POST /v1/auth/tokens` with the challenge ID, server ID, and base64url
   signature.
4. Use the returned token as `Authorization: Bearer ...`.

A challenge expires after 30 seconds, is bounded per server and globally, and is
removed before signature verification. A failed or successful proof therefore
cannot be replayed. Tokens are Ed25519-signed, scoped, capped at ten minutes by
the verifier, and issued for five minutes by the service.

Outstanding challenges and their non-secret public identity snapshots are held
in PostgreSQL. A database row lock serializes global/per-server quota checks, and
token exchange uses atomic `DELETE ... RETURNING`. Cloud A can issue a challenge
that Cloud B exchanges, while concurrent exchanges across both instances have
exactly one winner. Malformed, wrong-server, forged, expired, and successful
exchange attempts all burn the selected challenge before proof verification.

Authentication keys live under `<data>/identity/authentication/`. Evidence and
revocation audit keys live separately under `<data>/identity/audit/`. Distribute
only the corresponding public key files. A partial or mismatched key pair stops
service startup.

## API

| Method and path | Scope | Result |
| --- | --- | --- |
| `GET /health/live` | none | Process liveness |
| `GET /health/ready` | none | Real PostgreSQL readiness probe |
| `POST /v1/risk-events` | `RISK_WRITE` | Append an observation and return its server-assigned weight |
| `POST /v1/evidence-metadata` | `EVIDENCE_WRITE` | Append signed evidence-chain metadata |
| `GET /v1/revocations?after_sequence=N` | `REVOCATION_READ` | Return active ordered signed revocations |
| `POST /v1/revocations` | `REVOCATION_WRITE` | Create a signed revocation plus audit record in one transaction |
| `GET /v1/players/{uuid}/timeline?limit=N` | `TIMELINE_READ` | Read ordered provenance events and current workflow snapshots |
| `POST /v1/reviews` | `REVIEW_WRITE` | Open a human-review case |
| `POST /v1/reviews/{caseId}/transitions` | `REVIEW_WRITE` | Apply a version-checked review transition |
| `POST /v1/appeals` | `APPEAL_WRITE` | Submit one appeal for an eligible review case |
| `POST /v1/appeals/{appealId}/transitions` | `APPEAL_WRITE` | Apply a version-checked appeal transition |
| `GET/POST /v1/risk-policies` | `POLICY_READ` / `POLICY_WRITE` | List or create immutable complete policy releases |
| `GET/POST /v1/policy-rollouts` | `POLICY_READ` / `POLICY_WRITE` | Read or append ordered rollout/rollback events |
| `POST /v1/risk-feedback` | `FEEDBACK_WRITE` | Attach a reviewed outcome to a risk event |
| `GET /v1/policy-metrics?version=...&from=...&to=...` | `METRICS_READ` | Aggregate rollout and reviewed false-positive metrics |
| `POST /v1/web-handoffs/operator` | `WEB_OPERATOR_SESSION_WRITE` | Issue a two-minute operator handoff |
| `POST /v1/web-handoffs/player` | `WEB_PLAYER_SESSION_WRITE` | Issue a two-minute UUID-bound player handoff |

### Web routes

Web routes exist only when `MCACE_WEB_PUBLIC_ORIGIN` is configured.

| Method and path | Web authorization | Result |
| --- | --- | --- |
| `GET /login`, `/dashboard`, `/appeal` | none; APIs enforce authorization | CSP-protected portal pages |
| `POST /web/api/session/exchange` | one-time handoff + exact Origin | Establish opaque cookie session |
| `GET /web/api/session` | any active Web session | Current principal and roles |
| `POST /web/api/logout` | active session + Origin + CSRF | Revoke session and clear cookies |
| `GET /web/api/operator/reviews` | Operator Viewer | Review queue |
| `POST /web/api/operator/reviews/{id}/transitions` | Operator Reviewer + Origin + CSRF | Version-checked audited transition |
| `GET /web/api/operator/players/{uuid}/timeline` | Operator Viewer | Player investigation timeline |
| `GET /web/api/player/timeline` | Player self-only | Current player's timeline |
| `POST /web/api/player/appeals` | Player self-only + Origin + CSRF | Submit appeal bound to session UUID |
| `GET /web/api/player/notifications` | Player self-only | Current player's notification inbox |
| `POST /web/api/player/notifications/{id}/read` | Player self-only + Origin + CSRF | Append self-owned read receipt |

The SSO bridge or Velocity receives `login_url`; the code is placed after `#` so
it is not sent in HTTP requests or referrers. Login JavaScript posts it once,
immediately clears the fragment, and receives `__Host-MCAce-Session` plus a
separate CSRF cookie. Handoffs are deleted before secret/expiry validation and
sessions store only a domain-separated secret hash. Production TLS termination
must preserve the browser `Origin` header and serve exactly the configured
public origin. Rate-limit handoff issuance and exchange at the reverse proxy.

Requests are strict JSON: duplicate keys, unknown fields, excessive nesting,
oversized bodies, missing required booleans/numbers, invalid timestamps, and
unsupported enum values are rejected. Error responses use a stable code and
request ID without echoing credentials or signatures.

### Risk semantics

Callers submit an event type and provenance, not a weight. The Cloud service
assigns the weight from its `RiskPolicy`, binds the source to the authenticated
server ID, and stores `SERVER_CONFIRMED`, `CLIENT_REPORTED`, `INFERRED`, or
`MISSING` without promoting one class into another. A single signal remains an
observation, never an automatic punishment.

Every Cloud-ingested risk event also stores its applied policy, baseline and
candidate versions/weights, rollout stage, and deterministic cohort bucket in the
same database transaction. These fields are returned in the player timeline so a
reviewer can reconstruct the exact policy decision rather than infer it from the
current configuration.

### Policy rollout and metric semantics

Policy releases are immutable and SHA-256 bound. They must define a non-negative
weight for every known risk event plus strictly increasing risk thresholds.
Rollouts must progress through `SHADOW -> CANARY -> BROAD -> FULL`; CANARY is
bounded to 1–25%, BROAD to 26–99%, and percentages cannot decrease within a
stage. `PAUSED` can restart at SHADOW, while `ROLLED_BACK` and `FULL` are terminal.
Only one candidate may be active at a time. PostgreSQL enforces the same sequence
rules, so bypassing the API cannot skip SHADOW.

Player assignment is a stable SHA-256 bucket of player UUID and immutable policy
ID. SHADOW always computes the candidate weight but applies the baseline. CANARY
and BROAD apply the candidate only inside the configured cohort. A rollout event
never bans, kicks, or restricts a player.

False-positive feedback is accepted only when the risk event and review case
belong to the same player. `FALSE_POSITIVE` requires `CLOSED_NO_ACTION` or a
granted appeal; `CONFIRMED_SIGNAL` requires an action recommendation/actioned case
or upheld appeal. Metrics expose counts and the reviewed false-positive rate;
fewer than 30 decided labels is explicitly reported as an insufficient sample.
Promotion remains an operator decision and should use this guardrail, known-good
replays, rollback readiness, and independent server telemetry.

### Evidence semantics

The API stores metadata, hashes, provenance, and an object-storage URI—not the
evidence body. Accepted schemes are `s3`, `gs`, `az`, and `https`; user info,
queries, and fragments are rejected to reduce credential leakage. PostgreSQL
assigns the global evidence-chain sequence and signs each chain hash.

### External audit-anchor semantics

When `MCACE_AUDIT_ANCHOR_URL` is configured, Cloud periodically creates an
append-only `mcace.audit-anchor.v1` snapshot. It commits to:

- the current globally chained evidence sequence/hash;
- a domain-separated digest of the complete ordered revocation feed;
- a domain-separated digest of the complete insertion-ordered operator audit;
- the prior anchor hash and the current anchor sequence/time.

The anchor hash is signed under the independent
`mcace-audit-anchor-signature-v1` domain with the audit identity. Creation uses a
singleton database lock, so only one instance creates an anchor per interval.
Delivery rows use bounded leases and `FOR UPDATE SKIP LOCKED`; multiple instances
can publish without claiming the same pending row. Failed sends release their
lease for retry and never change player state.

The ledger request contains `Idempotency-Key: <anchor_id>` and an optional bearer
credential loaded indirectly from the named environment variable. The external
ledger must durably store the exact request, deduplicate by anchor ID, and return
a bounded `X-MCAce-Anchor-Receipt` header. MCAce stores that reference and the
SHA-256 of the response body in an append-only publication table. HTTPS is
mandatory except for loopback test endpoints. If the external send succeeds but
the database acknowledgement fails, the request may be retried; ledger-side
idempotency is therefore part of the contract.

### Revocation semantics

Every revocation requires a review ticket and HTTPS appeal URL. PostgreSQL
assigns a monotonically increasing sequence, hashes the canonical record, signs
it under the `mcace-revocation-signature-v1` domain, and inserts the revocation
and operator audit in one transaction. Consumers can recompute and verify it
with `RevocationSignatureCodec.verify` and the pinned audit public key.

Account and device-key revocations are high-impact signals. Consumers must still
apply their own review, staged rollout, rollback, and appeal rules rather than
turning the feed into an unconditional ban list.

### Review, appeal, and timeline semantics

Review cases follow `OPEN -> UNDER_REVIEW -> ACTION_RECOMMENDED ->
CLOSED_ACTIONED`, with explicit no-action exits. Appeals follow `SUBMITTED ->
UNDER_REVIEW -> GRANTED|UPHELD`. Terminal states cannot reopen. Every mutation
requires the caller's expected version; a stale concurrent decision returns HTTP
409. The snapshot update, append-only transition, and operator audit record commit
in one PostgreSQL transaction.

`ACTION_RECOMMENDED`, `CLOSED_ACTIONED`, `GRANTED`, and `UPHELD` are recorded
human decisions; Cloud never executes a ban or restriction. Review responses say
`NONE_REVIEW_ONLY`, and appeal responses say `NONE_APPEAL_DECISION_ONLY`.

Timeline events preserve `SERVER_PERSISTED`, `SERVER_CONFIRMED`,
`CLIENT_REPORTED`, `INFERRED`, `MISSING`, or `OPERATOR_AUDIT` provenance. Review
and appeal transition history is returned separately from current snapshots so
an operator can reconstruct how a decision changed. Every review/appeal creation
or transition appends a bounded player notification in the same transaction.
Notification content describes workflow state only and does not expose raw
evidence. The appeal portal can read and acknowledge notifications only for the
UUID bound to its opaque session.

## Verification

```powershell
.\gradlew.bat :mcace-cloud:test :mcace-core:test :mcace-storage-postgres:test --rerun-tasks --no-daemon
```

The suite covers cross-instance one-time challenges, concurrent replay races,
forged proofs, token tampering and expiry,
scope/role/self-only enforcement, strict JSON, server-owned risk weights, evidence receipts,
review/appeal requirements, signature domain separation, append-only database
triggers, one-time Web replay races, Secure Cookie/CSRF/Origin behavior,
notification ownership, chained/leased external anchors, and a full
HTTP-to-real-PostgreSQL flow.

## Remaining Phase 3 work

- licensed Vulcan runtime compatibility validation (the isolated adapter is
  implemented; Grim uses its official typed API);
- backup, retention, ledger monitoring, and object-storage immutability.
