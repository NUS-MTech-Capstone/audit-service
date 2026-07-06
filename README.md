# Audit Service

Internal retained session audit API for DenDenMushi.

Audit Service stores and queries retained command/output audit records captured
asynchronously by Proxy Dataplane. It does not proxy, broker, record, or
transform live terminal traffic.

## Run

```bash
PORT=8085 \
STORE_DRIVER=memory \
SESSION_MANAGER_URL=http://localhost:8081 \
go run ./cmd/server
```

Postgres:

```bash
make run-postgres
```

For an externally managed database:

```bash
PORT=8085 \
STORE_DRIVER=postgres \
DATABASE_URL='postgres://user:password@host:5432/database?sslmode=require' \
SESSION_MANAGER_URL=http://session-manager:8081 \
go run ./cmd/server
```

The Postgres migration creates `session_audit_records` idempotently when it is
missing. Existing rows from the former Session Manager-owned table are preserved.

## Endpoints

```http
GET  /healthz
GET  /openapi.yaml
GET  /sessions/audit?userId={userId}&hostId={hostId}&crId={crId}&sessionId={sessionId}
POST /sessions/{sessionId}/audit/records
GET  /sessions/{sessionId}/audit/records
```

Proxy Dataplane appends audit records with the assigned `ownerPodId` and
`ownerInstanceId`. Audit Service validates that owner pair against Session
Manager `GET /sessions/{sessionId}` before storing records.

Records include best-effort command lines, output bytes encoded as base64 in
JSON, control/session events, per-session sequence numbers, and truncation
flags. Defaults:

```bash
SESSION_AUDIT_RETENTION_SECONDS=604800
SESSION_AUDIT_MAX_BYTES_PER_SESSION=16777216
```

When the per-session cap is reached, existing records are preserved, the
truncating record is marked `truncated=true`, and Proxy Dataplane stops sending
additional audit output for that session. Command and output bodies must not be
written to normal application logs.

## Design Notes

Audit Service depends on Session Manager for session metadata and owner
validation, but Session Manager no longer stores or serves retained audit
records. This preserves the direct live terminal path:

```text
Browser <-> Proxy Dataplane <-> Target Host
```

Audit append/list calls are internal HTTP metadata/storage calls only.

## Tests

```bash
go test ./...
make test-postgres
```
