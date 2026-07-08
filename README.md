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

Optional SNS/SQS metadata timeline ingestion:

```bash
AUDIT_EVENT_CONSUMER_ENABLED=true
AUDIT_EVENTS_QUEUE_URL=https://sqs.ap-southeast-1.amazonaws.com/123456789012/dendenmushi-audit-events-dev
AWS_REGION=ap-southeast-1
```

When enabled, Audit Service polls the configured SQS queue for SNS-delivered
platform lifecycle events and stores sanitized metadata in `metadata_events`.
`event_id` is unique, so redeliveries are idempotent. Malformed or forbidden
payloads are left on the queue for SQS redrive to the configured DLQ. The
consumer stores metadata only; it never stores tokens, private keys, passwords,
terminal input/output, command bodies, prompts, or raw model responses.

## Endpoints

```http
GET  /healthz
GET  /openapi.yaml
GET  /sessions/audit?userId={userId}&hostId={hostId}&crId={crId}&sessionId={sessionId}
GET  /sessions/audit/records?sessionId={sessionId}&userId={userId}&hostId={hostId}&crId={crId}&recordType={recordType}
GET  /events?eventType={eventType}&source={source}&userId={userId}&sessionId={sessionId}&hostId={hostId}&crId={crId}&incidentId={incidentId}&runId={runId}
POST /sessions/{sessionId}/audit/records
GET  /sessions/{sessionId}/audit/records
```

Business endpoints require `x-api-version: 1`. `GET /healthz` and
`GET /openapi.yaml` are exempt so probes and spec reads do not need custom
headers.
Successful probe request logs are suppressed; failed probe responses still emit
request logs.

Proxy Dataplane appends audit records with the assigned `ownerPodId` and
`ownerInstanceId`. Audit Service validates that owner pair against Session
Manager `GET /sessions/{sessionId}` before storing records.

Records include best-effort command lines, output bytes encoded as base64 in
JSON, control/session events, per-session sequence numbers, and truncation
flags. Defaults:

The global record query is for dashboard/log search across retained SSH audit
records. It supports `from`, `to`, `limit`, and offset `cursor` query
parameters and sorts records newest first. It does not add incident or alert
identifiers to SSH audit rows; Agentic AI incident correlation is performed by
host and time window in the web dashboard.

```bash
SESSION_AUDIT_RETENTION_SECONDS=604800
SESSION_AUDIT_MAX_BYTES_PER_SESSION=16777216
```

When the per-session cap is reached, existing records are preserved, the
truncating record is marked `truncated=true`, and Proxy Dataplane stops sending
additional audit output for that session. Command and output bodies must not be
written to normal application logs.

The metadata event query returns platform lifecycle events newest first. It
supports `from`, `to`, `limit`, and offset `cursor` query parameters in addition
to the filters shown above. The endpoint is intended for operations timelines
and audit correlation; retained SSH command/output records remain under the
session audit endpoints.

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
