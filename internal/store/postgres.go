package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	db  *sql.DB
	now func() time.Time
}

var _ Store = (*PostgresStore)(nil)

func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	store := &PostgresStore{db: db, now: time.Now}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS session_audit_records (
	record_id BIGSERIAL PRIMARY KEY,
	session_id TEXT NOT NULL,
	user_id TEXT NOT NULL,
	host_id TEXT NOT NULL,
	cr_id TEXT NOT NULL,
	record_type TEXT NOT NULL,
	sequence BIGINT NOT NULL,
	command_id TEXT NOT NULL DEFAULT '',
	command_text TEXT NOT NULL DEFAULT '',
	output_data BYTEA NOT NULL DEFAULT ''::bytea,
	created_at TIMESTAMPTZ NOT NULL,
	truncated BOOLEAN NOT NULL DEFAULT FALSE,
	byte_count INTEGER NOT NULL DEFAULT 0,
	UNIQUE (session_id, sequence)
);

CREATE INDEX IF NOT EXISTS session_audit_records_session_sequence_idx
	ON session_audit_records (session_id, sequence);

CREATE INDEX IF NOT EXISTS session_audit_records_lookup_idx
	ON session_audit_records (user_id, host_id, cr_id, created_at DESC);

CREATE INDEX IF NOT EXISTS session_audit_records_global_lookup_idx
	ON session_audit_records (created_at DESC, session_id, sequence);

CREATE TABLE IF NOT EXISTS metadata_events (
	event_id TEXT PRIMARY KEY,
	schema_version TEXT NOT NULL,
	event_type TEXT NOT NULL,
	source TEXT NOT NULL,
	occurred_at TIMESTAMPTZ NOT NULL,
	request_id TEXT NOT NULL DEFAULT '',
	user_id TEXT NOT NULL DEFAULT '',
	session_id TEXT NOT NULL DEFAULT '',
	host_id TEXT NOT NULL DEFAULT '',
	cr_id TEXT NOT NULL DEFAULT '',
	pod_id TEXT NOT NULL DEFAULT '',
	instance_id TEXT NOT NULL DEFAULT '',
	incident_id TEXT NOT NULL DEFAULT '',
	run_id TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL DEFAULT '',
	mode TEXT NOT NULL DEFAULT '',
	outcome TEXT NOT NULL DEFAULT '',
	reason_code TEXT NOT NULL DEFAULT '',
	plan_hash TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS metadata_events_lookup_idx
	ON metadata_events (occurred_at DESC, event_type, source);

CREATE INDEX IF NOT EXISTS metadata_events_session_lookup_idx
	ON metadata_events (session_id, host_id, cr_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS metadata_events_incident_lookup_idx
	ON metadata_events (incident_id, run_id, occurred_at DESC);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate postgres store: %w", err)
	}
	return nil
}

func (s *PostgresStore) AppendSessionAuditRecords(
	ctx context.Context,
	session model.Session,
	req model.AppendSessionAuditRecordsRequest,
	retention time.Duration,
	maxBytes int,
) ([]model.SessionAuditRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin append session audit: %w", err)
	}
	defer tx.Rollback()
	if err := s.prune(ctx, tx, retention); err != nil {
		return nil, err
	}
	if len(req.Records) == 0 {
		return []model.SessionAuditRecord{}, nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, session.SessionID); err != nil {
		return nil, fmt.Errorf("lock session audit sequence: %w", err)
	}

	var sequence int64
	if err := tx.QueryRowContext(ctx, `
SELECT COALESCE(MAX(sequence), 0)
FROM session_audit_records
WHERE session_id = $1
`, session.SessionID).Scan(&sequence); err != nil {
		return nil, fmt.Errorf("read session audit sequence: %w", err)
	}
	var usedBytes int
	if err := tx.QueryRowContext(ctx, `
SELECT COALESCE(SUM(
	CASE
		WHEN record_type = $2 THEN octet_length(command_text::bytea)
		WHEN record_type = $3 THEN octet_length(output_data)
		ELSE 0
	END
), 0)::INTEGER
FROM session_audit_records
WHERE session_id = $1
`, session.SessionID, model.AuditRecordCommand, model.AuditRecordOutput).Scan(&usedBytes); err != nil {
		return nil, fmt.Errorf("read session audit byte total: %w", err)
	}

	appended := make([]model.SessionAuditRecord, 0, len(req.Records))
	for _, incoming := range req.Records {
		record, addBytes, err := buildAuditRecord(session, incoming, s.now().UTC())
		if err != nil {
			return nil, err
		}
		if maxBytes > 0 && usedBytes+addBytes > maxBytes {
			remaining := maxBytes - usedBytes
			if remaining < 0 {
				remaining = 0
			}
			truncateAuditRecord(&record, remaining)
			addBytes = remaining
		}
		sequence++
		record.Sequence = sequence
		outputData, err := base64.StdEncoding.DecodeString(record.OutputDataBase64)
		if record.OutputDataBase64 == "" {
			outputData = nil
			err = nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode audit output: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO session_audit_records (
	session_id, user_id, host_id, cr_id, record_type, sequence, command_id,
	command_text, output_data, created_at, truncated, byte_count
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
`, record.SessionID, record.UserID, record.HostID, record.CRID, record.RecordType, record.Sequence,
			record.CommandID, record.CommandText, outputData, record.CreatedAt, record.Truncated, record.ByteCount,
		); err != nil {
			return nil, fmt.Errorf("insert session audit record: %w", err)
		}
		appended = append(appended, record)
		usedBytes += addBytes
		if record.Truncated {
			break
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit session audit append: %w", err)
	}
	return appended, nil
}

func (s *PostgresStore) ListSessionAuditRecords(
	ctx context.Context,
	sessionID string,
	filter model.ListSessionAuditRecordsFilter,
	retention time.Duration,
) ([]model.SessionAuditRecord, error) {
	if err := s.prune(ctx, s.db, retention); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT session_id, user_id, host_id, cr_id, record_type, sequence, command_id,
	command_text, output_data, created_at, truncated, byte_count
FROM session_audit_records
WHERE session_id = $1 AND sequence > $2
ORDER BY sequence
LIMIT $3
`, sessionID, filter.AfterSequence, filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("list session audit records: %w", err)
	}
	defer rows.Close()
	records := make([]model.SessionAuditRecord, 0)
	for rows.Next() {
		var record model.SessionAuditRecord
		if err := scanAuditRecord(rows, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list session audit records: %w", err)
	}
	return records, nil
}

func (s *PostgresStore) ListAuditRecords(
	ctx context.Context,
	filter model.ListAuditRecordsFilter,
	retention time.Duration,
) ([]model.SessionAuditRecord, error) {
	if err := s.prune(ctx, s.db, retention); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT session_id, user_id, host_id, cr_id, record_type, sequence, command_id,
	command_text, output_data, created_at, truncated, byte_count
FROM session_audit_records
WHERE ($1 = '' OR session_id = $1)
	AND ($2 = '' OR user_id = $2)
	AND ($3 = '' OR host_id = $3)
	AND ($4 = '' OR cr_id = $4)
	AND ($5 = '' OR record_type = $5)
	AND ($6::timestamptz IS NULL OR created_at >= $6)
	AND ($7::timestamptz IS NULL OR created_at <= $7)
ORDER BY created_at DESC, session_id ASC, sequence DESC
LIMIT $8 OFFSET $9
`, filter.SessionID, filter.UserID, filter.HostID, filter.CRID, filter.RecordType,
		nullableTime(filter.From), nullableTime(filter.To), filter.Limit, filter.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit records: %w", err)
	}
	defer rows.Close()
	records := make([]model.SessionAuditRecord, 0)
	for rows.Next() {
		var record model.SessionAuditRecord
		if err := scanAuditRecord(rows, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit records: %w", err)
	}
	return records, nil
}

func (s *PostgresStore) ListAuditSessions(
	ctx context.Context,
	filter model.ListAuditSessionsFilter,
	retention time.Duration,
) ([]model.AuditSessionSummary, error) {
	if err := s.prune(ctx, s.db, retention); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT session_id, user_id, host_id, cr_id, MAX(created_at) AS last_audit_at,
	COUNT(*)::INTEGER AS record_count, BOOL_OR(truncated) AS truncated
FROM session_audit_records
WHERE ($1 = '' OR session_id = $1)
	AND ($2 = '' OR user_id = $2)
	AND ($3 = '' OR host_id = $3)
	AND ($4 = '' OR cr_id = $4)
	AND ($5::timestamptz IS NULL OR created_at >= $5)
	AND ($6::timestamptz IS NULL OR created_at <= $6)
GROUP BY session_id, user_id, host_id, cr_id
ORDER BY last_audit_at DESC, session_id
LIMIT $7 OFFSET $8
`, filter.SessionID, filter.UserID, filter.HostID, filter.CRID,
		nullableTime(filter.From), nullableTime(filter.To), filter.Limit, filter.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit sessions: %w", err)
	}
	defer rows.Close()
	summaries := make([]model.AuditSessionSummary, 0)
	for rows.Next() {
		var summary model.AuditSessionSummary
		if err := rows.Scan(
			&summary.SessionID,
			&summary.UserID,
			&summary.HostID,
			&summary.CRID,
			&summary.LastAuditAt,
			&summary.RecordCount,
			&summary.Truncated,
		); err != nil {
			return nil, fmt.Errorf("scan audit session: %w", err)
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit sessions: %w", err)
	}
	return summaries, nil
}

func (s *PostgresStore) AppendMetadataEvent(ctx context.Context, event model.MetadataEvent) error {
	if err := model.ValidateMetadataEvent(event); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO metadata_events (
	event_id, schema_version, event_type, source, occurred_at, request_id,
	user_id, session_id, host_id, cr_id, pod_id, instance_id, incident_id,
	run_id, action, mode, outcome, reason_code, plan_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
ON CONFLICT (event_id) DO NOTHING
`, event.EventID, event.SchemaVersion, event.EventType, event.Source, event.OccurredAt.UTC(), event.RequestID,
		event.UserID, event.SessionID, event.HostID, event.CRID, event.PodID, event.InstanceID, event.IncidentID,
		event.RunID, event.Action, event.Mode, event.Outcome, event.ReasonCode, event.PlanHash)
	if err != nil {
		return fmt.Errorf("append metadata event: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListMetadataEvents(ctx context.Context, filter model.ListMetadataEventsFilter) ([]model.MetadataEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT schema_version, event_id, event_type, source, occurred_at, request_id,
	user_id, session_id, host_id, cr_id, pod_id, instance_id, incident_id,
	run_id, action, mode, outcome, reason_code, plan_hash
FROM metadata_events
WHERE ($1 = '' OR event_type = $1)
	AND ($2 = '' OR source = $2)
	AND ($3 = '' OR user_id = $3)
	AND ($4 = '' OR session_id = $4)
	AND ($5 = '' OR host_id = $5)
	AND ($6 = '' OR cr_id = $6)
	AND ($7 = '' OR incident_id = $7)
	AND ($8 = '' OR run_id = $8)
	AND ($9::timestamptz IS NULL OR occurred_at >= $9)
	AND ($10::timestamptz IS NULL OR occurred_at <= $10)
ORDER BY occurred_at DESC, event_id
LIMIT $11 OFFSET $12
`, filter.EventType, filter.Source, filter.UserID, filter.SessionID, filter.HostID, filter.CRID,
		filter.IncidentID, filter.RunID, nullableTime(filter.From), nullableTime(filter.To), filter.Limit, filter.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list metadata events: %w", err)
	}
	defer rows.Close()
	events := make([]model.MetadataEvent, 0)
	for rows.Next() {
		var event model.MetadataEvent
		if err := rows.Scan(
			&event.SchemaVersion,
			&event.EventID,
			&event.EventType,
			&event.Source,
			&event.OccurredAt,
			&event.RequestID,
			&event.UserID,
			&event.SessionID,
			&event.HostID,
			&event.CRID,
			&event.PodID,
			&event.InstanceID,
			&event.IncidentID,
			&event.RunID,
			&event.Action,
			&event.Mode,
			&event.Outcome,
			&event.ReasonCode,
			&event.PlanHash,
		); err != nil {
			return nil, fmt.Errorf("scan metadata event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list metadata events: %w", err)
	}
	return events, nil
}

func (s *PostgresStore) prune(ctx context.Context, executor queryExecutor, retention time.Duration) error {
	if retention <= 0 {
		return nil
	}
	if _, err := executor.ExecContext(ctx, `
DELETE FROM session_audit_records
WHERE created_at < $1
`, s.now().UTC().Add(-retention)); err != nil {
		return fmt.Errorf("prune session audit records: %w", err)
	}
	return nil
}

type queryExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAuditRecord(row rowScanner, record *model.SessionAuditRecord) error {
	var outputData []byte
	if err := row.Scan(
		&record.SessionID,
		&record.UserID,
		&record.HostID,
		&record.CRID,
		&record.RecordType,
		&record.Sequence,
		&record.CommandID,
		&record.CommandText,
		&outputData,
		&record.CreatedAt,
		&record.Truncated,
		&record.ByteCount,
	); err != nil {
		return err
	}
	if len(outputData) > 0 {
		record.OutputDataBase64 = base64.StdEncoding.EncodeToString(outputData)
	}
	return nil
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
