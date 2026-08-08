package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
)

type fakeConnector struct{ conn *fakeSQLConn }

func (c fakeConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (fakeConnector) Driver() driver.Driver                          { return fakeSQLDriver{} }

type fakeSQLDriver struct{}

func (fakeSQLDriver) Open(string) (driver.Conn, error) { return &fakeSQLConn{}, nil }

type fakeSQLConn struct{}

func (*fakeSQLConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (*fakeSQLConn) Close() error                        { return nil }
func (c *fakeSQLConn) Begin() (driver.Tx, error)         { return fakeTx{}, nil }
func (c *fakeSQLConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return fakeTx{}, nil
}
func (*fakeSQLConn) Ping(context.Context) error { return nil }
func (*fakeSQLConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func (*fakeSQLConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	now := time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC)
	switch {
	case strings.Contains(query, "MAX(sequence)"):
		return &fakeRows{columns: []string{"sequence"}, values: [][]driver.Value{{int64(2)}}}, nil
	case strings.Contains(query, "COALESCE(SUM"):
		return &fakeRows{columns: []string{"bytes"}, values: [][]driver.Value{{int64(0)}}}, nil
	case strings.Contains(query, "FROM metadata_events"):
		return &fakeRows{columns: makeColumns(19), values: [][]driver.Value{{
			model.MetadataEventSchemaVersion, "evt-1", "SessionCreated", "session-manager", now,
			"req-1", "user-1", "sess-1", "host-1", "cr-1", "pod-1", "inst-1", "", "", "start", "owner", "allowed", "", "hash",
		}}}, nil
	case strings.Contains(query, "GROUP BY session_id"):
		return &fakeRows{columns: makeColumns(7), values: [][]driver.Value{{"sess-1", "user-1", "host-1", "cr-1", now, int64(1), false}}}, nil
	default:
		return &fakeRows{columns: makeColumns(12), values: [][]driver.Value{{
			"sess-1", "user-1", "host-1", "cr-1", model.AuditRecordOutput, int64(3), "cmd-1", "", []byte("hello"), now, false, int64(5),
		}}}, nil
	}
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *fakeRows) Columns() []string { return r.columns }
func (*fakeRows) Close() error        { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

func makeColumns(count int) []string {
	columns := make([]string, count)
	for i := range columns {
		columns[i] = "column"
	}
	return columns
}

func TestPostgresStoreWithInProcessSQLDriver(t *testing.T) {
	db := sql.OpenDB(fakeConnector{conn: &fakeSQLConn{}})
	store := &PostgresStore{db: db, now: func() time.Time { return time.Date(2026, 7, 6, 2, 0, 0, 0, time.UTC) }}
	ctx := context.Background()
	if err := store.migrate(ctx); err != nil {
		t.Fatalf("migrate() error = %v", err)
	}
	session := model.Session{SessionID: "sess-1", UserID: "user-1", HostID: "host-1", CRID: "cr-1"}
	appended, err := store.AppendSessionAuditRecords(ctx, session, model.AppendSessionAuditRecordsRequest{Records: []model.AppendSessionAuditRecord{
		{RecordType: model.AuditRecordCommand, CommandID: "cmd-1", CommandText: "pwd"},
		{RecordType: model.AuditRecordOutput, CommandID: "cmd-1", OutputDataBase64: "aGVsbG8="},
	}}, time.Hour, 1024)
	if err != nil || len(appended) != 2 || appended[0].Sequence != 3 {
		t.Fatalf("AppendSessionAuditRecords()=%#v error=%v", appended, err)
	}
	records, err := store.ListSessionAuditRecords(ctx, "sess-1", model.ListSessionAuditRecordsFilter{Limit: 10}, time.Hour)
	if err != nil || len(records) != 1 || records[0].OutputDataBase64 != "aGVsbG8=" {
		t.Fatalf("ListSessionAuditRecords()=%#v error=%v", records, err)
	}
	records, err = store.ListAuditRecords(ctx, model.ListAuditRecordsFilter{Limit: 10}, time.Hour)
	if err != nil || len(records) != 1 {
		t.Fatalf("ListAuditRecords()=%#v error=%v", records, err)
	}
	summaries, err := store.ListAuditSessions(ctx, model.ListAuditSessionsFilter{Limit: 10}, time.Hour)
	if err != nil || len(summaries) != 1 || summaries[0].SessionID != "sess-1" {
		t.Fatalf("ListAuditSessions()=%#v error=%v", summaries, err)
	}
	event := model.MetadataEvent{SchemaVersion: model.MetadataEventSchemaVersion, EventID: "evt-1", EventType: "SessionCreated", Source: "session-manager", OccurredAt: time.Now().UTC()}
	if err := store.AppendMetadataEvent(ctx, event); err != nil {
		t.Fatalf("AppendMetadataEvent() error = %v", err)
	}
	events, err := store.ListMetadataEvents(ctx, model.ListMetadataEventsFilter{Limit: 10})
	if err != nil || len(events) != 1 || events[0].EventID != "evt-1" {
		t.Fatalf("ListMetadataEvents()=%#v error=%v", events, err)
	}
	if err := store.prune(ctx, db, 0); err != nil {
		t.Fatalf("prune(disabled) error = %v", err)
	}
	if nullableTime(time.Time{}) != nil || nullableTime(time.Now()) == nil {
		t.Fatal("nullableTime() returned unexpected values")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
