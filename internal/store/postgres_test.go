package store

import (
	"os"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
)

func TestPostgresStoreAppendListAndPreserveRows(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	st, err := NewPostgresStore(t.Context(), databaseURL)
	if err != nil {
		t.Fatalf("NewPostgresStore() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	session := model.Session{
		SessionID:      "sess-audit-postgres-test",
		UserID:         "user-1",
		HostID:         "host-1",
		CRID:           "cr-1",
		ConnectionType: "ssh",
		Status:         "ACTIVE",
		CreatedAt:      time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC),
	}
	if _, err := st.db.ExecContext(t.Context(), `DELETE FROM session_audit_records WHERE session_id = $1`, session.SessionID); err != nil {
		t.Fatalf("cleanup audit rows: %v", err)
	}
	_, _ = st.db.ExecContext(t.Context(), `
INSERT INTO sessions (
	session_id, user_id, host_id, cr_id, connection_type, owner_pod_id, owner_instance_id,
	websocket_url, status, created_at, last_heartbeat_at, lease_expires_at
) VALUES ($1, $2, $3, $4, $5, 'pod-1', 'inst-1', 'ws://proxy/sessions/test/ws', $6, $7, $7, $8)
ON CONFLICT (session_id) DO NOTHING
`, session.SessionID, session.UserID, session.HostID, session.CRID, session.ConnectionType, session.Status, session.CreatedAt, session.CreatedAt.Add(time.Hour))
	t.Cleanup(func() {
		_, _ = st.db.ExecContext(t.Context(), `DELETE FROM session_audit_records WHERE session_id = $1`, session.SessionID)
	})

	appended, err := st.AppendSessionAuditRecords(t.Context(), session, model.AppendSessionAuditRecordsRequest{
		Records: []model.AppendSessionAuditRecord{{RecordType: model.AuditRecordCommand, CommandID: "cmd-1", CommandText: "pwd"}},
	}, time.Hour, 1024)
	if err != nil {
		t.Fatalf("AppendSessionAuditRecords() error = %v", err)
	}
	if len(appended) != 1 || appended[0].Sequence != 1 {
		t.Fatalf("appended = %#v", appended)
	}
	records, err := st.ListSessionAuditRecords(t.Context(), session.SessionID, model.ListSessionAuditRecordsFilter{Limit: 10}, time.Hour)
	if err != nil {
		t.Fatalf("ListSessionAuditRecords() error = %v", err)
	}
	if len(records) != 1 || records[0].CommandText != "pwd" {
		t.Fatalf("records = %#v", records)
	}
	summaries, err := st.ListAuditSessions(t.Context(), model.ListAuditSessionsFilter{SessionID: session.SessionID, Limit: 10}, time.Hour)
	if err != nil {
		t.Fatalf("ListAuditSessions() error = %v", err)
	}
	if len(summaries) != 1 || summaries[0].RecordCount != 1 {
		t.Fatalf("summaries = %#v", summaries)
	}
}
