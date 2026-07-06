package store

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
)

func TestMemoryStoreSessionAuditAppendListAndCap(t *testing.T) {
	st := NewMemoryStore()
	st.now = func() time.Time { return time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC) }
	session := model.Session{
		SessionID:      "sess-1",
		UserID:         "user-1",
		HostID:         "host-1",
		CRID:           "cr-1",
		ConnectionType: "ssh",
		Status:         "ACTIVE",
		CreatedAt:      time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC),
	}
	output := base64.StdEncoding.EncodeToString([]byte("hello\n"))
	appended, err := st.AppendSessionAuditRecords(t.Context(), session, model.AppendSessionAuditRecordsRequest{
		Records: []model.AppendSessionAuditRecord{
			{RecordType: model.AuditRecordCommand, CommandID: "cmd-1", CommandText: "pwd"},
			{RecordType: model.AuditRecordOutput, CommandID: "cmd-1", OutputDataBase64: output, ByteCount: 6},
		},
	}, 7*24*time.Hour, 9)
	if err != nil {
		t.Fatalf("AppendSessionAuditRecords() error = %v", err)
	}
	if len(appended) != 2 || appended[0].Sequence != 1 || appended[1].Sequence != 2 {
		t.Fatalf("appended = %#v", appended)
	}
	if appended[1].Truncated || appended[1].OutputDataBase64 != output {
		t.Fatalf("output record = %#v", appended[1])
	}

	appended, err = st.AppendSessionAuditRecords(t.Context(), session, model.AppendSessionAuditRecordsRequest{
		Records: []model.AppendSessionAuditRecord{{RecordType: model.AuditRecordCommand, CommandID: "cmd-2", CommandText: "long-command"}},
	}, 7*24*time.Hour, 9)
	if err != nil {
		t.Fatalf("AppendSessionAuditRecords() second error = %v", err)
	}
	if len(appended) != 1 || !appended[0].Truncated || appended[0].CommandText != "" {
		t.Fatalf("truncated append = %#v", appended)
	}

	records, err := st.ListSessionAuditRecords(t.Context(), session.SessionID, model.ListSessionAuditRecordsFilter{Limit: 10}, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("ListSessionAuditRecords() error = %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %#v", records)
	}
	summaries, err := st.ListAuditSessions(t.Context(), model.ListAuditSessionsFilter{UserID: "user-1", Limit: 10}, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("ListAuditSessions() error = %v", err)
	}
	if len(summaries) != 1 || summaries[0].RecordCount != 3 || !summaries[0].Truncated {
		t.Fatalf("summaries = %#v", summaries)
	}
}

func TestMemoryStoreRejectsInvalidAuditRecords(t *testing.T) {
	st := NewMemoryStore()
	session := model.Session{SessionID: "sess-1"}
	_, err := st.AppendSessionAuditRecords(t.Context(), session, model.AppendSessionAuditRecordsRequest{
		Records: []model.AppendSessionAuditRecord{{RecordType: "unknown"}},
	}, time.Hour, 1024)
	if err == nil {
		t.Fatal("AppendSessionAuditRecords() accepted unsupported recordType")
	}
	_, err = st.AppendSessionAuditRecords(t.Context(), session, model.AppendSessionAuditRecordsRequest{
		Records: []model.AppendSessionAuditRecord{{RecordType: model.AuditRecordOutput, OutputDataBase64: "not-base64"}},
	}, time.Hour, 1024)
	if err == nil {
		t.Fatal("AppendSessionAuditRecords() accepted invalid outputDataBase64")
	}
}

func TestMemoryStoreListAuditRecordsFiltersCursorAndRetention(t *testing.T) {
	st := NewMemoryStore()
	st.now = func() time.Time { return time.Date(2026, 7, 6, 2, 0, 0, 0, time.UTC) }
	session1 := model.Session{SessionID: "sess-1", UserID: "user-1", HostID: "host-1", CRID: "cr-1"}
	session2 := model.Session{SessionID: "sess-2", UserID: "user-2", HostID: "host-1", CRID: "cr-2"}
	_, err := st.AppendSessionAuditRecords(t.Context(), session1, model.AppendSessionAuditRecordsRequest{
		Records: []model.AppendSessionAuditRecord{
			{RecordType: model.AuditRecordCommand, CommandID: "cmd-old", CommandText: "old", CreatedAt: "2026-07-06T00:00:00Z"},
			{RecordType: model.AuditRecordOutput, CommandID: "cmd-old", OutputDataBase64: base64.StdEncoding.EncodeToString([]byte("old\n")), CreatedAt: "2026-07-06T00:00:01Z"},
			{RecordType: model.AuditRecordCommand, CommandID: "cmd-new", CommandText: "new", CreatedAt: "2026-07-06T01:00:00Z"},
		},
	}, 24*time.Hour, 1024)
	if err != nil {
		t.Fatalf("append session1: %v", err)
	}
	_, err = st.AppendSessionAuditRecords(t.Context(), session2, model.AppendSessionAuditRecordsRequest{
		Records: []model.AppendSessionAuditRecord{
			{RecordType: model.AuditRecordCommand, CommandID: "cmd-other", CommandText: "other", CreatedAt: "2026-07-06T01:30:00Z"},
		},
	}, 24*time.Hour, 1024)
	if err != nil {
		t.Fatalf("append session2: %v", err)
	}

	records, err := st.ListAuditRecords(t.Context(), model.ListAuditRecordsFilter{
		HostID: "host-1", RecordType: model.AuditRecordCommand, Limit: 2,
	}, 24*time.Hour)
	if err != nil {
		t.Fatalf("ListAuditRecords() error = %v", err)
	}
	if len(records) != 2 || records[0].SessionID != "sess-2" || records[1].CommandText != "new" {
		t.Fatalf("records = %#v", records)
	}
	records, err = st.ListAuditRecords(t.Context(), model.ListAuditRecordsFilter{
		HostID: "host-1", RecordType: model.AuditRecordCommand, Limit: 2, Offset: 2,
	}, 24*time.Hour)
	if err != nil {
		t.Fatalf("ListAuditRecords() cursor error = %v", err)
	}
	if len(records) != 1 || records[0].CommandText != "old" {
		t.Fatalf("cursor records = %#v", records)
	}
	records, err = st.ListAuditRecords(t.Context(), model.ListAuditRecordsFilter{
		From:  time.Date(2026, 7, 6, 0, 30, 0, 0, time.UTC),
		To:    time.Date(2026, 7, 6, 1, 15, 0, 0, time.UTC),
		Limit: 10,
	}, 24*time.Hour)
	if err != nil {
		t.Fatalf("ListAuditRecords() time error = %v", err)
	}
	if len(records) != 1 || records[0].CommandText != "new" {
		t.Fatalf("time records = %#v", records)
	}
	records, err = st.ListAuditRecords(t.Context(), model.ListAuditRecordsFilter{Limit: 10}, time.Hour)
	if err != nil {
		t.Fatalf("ListAuditRecords() retention error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("retained records = %#v", records)
	}
}
