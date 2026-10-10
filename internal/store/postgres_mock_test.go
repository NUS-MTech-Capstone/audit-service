package store

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
)

var auditNow = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
var auditColumns = []string{"session_id", "user_id", "host_id", "cr_id", "record_type", "sequence", "command_id", "command_text", "output_data", "created_at", "truncated", "byte_count"}

func mockAuditStore(t *testing.T) (*PostgresStore, sqlmock.Sqlmock) {
	t.Helper()
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		_ = db.Close()
	})
	return &PostgresStore{db: db, now: func() time.Time { return auditNow }}, m
}
func expectPrune(m sqlmock.Sqlmock) {
	m.ExpectExec("DELETE FROM session_audit_records").WithArgs(auditNow.Add(-time.Hour)).WillReturnResult(sqlmock.NewResult(0, 2))
}
func auditRows() *sqlmock.Rows {
	return sqlmock.NewRows(auditColumns).AddRow("s", "u", "h", "cr", "output", int64(9), "cmd", "", []byte("ok"), auditNow, false, 2)
}

func TestSQLAuditAppendCommitsBoundedOutput(t *testing.T) {
	s, m := mockAuditStore(t)
	m.ExpectBegin()
	expectPrune(m)
	m.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("s").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery("SELECT COALESCE\\(MAX\\(sequence\\)").WithArgs("s").WillReturnRows(sqlmock.NewRows([]string{"sequence"}).AddRow(8))
	m.ExpectQuery("SELECT COALESCE\\(SUM").WithArgs("s", model.AuditRecordCommand, model.AuditRecordOutput).WillReturnRows(sqlmock.NewRows([]string{"bytes"}).AddRow(3))
	m.ExpectExec("INSERT INTO session_audit_records").WithArgs("s", "u", "h", "cr", model.AuditRecordOutput, int64(9), "cmd", "", []byte("ok"), auditNow, true, 4).WillReturnResult(sqlmock.NewResult(1, 1))
	m.ExpectCommit()
	got, err := s.AppendSessionAuditRecords(t.Context(), model.Session{SessionID: "s", UserID: "u", HostID: "h", CRID: "cr"}, model.AppendSessionAuditRecordsRequest{Records: []model.AppendSessionAuditRecord{{RecordType: model.AuditRecordOutput, CommandID: "cmd", OutputDataBase64: base64.StdEncoding.EncodeToString([]byte("okay"))}}}, time.Hour, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Sequence != 9 || !got[0].Truncated || got[0].ByteCount != 4 || got[0].OutputDataBase64 != base64.StdEncoding.EncodeToString([]byte("ok")) {
		t.Fatalf("bounded append=%+v", got)
	}
}

func TestSQLAuditAppendRollsBackFailures(t *testing.T) {
	failure := errors.New("database unavailable")
	for _, stage := range []string{"begin", "prune", "lock", "sequence", "bytes", "record", "insert", "commit"} {
		t.Run(stage, func(t *testing.T) {
			s, m := mockAuditStore(t)
			b := m.ExpectBegin()
			if stage == "begin" {
				b.WillReturnError(failure)
			} else {
				p := m.ExpectExec("DELETE FROM session_audit_records")
				if stage == "prune" {
					p.WillReturnError(failure)
				} else {
					p.WillReturnResult(sqlmock.NewResult(0, 0))
					lock := m.ExpectExec("SELECT pg_advisory_xact_lock")
					if stage == "lock" {
						lock.WillReturnError(failure)
					} else {
						lock.WillReturnResult(sqlmock.NewResult(0, 1))
						seq := m.ExpectQuery("SELECT COALESCE\\(MAX")
						if stage == "sequence" {
							seq.WillReturnError(failure)
						} else {
							seq.WillReturnRows(sqlmock.NewRows([]string{"seq"}).AddRow(0))
							bytes := m.ExpectQuery("SELECT COALESCE\\(SUM")
							if stage == "bytes" {
								bytes.WillReturnError(failure)
							} else {
								bytes.WillReturnRows(sqlmock.NewRows([]string{"bytes"}).AddRow(0))
								if stage != "record" {
									insert := m.ExpectExec("INSERT INTO session_audit_records")
									if stage == "insert" {
										insert.WillReturnError(failure)
									} else {
										insert.WillReturnResult(sqlmock.NewResult(1, 1))
										m.ExpectCommit().WillReturnError(failure)
									}
								}
							}
						}
					}
				}
				if stage != "commit" {
					m.ExpectRollback()
				}
			}
			kind := model.AuditRecordCommand
			if stage == "record" {
				kind = "invalid"
			}
			got, err := s.AppendSessionAuditRecords(t.Context(), model.Session{SessionID: "s"}, model.AppendSessionAuditRecordsRequest{Records: []model.AppendSessionAuditRecord{{RecordType: kind, CommandText: "pwd"}}}, time.Hour, 100)
			if err == nil || got != nil {
				t.Fatalf("failure returned records: %v, %v", got, err)
			}
			if stage != "record" && !errors.Is(err, failure) {
				t.Fatalf("lost cause: %v", err)
			}
		})
	}
}

func TestSQLAuditReadFiltersAndDecoding(t *testing.T) {
	s, m := mockAuditStore(t)
	expectPrune(m)
	m.ExpectQuery("SELECT session_id.*FROM session_audit_records.*sequence >").WithArgs("s", int64(8), 2).WillReturnRows(auditRows()).RowsWillBeClosed()
	got, err := s.ListSessionAuditRecords(t.Context(), "s", model.ListSessionAuditRecordsFilter{AfterSequence: 8, Limit: 2}, time.Hour)
	if err != nil || len(got) != 1 || got[0].OutputDataBase64 != "b2s=" || got[0].Sequence != 9 {
		t.Fatalf("read=%+v err=%v", got, err)
	}
	expectPrune(m)
	m.ExpectQuery("SELECT session_id.*ORDER BY created_at DESC").WithArgs("s", "u", "h", "cr", model.AuditRecordOutput, auditNow.Add(-time.Minute), nil, 2, 3).WillReturnRows(auditRows()).RowsWillBeClosed()
	got, err = s.ListAuditRecords(t.Context(), model.ListAuditRecordsFilter{SessionID: "s", UserID: "u", HostID: "h", CRID: "cr", RecordType: model.AuditRecordOutput, From: auditNow.Add(-time.Minute), Limit: 2, Offset: 3}, time.Hour)
	if err != nil || len(got) != 1 || got[0].HostID != "h" {
		t.Fatalf("filtered=%+v err=%v", got, err)
	}
	expectPrune(m)
	m.ExpectQuery("SELECT session_id.*MAX\\(created_at\\)").WithArgs("s", "u", "h", "cr", nil, auditNow, 2, 4).WillReturnRows(sqlmock.NewRows([]string{"session_id", "user_id", "host_id", "cr_id", "last_audit_at", "count", "truncated"}).AddRow("s", "u", "h", "cr", auditNow, 5, true)).RowsWillBeClosed()
	summaries, err := s.ListAuditSessions(t.Context(), model.ListAuditSessionsFilter{SessionID: "s", UserID: "u", HostID: "h", CRID: "cr", To: auditNow, Limit: 2, Offset: 4}, time.Hour)
	if err != nil || len(summaries) != 1 || summaries[0].RecordCount != 5 || !summaries[0].Truncated {
		t.Fatalf("summary=%+v err=%v", summaries, err)
	}
}

func TestSQLAuditReadFailures(t *testing.T) {
	for _, operation := range []string{"session", "global", "summary"} {
		for _, stage := range []string{"prune", "query", "scan", "iteration"} {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				s, m := mockAuditStore(t)
				failure := errors.New("read failure")
				p := m.ExpectExec("DELETE FROM session_audit_records")
				if stage == "prune" {
					p.WillReturnError(failure)
				} else {
					p.WillReturnResult(sqlmock.NewResult(0, 0))
					q := m.ExpectQuery("SELECT session_id")
					switch stage {
					case "query":
						q.WillReturnError(failure)
					case "scan":
						q.WillReturnRows(sqlmock.NewRows([]string{"wrong"}).AddRow("invalid"))
					case "iteration":
						q.WillReturnRows(auditRows().RowError(0, failure))
					}
				}
				var err error
				switch operation {
				case "session":
					_, err = s.ListSessionAuditRecords(t.Context(), "s", model.ListSessionAuditRecordsFilter{}, time.Hour)
				case "global":
					_, err = s.ListAuditRecords(t.Context(), model.ListAuditRecordsFilter{}, time.Hour)
				case "summary":
					_, err = s.ListAuditSessions(t.Context(), model.ListAuditSessionsFilter{}, time.Hour)
				}
				if err == nil {
					t.Fatal("read failure silently accepted")
				}
				if stage != "scan" && !errors.Is(err, failure) {
					t.Fatalf("lost database cause: %v", err)
				}
			})
		}
	}
}

func TestSQLMetadataValidationAndIdempotentInsert(t *testing.T) {
	s, m := mockAuditStore(t)
	if err := s.AppendMetadataEvent(t.Context(), model.MetadataEvent{}); !errors.Is(err, model.ErrInvalidMetadataEvent) {
		t.Fatalf("invalid metadata: %v", err)
	}
	event := model.MetadataEvent{SchemaVersion: model.MetadataEventSchemaVersion, EventID: "evt-1", EventType: "SessionCreated", Source: "session-manager", OccurredAt: auditNow}
	for _, n := range []int64{1, 0} {
		m.ExpectExec("INSERT INTO metadata_events.*ON CONFLICT \\(event_id\\) DO NOTHING").WithArgs(event.EventID, event.SchemaVersion, event.EventType, event.Source, auditNow, "", "", "", "", "", "", "", "", "", "", "", "", "", "").WillReturnResult(sqlmock.NewResult(0, n))
		if err := s.AppendMetadataEvent(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	failure := errors.New("insert failed")
	m.ExpectExec("INSERT INTO metadata_events").WillReturnError(failure)
	if err := s.AppendMetadataEvent(t.Context(), event); !errors.Is(err, failure) {
		t.Fatalf("error=%v", err)
	}
}

func TestSQLMetadataFilterAndFailures(t *testing.T) {
	columns := []string{"schema", "id", "type", "source", "at", "request", "user", "session", "host", "cr", "pod", "instance", "incident", "run", "action", "mode", "outcome", "reason", "hash"}
	for _, stage := range []string{"success", "query", "scan", "iteration"} {
		t.Run(stage, func(t *testing.T) {
			s, m := mockAuditStore(t)
			q := m.ExpectQuery("SELECT schema_version.*LIMIT").WithArgs("PlanApproved", "agent-controlplane", "u", "s", "h", "cr", "inc", "run", nil, auditNow, 10, 20)
			failure := errors.New("read failed")
			rows := sqlmock.NewRows(columns).AddRow(model.MetadataEventSchemaVersion, "evt", "PlanApproved", "agent-controlplane", auditNow, "request", "u", "s", "h", "cr", "pod", "instance", "inc", "run", "approve", "", "approved", "", "hash")
			switch stage {
			case "success":
				q.WillReturnRows(rows).RowsWillBeClosed()
			case "query":
				q.WillReturnError(failure)
			case "scan":
				q.WillReturnRows(sqlmock.NewRows([]string{"wrong"}).AddRow("bad"))
			case "iteration":
				q.WillReturnRows(rows.RowError(0, failure))
			}
			got, err := s.ListMetadataEvents(t.Context(), model.ListMetadataEventsFilter{EventType: "PlanApproved", Source: "agent-controlplane", UserID: "u", SessionID: "s", HostID: "h", CRID: "cr", IncidentID: "inc", RunID: "run", To: auditNow, Limit: 10, Offset: 20})
			if stage == "success" {
				if err != nil || len(got) != 1 || got[0].PlanHash != "hash" || got[0].InstanceID != "instance" {
					t.Fatalf("metadata=%+v err=%v", got, err)
				}
			} else if err == nil {
				t.Fatal("read failure ignored")
			}
		})
	}
}

func TestSQLMigrationErrorAndDisabledRetention(t *testing.T) {
	s, m := mockAuditStore(t)
	failure := errors.New("DDL denied")
	m.ExpectExec("CREATE TABLE IF NOT EXISTS session_audit_records").WillReturnError(failure)
	if err := s.migrate(t.Context()); !errors.Is(err, failure) || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("migration=%v", err)
	}
	if err := s.prune(t.Context(), s.db, 0); err != nil {
		t.Fatal(err)
	}
}
