package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
	"github.com/NUS-MTech-Capstone/audit-service/internal/sessionmanager"
	"github.com/NUS-MTech-Capstone/audit-service/internal/store"
)

type fakeSessionManager struct {
	session model.Session
	err     error
}

func (f fakeSessionManager) GetSession(context.Context, string) (model.Session, error) {
	if f.err != nil {
		return model.Session{}, f.err
	}
	return f.session, nil
}

func TestServiceRejectsStaleOwnerInstance(t *testing.T) {
	session := model.Session{SessionID: "sess-1", OwnerPodID: "pod-1", OwnerInstanceID: "inst-1"}
	svc := New(store.NewMemoryStore(), fakeSessionManager{session: session}, time.Hour, 1024)
	_, err := svc.AppendSessionAuditRecords(t.Context(), "sess-1", model.AppendSessionAuditRecordsRequest{
		OwnerPodID:      "pod-1",
		OwnerInstanceID: "stale",
		Records:         []model.AppendSessionAuditRecord{{RecordType: model.AuditRecordCommand, CommandText: "pwd"}},
	})
	if !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("AppendSessionAuditRecords() error = %v, want ErrOwnerMismatch", err)
	}
}

func TestServiceAppendsAndHydratesAuditSummaries(t *testing.T) {
	createdAt := time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC)
	session := model.Session{
		SessionID:       "sess-1",
		UserID:          "user-1",
		HostID:          "host-1",
		CRID:            "cr-1",
		ConnectionType:  "ssh",
		OwnerPodID:      "pod-1",
		OwnerInstanceID: "inst-1",
		Status:          "ACTIVE",
		CreatedAt:       createdAt,
	}
	svc := New(store.NewMemoryStore(), fakeSessionManager{session: session}, time.Hour, 1024)
	records, err := svc.AppendSessionAuditRecords(t.Context(), "sess-1", model.AppendSessionAuditRecordsRequest{
		OwnerPodID:      "pod-1",
		OwnerInstanceID: "inst-1",
		Records:         []model.AppendSessionAuditRecord{{RecordType: model.AuditRecordCommand, CommandText: "pwd"}},
	})
	if err != nil {
		t.Fatalf("AppendSessionAuditRecords() error = %v", err)
	}
	if len(records) != 1 || records[0].UserID != "user-1" {
		t.Fatalf("records = %#v", records)
	}
	response, err := svc.ListAuditSessions(t.Context(), model.ListAuditSessionsFilter{UserID: "user-1", Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditSessions() error = %v", err)
	}
	if len(response.Sessions) != 1 || response.Sessions[0].ConnectionType != "ssh" || !response.Sessions[0].CreatedAt.Equal(createdAt) {
		t.Fatalf("response = %#v", response)
	}
}

func TestServiceMapsMissingSession(t *testing.T) {
	svc := New(store.NewMemoryStore(), fakeSessionManager{err: sessionmanager.ErrNotFound}, time.Hour, 1024)
	_, err := svc.ListSessionAuditRecords(t.Context(), "missing", model.ListSessionAuditRecordsFilter{})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ListSessionAuditRecords() error = %v, want store.ErrNotFound", err)
	}
}
