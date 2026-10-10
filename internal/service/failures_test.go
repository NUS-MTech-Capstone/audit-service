package service

import (
	"context"
	"errors"
	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
	"github.com/NUS-MTech-Capstone/audit-service/internal/store"
	"testing"
	"time"
)

type failingStore struct {
	store.Store
	err error
}

func (f failingStore) AppendSessionAuditRecords(context.Context, model.Session, model.AppendSessionAuditRecordsRequest, time.Duration, int) ([]model.SessionAuditRecord, error) {
	return nil, f.err
}
func (f failingStore) ListSessionAuditRecords(context.Context, string, model.ListSessionAuditRecordsFilter, time.Duration) ([]model.SessionAuditRecord, error) {
	return nil, f.err
}
func (f failingStore) ListAuditRecords(context.Context, model.ListAuditRecordsFilter, time.Duration) ([]model.SessionAuditRecord, error) {
	return nil, f.err
}
func (f failingStore) ListAuditSessions(context.Context, model.ListAuditSessionsFilter, time.Duration) ([]model.AuditSessionSummary, error) {
	return nil, f.err
}
func (f failingStore) ListMetadataEvents(context.Context, model.ListMetadataEventsFilter) ([]model.MetadataEvent, error) {
	return nil, f.err
}

func TestStoreFailuresReachCaller(t *testing.T) {
	failure := errors.New("store unavailable")
	svc := New(failingStore{err: failure}, fakeSessionManager{session: model.Session{OwnerPodID: "pod", OwnerInstanceID: "instance"}}, 0, 0)
	calls := []struct {
		name string
		run  func() error
	}{
		{"append", func() error {
			_, e := svc.AppendSessionAuditRecords(t.Context(), "s", model.AppendSessionAuditRecordsRequest{OwnerPodID: "pod", OwnerInstanceID: "instance"})
			return e
		}},
		{"session records", func() error {
			_, e := svc.ListSessionAuditRecords(t.Context(), "s", model.ListSessionAuditRecordsFilter{})
			return e
		}},
		{"global records", func() error { _, e := svc.ListAuditRecords(t.Context(), model.ListAuditRecordsFilter{}); return e }},
		{"summaries", func() error { _, e := svc.ListAuditSessions(t.Context(), model.ListAuditSessionsFilter{}); return e }},
		{"metadata", func() error { _, e := svc.ListMetadataEvents(t.Context(), model.ListMetadataEventsFilter{}); return e }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if e := c.run(); !errors.Is(e, failure) {
				t.Fatalf("error=%v", e)
			}
		})
	}
}

func TestMetadataPaginationAndValidation(t *testing.T) {
	svc := New(store.NewMemoryStore(), fakeSessionManager{}, 0, 0)
	if e := svc.AppendMetadataEvent(t.Context(), model.MetadataEvent{}); !errors.Is(e, model.ErrInvalidMetadataEvent) {
		t.Fatalf("invalid metadata=%v", e)
	}
	for _, id := range []string{"evt-1", "evt-2"} {
		if e := svc.AppendMetadataEvent(t.Context(), model.MetadataEvent{SchemaVersion: model.MetadataEventSchemaVersion, EventID: id, EventType: "PlanApproved", Source: "agent-controlplane", IncidentID: "inc", RunID: "run", PlanHash: "hash", OccurredAt: time.Now().UTC()}); e != nil {
			t.Fatal(e)
		}
	}
	page, e := svc.ListMetadataEvents(t.Context(), model.ListMetadataEventsFilter{IncidentID: "inc", RunID: "run", EventType: "PlanApproved", Limit: 1})
	if e != nil || len(page.Events) != 1 || page.NextCursor != "1" || page.Events[0].PlanHash != "hash" {
		t.Fatalf("page=%+v error=%v", page, e)
	}
	end, e := svc.ListMetadataEvents(t.Context(), model.ListMetadataEventsFilter{Offset: 2, Limit: 1})
	if e != nil || len(end.Events) != 0 || end.NextCursor != "" {
		t.Fatalf("end=%+v error=%v", end, e)
	}
}

func TestSessionRecordCursorAndOwnerDenials(t *testing.T) {
	st := store.NewMemoryStore()
	session := model.Session{SessionID: "s", OwnerPodID: "pod", OwnerInstanceID: "instance"}
	svc := New(st, fakeSessionManager{session: session}, time.Hour, 100)
	req := model.AppendSessionAuditRecordsRequest{OwnerPodID: "pod", OwnerInstanceID: "instance", Records: []model.AppendSessionAuditRecord{{RecordType: model.AuditRecordCommand, CommandText: "pwd"}, {RecordType: model.AuditRecordCommand, CommandText: "whoami"}}}
	if _, e := svc.AppendSessionAuditRecords(t.Context(), "s", req); e != nil {
		t.Fatal(e)
	}
	page, e := svc.ListSessionAuditRecords(t.Context(), "s", model.ListSessionAuditRecordsFilter{Limit: 1})
	if e != nil || len(page.Records) != 1 || page.NextCursor != "1" {
		t.Fatalf("page=%+v err=%v", page, e)
	}
	end, e := svc.ListSessionAuditRecords(t.Context(), "s", model.ListSessionAuditRecordsFilter{AfterSequence: 2, Limit: 1})
	if e != nil || len(end.Records) != 0 || end.NextCursor != "" {
		t.Fatalf("end=%+v err=%v", end, e)
	}
	req.OwnerPodID = "other"
	if _, e := svc.AppendSessionAuditRecords(t.Context(), "s", req); !errors.Is(e, ErrOwnerMismatch) {
		t.Fatal(e)
	}
	failure := errors.New("manager unavailable")
	svc.sessionManager = fakeSessionManager{err: failure}
	if _, e := svc.AppendSessionAuditRecords(t.Context(), "s", req); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	if _, e := svc.ListAuditSessions(t.Context(), model.ListAuditSessionsFilter{}); !errors.Is(e, failure) {
		t.Fatal(e)
	}
}
