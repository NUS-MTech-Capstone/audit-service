package service

import (
	"errors"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
	"github.com/NUS-MTech-Capstone/audit-service/internal/sessionmanager"
	"github.com/NUS-MTech-Capstone/audit-service/internal/store"
)

func TestServiceListSessionAuditRecordsDefaultsLimitAndCursor(t *testing.T) {
	session := model.Session{
		SessionID: "sess-1", UserID: "user-1", HostID: "host-1", CRID: "cr-1",
		OwnerPodID: "pod-1", OwnerInstanceID: "inst-1",
	}
	svc := New(store.NewMemoryStore(), fakeSessionManager{session: session}, time.Hour, 1024)
	_, err := svc.AppendSessionAuditRecords(t.Context(), "sess-1", model.AppendSessionAuditRecordsRequest{
		OwnerPodID: "pod-1", OwnerInstanceID: "inst-1",
		Records: []model.AppendSessionAuditRecord{
			{RecordType: model.AuditRecordCommand, CommandID: "cmd-1", CommandText: "pwd"},
			{RecordType: model.AuditRecordSessionEvent, CommandText: "detached"},
		},
	})
	if err != nil {
		t.Fatalf("AppendSessionAuditRecords() error = %v", err)
	}

	response, err := svc.ListSessionAuditRecords(t.Context(), "sess-1", model.ListSessionAuditRecordsFilter{Limit: 1})
	if err != nil {
		t.Fatalf("ListSessionAuditRecords() error = %v", err)
	}
	if len(response.Records) != 1 || response.NextCursor != "1" {
		t.Fatalf("response = %#v", response)
	}

	response, err = svc.ListSessionAuditRecords(t.Context(), "sess-1", model.ListSessionAuditRecordsFilter{Limit: 999})
	if err != nil {
		t.Fatalf("ListSessionAuditRecords() capped error = %v", err)
	}
	if len(response.Records) != 2 {
		t.Fatalf("capped response = %#v", response)
	}
}

func TestServiceMetadataEventsAppendListAndCursor(t *testing.T) {
	svc := New(store.NewMemoryStore(), fakeSessionManager{session: model.Session{}}, time.Hour, 1024)
	base := time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC)
	for _, event := range []model.MetadataEvent{
		{SchemaVersion: model.MetadataEventSchemaVersion, EventID: "evt-1", EventType: "SessionStarted", Source: "proxy", OccurredAt: base},
		{SchemaVersion: model.MetadataEventSchemaVersion, EventID: "evt-2", EventType: "SessionClosed", Source: "proxy", OccurredAt: base.Add(time.Minute)},
	} {
		if err := svc.AppendMetadataEvent(t.Context(), event); err != nil {
			t.Fatalf("AppendMetadataEvent() error = %v", err)
		}
	}

	response, err := svc.ListMetadataEvents(t.Context(), model.ListMetadataEventsFilter{Source: "proxy", Limit: 1})
	if err != nil {
		t.Fatalf("ListMetadataEvents() error = %v", err)
	}
	if len(response.Events) != 1 || response.Events[0].EventID != "evt-2" || response.NextCursor != "1" {
		t.Fatalf("response = %#v", response)
	}
}

func TestServiceListAuditSessionsMapsMissingHydrationSession(t *testing.T) {
	session := model.Session{SessionID: "sess-1", UserID: "user-1", OwnerPodID: "pod-1", OwnerInstanceID: "inst-1"}
	st := store.NewMemoryStore()
	svc := New(st, fakeSessionManager{session: session}, time.Hour, 1024)
	_, err := svc.AppendSessionAuditRecords(t.Context(), "sess-1", model.AppendSessionAuditRecordsRequest{
		OwnerPodID: "pod-1", OwnerInstanceID: "inst-1",
		Records: []model.AppendSessionAuditRecord{{RecordType: model.AuditRecordCommand, CommandText: "pwd"}},
	})
	if err != nil {
		t.Fatalf("AppendSessionAuditRecords() error = %v", err)
	}

	svc = New(st, fakeSessionManager{err: sessionmanager.ErrNotFound}, time.Hour, 1024)
	_, err = svc.ListAuditSessions(t.Context(), model.ListAuditSessionsFilter{Limit: 10})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ListAuditSessions() error = %v, want store.ErrNotFound", err)
	}
}
