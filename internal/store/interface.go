package store

import (
	"context"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
)

type Store interface {
	AppendSessionAuditRecords(context.Context, model.Session, model.AppendSessionAuditRecordsRequest, time.Duration, int) ([]model.SessionAuditRecord, error)
	ListSessionAuditRecords(context.Context, string, model.ListSessionAuditRecordsFilter, time.Duration) ([]model.SessionAuditRecord, error)
	ListAuditRecords(context.Context, model.ListAuditRecordsFilter, time.Duration) ([]model.SessionAuditRecord, error)
	ListAuditSessions(context.Context, model.ListAuditSessionsFilter, time.Duration) ([]model.AuditSessionSummary, error)
	AppendMetadataEvent(context.Context, model.MetadataEvent) error
	ListMetadataEvents(context.Context, model.ListMetadataEventsFilter) ([]model.MetadataEvent, error)
}
