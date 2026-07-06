package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
	"github.com/NUS-MTech-Capstone/audit-service/internal/sessionmanager"
	"github.com/NUS-MTech-Capstone/audit-service/internal/store"
)

var ErrOwnerMismatch = errors.New("session owner mismatch")

type SessionManager interface {
	GetSession(context.Context, string) (model.Session, error)
}

type Service struct {
	store          store.Store
	sessionManager SessionManager
	auditRetention time.Duration
	auditMaxBytes  int
}

func New(st store.Store, sm SessionManager, auditRetention time.Duration, auditMaxBytes int) *Service {
	if auditRetention <= 0 {
		auditRetention = 7 * 24 * time.Hour
	}
	if auditMaxBytes <= 0 {
		auditMaxBytes = 16 * 1024 * 1024
	}
	return &Service{store: st, sessionManager: sm, auditRetention: auditRetention, auditMaxBytes: auditMaxBytes}
}

func (s *Service) AppendSessionAuditRecords(
	ctx context.Context,
	sessionID string,
	req model.AppendSessionAuditRecordsRequest,
) ([]model.SessionAuditRecord, error) {
	session, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		return nil, classifySessionManagerError(err)
	}
	if session.OwnerPodID != req.OwnerPodID || session.OwnerInstanceID != req.OwnerInstanceID {
		return nil, ErrOwnerMismatch
	}
	return s.store.AppendSessionAuditRecords(ctx, session, req, s.auditRetention, s.auditMaxBytes)
}

func (s *Service) ListSessionAuditRecords(
	ctx context.Context,
	sessionID string,
	filter model.ListSessionAuditRecordsFilter,
) (model.ListSessionAuditRecordsResponse, error) {
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 100
	}
	if _, err := s.sessionManager.GetSession(ctx, sessionID); err != nil {
		return model.ListSessionAuditRecordsResponse{}, classifySessionManagerError(err)
	}
	records, err := s.store.ListSessionAuditRecords(ctx, sessionID, filter, s.auditRetention)
	if err != nil {
		return model.ListSessionAuditRecordsResponse{}, err
	}
	response := model.ListSessionAuditRecordsResponse{Records: records}
	if len(records) == filter.Limit {
		response.NextCursor = strconv.FormatInt(records[len(records)-1].Sequence, 10)
	}
	return response, nil
}

func (s *Service) ListAuditSessions(
	ctx context.Context,
	filter model.ListAuditSessionsFilter,
) (model.ListAuditSessionsResponse, error) {
	if filter.Limit <= 0 || filter.Limit > 200 {
		filter.Limit = 50
	}
	sessions, err := s.store.ListAuditSessions(ctx, filter, s.auditRetention)
	if err != nil {
		return model.ListAuditSessionsResponse{}, err
	}
	for i := range sessions {
		session, err := s.sessionManager.GetSession(ctx, sessions[i].SessionID)
		if err != nil {
			return model.ListAuditSessionsResponse{}, classifySessionManagerError(err)
		}
		sessions[i].ConnectionType = session.ConnectionType
		sessions[i].Status = session.Status
		sessions[i].CreatedAt = session.CreatedAt
	}
	response := model.ListAuditSessionsResponse{Sessions: sessions}
	if len(sessions) == filter.Limit {
		response.NextCursor = strconv.Itoa(filter.Offset + len(sessions))
	}
	return response, nil
}

func classifySessionManagerError(err error) error {
	if errors.Is(err, sessionmanager.ErrNotFound) {
		return store.ErrNotFound
	}
	return err
}
