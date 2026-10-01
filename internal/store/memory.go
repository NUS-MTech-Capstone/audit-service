package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
)

type MemoryStore struct {
	mu      sync.Mutex
	records map[string][]model.SessionAuditRecord
	events  map[string]model.MetadataEvent
	now     func() time.Time
}

var _ Store = (*MemoryStore)(nil)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records: make(map[string][]model.SessionAuditRecord),
		events:  make(map[string]model.MetadataEvent),
		now:     time.Now,
	}
}

func (s *MemoryStore) AppendSessionAuditRecords(
	_ context.Context,
	session model.Session,
	req model.AppendSessionAuditRecordsRequest,
	retention time.Duration,
	maxBytes int,
) ([]model.SessionAuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(retention)
	if len(req.Records) == 0 {
		return []model.SessionAuditRecord{}, nil
	}
	existing := s.records[session.SessionID]
	sequence := int64(0)
	if len(existing) > 0 {
		sequence = existing[len(existing)-1].Sequence
	}
	usedBytes := auditByteTotal(existing)
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
			addBytes = truncateAuditRecord(&record, remaining)
		}
		sequence++
		record.Sequence = sequence
		existing = append(existing, record)
		appended = append(appended, record)
		usedBytes += addBytes
		if record.Truncated {
			break
		}
	}
	s.records[session.SessionID] = existing
	return appended, nil
}

func (s *MemoryStore) ListSessionAuditRecords(
	_ context.Context,
	sessionID string,
	filter model.ListSessionAuditRecordsFilter,
	retention time.Duration,
) ([]model.SessionAuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(retention)
	records := make([]model.SessionAuditRecord, 0)
	for _, record := range s.records[sessionID] {
		if record.Sequence <= filter.AfterSequence {
			continue
		}
		records = append(records, record)
		if filter.Limit > 0 && len(records) >= filter.Limit {
			break
		}
	}
	return records, nil
}

func (s *MemoryStore) ListAuditRecords(
	_ context.Context,
	filter model.ListAuditRecordsFilter,
	retention time.Duration,
) ([]model.SessionAuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(retention)
	records := make([]model.SessionAuditRecord, 0)
	for _, sessionRecords := range s.records {
		for _, record := range sessionRecords {
			if filter.SessionID != "" && record.SessionID != filter.SessionID {
				continue
			}
			if filter.UserID != "" && record.UserID != filter.UserID {
				continue
			}
			if filter.HostID != "" && record.HostID != filter.HostID {
				continue
			}
			if filter.CRID != "" && record.CRID != filter.CRID {
				continue
			}
			if filter.RecordType != "" && record.RecordType != filter.RecordType {
				continue
			}
			if !filter.From.IsZero() && record.CreatedAt.Before(filter.From) {
				continue
			}
			if !filter.To.IsZero() && record.CreatedAt.After(filter.To) {
				continue
			}
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			if records[i].SessionID == records[j].SessionID {
				return records[i].Sequence > records[j].Sequence
			}
			return records[i].SessionID < records[j].SessionID
		}
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})
	if filter.Offset > len(records) {
		return []model.SessionAuditRecord{}, nil
	}
	end := filter.Offset + filter.Limit
	if filter.Limit <= 0 || end > len(records) {
		end = len(records)
	}
	return append([]model.SessionAuditRecord(nil), records[filter.Offset:end]...), nil
}

func (s *MemoryStore) ListAuditSessions(
	_ context.Context,
	filter model.ListAuditSessionsFilter,
	retention time.Duration,
) ([]model.AuditSessionSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(retention)
	summaries := make([]model.AuditSessionSummary, 0)
	for sessionID, records := range s.records {
		if len(records) == 0 {
			continue
		}
		first := records[0]
		lastAuditAt := records[len(records)-1].CreatedAt
		if filter.SessionID != "" && sessionID != filter.SessionID {
			continue
		}
		if filter.UserID != "" && first.UserID != filter.UserID {
			continue
		}
		if filter.HostID != "" && first.HostID != filter.HostID {
			continue
		}
		if filter.CRID != "" && first.CRID != filter.CRID {
			continue
		}
		if !filter.From.IsZero() && lastAuditAt.Before(filter.From) {
			continue
		}
		if !filter.To.IsZero() && lastAuditAt.After(filter.To) {
			continue
		}
		truncated := false
		for _, record := range records {
			if record.Truncated {
				truncated = true
				break
			}
		}
		summaries = append(summaries, model.AuditSessionSummary{
			SessionID:   sessionID,
			UserID:      first.UserID,
			HostID:      first.HostID,
			CRID:        first.CRID,
			LastAuditAt: lastAuditAt,
			RecordCount: len(records),
			Truncated:   truncated,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].LastAuditAt.Equal(summaries[j].LastAuditAt) {
			return summaries[i].SessionID < summaries[j].SessionID
		}
		return summaries[i].LastAuditAt.After(summaries[j].LastAuditAt)
	})
	if filter.Offset > len(summaries) {
		return []model.AuditSessionSummary{}, nil
	}
	end := filter.Offset + filter.Limit
	if filter.Limit <= 0 || end > len(summaries) {
		end = len(summaries)
	}
	return append([]model.AuditSessionSummary(nil), summaries[filter.Offset:end]...), nil
}

func (s *MemoryStore) AppendMetadataEvent(_ context.Context, event model.MetadataEvent) error {
	if err := model.ValidateMetadataEvent(event); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event.OccurredAt = event.OccurredAt.UTC()
	if _, exists := s.events[event.EventID]; exists {
		return nil
	}
	s.events[event.EventID] = event
	return nil
}

func (s *MemoryStore) ListMetadataEvents(_ context.Context, filter model.ListMetadataEventsFilter) ([]model.MetadataEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]model.MetadataEvent, 0)
	for _, event := range s.events {
		if filter.EventType != "" && event.EventType != filter.EventType {
			continue
		}
		if filter.Source != "" && event.Source != filter.Source {
			continue
		}
		if filter.UserID != "" && event.UserID != filter.UserID {
			continue
		}
		if filter.SessionID != "" && event.SessionID != filter.SessionID {
			continue
		}
		if filter.HostID != "" && event.HostID != filter.HostID {
			continue
		}
		if filter.CRID != "" && event.CRID != filter.CRID {
			continue
		}
		if filter.IncidentID != "" && event.IncidentID != filter.IncidentID {
			continue
		}
		if filter.RunID != "" && event.RunID != filter.RunID {
			continue
		}
		if !filter.From.IsZero() && event.OccurredAt.Before(filter.From) {
			continue
		}
		if !filter.To.IsZero() && event.OccurredAt.After(filter.To) {
			continue
		}
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].EventID < events[j].EventID
		}
		return events[i].OccurredAt.After(events[j].OccurredAt)
	})
	if filter.Offset > len(events) {
		return []model.MetadataEvent{}, nil
	}
	end := filter.Offset + filter.Limit
	if filter.Limit <= 0 || end > len(events) {
		end = len(events)
	}
	return append([]model.MetadataEvent(nil), events[filter.Offset:end]...), nil
}

func (s *MemoryStore) prune(retention time.Duration) {
	if retention <= 0 {
		return
	}
	cutoff := s.now().UTC().Add(-retention)
	for sessionID, records := range s.records {
		kept := records[:0]
		for _, record := range records {
			if !record.CreatedAt.Before(cutoff) {
				kept = append(kept, record)
			}
		}
		if len(kept) == 0 {
			delete(s.records, sessionID)
			continue
		}
		s.records[sessionID] = append([]model.SessionAuditRecord(nil), kept...)
	}
}

func buildAuditRecord(session model.Session, incoming model.AppendSessionAuditRecord, fallback time.Time) (model.SessionAuditRecord, int, error) {
	createdAt := fallback
	if incoming.CreatedAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, incoming.CreatedAt)
		if err != nil {
			return model.SessionAuditRecord{}, 0, fmt.Errorf("invalid audit createdAt: %w", err)
		}
		createdAt = parsed.UTC()
	}
	record := model.SessionAuditRecord{
		SessionID:   session.SessionID,
		UserID:      session.UserID,
		HostID:      session.HostID,
		CRID:        session.CRID,
		RecordType:  incoming.RecordType,
		CommandID:   incoming.CommandID,
		CommandText: incoming.CommandText,
		CreatedAt:   createdAt,
		Truncated:   incoming.Truncated,
	}
	var bodyBytes int
	switch incoming.RecordType {
	case model.AuditRecordCommand:
		record.ByteCount = len([]byte(incoming.CommandText))
		bodyBytes = record.ByteCount
	case model.AuditRecordOutput:
		data, err := base64.StdEncoding.DecodeString(incoming.OutputDataBase64)
		if err != nil {
			return model.SessionAuditRecord{}, 0, fmt.Errorf("invalid outputDataBase64: %w", err)
		}
		record.OutputDataBase64 = base64.StdEncoding.EncodeToString(data)
		if incoming.ByteCount > 0 {
			record.ByteCount = incoming.ByteCount
		} else {
			record.ByteCount = len(data)
		}
		bodyBytes = len(data)
	case model.AuditRecordControl, model.AuditRecordSessionEvent:
		record.ByteCount = incoming.ByteCount
	default:
		return model.SessionAuditRecord{}, 0, errors.New("unsupported audit recordType")
	}
	return record, bodyBytes, nil
}

func auditByteTotal(records []model.SessionAuditRecord) int {
	total := 0
	for _, record := range records {
		switch record.RecordType {
		case model.AuditRecordCommand:
			total += len([]byte(record.CommandText))
		case model.AuditRecordOutput:
			data, err := base64.StdEncoding.DecodeString(record.OutputDataBase64)
			if err == nil {
				total += len(data)
			}
		}
	}
	return total
}

func truncateAuditRecord(record *model.SessionAuditRecord, remaining int) int {
	record.Truncated = true
	switch record.RecordType {
	case model.AuditRecordCommand:
		data := []byte(record.CommandText)
		if remaining < len(data) {
			end := remaining
			for end > 0 && !utf8.Valid(data[:end]) {
				end--
			}
			record.CommandText = string(data[:end])
		}
		return len([]byte(record.CommandText))
	case model.AuditRecordOutput:
		data, err := base64.StdEncoding.DecodeString(record.OutputDataBase64)
		if err == nil && remaining < len(data) {
			record.OutputDataBase64 = base64.StdEncoding.EncodeToString(data[:remaining])
			return remaining
		}
		return len(data)
	}
	return 0
}
