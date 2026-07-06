package model

import "time"

type Session struct {
	SessionID       string    `json:"sessionId"`
	UserID          string    `json:"userId"`
	HostID          string    `json:"hostId"`
	CRID            string    `json:"crId"`
	ConnectionType  string    `json:"connectionType"`
	OwnerPodID      string    `json:"ownerPodId"`
	OwnerInstanceID string    `json:"ownerInstanceId"`
	WebsocketURL    string    `json:"websocketUrl"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
	LastHeartbeatAt time.Time `json:"lastHeartbeatAt"`
	LeaseExpiresAt  time.Time `json:"leaseExpiresAt"`
}

const (
	AuditRecordCommand      = "command"
	AuditRecordOutput       = "output"
	AuditRecordControl      = "control"
	AuditRecordSessionEvent = "session_event"
)

type SessionAuditRecord struct {
	SessionID        string    `json:"sessionId"`
	UserID           string    `json:"userId"`
	HostID           string    `json:"hostId"`
	CRID             string    `json:"crId"`
	RecordType       string    `json:"recordType"`
	Sequence         int64     `json:"sequence"`
	CommandID        string    `json:"commandId,omitempty"`
	CommandText      string    `json:"commandText,omitempty"`
	OutputDataBase64 string    `json:"outputDataBase64,omitempty"`
	CreatedAt        time.Time `json:"createdAt"`
	Truncated        bool      `json:"truncated"`
	ByteCount        int       `json:"byteCount"`
}

type AppendSessionAuditRecord struct {
	RecordType       string `json:"recordType"`
	CommandID        string `json:"commandId,omitempty"`
	CommandText      string `json:"commandText,omitempty"`
	OutputDataBase64 string `json:"outputDataBase64,omitempty"`
	CreatedAt        string `json:"createdAt,omitempty"`
	Truncated        bool   `json:"truncated,omitempty"`
	ByteCount        int    `json:"byteCount,omitempty"`
}

type AppendSessionAuditRecordsRequest struct {
	OwnerPodID      string                     `json:"ownerPodId"`
	OwnerInstanceID string                     `json:"ownerInstanceId"`
	Records         []AppendSessionAuditRecord `json:"records"`
}

type ListSessionAuditRecordsFilter struct {
	AfterSequence int64
	Limit         int
}

type ListAuditRecordsFilter struct {
	SessionID  string
	UserID     string
	HostID     string
	CRID       string
	RecordType string
	From       time.Time
	To         time.Time
	Limit      int
	Offset     int
}

type ListSessionAuditRecordsResponse struct {
	Records    []SessionAuditRecord `json:"records"`
	NextCursor string               `json:"nextCursor,omitempty"`
}

type ListAuditSessionsFilter struct {
	SessionID string
	UserID    string
	HostID    string
	CRID      string
	From      time.Time
	To        time.Time
	Limit     int
	Offset    int
}

type AuditSessionSummary struct {
	SessionID      string    `json:"sessionId"`
	UserID         string    `json:"userId"`
	HostID         string    `json:"hostId"`
	CRID           string    `json:"crId"`
	ConnectionType string    `json:"connectionType"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
	LastAuditAt    time.Time `json:"lastAuditAt"`
	RecordCount    int       `json:"recordCount"`
	Truncated      bool      `json:"truncated"`
}

type ListAuditSessionsResponse struct {
	Sessions   []AuditSessionSummary `json:"sessions"`
	NextCursor string                `json:"nextCursor,omitempty"`
}

const MetadataEventSchemaVersion = "2026-07-ops-timeline.v1"

type MetadataEvent struct {
	SchemaVersion string    `json:"schemaVersion"`
	EventID       string    `json:"eventId"`
	EventType     string    `json:"eventType"`
	Source        string    `json:"source"`
	OccurredAt    time.Time `json:"occurredAt"`
	RequestID     string    `json:"requestId,omitempty"`
	UserID        string    `json:"userId,omitempty"`
	SessionID     string    `json:"sessionId,omitempty"`
	HostID        string    `json:"hostId,omitempty"`
	CRID          string    `json:"crId,omitempty"`
	PodID         string    `json:"podId,omitempty"`
	InstanceID    string    `json:"instanceId,omitempty"`
	IncidentID    string    `json:"incidentId,omitempty"`
	RunID         string    `json:"runId,omitempty"`
	Action        string    `json:"action,omitempty"`
	Mode          string    `json:"mode,omitempty"`
	Outcome       string    `json:"outcome,omitempty"`
	ReasonCode    string    `json:"reasonCode,omitempty"`
	PlanHash      string    `json:"planHash,omitempty"`
}

type ListMetadataEventsFilter struct {
	EventType  string
	Source     string
	UserID     string
	SessionID  string
	HostID     string
	CRID       string
	IncidentID string
	RunID      string
	From       time.Time
	To         time.Time
	Limit      int
	Offset     int
}

type ListMetadataEventsResponse struct {
	Events     []MetadataEvent `json:"events"`
	NextCursor string          `json:"nextCursor,omitempty"`
}
