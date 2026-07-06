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
