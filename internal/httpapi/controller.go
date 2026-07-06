package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
	"github.com/NUS-MTech-Capstone/audit-service/internal/service"
	"github.com/NUS-MTech-Capstone/audit-service/internal/store"
)

func (s *Server) listAuditSessions(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	from, err := parseOptionalTime(query.Get("from"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "from must be RFC3339")
		return
	}
	to, err := parseOptionalTime(query.Get("to"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "to must be RFC3339")
		return
	}
	response, err := s.svc.ListAuditSessions(r.Context(), model.ListAuditSessionsFilter{
		SessionID: query.Get("sessionId"),
		UserID:    query.Get("userId"),
		HostID:    query.Get("hostId"),
		CRID:      query.Get("crId"),
		From:      from,
		To:        to,
		Limit:     parsePositiveInt(query.Get("limit"), 50),
		Offset:    parsePositiveInt(query.Get("cursor"), 0),
	})
	if err != nil {
		writeError(w, statusForError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) getSessionAudit(w http.ResponseWriter, r *http.Request) {
	id, action := parseSessionPath(r.URL.Path)
	if action != "audit/records" {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query()
	afterSequence, err := parseOptionalInt64(query.Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "cursor must be an integer sequence")
		return
	}
	response, err := s.svc.ListSessionAuditRecords(r.Context(), id, model.ListSessionAuditRecordsFilter{
		AfterSequence: afterSequence,
		Limit:         parsePositiveInt(query.Get("limit"), 100),
	})
	if err != nil {
		writeError(w, statusForError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) sessionAuditAction(w http.ResponseWriter, r *http.Request) {
	id, action := parseSessionPath(r.URL.Path)
	if action != "audit/records" {
		http.NotFound(w, r)
		return
	}
	var req model.AppendSessionAuditRecordsRequest
	if !decode(w, r, &req) {
		return
	}
	if req.OwnerPodID == "" || req.OwnerInstanceID == "" {
		writeError(w, http.StatusBadRequest, "ownerPodId and ownerInstanceId are required")
		return
	}
	records, err := s.svc.AppendSessionAuditRecords(r.Context(), id, req)
	if err != nil {
		writeError(w, statusForError(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, model.ListSessionAuditRecordsResponse{Records: records})
}

func parseSessionPath(path string) (string, string) {
	trimmed := strings.TrimPrefix(path, "/sessions/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func parseOptionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, value)
}

func parseOptionalInt64(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	return strconv.ParseInt(value, 10, 64)
}

func parsePositiveInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func statusForError(err error) int {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, service.ErrOwnerMismatch) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}
