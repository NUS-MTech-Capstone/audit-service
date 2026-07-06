package httpapi

import (
	"net/http"

	"github.com/NUS-MTech-Capstone/audit-service/api"
)

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /openapi.yaml", serveYAML(api.OpenAPI))
	s.mux.HandleFunc("GET /events", s.listMetadataEvents)
	s.mux.HandleFunc("GET /sessions/audit/records", s.listAuditRecords)
	s.mux.HandleFunc("GET /sessions/audit", s.listAuditSessions)
	s.mux.HandleFunc("GET /sessions/", s.getSessionAudit)
	s.mux.HandleFunc("POST /sessions/", s.sessionAuditAction)
}
