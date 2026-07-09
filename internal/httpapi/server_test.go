package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
	"github.com/NUS-MTech-Capstone/audit-service/internal/service"
	"github.com/NUS-MTech-Capstone/audit-service/internal/store"
)

type httpSessionManager struct {
	session model.Session
}

func (f httpSessionManager) GetSession(_ context.Context, _ string) (model.Session, error) {
	return f.session, nil
}

func newHTTPTestServer() *Server {
	session := model.Session{
		SessionID:       "sess-1",
		UserID:          "user-1",
		HostID:          "host-1",
		CRID:            "cr-1",
		ConnectionType:  "ssh",
		OwnerPodID:      "pod-1",
		OwnerInstanceID: "inst-1",
		Status:          "ACTIVE",
		CreatedAt:       time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC),
	}
	return New(service.New(store.NewMemoryStore(), httpSessionManager{session: session}, time.Hour, 1024))
}

func TestSessionAuditHTTPAppendAndList(t *testing.T) {
	server := newHTTPTestServer()
	doJSON(t, server, http.MethodPost, "/sessions/sess-1/audit/records", `{"ownerPodId":"pod-1","ownerInstanceId":"wrong","records":[]}`, http.StatusBadRequest)
	appendResponse := doJSON(t, server, http.MethodPost, "/sessions/sess-1/audit/records", `{
		"ownerPodId":"pod-1",
		"ownerInstanceId":"inst-1",
		"records":[
			{"recordType":"command","commandId":"cmd-1","commandText":"pwd"},
			{"recordType":"output","commandId":"cmd-1","outputDataBase64":"aG9tZQo=","byteCount":5}
		]
	}`, http.StatusCreated)
	if !strings.Contains(appendResponse.Body.String(), `"sequence":1`) {
		t.Fatalf("append body = %s", appendResponse.Body.String())
	}

	records := doJSON(t, server, http.MethodGet, "/sessions/sess-1/audit/records?limit=10", ``, http.StatusOK)
	if !strings.Contains(records.Body.String(), `"commandText":"pwd"`) {
		t.Fatalf("records body = %s", records.Body.String())
	}
	globalRecords := doJSON(t, server, http.MethodGet, "/sessions/audit/records?hostId=host-1&recordType=command&limit=10", ``, http.StatusOK)
	if !strings.Contains(globalRecords.Body.String(), `"commandText":"pwd"`) {
		t.Fatalf("global records body = %s", globalRecords.Body.String())
	}
	sessions := doJSON(t, server, http.MethodGet, "/sessions/audit?userId=user-1", ``, http.StatusOK)
	if !strings.Contains(sessions.Body.String(), `"connectionType":"ssh"`) {
		t.Fatalf("audit sessions body = %s", sessions.Body.String())
	}
}

func TestSessionAuditHTTPValidationAndUnknownRoutes(t *testing.T) {
	server := newHTTPTestServer()
	doJSON(t, server, http.MethodPost, "/sessions/sess-1/audit/records", `{}`, http.StatusBadRequest)
	doJSON(t, server, http.MethodGet, "/sessions/sess-1/unknown", ``, http.StatusNotFound)
	doJSON(t, server, http.MethodPost, "/sessions/sess-1/unknown", `{}`, http.StatusNotFound)
	doJSON(t, server, http.MethodGet, "/sessions/audit?from=bad", ``, http.StatusBadRequest)
	doJSON(t, server, http.MethodGet, "/sessions/audit/records?to=bad", ``, http.StatusBadRequest)
	doJSON(t, server, http.MethodGet, "/sessions/audit/records?recordType=bad", ``, http.StatusBadRequest)
	doJSON(t, server, http.MethodGet, "/sessions/sess-1/audit/records?cursor=bad", ``, http.StatusBadRequest)
}

func TestMetadataEventsHTTPList(t *testing.T) {
	server := newHTTPTestServer()
	err := server.svc.AppendMetadataEvent(t.Context(), model.MetadataEvent{
		SchemaVersion: model.MetadataEventSchemaVersion,
		EventID:       "evt-1",
		EventType:     "SessionCreated",
		Source:        "session-manager",
		OccurredAt:    time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC),
		UserID:        "user-1",
		SessionID:     "sess-1",
		HostID:        "host-1",
		CRID:          "cr-1",
		PodID:         "pod-1",
		InstanceID:    "inst-1",
	})
	if err != nil {
		t.Fatalf("AppendMetadataEvent() error = %v", err)
	}
	response := doJSON(t, server, http.MethodGet, "/events?eventType=SessionCreated&source=session-manager&sessionId=sess-1&limit=10", ``, http.StatusOK)
	body := response.Body.String()
	if !strings.Contains(body, `"eventId":"evt-1"`) || !strings.Contains(body, `"podId":"pod-1"`) || !strings.Contains(body, `"instanceId":"inst-1"`) {
		t.Fatalf("events body = %s", body)
	}
	doJSON(t, server, http.MethodGet, "/events?from=bad", ``, http.StatusBadRequest)
}

func doJSON(t *testing.T, server *Server, method, path, body string, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(apiVersionHeader, supportedAPIVersion)
	server.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("%s %s status = %d, want %d, body=%s", method, path, rec.Code, wantStatus, rec.Body.String())
	}
	return rec
}
