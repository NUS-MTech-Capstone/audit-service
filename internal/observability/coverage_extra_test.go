package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDMiddlewareAndHeaders(t *testing.T) {
	ctx := ContextWithRequestID(context.Background(), "req-1")
	if RequestID(ctx) != "req-1" {
		t.Fatalf("RequestID() = %q", RequestID(ctx))
	}
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	SetRequestHeaders(ctx, req)
	if req.Header.Get("x-api-version") != "1" || req.Header.Get("X-Request-ID") != "req-1" {
		t.Fatalf("headers = %#v", req.Header)
	}

	var observed string
	handler := RequestIDMiddleware(LogRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = RequestID(r.Context())
		w.WriteHeader(http.StatusCreated)
	})))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/events", nil)
	request.Header.Set("X-Request-ID", "incoming")
	handler.ServeHTTP(recorder, request)
	if observed != "incoming" || recorder.Header().Get("X-Request-ID") != "incoming" || recorder.Code != http.StatusCreated {
		t.Fatalf("observed=%q headers=%#v status=%d", observed, recorder.Header(), recorder.Code)
	}

	recorder = httptest.NewRecorder()
	RequestIDMiddleware(LogRequests(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if got := recorder.Header().Get("X-Request-ID"); len(got) != 32 {
		t.Fatalf("generated request id = %q", got)
	}
	ConfigureLogger("audit-service")
	if got := newRequestID(); len(got) != 32 {
		t.Fatalf("newRequestID() length = %d", len(got))
	}
}
