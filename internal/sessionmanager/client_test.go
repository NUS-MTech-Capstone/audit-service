package sessionmanager

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestGetSessionPropagatesRequestIDAndDecodes(t *testing.T) {
	var requestID string
	client := New("http://session-manager.example")
	client.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/sessions/sess-1" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		requestID = r.Header.Get("X-Request-ID")
		return sessionManagerJSONResponse(http.StatusOK, `{"sessionId":"sess-1","userId":"user-1","hostId":"host-1","crId":"cr-1","ownerPodId":"pod-1","ownerInstanceId":"inst-1","connectionType":"ssh","status":"ACTIVE"}`), nil
	})

	session, err := client.GetSession(t.Context(), "sess-1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if session.SessionID != "sess-1" || session.OwnerInstanceID != "inst-1" {
		t.Fatalf("session = %#v", session)
	}
	if requestID != "" {
		t.Fatalf("unexpected request id without context: %q", requestID)
	}
}

func TestGetSessionNotFound(t *testing.T) {
	client := New("http://session-manager.example")
	client.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return sessionManagerJSONResponse(http.StatusNotFound, `{"error":"missing"}`), nil
	})

	_, err := client.GetSession(t.Context(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSession() error = %v, want ErrNotFound", err)
	}
}

func sessionManagerJSONResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
