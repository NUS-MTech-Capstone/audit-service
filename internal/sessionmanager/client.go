package sessionmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
	"github.com/NUS-MTech-Capstone/audit-service/internal/observability"
)

type Client struct {
	baseURL string
	client  *http.Client
}

func New(baseURL string) *Client {
	return &Client{baseURL: baseURL, client: &http.Client{Timeout: 5 * time.Second}}
}

func (c *Client) GetSession(ctx context.Context, sessionID string) (model.Session, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/sessions/"+sessionID, nil)
	if err != nil {
		return model.Session{}, err
	}
	observability.SetRequestHeaders(ctx, req)
	resp, err := c.client.Do(req)
	if err != nil {
		return model.Session{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return model.Session{}, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model.Session{}, fmt.Errorf("session-manager returned status %d", resp.StatusCode)
	}
	var session model.Session
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return model.Session{}, err
	}
	return session, nil
}

type notFoundError struct{}

func (notFoundError) Error() string {
	return "session not found"
}

var ErrNotFound error = notFoundError{}
