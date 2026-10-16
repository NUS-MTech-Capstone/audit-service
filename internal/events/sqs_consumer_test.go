package events

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
)

func TestNewConsumerValidation(t *testing.T) {
	if _, err := NewConsumer(context.Background(), "region", "", nil); err == nil {
		t.Fatal("missing queue URL accepted")
	}
	if _, err := NewConsumer(context.Background(), "", "queue", nil); err == nil {
		t.Fatal("missing region accepted")
	}
}

func TestDecodeQueueMessageRawAndSNSEnvelope(t *testing.T) {
	raw := `{"schemaVersion":"2026-07-ops-timeline.v1","eventId":"evt-1","eventType":"SessionCreated","source":"session-manager","occurredAt":"2026-07-06T01:00:00Z"}`
	event, err := decodeQueueMessage([]byte(raw))
	if err != nil || event.EventID != "evt-1" {
		t.Fatalf("raw event=%#v error=%v", event, err)
	}
	envelope := `{"Type":"Notification","Message":"{\"schemaVersion\":\"2026-07-ops-timeline.v1\",\"eventId\":\"evt-2\",\"eventType\":\"SessionClosed\",\"source\":\"proxy-dataplane\",\"occurredAt\":\"2026-07-06T01:01:00Z\"}"}`
	event, err = decodeQueueMessage([]byte(envelope))
	if err != nil || event.EventID != "evt-2" || event.EventType != "SessionClosed" {
		t.Fatalf("envelope event=%#v error=%v", event, err)
	}
	if _, err := decodeQueueMessage([]byte(`{"bad":true}`)); !errors.Is(err, model.ErrInvalidMetadataEvent) {
		t.Fatalf("invalid envelope error = %v", err)
	}
}

func TestSleepCancellationAndErrorKinds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	sleep(ctx, time.Hour)
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("cancelled sleep did not return promptly")
	}
	cases := []struct {
		err  error
		want string
	}{{nil, ""}, {context.DeadlineExceeded, "timeout"}, {context.Canceled, "cancelled"}, {errors.New("boom"), "error"}}
	for _, tc := range cases {
		if got := errorKind(tc.err); got != tc.want {
			t.Fatalf("errorKind(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
