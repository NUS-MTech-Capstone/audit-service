package model

import (
	"errors"
	"testing"
	"time"
)

func TestDecodeMetadataEventRejectsForbiddenFields(t *testing.T) {
	_, err := DecodeMetadataEvent([]byte(`{
		"schemaVersion":"2026-07-ops-timeline.v1",
		"eventId":"evt-1",
		"eventType":"AccessAllowed",
		"source":"sts",
		"occurredAt":"2026-07-06T01:00:00Z",
		"token":"do-not-store"
	}`))
	if !errors.Is(err, ErrInvalidMetadataEvent) {
		t.Fatalf("DecodeMetadataEvent() error = %v, want ErrInvalidMetadataEvent", err)
	}
}

func TestDecodeMetadataEventAcceptsSanitizedMetadata(t *testing.T) {
	event, err := DecodeMetadataEvent([]byte(`{
		"schemaVersion":"2026-07-ops-timeline.v1",
		"eventId":"evt-1",
		"eventType":"SessionCreated",
		"source":"session-manager",
		"occurredAt":"2026-07-06T01:00:00Z",
		"requestId":"req-1",
		"userId":"user-1",
		"sessionId":"sess-1",
		"hostId":"host-1",
		"crId":"cr-1",
		"podId":"pod-1",
		"instanceId":"inst-1",
		"action":"start",
		"mode":"owner",
		"outcome":"created"
	}`))
	if err != nil {
		t.Fatalf("DecodeMetadataEvent() error = %v", err)
	}
	if event.EventID != "evt-1" || event.PodID != "pod-1" || !event.OccurredAt.Equal(time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("event = %#v", event)
	}
}
