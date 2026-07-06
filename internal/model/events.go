package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrInvalidMetadataEvent = errors.New("invalid metadata event")

func DecodeMetadataEvent(data []byte) (MetadataEvent, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return MetadataEvent{}, fmt.Errorf("%w: decode JSON: %v", ErrInvalidMetadataEvent, err)
	}
	forbidden := []string{
		"token", "tokens", "secret", "secrets", "privateKey", "password",
		"terminalInput", "terminalOutput", "stdin", "stdout", "stderr",
		"command", "commandText", "commandBody", "prompt", "renderedPrompt",
		"modelResponse", "rawModelResponse",
	}
	for _, field := range forbidden {
		if _, ok := raw[field]; ok {
			return MetadataEvent{}, fmt.Errorf("%w: forbidden field %q", ErrInvalidMetadataEvent, field)
		}
	}
	var event MetadataEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return MetadataEvent{}, fmt.Errorf("%w: decode event: %v", ErrInvalidMetadataEvent, err)
	}
	if err := ValidateMetadataEvent(event); err != nil {
		return MetadataEvent{}, err
	}
	return event, nil
}

func ValidateMetadataEvent(event MetadataEvent) error {
	if event.SchemaVersion != MetadataEventSchemaVersion {
		return fmt.Errorf("%w: unsupported schemaVersion", ErrInvalidMetadataEvent)
	}
	if event.EventID == "" {
		return fmt.Errorf("%w: eventId is required", ErrInvalidMetadataEvent)
	}
	if event.EventType == "" {
		return fmt.Errorf("%w: eventType is required", ErrInvalidMetadataEvent)
	}
	if event.Source == "" {
		return fmt.Errorf("%w: source is required", ErrInvalidMetadataEvent)
	}
	if event.OccurredAt.IsZero() {
		return fmt.Errorf("%w: occurredAt is required", ErrInvalidMetadataEvent)
	}
	event.OccurredAt = event.OccurredAt.UTC()
	if event.OccurredAt.After(time.Now().UTC().Add(24 * time.Hour)) {
		return fmt.Errorf("%w: occurredAt is too far in the future", ErrInvalidMetadataEvent)
	}
	return nil
}
