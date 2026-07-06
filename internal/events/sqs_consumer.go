package events

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/model"
	"github.com/NUS-MTech-Capstone/audit-service/internal/service"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type Consumer struct {
	queueURL string
	client   *sqs.Client
	service  *service.Service
}

func NewConsumer(ctx context.Context, region, queueURL string, svc *service.Service) (*Consumer, error) {
	if queueURL == "" {
		return nil, errors.New("AUDIT_EVENTS_QUEUE_URL is required")
	}
	if region == "" {
		return nil, errors.New("AWS_REGION is required when AUDIT_EVENT_CONSUMER_ENABLED=true")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return &Consumer{
		queueURL: queueURL,
		client:   sqs.NewFromConfig(cfg),
		service:  svc,
	}, nil
}

func (c *Consumer) Run(ctx context.Context) {
	slog.InfoContext(ctx, "MetadataEventConsumerStarted", "queueConfigured", c.queueURL != "")
	for {
		if ctx.Err() != nil {
			return
		}
		resp, err := c.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(c.queueURL),
			MaxNumberOfMessages: 10,
			WaitTimeSeconds:     20,
		})
		if err != nil {
			slog.WarnContext(ctx, "MetadataEventReceiveFailed", "reason", errorKind(err), "error", err)
			sleep(ctx, time.Second)
			continue
		}
		for _, message := range resp.Messages {
			if message.Body == nil || message.ReceiptHandle == nil {
				continue
			}
			event, err := decodeQueueMessage([]byte(*message.Body))
			if err != nil {
				slog.WarnContext(ctx, "MetadataEventInvalid", "error", err)
				continue
			}
			if err := c.service.AppendMetadataEvent(ctx, event); err != nil {
				slog.WarnContext(ctx, "MetadataEventStoreFailed", "eventId", event.EventID, "eventType", event.EventType, "reason", errorKind(err), "error", err)
				continue
			}
			if _, err := c.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
				QueueUrl:      aws.String(c.queueURL),
				ReceiptHandle: message.ReceiptHandle,
			}); err != nil {
				slog.WarnContext(ctx, "MetadataEventDeleteFailed", "eventId", event.EventID, "reason", errorKind(err), "error", err)
			}
		}
	}
}

func decodeQueueMessage(body []byte) (model.MetadataEvent, error) {
	var envelope struct {
		Type    string `json:"Type"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Type == "Notification" && envelope.Message != "" {
		return model.DecodeMetadataEvent([]byte(envelope.Message))
	}
	return model.DecodeMetadataEvent(body)
}

func sleep(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func errorKind(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "error"
}
