package types

import (
	"time"
)

type WebhookOutboxPayloadKind string

const (
	WebhookOutboxPayloadKindProfile WebhookOutboxPayloadKind = "profile"
)

// WebhookOutboxItem represents one pending webhook outbox record.
type WebhookOutboxItem[T any] struct {
	ID            string                   `json:"id" db:"id"`
	WebhookID     string                   `json:"webhook_id" db:"webhook_id"`
	PayloadKind   WebhookOutboxPayloadKind `json:"payload_kind" db:"payload_kind"`
	Payload       T                        `json:"payload" db:"payload"`
	AttemptCount  int                      `json:"attempt_count" db:"attempt_count"`
	NextAttemptAt time.Time                `json:"next_attempt_at" db:"next_attempt_at"`
	LastError     *string                  `json:"last_error,omitempty" db:"last_error"`
	CreatedAt     time.Time                `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time                `json:"updated_at" db:"updated_at"`

	Webhook Webhook `json:"webhook" db:"webhook"`
}
