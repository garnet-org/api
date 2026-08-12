package types

import (
	"encoding/json"
	"time"
)

// GitHubWebhookOutboxItem represents one pending GitHub webhook event.
type GitHubWebhookOutboxItem struct {
	ID               string          `json:"id" db:"id"`
	GitHubDeliveryID string          `json:"githubDeliveryID" db:"github_delivery_id"`
	GitHubEvent      string          `json:"githubEvent" db:"github_event"`
	Payload          json.RawMessage `json:"payload" db:"payload"`
	AttemptCount     int             `json:"attemptCount" db:"attempt_count"`
	NextAttemptAt    time.Time       `json:"nextAttemptAt" db:"next_attempt_at"`
	LastError        *string         `json:"lastError" db:"last_error"`
	CreatedAt        time.Time       `json:"createdAt" db:"created_at"`
	UpdatedAt        time.Time       `json:"updatedAt" db:"updated_at"`
}

type CreateGitHubWebhookOutboxItem struct {
	GitHubDeliveryID string
	GitHubEvent      string
	Payload          any
}
