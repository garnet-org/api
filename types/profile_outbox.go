package types

import (
	"time"

	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
)

// ProfileOutboxItem represents one pending profile outbox record.
type ProfileOutboxItem struct {
	ID          string          `json:"id" db:"id"`
	ProjectID   string          `json:"project_id" db:"project_id"`
	RunID       string          `json:"run_id" db:"run_id"`
	WebhookKind WebhookKind     `json:"webhook_kind" db:"webhook_kind"`
	Payload     ongoing.Profile `json:"payload" db:"payload"`

	AttemptCount  int       `json:"attempt_count" db:"attempt_count"`
	NextAttemptAt time.Time `json:"next_attempt_at" db:"next_attempt_at"`
	LastError     *string   `json:"last_error,omitempty" db:"last_error"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}
