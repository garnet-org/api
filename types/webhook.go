package types //nolint:revive // Package name is intentionally descriptive

import (
	"net/url"
	"time"

	"github.com/garnet-org/api/types/errs"
)

var (
	// ErrWebhookNotFound returns when a webhook is not found.
	ErrWebhookNotFound = errs.NotFoundError("webhook not found")

	// ErrUnauthorizedWebhookAccess returns when there is an unauthorized access to a webhook.
	ErrUnauthorizedWebhookAccess = errs.UnauthorizedError("permission denied for webhook access")

	// ErrWebHookInvalidKind returns when a webhook already exists.
	ErrWebHookInvalidKind = errs.InvalidArgumentError("invalid webhook kind")
)

// WebhookKind represents the kind of webhook.
type WebhookKind string

// String returns the string representation of the WebhookKind.
func (k WebhookKind) String() string {
	return string(k)
}

// IsValid checks if the WebhookKind is valid.
func (k WebhookKind) IsValid() bool {
	switch k {
	case WebhookKindSlack:
		return true
	default:
		return false
	}
}

const (
	// WebhookKindSlack is the kind for Slack webhooks.
	WebhookKindSlack WebhookKind = "slack"
)

// WebhookCreate represents a webhook configuration.
type WebhookCreate struct {
	Kind WebhookKind `json:"kind"`
	Name string      `json:"name"`
	URL  string      `json:"url"`
}

func isValidURL(testURL string) bool {
	parsedURL, err := url.ParseRequestURI(testURL)
	return err == nil && parsedURL.Scheme != "" && parsedURL.Host != ""
}

// Validate checks if the WebhookCreate fields are valid.
func (w *WebhookCreate) Validate() error {
	if !w.Kind.IsValid() {
		return ErrWebHookInvalidKind
	}

	if w.Name == "" {
		return errs.ErrInvalidArgument
	}

	if w.URL == "" {
		return errs.ErrInvalidArgument
	}

	if !isValidURL(w.URL) {
		return errs.ErrInvalidArgument
	}

	return nil
}

// Webhook represents a webhook configuration.
type Webhook struct {
	WebhookCreate

	ID        string    `json:"id"`
	ProjectID string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// WebhookCreated represents a webhook creation response.
type WebhookCreated struct {
	WebhookCreate

	ID string `json:"id"`
}

// WebhookList represents a list of webhooks.
type WebhookList struct {
	PageArgs
}

// WebhookUpdate represents a webhook update request.
type WebhookUpdate struct {
	Name *string      `json:"name,omitempty"`
	Kind *WebhookKind `json:"kind,omitempty"`
	URL  *string      `json:"url,omitempty"`
}

// Validate checks if the WebhookUpdate fields are valid.
func (w *WebhookUpdate) Validate() error {
	if w.Name == nil && w.URL == nil && w.Kind == nil {
		return errs.ErrInvalidArgument
	}

	if w.Name != nil && *w.Name == "" {
		return errs.ErrInvalidArgument
	}

	if w.URL != nil && *w.URL == "" {
		return errs.ErrInvalidArgument
	}

	if w.URL != nil && !isValidURL(*w.URL) {
		return ErrWebHookInvalidKind
	}

	if w.Kind != nil && !w.Kind.IsValid() {
		return errs.ErrInvalidArgument
	}

	return nil
}

// WebhookUpdated represents a webhook update response.
type WebhookUpdated struct {
	WebhookCreated

	UpdatedAt time.Time `json:"updated_at"`
}
