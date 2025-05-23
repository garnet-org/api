package types

import (
	"encoding/json"
	"time"

	"slices"

	"github.com/garnet-org/api/types/errs"
)

// Project settings error constants.
const (
	ErrProjectSettingNotFound      = errs.NotFoundError("project setting not found")
	ErrInvalidProjectSettingKey    = errs.InvalidArgumentError("invalid project setting key")
	ErrInvalidProjectSettingValue  = errs.InvalidArgumentError("invalid project setting value")
	ErrUnauthorizedProjectSetting  = errs.UnauthorizedError("permission denied for project setting")
	ErrProjectSettingAlreadyExists = errs.ConflictError("project setting already exists")
)

// ProjectSettingKey represents the possible keys for project settings.
type ProjectSettingKey string

const (
	// ProjectSettingKeyWebhookEnabledIssueClasses is the key for webhook enabled issue classes.
	ProjectSettingKeyWebhookEnabledIssueClasses ProjectSettingKey = "webhook_enabled_issue_classes"

	// ProjectSettingKeyEnabledGithubCommentPR is the key for enabled GitHub comment PR.
	ProjectSettingKeyEnabledGithubCommentPR ProjectSettingKey = "enabled_github_comment_pr"

	// MaxProjectSettingKeyLength is the maximum length for a project setting key.
	MaxProjectSettingKeyLength = 255 // Same as the database column size
)

// String returns the string representation of the ProjectSettingKey.
func (k ProjectSettingKey) String() string {
	return string(k)
}

// IsValid checks if the ProjectSettingKey is valid.
func (k ProjectSettingKey) IsValid() bool {
	switch k {
	case ProjectSettingKeyWebhookEnabledIssueClasses, ProjectSettingKeyEnabledGithubCommentPR:
		return true
	default:
		return false
	}
}

// ProjectSetting represents a project setting.
type ProjectSetting struct {
	ID        string          `json:"id"`
	ProjectID string          `json:"-"` // Not exposed in API
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ProjectSettingCreate represents a request to create a project setting.
type ProjectSettingCreate struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

// Validate checks if the ProjectSettingCreate has all required fields set.
func (c *ProjectSettingCreate) Validate() error {
	if c.Key == "" {
		return ErrInvalidProjectSettingKey
	}

	if len(c.Key) > MaxProjectSettingKeyLength {
		return ErrInvalidProjectSettingKey
	}

	if !ProjectSettingKey(c.Key).IsValid() {
		return ErrInvalidProjectSettingKey
	}

	if len(c.Value) == 0 {
		return ErrInvalidProjectSettingValue
	}

	return nil
}

// ProjectSettingUpdate represents a request to update a project setting.
type ProjectSettingUpdate struct {
	Value json.RawMessage `json:"value"`
}

// Validate checks if the ProjectSettingUpdate has all required fields set.
func (u *ProjectSettingUpdate) Validate() error {
	if len(u.Value) == 0 {
		return ErrInvalidProjectSettingValue
	}

	return nil
}

// ProjectSettingCreated represents a response to creating a project setting.
type ProjectSettingCreated struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProjectSettingUpdated represents a response to updating a project setting.
type ProjectSettingUpdated struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListProjectSettings represents the query parameters for listing project settings.
type ListProjectSettings struct {
	ProjectID string `json:"-"` // Set internally, not from user input
	PageArgs
}

// WebhookEnabledIssueClasses represents the enabled issue classes for webhooks.
type WebhookEnabledIssueClasses struct {
	Classes []IssueClass `json:"classes"`
}

// Validate checks if the WebhookEnabledIssueClasses has valid classes.
func (w *WebhookEnabledIssueClasses) Validate() error {
	// nil Classes is valid - indicates all classes are enabled (default)

	// Validate each class if provided
	if w.Classes != nil {
		for _, class := range w.Classes {
			if !class.IsValid() {
				return ErrInvalidIssueClass
			}
		}
	}

	return nil
}

// IsIssueClassEnabled checks if a specific issue class is enabled for webhooks.
func (w *WebhookEnabledIssueClasses) IsIssueClassEnabled(class IssueClass) bool {
	// If the classes list is nil, all classes are enabled (default behavior)
	if w.Classes == nil {
		return true
	}

	// If the classes list is empty, no classes are enabled
	if len(w.Classes) == 0 {
		return false
	}

	// Check if the class is in the list
	return slices.Contains(w.Classes, class)
}
