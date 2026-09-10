package types

import (
	"encoding/json"
	"time"
)

type GitHubCommentOutboxPayloadKind string

type GitHubCommentOutboxSourceEntityKind string

const (
	GitHubCommentOutboxPayloadKindPending GitHubCommentOutboxPayloadKind = "pending_pr_commit_comment"
	GitHubCommentOutboxPayloadKindProfile GitHubCommentOutboxPayloadKind = "pr_commit_comment"
	GitHubCommentOutboxPayloadKindStopped GitHubCommentOutboxPayloadKind = "stopped_pr_commit_comment"

	GitHubCommentOutboxSourceEntityKindAgent   GitHubCommentOutboxSourceEntityKind = "agent"
	GitHubCommentOutboxSourceEntityKindProfile GitHubCommentOutboxSourceEntityKind = "profile"
)

// GitHubCommentOutboxItem represents one pending GitHub comment outbox record.
type GitHubCommentOutboxItem struct {
	ID               string                              `json:"id" db:"id"`
	ProjectID        *string                             `json:"projectID,omitempty" db:"project_id"`
	PayloadKind      GitHubCommentOutboxPayloadKind      `json:"payloadKind" db:"payload_kind"`
	SourceEntityKind GitHubCommentOutboxSourceEntityKind `json:"sourceEntityKind" db:"source_entity_kind"`
	SourceEntityID   string                              `json:"sourceEntityID" db:"source_entity_id"`
	Payload          json.RawMessage                     `json:"payload" db:"payload"`
	AttemptCount     int                                 `json:"attemptCount" db:"attempt_count"`
	NextAttemptAt    time.Time                           `json:"nextAttemptAt" db:"next_attempt_at"`
	LastError        *string                             `json:"lastError" db:"last_error"`
	CreatedAt        time.Time                           `json:"createdAt" db:"created_at"`
	UpdatedAt        time.Time                           `json:"updatedAt" db:"updated_at"`
}

type CreateGitHubCommentOutboxItem struct {
	ProjectID        *string
	PayloadKind      GitHubCommentOutboxPayloadKind
	SourceEntityKind GitHubCommentOutboxSourceEntityKind
	SourceEntityID   string
	Payload          any
}

// AgentPendingOutboxPayload is stored when an agent checks in, to trigger the
// initial "still recording" pull-request comment.
type AgentPendingOutboxPayload struct {
	AgentID   string `json:"agentID"`
	Owner     string `json:"owner"`
	Repo      string `json:"repo"`
	PRNumber  int    `json:"prNumber"`
	CommitSHA string `json:"commitSHA"`
}

// ProfileOutboxPayload is stored when a profile arrives, to trigger the final
// pull-request comment with the recorded behaviour.
type ProfileOutboxPayload struct {
	ProfileID  string `json:"profileID"`
	Owner      string `json:"owner"`
	Repo       string `json:"repo"`
	PRNumber   int    `json:"prNumber"`
	ProfileSHA string `json:"profileSHA"`
}

// AgentStoppedOutboxPayload is stored when an agent's run ends without a
// profile, to refresh the pull-request comment so it no longer waits forever.
type AgentStoppedOutboxPayload struct {
	AgentID   string `json:"agentID"`
	Owner     string `json:"owner"`
	Repo      string `json:"repo"`
	PRNumber  int    `json:"prNumber"`
	CommitSHA string `json:"commitSHA"`
}
