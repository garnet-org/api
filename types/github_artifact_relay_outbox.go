package types

import "time"

// GitHubArtifactRelayOutboxItem is one workflow run whose agents we may still
// have to reconstruct from its workflow artifacts.
//
// A run lands here when it finished without any agent of its own, which is
// what a pull request opened from a fork always looks like: GitHub withholds
// OIDC tokens from such a run, so nothing in it could authenticate.
type GitHubArtifactRelayOutboxItem struct {
	ID           string `json:"id" db:"id"`
	RepositoryID int64  `json:"repositoryID" db:"github_repository_id"`
	OwnerLogin   string `json:"ownerLogin" db:"github_owner_login"`
	RepoName     string `json:"repoName" db:"github_repo_name"`
	RunID        int64  `json:"runID" db:"github_run_id"`
	RunAttempt   int    `json:"runAttempt" db:"github_run_attempt"`
	HeadSHA      string `json:"headSHA" db:"github_head_sha"`

	// IngestedArtifactIDs are the artifacts already turned into agents, so a
	// retry resumes instead of creating a second agent for the same job.
	IngestedArtifactIDs []int64 `json:"ingestedArtifactIDs" db:"ingested_artifact_ids"`

	AttemptCount  int       `json:"attemptCount" db:"attempt_count"`
	NextAttemptAt time.Time `json:"nextAttemptAt" db:"next_attempt_at"`
	LastError     *string   `json:"lastError" db:"last_error"`
	CreatedAt     time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt     time.Time `json:"updatedAt" db:"updated_at"`
}

func (in GitHubArtifactRelayOutboxItem) Repository() string {
	return in.OwnerLogin + "/" + in.RepoName
}

type CreateGitHubArtifactRelayOutboxItem struct {
	RepositoryID int64
	OwnerLogin   string
	RepoName     string
	RunID        int64
	RunAttempt   int
	HeadSHA      string
}
