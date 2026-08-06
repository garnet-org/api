package types

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/garnet-org/api/types/errs"
)

const (
	GitHubRepositoryVisibilityPublic   = "public"
	GitHubRepositoryVisibilityPrivate  = "private"
	GitHubRepositoryVisibilityInternal = "internal"
)

// GitHubRunClaims is the verified identity of a GitHub Actions workflow run.
type GitHubRunClaims struct {
	RepositoryID         string `json:"repositoryID"`
	Repository           string `json:"repository"`
	RepositoryOwnerID    string `json:"repositoryOwnerID"`
	RepositoryOwner      string `json:"repositoryOwner"`
	RepositoryVisibility string `json:"repositoryVisibility"`
	RunID                string `json:"runID"`
	RunAttempt           string `json:"runAttempt"`
	RunNumber            string `json:"runNumber,omitempty"`
	SHA                  string `json:"sha,omitempty"`
	Ref                  string `json:"ref,omitempty"`
	ActorID              string `json:"actorID,omitempty"`
	EventName            string `json:"eventName,omitempty"`
	WorkflowRef          string `json:"workflowRef,omitempty"`
	JobWorkflowRef       string `json:"jobWorkflowRef,omitempty"`
	RunnerEnvironment    string `json:"runnerEnvironment,omitempty"`
}

// Validate checks the mandatory fields for workflow token and exchange response usage.
func (c GitHubRunClaims) Validate() error {
	if strings.TrimSpace(c.RepositoryID) == "" {
		return errs.InvalidArgumentError("repositoryID is required")
	}
	if strings.TrimSpace(c.RepositoryOwnerID) == "" {
		return errs.InvalidArgumentError("repositoryOwnerID is required")
	}
	if strings.TrimSpace(c.RunID) == "" {
		return errs.InvalidArgumentError("runID is required")
	}
	if strings.TrimSpace(c.RunAttempt) == "" {
		return errs.InvalidArgumentError("runAttempt is required")
	}

	switch c.RepositoryVisibility {
	case GitHubRepositoryVisibilityPublic, GitHubRepositoryVisibilityPrivate, GitHubRepositoryVisibilityInternal:
		return nil
	default:
		return errs.InvalidArgumentError("repositoryVisibility must be one of public, private, internal")
	}
}

type GitHubOIDCExchange struct {
	IDToken string `json:"idToken"`
}

func (in GitHubOIDCExchange) Validate() error {
	if strings.TrimSpace(in.IDToken) == "" {
		return errs.InvalidArgumentError("idToken is required")
	}

	return nil
}

type GitHubOIDCExchangeCreated struct {
	WorkflowToken string          `json:"workflowToken"`
	ExpiresAt     time.Time       `json:"expiresAt"`
	GitHub        GitHubRunClaims `json:"github"`
}

type VerifiedGitHubOIDCToken struct {
	JTI       string
	ExpiresAt time.Time
	GitHub    GitHubRunClaims
}

// GitHubRunClaimIDs holds the parsed integer IDs from a GitHubRunClaims.
type GitHubRunClaimIDs struct {
	RepositoryID      int64
	RepositoryOwnerID int64
	RunID             int64
}

// ParseIDs parses RepositoryID, RepositoryOwnerID, and RunID into integers.
func (c GitHubRunClaims) ParseIDs() (GitHubRunClaimIDs, error) {
	var ids GitHubRunClaimIDs
	var err error

	if ids.RepositoryID, err = parsePositiveClaimInt64(c.RepositoryID, "repository_id"); err != nil {
		return ids, err
	}
	if ids.RepositoryOwnerID, err = parsePositiveClaimInt64(c.RepositoryOwnerID, "repository_owner_id"); err != nil {
		return ids, err
	}
	if ids.RunID, err = parsePositiveClaimInt64(c.RunID, "run_id"); err != nil {
		return ids, err
	}

	return ids, nil
}

func parsePositiveClaimInt64(raw, field string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid %s", field)
	}
	return value, nil
}
