package types

import (
	"strings"
	"time"

	"github.com/garnet-org/api/id"
	"github.com/garnet-org/api/validator"
)

const (
	GitHubLinkScopeOwner      = "owner"
	GitHubLinkScopeRepository = "repository"
)

// CreateProjectGitHubLink claims a GitHub owner or repository for a project.
// GitHubOwnerID is resolved server-side for repository scope, so it is not part
// of the request body for that scope.
type CreateProjectGitHubLink struct {
	ProjectID          string  `json:"-"`
	Scope              string  `json:"scope"`
	GitHubOwnerID      *int64  `json:"githubOwnerID,omitempty"`
	GitHubRepositoryID *int64  `json:"githubRepositoryID,omitempty"`
	CreatedBy          *string `json:"-"`
}

func (in CreateProjectGitHubLink) Validate() error {
	v := validator.New()

	if !id.Valid(in.ProjectID) {
		v.Add("projectID", "invalid projectID")
	}
	if in.GitHubOwnerID == nil || *in.GitHubOwnerID <= 0 {
		v.Add("githubOwnerID", "githubOwnerID is required")
	}
	if in.CreatedBy != nil && !id.Valid(*in.CreatedBy) {
		v.Add("createdBy", "invalid createdBy")
	}

	switch in.Scope {
	case GitHubLinkScopeOwner:
		if in.GitHubRepositoryID != nil {
			v.Add("githubRepositoryID", "githubRepositoryID must not be set for owner scope")
		}
	case GitHubLinkScopeRepository:
		if in.GitHubRepositoryID == nil || *in.GitHubRepositoryID <= 0 {
			v.Add("githubRepositoryID", "githubRepositoryID is required for repository scope")
		}
	default:
		v.Add("scope", "scope must be owner or repository")
	}

	return v.AsError()
}

type ProjectGitHubLink struct {
	ID                 string     `json:"id" db:"id"`
	ProjectID          string     `json:"projectID" db:"project_id"`
	Scope              string     `json:"scope" db:"scope"`
	GitHubOwnerID      int64      `json:"githubOwnerID" db:"github_owner_id"`
	GitHubRepositoryID *int64     `json:"githubRepositoryID,omitempty" db:"github_repository_id"`
	CreatedBy          *string    `json:"createdBy,omitempty" db:"created_by"`
	CreatedAt          time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt          time.Time  `json:"updatedAt" db:"updated_at"`
	DeletedAt          *time.Time `json:"deletedAt,omitempty" db:"deleted_at"`
}

type AvailableGitHubRepository struct {
	GitHubRepositoryID   int64  `json:"githubRepositoryID" db:"repository_id"`
	GitHubOwnerID        int64  `json:"githubOwnerID" db:"owner_id"`
	GitHubOwnerLogin     string `json:"githubOwnerLogin" db:"owner_login"`
	GitHubRepositoryName string `json:"githubRepositoryName" db:"name"`
	GitHubVisibility     string `json:"githubVisibility" db:"visibility"`
	GitHubInstallationID *int64 `json:"githubInstallationID,omitempty" db:"github_installation_id"`
}

type GitHubInstallation struct {
	GitHubInstallationID int64      `json:"githubInstallationID" db:"github_installation_id"`
	GitHubAccountID      int64      `json:"githubAccountID" db:"github_account_id"`
	GitHubAccountLogin   string     `json:"githubAccountLogin" db:"github_account_login"`
	GitHubAccountType    string     `json:"githubAccountType" db:"github_account_type"`
	GitHubSuspendedAt    *time.Time `json:"githubSuspendedAt,omitempty" db:"github_suspended_at"`
}

func (in GitHubInstallation) Validate() error {
	v := validator.New()

	if in.GitHubInstallationID <= 0 {
		v.Add("githubInstallationID", "githubInstallationID must be greater than 0")
	}
	if in.GitHubAccountID <= 0 {
		v.Add("githubAccountID", "githubAccountID must be greater than 0")
	}
	if strings.TrimSpace(in.GitHubAccountLogin) == "" {
		v.Add("githubAccountLogin", "githubAccountLogin is required")
	}
	if strings.TrimSpace(in.GitHubAccountType) == "" {
		v.Add("githubAccountType", "githubAccountType is required")
	}

	return v.AsError()
}
