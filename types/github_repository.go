package types

import (
	"strings"
	"time"

	"github.com/garnet-org/api/validator"
)

const (
	GitHubRepositoryVisibilitySourceOIDC    = "oidc"
	GitHubRepositoryVisibilitySourceAPI     = "api"
	GitHubRepositoryVisibilitySourceWebhook = "webhook"
)

type GitHubRepository struct {
	RepositoryID      int64      `json:"repositoryID" db:"repository_id"`
	OwnerID           int64      `json:"ownerID" db:"owner_id"`
	OwnerLogin        string     `json:"ownerLogin" db:"owner_login"`
	Name              string     `json:"name" db:"name"`
	Visibility        string     `json:"visibility" db:"visibility"`
	VisibilitySource  string     `json:"visibilitySource" db:"visibility_source"`
	VisibilityUpdated *time.Time `json:"visibilityUpdatedAt,omitempty" db:"visibility_updated_at"`
	CreatedAt         time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt         time.Time  `json:"updatedAt" db:"updated_at"`
}

type UpsertGitHubRepository struct {
	RepositoryID     int64
	OwnerID          int64
	OwnerLogin       string
	Name             string
	Visibility       string
	VisibilitySource string
	// InstallationID links the repository to a GitHub App installation.
	// A nil value leaves any existing link untouched.
	InstallationID *int64
}

func (in UpsertGitHubRepository) Validate() error {
	v := validator.New()

	if in.RepositoryID <= 0 {
		v.Add("repositoryID", "repositoryID must be greater than 0")
	}
	if in.OwnerID <= 0 {
		v.Add("ownerID", "ownerID must be greater than 0")
	}
	if strings.TrimSpace(in.OwnerLogin) == "" {
		v.Add("ownerLogin", "ownerLogin is required")
	}
	if strings.TrimSpace(in.Name) == "" {
		v.Add("name", "name is required")
	}
	if !ValidGitHubRepositoryVisibility(in.Visibility) {
		v.Add("visibility", "visibility must be one of public, private, internal")
	}
	if in.InstallationID != nil && *in.InstallationID <= 0 {
		v.Add("installationID", "installationID must be greater than 0 when set")
	}

	return v.AsError()
}

func ValidGitHubRepositoryVisibility(visibility string) bool {
	switch visibility {
	case GitHubRepositoryVisibilityPublic, GitHubRepositoryVisibilityPrivate, GitHubRepositoryVisibilityInternal:
		return true
	default:
		return false
	}
}
