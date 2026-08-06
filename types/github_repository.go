package types

import "time"

const (
	GitHubRepositoryVisibilitySourceOIDC = "oidc"
	GitHubRepositoryVisibilitySourceAPI  = "api"
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
}
