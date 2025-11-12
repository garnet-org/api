package types //nolint:revive // Package name is intentionally descriptive

import (
	"time"

	"github.com/garnet-org/api/types/errs"
)

const (
	// ErrUnauthorizedProject is returned when a user does not have permission to access a project.
	ErrUnauthorizedProject = errs.UnauthorizedError("permission denied")

	// ErrInvalidProjectName is returned when the project name is invalid.
	ErrInvalidProjectName = errs.InvalidArgumentError("invalid project name")

	// ErrProjectExists is returned when a project with the same name already exists in the organization.
	ErrProjectExists = errs.ConflictError("project with this name already exists in this organization")

	// MaxProjectNameLength is the maximum length for a project name.
	MaxProjectNameLength = 128
)

// Project represents a project in the system.
type Project struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Description    *string   `json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// CreateProject represents the data needed to create a new project.
type CreateProject struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// Validate checks if the CreateProject fields are valid.
func (c *CreateProject) Validate() error {
	if c.Name == "" {
		return ErrInvalidProjectName
	}

	if len(c.Name) > MaxProjectNameLength {
		return ErrInvalidProjectName
	}

	return nil
}

// ProjectCreated represents the response after a project is created.
type ProjectCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// UpdateProject represents the data needed to update an existing project.
type UpdateProject struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// Validate checks if the UpdateProject fields are valid.
func (u *UpdateProject) Validate() error {
	if u.Name == nil && u.Description == nil {
		return errs.ErrInvalidArgument
	}

	if u.Name != nil {
		if *u.Name == "" {
			return ErrInvalidProjectName
		}

		if len(*u.Name) > MaxProjectNameLength {
			return ErrInvalidProjectName
		}
	}

	return nil
}

// ProjectUpdated represents the response after a project is updated.
type ProjectUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListProjects represents the query parameters for listing projects.
type ListProjects struct {
	PageArgs

	OrganizationID string `json:"organization_id,omitempty"`
}

// ListUserProjects represents the query parameters for listing projects a user has access to.
type ListUserProjects struct {
	PageArgs

	UserID string `json:"user_id"`
}

// ProjectCounters represents the count of repositories and workflows in a project.
type ProjectCounters struct {
	RepositoryCount int `json:"repository_count"`
	WorkflowCount   int `json:"workflow_count"`
}
