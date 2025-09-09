package types

import (
	"regexp"
	"strings"
	"time"

	"github.com/garnet-org/api/types/errs"
)

const (
	// ErrUserEmailRequired is returned when the email is required but not provided.
	ErrUserEmailRequired = errs.InvalidArgumentError("email is required")

	// ErrUserEmailInvalid is returned when the email format is invalid.
	ErrUserEmailInvalid = errs.InvalidArgumentError("email is invalid")

	// ErrUserNameRequired is returned when the name is required but not provided.
	ErrUserNameRequired = errs.InvalidArgumentError("name is required")

	// ErrUserEmailExists is returned when the email already exists in the system.
	ErrUserEmailExists = errs.InvalidArgumentError("email already exists")

	// ErrUserGithubIDExists is returned when the GitHub ID already exists in the system.
	ErrUserGithubIDExists = errs.InvalidArgumentError("github_id already exists")

	// ErrUserGoogleIDExists is returned when the Google ID already exists in the system.
	ErrUserGoogleIDExists = errs.InvalidArgumentError("google_id already exists")

	// ErrUserAuth0SubExists is returned when the Auth0 sub already exists in the system.
	ErrUserAuth0SubExists = errs.InvalidArgumentError("auth0_sub already exists")

	// ErrUserNotFound is returned when the user is not found in the system.
	ErrUserNotFound = errs.NotFoundError("user not found")
)

var emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// User represents a user in the system.
type User struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	Email          string     `json:"email"`
	Name           string     `json:"name"`
	GithubID       *string    `json:"github_id,omitempty"`
	GoogleID       *string    `json:"google_id,omitempty"` // Deprecated: use Auth0Sub
	Auth0Sub       *string    `json:"auth0_sub,omitempty"`  // Auth0 subject identifier
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"-"`
}

// CreateUser represents the input for creating a new user.
type CreateUser struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	GithubID string `json:"github_id,omitempty"`
	GoogleID string `json:"google_id,omitempty"` // Deprecated: use Auth0Sub
	Auth0Sub string `json:"auth0_sub,omitempty"` // Auth0 subject identifier
}

// UserCreated represents the result of a successful user creation.
type UserCreated struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id,omitempty"`
	ProjectID      string    `json:"project_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

// Validate validates the CreateUser input.
func (c *CreateUser) Validate() error {
	c.Email = strings.TrimSpace(c.Email)
	c.Email = strings.ToLower(c.Email)
	if c.Email == "" {
		return ErrUserEmailRequired
	}

	if !emailRegex.MatchString(c.Email) {
		return ErrUserEmailInvalid
	}

	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return ErrUserNameRequired
	}

	return nil
}

// UpdateUser represents the input for updating a user.
type UpdateUser struct {
	Email    *string `json:"email,omitempty"`
	Name     *string `json:"name,omitempty"`
	Auth0Sub *string `json:"auth0_sub,omitempty"`
}

// UserUpdated represents the result of a successful user update.
type UserUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate validates the UpdateUser input.
func (u *UpdateUser) Validate() error {
	if u.Email != nil {
		*u.Email = strings.TrimSpace(*u.Email)
		*u.Email = strings.ToLower(*u.Email)
		if *u.Email == "" {
			return ErrUserEmailRequired
		}

		if !emailRegex.MatchString(*u.Email) {
			return ErrUserEmailInvalid
		}
	}

	if u.Name != nil {
		*u.Name = strings.TrimSpace(*u.Name)
		if *u.Name == "" {
			return ErrUserNameRequired
		}
	}

	return nil
}

// ListUsers represents the query parameters for listing users.
type ListUsers struct {
	OrganizationID string `json:"organization_id,omitempty"`
	PageArgs
}
