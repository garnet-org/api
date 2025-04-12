package types

import (
	"time"

	"github.com/garnet-org/api/types/errs"
)

const (
	// ErrInvalidOrganizationName is returned when the organization name is invalid.
	ErrInvalidOrganizationName = errs.InvalidArgumentError("invalid organization name")

	// ErrOrganizationSlugExists is returned when the organization slug already exists.
	ErrOrganizationSlugExists = errs.ConflictError("organization with this slug already exists")

	// MaxOrganizationNameLength is the maximum length for an organization name.
	MaxOrganizationNameLength = 128
)

// Organization represents an organization in the system.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateOrganization represents the data needed to create a new organization.
type CreateOrganization struct {
	Name string `json:"name"`
}

// Validate checks if the CreateOrganization fields are valid.
func (c *CreateOrganization) Validate() error {
	if c.Name == "" {
		return ErrInvalidOrganizationName
	}

	if len(c.Name) > MaxOrganizationNameLength {
		return ErrInvalidOrganizationName
	}

	return nil
}

// OrganizationCreated represents the result of a successful organization creation.
type OrganizationCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// UpdateOrganization represents the data needed to update an organization.
type UpdateOrganization struct {
	Name *string `json:"name,omitempty"`
}

// Validate checks if the UpdateOrganization fields are valid.
func (u *UpdateOrganization) Validate() error {
	if u.Name == nil {
		return errs.ErrInvalidArgument
	}

	if u.Name != nil {
		if *u.Name == "" {
			return ErrInvalidOrganizationName
		}

		if len(*u.Name) > MaxOrganizationNameLength {
			return ErrInvalidOrganizationName
		}
	}

	return nil
}

// OrganizationUpdated represents the response after an organization is updated.
type OrganizationUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListOrganizations represents the query parameters for listing organizations.
type ListOrganizations struct {
	PageArgs
}
