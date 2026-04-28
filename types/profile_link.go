package types

import (
	"strings"
	"time"

	"github.com/garnet-org/api/id"
	"github.com/garnet-org/api/types/errs"
	"github.com/garnet-org/api/validator"
)

const MaxProfileLinkDescriptionLength = 255

var (
	ErrProfileLinkNotFound           = errs.NotFoundError("profile link not found")
	ErrUnauthorizedProfileLinkAccess = errs.UnauthorizedError("permission denied for profile link access")
)

type ProfileLink struct {
	ID          string     `json:"id" db:"id"`
	ProfileID   string     `json:"profileID" db:"profile_id"`
	Description *string    `json:"description" db:"description"`
	CreatedBy   string     `json:"createdBy" db:"created_by"`
	CreatedAt   time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time  `json:"updatedAt" db:"updated_at"`
	UsageCount  int64      `json:"usageCount" db:"usage_count"`
	ExpiresAt   *time.Time `json:"expiresAt" db:"expires_at"`
	LastUsedAt  *time.Time `json:"lastUsedAt" db:"last_used_at"`
	RevokedAt   *time.Time `json:"revokedAt" db:"revoked_at"`
}

type CreateProfileLink struct {
	ProfileID   string     `json:"-"`
	CreatedBy   string     `json:"-"`
	Description *string    `json:"description"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	TokenHash   []byte     `json:"-"`
}

func (in *CreateProfileLink) Validate() error {
	v := validator.New()

	if !id.Valid(in.ProfileID) {
		v.Add("profileID", "invalid profileID format")
	}

	if !id.Valid(in.CreatedBy) {
		v.Add("createdBy", "invalid createdBy format")
	}

	if in.Description != nil {
		description := strings.TrimSpace(*in.Description)
		if len(description) > MaxProfileLinkDescriptionLength {
			v.Add("description", "description exceeds maximum length")
		}
		if description == "" {
			in.Description = nil
		} else {
			*in.Description = description
		}
	}

	if in.ExpiresAt != nil {
		expiresAt := in.ExpiresAt.UTC()
		if !expiresAt.After(time.Now().UTC()) {
			v.Add("expiresAt", "expiresAt must be in the future")
		}
		*in.ExpiresAt = expiresAt
	}

	if len(in.TokenHash) == 0 {
		v.Add("tokenHash", "tokenHash is required")
	}

	return v.AsError()
}

type CreatedProfileLink struct {
	ID             string    `json:"id"`
	CreatedAt      time.Time `json:"createdAt"`
	PlainTextToken string    `json:"plainTextToken"`
}

type UpdateProfileLink struct {
	Description      *string    `json:"description"`
	ClearDescription bool       `json:"clearDescription"`
	ExpiresAt        *time.Time `json:"expiresAt"`
	ClearExpiresAt   bool       `json:"clearExpiresAt"`
	Revoke           bool       `json:"revoke"`
}

func (in *UpdateProfileLink) Validate() error {
	v := validator.New()
	hasDescription := in.Description != nil

	if !hasDescription && !in.ClearDescription && in.ExpiresAt == nil && !in.ClearExpiresAt && !in.Revoke {
		v.Add("fields", "at least one field is required")
	}

	if in.Description != nil {
		description := strings.TrimSpace(*in.Description)
		if len(description) > MaxProfileLinkDescriptionLength {
			v.Add("description", "description exceeds maximum length")
		}
		if description == "" {
			in.Description = nil
			in.ClearDescription = true
		} else {
			*in.Description = description
		}
	}

	if hasDescription && in.ClearDescription {
		v.Add("description", "description and clearDescription cannot both be set")
	}

	if in.ExpiresAt != nil {
		expiresAt := in.ExpiresAt.UTC()
		if !expiresAt.After(time.Now().UTC()) {
			v.Add("expiresAt", "expiresAt must be in the future")
		}
		*in.ExpiresAt = expiresAt
	}

	if in.ExpiresAt != nil && in.ClearExpiresAt {
		v.Add("expiresAt", "expiresAt and clearExpiresAt cannot both be set")
	}

	return v.AsError()
}

type ListProfileLinks struct {
	ProfileID string `json:"-"`
	PageArgs
}

func (in *ListProfileLinks) Validate() error {
	v := validator.New()

	if !id.Valid(in.ProfileID) {
		v.Add("profileID", "invalid profileID format")
	}

	return v.AsError()
}
