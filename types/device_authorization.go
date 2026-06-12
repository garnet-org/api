package types

import (
	"time"

	"github.com/garnet-org/api/id"
	"github.com/garnet-org/api/types/errs"
)

type DeviceAuthorizationStatus string

const (
	DeviceAuthorizationStatusPending  DeviceAuthorizationStatus = "pending"
	DeviceAuthorizationStatusApproved DeviceAuthorizationStatus = "approved"
	DeviceAuthorizationStatusRejected DeviceAuthorizationStatus = "rejected"
	DeviceAuthorizationStatusExpired  DeviceAuthorizationStatus = "expired"
)

type DeviceAuthorization struct {
	ID               string                    `db:"id"`
	DeviceCodeHash   []byte                    `db:"device_code_hash"`
	Status           DeviceAuthorizationStatus `db:"status"`
	UserID           *string                   `db:"user_id"`
	ProjectID        *string                   `db:"project_id"`
	TokenID          *string                   `db:"token_id"`
	ExpiresAt        time.Time                 `db:"expires_at"`
	ApprovedAt       *time.Time                `db:"approved_at"`
	RejectedAt       *time.Time                `db:"rejected_at"`
	TokenRetrievedAt *time.Time                `db:"token_retrieved_at"`
	CreatedAt        time.Time                 `db:"created_at"`
	UpdatedAt        time.Time                 `db:"updated_at"`
}

func (s DeviceAuthorizationStatus) IsValid() bool {
	switch s {
	case DeviceAuthorizationStatusPending, DeviceAuthorizationStatusApproved, DeviceAuthorizationStatusRejected, DeviceAuthorizationStatusExpired:
		return true
	}

	return false
}

type CreateDeviceAuthorization struct{}

func (in *CreateDeviceAuthorization) Validate() error {
	return nil
}

type CreateDeviceAuthorizationRecord struct {
	DeviceCodeHash []byte
	ExpiresAt      time.Time
}

type DeviceAuthorizationCreated struct {
	DeviceCode              string                    `json:"deviceCode"`
	VerificationURI         string                    `json:"verificationURI"`
	VerificationURIComplete string                    `json:"verificationURIComplete"`
	Status                  DeviceAuthorizationStatus `json:"status"`
	ExpiresAt               time.Time                 `json:"expiresAt"`
	PollIntervalSeconds     int                       `json:"pollIntervalSeconds"`
}

type DeviceAuthorizationState struct {
	Status       DeviceAuthorizationStatus `json:"status"`
	ExpiresAt    *time.Time                `json:"expiresAt,omitempty"`
	ProjectID    *string                   `json:"projectID,omitempty"`
	TokenKind    *string                   `json:"tokenKind,omitempty"`
	IssuedAt     *time.Time                `json:"issuedAt,omitempty"`
	ProjectToken *string                   `json:"projectToken,omitempty"`
}

type ApproveDeviceAuthorization struct {
	DeviceCode string `json:"-"`
	ProjectID  string `json:"projectID"`
}

func (in *ApproveDeviceAuthorization) Validate() error {
	if !id.Valid(in.ProjectID) {
		return errs.InvalidArgumentError("invalid projectID")
	}

	if in.DeviceCode == "" {
		return errs.InvalidArgumentError("invalid deviceCode")
	}

	return nil
}
