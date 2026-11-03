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

type RetrieveDeviceAuthorizationStatus struct {
	DeviceCode string `json:"deviceCode" desc:"Device code returned by create_device_authorization"`
}

type CreateDeviceAuthorizationRecord struct {
	DeviceCodeHash []byte
	ExpiresAt      time.Time
}

type DeviceAuthorizationCreated struct {
	DeviceCode              string                    `json:"deviceCode" desc:"Device authorization code used to poll status"`
	VerificationURI         string                    `json:"verificationURI" desc:"URL where the user enters the device code"`
	VerificationURIComplete string                    `json:"verificationURIComplete" desc:"Complete URL with embedded device code for the user to open and approve"`
	Status                  DeviceAuthorizationStatus `json:"status" desc:"Current authorization status (pending, approved, rejected, expired)"`
	ExpiresAt               time.Time                 `json:"expiresAt" desc:"Expiration timestamp of the device code"`
	PollIntervalSeconds     int                       `json:"pollIntervalSeconds" desc:"Recommended polling interval in seconds"`
}

type DeviceAuthorizationState struct {
	Status       DeviceAuthorizationStatus `json:"status" desc:"Current authorization status (pending, approved, rejected, expired)"`
	ExpiresAt    *time.Time                `json:"expiresAt,omitempty" desc:"Expiration timestamp while pending or expired"`
	ProjectID    *string                   `json:"projectID,omitempty" desc:"Authorized project ID when approved"`
	TokenKind    *string                   `json:"tokenKind,omitempty" desc:"Issued token kind (project_token)"`
	IssuedAt     *time.Time                `json:"issuedAt,omitempty" desc:"Timestamp when the project token was issued"`
	ProjectToken *string                   `json:"projectToken,omitempty" desc:"Issued project token (returned only on the first approved poll)"`
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
