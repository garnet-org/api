package types

import (
	"time"

	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
	"github.com/garnet-org/api/id"
	"github.com/garnet-org/api/validator"
)

type Profile struct {
	RunID     string          `json:"runID" db:"run_id"`
	AgentID   string          `json:"agentID" db:"agent_id"`
	Data      ongoing.Profile `json:"data" db:"data"`
	CreatedAt time.Time       `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time       `json:"updatedAt" db:"updated_at"`
}

type CreateProfile struct {
	agentID string
	ongoing.Profile
}

func (in *CreateProfile) SetAgentID(agentID string) {
	in.agentID = agentID
}

func (in CreateProfile) AgentID() string {
	return in.agentID
}

func (in CreateProfile) RunID() string {
	return in.Profile.Scenarios.GitHub.RunID
}

func (in *CreateProfile) Validate() error {
	v := validator.New()

	if in.RunID() == "" {
		v.Add("run_id", "run_id is required in github scenario")
	}

	return v.AsError()
}

type CreatedProfile struct {
	// Created tells whether the profile was newly created or if it was updated (upserted).
	Created   bool      `json:"created" db:"created"`
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}

type ListProfiles struct {
	AgentID   *string
	ProjectID *string
	PageArgs  CursorPageArgs
}

func (in *ListProfiles) Validate() error {
	v := validator.New()

	if in.AgentID != nil && !id.Valid(*in.AgentID) {
		v.Add("agent_id", "invalid agent ID format")
	}

	if in.ProjectID != nil && !id.Valid(*in.ProjectID) {
		v.Add("project_id", "invalid project ID format")
	}

	if in.AgentID == nil && in.ProjectID == nil {
		v.Add("agent_id", "agent_id or project_id is required")
		v.Add("project_id", "agent_id or project_id is required")
	}

	v.Join(in.PageArgs.Validator())

	return v.AsError()
}
