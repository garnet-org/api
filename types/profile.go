package types

import (
	"strconv"
	"strings"
	"time"

	"github.com/garnet-org/api/id"
	"github.com/garnet-org/api/validator"
	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
)

type Profile struct {
	ID        string          `json:"id"`
	AgentID   string          `json:"agentID" db:"agent_id"`
	GithubOrg string          `json:"githubOrg" db:"github_org"`
	Repo      string          `json:"repo"`
	Job       string          `json:"job"`
	RunID     string          `json:"runID" db:"run_id"`
	Data      ongoing.Profile `json:"data"`
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

func (in CreateProfile) GithubOrg() string {
	org, _, ok := strings.Cut(in.Profile.Scenarios.GitHub.Repository, "/")
	if !ok {
		return ""
	}
	return org
}

func (in CreateProfile) Repo() string {
	_, repo, ok := strings.Cut(in.Profile.Scenarios.GitHub.Repository, "/")
	if !ok {
		return ""
	}
	return repo
}

func (in CreateProfile) Job() string {
	return in.Profile.Scenarios.GitHub.Job
}

func (in CreateProfile) RunID() string {
	return in.Profile.Scenarios.GitHub.RunID
}

func (in *CreateProfile) Validate() error {
	v := validator.New()

	if in.Repo() == "" {
		v.Add("repo", "repo is required in github scenario")
	}

	if in.GithubOrg() == "" {
		v.Add("github_org", "github_org is required in github scenario")
	}
	if in.Job() == "" {
		v.Add("job", "job is required in github scenario")
	}
	if in.RunID() == "" {
		v.Add("run_id", "run_id is required in github scenario")
	} else if id, err := strconv.ParseInt(in.RunID(), 10, 64); err != nil {
		v.Add("run_id", "run_id must be a valid integer")
	} else if id <= 0 {
		v.Add("run_id", "run_id must be a positive integer")
	}

	return v.AsError()
}

type ListProfiles struct {
	AgentID   *string
	ProjectID *string
	GitHubOrg *string
	Repo      *string
	Job       *string
	RunID     *string
	TimeStart *time.Time
	TimeEnd   *time.Time
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

	if in.GitHubOrg != nil {
		*in.GitHubOrg = strings.TrimSpace(*in.GitHubOrg)
		if *in.GitHubOrg == "" {
			v.Add("github_org", "github_org cannot be empty if provided")
		}
	}

	if in.Repo != nil {
		*in.Repo = strings.TrimSpace(*in.Repo)
		if *in.Repo == "" {
			v.Add("repo", "repo cannot be empty if provided")
		}
	}

	if in.Job != nil {
		*in.Job = strings.TrimSpace(*in.Job)
		if *in.Job == "" {
			v.Add("job", "job cannot be empty if provided")
		}
	}

	if in.RunID != nil {
		*in.RunID = strings.TrimSpace(*in.RunID)
		if *in.RunID == "" {
			v.Add("run_id", "run_id cannot be empty if provided")
		} else if id, err := strconv.ParseInt(*in.RunID, 10, 64); err != nil {
			v.Add("run_id", "run_id must be a valid integer")
		} else if id <= 0 {
			v.Add("run_id", "run_id must be a positive integer")
		}
	}

	if in.TimeStart != nil && in.TimeEnd != nil && in.TimeStart.After(*in.TimeEnd) {
		v.Add("time_range", "time_start must be before time_end")
	}

	v.Join(in.PageArgs.Validator())

	return v.AsError()
}
