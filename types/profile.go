package types

import (
	"strconv"
	"strings"
	"time"

	"github.com/garnet-org/api/id"
	"github.com/garnet-org/api/types/errs"
	"github.com/garnet-org/api/validator"
	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
)

// ErrPublicProfileNotFound marks every denied public profile lookup (unknown
// profile, private or unresolvable repository) so callers cannot enumerate
// which profiles exist.
var ErrPublicProfileNotFound = errs.NotFoundError("public profile not found")

type Profile struct {
	ID                    string          `json:"id" desc:"Unique profile identifier"`
	AgentID               string          `json:"agentID" db:"agent_id" desc:"Identifier of the agent that generated the profile"`
	GithubOrg             string          `json:"githubOrg" db:"github_org" desc:"GitHub organization or owner"`
	Repo                  string          `json:"repo" desc:"GitHub repository name"`
	GitHubRepositoryID    *int64          `json:"githubRepositoryID,omitempty" db:"github_repository_id" desc:"GitHub repository numeric ID"`
	GitHubDetailsVerified bool            `json:"github_details_verified" db:"github_details_verified" desc:"Whether GitHub context was verified"`
	Job                   string          `json:"job" desc:"GitHub Actions job name"`
	RunID                 string          `json:"runID" db:"run_id" desc:"GitHub Actions workflow run ID"`
	RunAttempt            int64           `json:"runAttempt" db:"run_attempt" desc:"GitHub Actions workflow run attempt number"`
	JobIndex              *uint32         `json:"jobIndex,omitempty" db:"job_index" desc:"Matrix job index within the workflow run"`
	Data                  ongoing.Profile `json:"data" desc:"Garnet runtime review profile payload"`
	CreatedAt             time.Time       `json:"createdAt" db:"created_at" desc:"Creation timestamp"`
	UpdatedAt             time.Time       `json:"updatedAt" db:"updated_at" desc:"Last update timestamp"`
}

type CreateProfile struct {
	ongoing.Profile
}

func (in CreateProfile) GitHubOrg() string {
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

func (in CreateProfile) GitHubRef() string {
	return in.Profile.Scenarios.GitHub.Ref
}

func (in CreateProfile) GitHubSHA() string {
	return in.Profile.Scenarios.GitHub.SHA
}

func (in CreateProfile) Job() string {
	return in.Profile.Scenarios.GitHub.Job
}

func (in CreateProfile) RunID() string {
	return in.Profile.Scenarios.GitHub.RunID
}

func (in CreateProfile) RunAttempt() int64 {
	runAttempt, err := strconv.ParseInt(strings.TrimSpace(in.Profile.Scenarios.GitHub.RunAttempt), 10, 64)
	if err != nil || runAttempt <= 0 {
		return 1
	}

	return runAttempt
}

func (in CreateProfile) JobIndex() *uint32 {
	return in.Profile.Scenarios.GitHub.JobIndex
}

func (in *CreateProfile) Validate() error {
	v := validator.New()

	if in.Repo() == "" {
		v.Add("repo", "repo is required in github scenario")
	}

	if in.GitHubOrg() == "" {
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

	runAttempt := strings.TrimSpace(in.Profile.Scenarios.GitHub.RunAttempt)
	if runAttempt == "" {
		v.Add("run_attempt", "run_attempt is required in github scenario")
	} else if attempt, err := strconv.ParseInt(runAttempt, 10, 64); err != nil {
		v.Add("run_attempt", "run_attempt must be a valid integer")
	} else if attempt <= 0 {
		v.Add("run_attempt", "run_attempt must be a positive integer")
	}

	return v.AsError()
}

type ListProfiles struct {
	AgentID    *string        `json:"agentID,omitempty" desc:"Filter by agent ID (required unless projectID or both githubOrg and repo are provided)"`
	ProjectID  *string        `json:"projectID,omitempty" desc:"Filter by project ID (required unless agentID or both githubOrg and repo are provided)"`
	GitHubOrg  *string        `json:"githubOrg,omitempty" desc:"Filter by GitHub organization"`
	Repo       *string        `json:"repo,omitempty" desc:"Filter by GitHub repository name"`
	Job        *string        `json:"job,omitempty" desc:"Filter by GitHub Actions job name"`
	RunID      *string        `json:"runID,omitempty" desc:"Filter by GitHub Actions workflow run ID"`
	RunAttempt *int64         `json:"runAttempt,omitempty" desc:"Filter by GitHub Actions workflow run attempt"`
	JobIndex   *uint32        `json:"jobIndex,omitempty" desc:"Filter by matrix job index"`
	TimeStart  *time.Time     `json:"timeStart,omitempty" desc:"Filter profiles created at or after this RFC3339 timestamp"`
	TimeEnd    *time.Time     `json:"timeEnd,omitempty" desc:"Filter profiles created at or before this RFC3339 timestamp"`
	PageArgs   CursorPageArgs `json:"pageArgs,omitzero" desc:"Cursor pagination arguments"`
}

func (in *ListProfiles) Validate() error {
	v := validator.New()

	if in.AgentID != nil && !id.Valid(*in.AgentID) {
		v.Add("agent_id", "invalid agent ID format")
	}

	if in.ProjectID != nil && !id.Valid(*in.ProjectID) {
		v.Add("project_id", "invalid project ID format")
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

	if in.AgentID == nil && in.ProjectID == nil && (in.GitHubOrg == nil || in.Repo == nil) {
		v.Add("agent_id", "agent_id, project_id, or github_org and repo is required")
		v.Add("project_id", "agent_id, project_id, or github_org and repo is required")
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

	if in.RunAttempt != nil && *in.RunAttempt <= 0 {
		v.Add("run_attempt", "run_attempt must be a positive integer")
	}

	if in.TimeStart != nil && in.TimeEnd != nil && in.TimeStart.After(*in.TimeEnd) {
		v.Add("time_range", "time_start must be before time_end")
	}

	v.Join(in.PageArgs.Validator())

	return v.AsError()
}
