package types

import (
	"encoding/json"
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
	ID                    string      `json:"id" desc:"Unique profile identifier"`
	AgentID               string      `json:"agentID" db:"agent_id" desc:"Identifier of the agent that generated the profile"`
	GithubOrg             string      `json:"githubOrg" db:"github_org" desc:"GitHub organization or owner"`
	Repo                  string      `json:"repo" desc:"GitHub repository name"`
	GitHubRepositoryID    *int64      `json:"githubRepositoryID,omitempty" db:"github_repository_id" desc:"GitHub repository numeric ID"`
	GitHubDetailsVerified bool        `json:"github_details_verified" db:"github_details_verified" desc:"Whether GitHub context was verified"`
	Job                   string      `json:"job" desc:"GitHub Actions job name"`
	RunID                 string      `json:"runID" db:"run_id" desc:"GitHub Actions workflow run ID"`
	RunAttempt            int64       `json:"runAttempt" db:"run_attempt" desc:"GitHub Actions workflow run attempt number"`
	JobIndex              *uint32     `json:"jobIndex,omitempty" db:"job_index" desc:"Matrix job index within the workflow run"`
	Data                  ProfileData `json:"data" desc:"Garnet runtime review profile payload"`
	CreatedAt             time.Time   `json:"createdAt" db:"created_at" desc:"Creation timestamp"`
	UpdatedAt             time.Time   `json:"updatedAt" db:"updated_at" desc:"Last update timestamp"`
}

// ProfileData is a stored profile document: the profile, plus each egress
// peer's queried_name decoded from the same document. It encodes as the
// profile alone.
type ProfileData struct {
	ongoing.Profile
	EgressQueriedNames EgressQueriedNames `json:"-"`
}

// MarshalYAML keeps YAML output the profile alone, as before.
func (data ProfileData) MarshalYAML() (any, error) {
	return data.Profile, nil
}

func (data ProfileData) MarshalJSON() ([]byte, error) {
	return json.Marshal(data.Profile)
}

func (data *ProfileData) UnmarshalJSON(raw []byte) error {
	if err := json.Unmarshal(raw, &data.Profile); err != nil {
		return err
	}
	return json.Unmarshal(raw, &data.EgressQueriedNames)
}

type CreateProfile struct {
	ongoing.Profile
	// Ashkaal does not carry queried_name yet, so the names are the only
	// part of the request body kept beside the decoded profile.
	EgressQueriedNames EgressQueriedNames `json:"-"`
}

// EgressQueriedNames holds each egress peer's queried_name, by peer index. It
// decodes from a whole profile document, and is empty when no peer has a
// name.
type EgressQueriedNames []string

// maxQueriedNameLength is the longest DNS name.
const maxQueriedNameLength = 253

func (names *EgressQueriedNames) UnmarshalJSON(data []byte) error {
	*names = nil
	var profile struct {
		Network struct {
			Egress struct {
				Peers []struct {
					QueriedName string `json:"queried_name"`
				} `json:"peers"`
			} `json:"egress"`
		} `json:"network"`
	}
	// A malformed queried_name only costs the names, not the profile.
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil
	}
	peers := profile.Network.Egress.Peers
	queriedNames := make(EgressQueriedNames, len(peers))
	found := false
	for index, peer := range peers {
		name := strings.TrimSpace(peer.QueriedName)
		if name == "" || len(name) > maxQueriedNameLength {
			continue
		}
		queriedNames[index] = name
		found = true
	}
	if found {
		*names = queriedNames
	}
	return nil
}

func (in *CreateProfile) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &in.Profile); err != nil {
		return err
	}

	in.EgressQueriedNames = nil
	var names EgressQueriedNames
	if err := json.Unmarshal(data, &names); err != nil {
		return err
	}
	if len(names) == len(in.Network.Egress.Peers) {
		in.EgressQueriedNames = names
	}
	return nil
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
