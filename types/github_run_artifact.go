package types //nolint:revive // Package name is intentionally descriptive

import (
	"strconv"

	"github.com/garnet-org/api/types/errs"
)

const (
	// GitHubRunArtifactSchemaVersion is the envelope version this control
	// plane reads. The action writes the envelope and the two are released
	// independently, so an envelope from the future is dropped rather than
	// guessed at.
	GitHubRunArtifactSchemaVersion = 1

	// GitHubRunArtifactNamePrefix is the artifact name prefix the action
	// uploads under, one artifact per job. The name only finds candidates:
	// which run an artifact belongs to is verified against GitHub.
	GitHubRunArtifactNamePrefix = "garnet-run-"

	GitHubRunArtifactEntryPath = "garnet/run.json"
)

// GitHubRunArtifactAttemptSuffix is the suffix the action ends an artifact
// name with.
//
// Listing a run's artifacts spans every attempt at once, and an artifact does
// not record which attempt uploaded it, so the name is the only way a re-run
// can tell its own artifacts from the previous attempt's.
func GitHubRunArtifactAttemptSuffix(runAttempt int) string {
	return "-attempt-" + strconv.Itoa(max(runAttempt, 1))
}

// GitHubRunArtifact is what one job of a workflow run leaves behind for the
// control plane to collect: everything the job would have reported itself, had
// it been able to authenticate.
//
// Its contents come from a run we do not trust, so the fields naming that run
// are cross-checked against GitHub rather than believed.
type GitHubRunArtifact struct {
	SchemaVersion int         `json:"schema_version"`
	Agent         CreateAgent `json:"agent"`

	// Profile is absent when the job never recorded one, which
	// Stopped.ProfileState explains.
	Profile *CreateProfile `json:"profile"`

	Stopped AgentStopped `json:"stopped"`
}

// VerifiedGitHubRun is what GitHub told us about a workflow run, read back
// from its own API with our installation credentials. When the run itself
// could not authenticate, this is the only account of it we trust.
type VerifiedGitHubRun struct {
	RepositoryID         int64
	RepositoryOwnerID    int64
	Repository           string
	RepositoryOwner      string
	RepositoryVisibility string
	RunID                int64
	RunAttempt           int
	PullRequestNumber    int

	// CommitSHA is the commit the run's work belongs to: either the head of
	// the pull request or the merge commit GitHub built from it.
	CommitSHA string
}

// IngestGitHubRunArtifact is one job's artifact together with the verified run
// it was collected from.
type IngestGitHubRunArtifact struct {
	Run      VerifiedGitHubRun
	Artifact GitHubRunArtifact
}

// Validate checks only that the envelope is one we can act on; the run it
// names is verified against GitHub separately.
func (in *GitHubRunArtifact) Validate() error {
	if in.SchemaVersion != GitHubRunArtifactSchemaVersion {
		return errs.InvalidArgumentError("unsupported github run artifact schema version")
	}

	if in.Agent.Kind != AgentKindGithub {
		return errs.InvalidArgumentError("github run artifact must describe a github agent")
	}

	if in.Agent.GithubContext == nil {
		return errs.InvalidArgumentError("github run artifact is missing github_context")
	}

	if err := in.Agent.Validate(); err != nil {
		return err
	}

	if err := in.Stopped.Validate(); err != nil {
		return err
	}

	if in.Profile == nil {
		return nil
	}

	return in.Profile.Validate()
}
