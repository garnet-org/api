package types

import (
	"strings"

	"github.com/garnet-org/api/validator"
)

type AgentStoppedReason string

const (
	AgentStoppedReasonRunCancelled   AgentStoppedReason = "run_cancelled"
	AgentStoppedReasonCrashed        AgentStoppedReason = "crashed"
	AgentStoppedReasonFlushTimeout   AgentStoppedReason = "flush_timeout"
	AgentStoppedReasonStoppedCleanly AgentStoppedReason = "stopped_cleanly"
)

func (r AgentStoppedReason) IsValid() bool {
	switch r {
	case AgentStoppedReasonRunCancelled, AgentStoppedReasonCrashed, AgentStoppedReasonFlushTimeout, AgentStoppedReasonStoppedCleanly:
		return true
	default:
		return false
	}
}

type AgentStoppedProfileState string

const (
	AgentStoppedProfileStatePresent AgentStoppedProfileState = "present"
	AgentStoppedProfileStateMissing AgentStoppedProfileState = "missing"
	AgentStoppedProfileStateEmpty   AgentStoppedProfileState = "empty"
	AgentStoppedProfileStateInvalid AgentStoppedProfileState = "invalid"
)

func (s AgentStoppedProfileState) IsValid() bool {
	switch s {
	case AgentStoppedProfileStatePresent, AgentStoppedProfileStateMissing, AgentStoppedProfileStateEmpty, AgentStoppedProfileStateInvalid:
		return true
	default:
		return false
	}
}

type AgentStoppedJobStatus string

const (
	AgentStoppedJobStatusCancelled AgentStoppedJobStatus = "cancelled"
	AgentStoppedJobStatusFailure   AgentStoppedJobStatus = "failure"
)

func (s AgentStoppedJobStatus) IsValid() bool {
	switch s {
	case AgentStoppedJobStatusCancelled, AgentStoppedJobStatusFailure:
		return true
	default:
		return false
	}
}

// AgentStoppedSource names who told us the run stopped. It is never part of a
// request: the agent speaks for itself, and GitHub speaks for the agents that
// never got to.
type AgentStoppedSource string

const (
	AgentStoppedSourceAgent         AgentStoppedSource = "agent"
	AgentStoppedSourceGitHubWebhook AgentStoppedSource = "github_webhook"
)

type AgentStoppedStopOutcome string

const (
	AgentStoppedStopOutcomeCompleted AgentStoppedStopOutcome = "completed"
	AgentStoppedStopOutcomeTimedOut  AgentStoppedStopOutcome = "timed_out"
)

func (s AgentStoppedStopOutcome) IsValid() bool {
	switch s {
	case AgentStoppedStopOutcomeCompleted, AgentStoppedStopOutcomeTimedOut:
		return true
	default:
		return false
	}
}

// AgentStopped is what an agent reports when its run ends. It says only what
// the agent alone knows; which run it belongs to is already known from the
// agent itself.
type AgentStopped struct {
	Reason       AgentStoppedReason       `json:"reason"`
	ProfileState AgentStoppedProfileState `json:"profileState"`
	Detail       *string                  `json:"detail,omitempty"`
	JobStatus    *AgentStoppedJobStatus   `json:"jobStatus,omitempty"`
	Jibril       *AgentStoppedJibril      `json:"jibril,omitempty"`
}

type AgentStoppedJibril struct {
	ActiveState    *string                  `json:"activeState,omitempty"`
	Result         *string                  `json:"result,omitempty"`
	ExecMainStatus *int64                   `json:"execMainStatus,omitempty"`
	StopOutcome    *AgentStoppedStopOutcome `json:"stopOutcome,omitempty"`
	ForceStopped   *bool                    `json:"forceStopped,omitempty"`
}

func (in *AgentStopped) Validate() error {
	v := validator.New()

	if !in.Reason.IsValid() {
		v.Add("reason", "reason must be one of run_cancelled, crashed, flush_timeout, stopped_cleanly")
	}

	if !in.ProfileState.IsValid() {
		v.Add("profileState", "profileState must be one of present, missing, empty, invalid")
	}

	if in.Detail != nil {
		detail := strings.TrimSpace(*in.Detail)
		if detail == "" {
			in.Detail = nil
		} else {
			in.Detail = &detail
		}
	}

	if in.JobStatus != nil && !in.JobStatus.IsValid() {
		v.Add("jobStatus", "jobStatus must be one of cancelled, failure")
	}

	if in.Jibril != nil {
		if err := in.Jibril.Validate(); err != nil {
			if errValidator, ok := err.(*validator.Validator); ok {
				v.Join(errValidator)
			} else {
				v.Add("jibril", err.Error())
			}
		}
	}

	return v.AsError()
}

func (in *AgentStoppedJibril) Validate() error {
	v := validator.New()

	if in.StopOutcome != nil && !in.StopOutcome.IsValid() {
		v.Add("jibril.stopOutcome", "stopOutcome must be one of completed, timed_out")
	}

	return v.AsError()
}
