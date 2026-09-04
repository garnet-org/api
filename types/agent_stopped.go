package types

import (
	"strconv"
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

type AgentStoppedJobStatusSource string

const (
	AgentStoppedJobStatusSourceGitHubAPI AgentStoppedJobStatusSource = "github_api"
)

func (s AgentStoppedJobStatusSource) IsValid() bool {
	switch s {
	case AgentStoppedJobStatusSourceGitHubAPI:
		return true
	default:
		return false
	}
}

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

type AgentStopped struct {
	Reason          AgentStoppedReason           `json:"reason"`
	ProfileState    AgentStoppedProfileState     `json:"profileState"`
	Detail          *string                      `json:"detail,omitempty"`
	RunID           string                       `json:"runID"`
	RunAttempt      *string                      `json:"runAttempt,omitempty"`
	Job             *string                      `json:"job,omitempty"`
	JobStatus       *AgentStoppedJobStatus       `json:"jobStatus,omitempty"`
	JobStatusSource *AgentStoppedJobStatusSource `json:"jobStatusSource,omitempty"`
	Jibril          *AgentStoppedJibril          `json:"jibril,omitempty"`
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

	in.RunID = strings.TrimSpace(in.RunID)
	if in.RunID == "" {
		v.Add("runID", "runID is required")
	} else if runID, err := strconv.ParseInt(in.RunID, 10, 64); err != nil || runID <= 0 {
		v.Add("runID", "runID must be a positive integer")
	}

	if in.RunAttempt != nil {
		runAttempt := strings.TrimSpace(*in.RunAttempt)
		if runAttempt == "" {
			in.RunAttempt = nil
		} else if attempt, err := strconv.ParseInt(runAttempt, 10, 64); err != nil || attempt <= 0 {
			v.Add("runAttempt", "runAttempt must be a positive integer")
		} else {
			in.RunAttempt = &runAttempt
		}
	}

	if in.Job != nil {
		job := strings.TrimSpace(*in.Job)
		if job == "" {
			in.Job = nil
		} else {
			in.Job = &job
		}
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

	if in.JobStatusSource != nil && !in.JobStatusSource.IsValid() {
		v.Add("jobStatusSource", "jobStatusSource must be one of github_api")
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
