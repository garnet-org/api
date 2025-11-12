package types //nolint:revive // Package name is intentionally descriptive

import (
	"fmt"
	"time"
)

// AgentVanillaContext represents the context of a vanilla agent (plain linux for example).
type AgentVanillaContext struct {
	ID        string    `json:"id"`
	Job       string    `json:"job"`
	RunnerOS  string    `json:"runner_os"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate checks if the AgentVanillaContext has all required fields set.
func (v *AgentVanillaContext) Validate() error {
	var errs []string

	if v.Job == "" {
		errs = append(errs, "job is required")
	}

	if v.RunnerOS == "" {
		errs = append(errs, "runner_os is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation errors: %v", errs)
	}
	return nil
}
