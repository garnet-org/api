package types //nolint:revive // Package name is intentionally descriptive

import (
	"time"

	"github.com/garnet-org/api/validator"
)

// AgentVanillaContext represents the context of a vanilla agent (plain linux for example).
type AgentVanillaContext struct {
	ID        string    `json:"id"`
	Job       string    `json:"job"`
	RunnerOS  string    `json:"runner_os"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validator checks if the AgentVanillaContext has all required fields set.
func (v *AgentVanillaContext) Validator() *validator.Validator {
	validation := validator.New()

	if v.Job == "" {
		validation.Add("job", "job is required")
	}

	if v.RunnerOS == "" {
		validation.Add("runner_os", "runner_os is required")
	}

	return validation
}
