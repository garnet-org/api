package types

// AgentWithProfile is an agent paired with the profile it recorded. The
// relation is 1:1, so Profile is nil while the agent is still recording, and
// stays nil when the agent stopped before it could report one — the agent's
// stop fields then tell why.
type AgentWithProfile struct {
	Agent
	Profile *Profile `db:"profile"`
}
