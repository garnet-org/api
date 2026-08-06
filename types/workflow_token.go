package types

// WorkflowToken is the verified identity carried by an X-Workflow-Token,
// issued by the OIDC exchange endpoint and used to register GitHub agents.
type WorkflowToken struct {
	Kind   string
	Scopes []string
	GitHub GitHubRunClaims
}
