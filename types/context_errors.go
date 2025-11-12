package types //nolint:revive // Package name is intentionally descriptive

import "github.com/garnet-org/api/types/errs"

// Common context-related errors for agent contexts.
const (
	// Kubernetes context errors.
	ErrMissingKubernetesContext = errs.InvalidArgumentError("missing Kubernetes context")
	ErrMissingClusterName       = errs.InvalidArgumentError("missing cluster name")
	ErrMissingNodeName          = errs.InvalidArgumentError("missing node name")
)