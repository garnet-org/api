package types //nolint:revive // Package name is intentionally descriptive

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/garnet-org/api/types/errs"
)

// AgentKind represents the type of agent.
type AgentKind string

const (
	// AgentKindGithub represents a GitHub agent.
	AgentKindGithub AgentKind = "github"

	// AgentKindKubernetes represents a Kubernetes agent.
	AgentKindKubernetes AgentKind = "kubernetes"

	// AgentKindVanilla represents a vanilla agent.
	AgentKindVanilla AgentKind = "vanilla"

	// ErrUnauthorizedAgent is returned when the user does not have permission to access the agent.
	ErrUnauthorizedAgent = errs.UnauthorizedError("permission denied")

	// ErrAgentNotFound is returned when the agent is not found.
	ErrAgentNotFound = errs.NotFoundError("agent not found")
)

// String returns the string representation of the AgentKind.
func (k AgentKind) String() string {
	return string(k)
}

// IsValid checks if the AgentKind is valid.
func (k AgentKind) IsValid() bool {
	switch k {
	case AgentKindGithub, AgentKindKubernetes, AgentKindVanilla:
		return true
	}

	return false
}

// AgentLabels represents a typed map of labels.
type AgentLabels map[string]string

// UnmarshalJSON implements custom JSON unmarshaling for AgentLabels.
func (l *AgentLabels) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*l = make(AgentLabels)

		return nil
	}

	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	*l = m

	return nil
}

// Scan implements sql.Scanner interface.
func (l *AgentLabels) Scan(value interface{}) error {
	if value == nil {
		*l = make(AgentLabels)

		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, l)
	case string:
		return json.Unmarshal([]byte(v), l)
	default:
		return fmt.Errorf("unsupported type for AgentLabels: %T", value)
	}
}

// Validate checks the labels against defined validation rules.
func (l AgentLabels) Validate() error {
	return ValidateLabels(map[string]string(l))
}

// Encode encodes the AgentLabels into URL query parameters.
func (l *AgentLabels) Encode() url.Values {
	values := url.Values{}

	if l == nil {
		return values
	}

	for key, value := range *l {
		values.Set("label."+key, value)
	}

	return values
}

// DecodeAgentLabels extracts AgentLabels from URL query parameters.
func DecodeAgentLabels(values url.Values) AgentLabels {
	labels := AgentLabels{}

	prefix := "label."
	for key, vals := range values {
		if len(vals) > 0 && len(key) > len(prefix) && key[:len(prefix)] == prefix {
			labelKey := key[len(prefix):]
			labels[labelKey] = vals[0]
		}
	}

	return labels
}

// AgentKubernetesContext represents Kubernetes-specific context.
type AgentKubernetesContext struct {
	ID        string    `json:"id"`
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace"`
	Node      string    `json:"node"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate checks if the AgentKubernetesContext has all required fields set
// and validates that fields conform to Kubernetes naming conventions.
func (c *AgentKubernetesContext) Validate() error {
	if c == nil {
		return errors.New("kubernetes context is required")
	}

	var errs []string
	
	// Validate cluster name
	if c.Cluster == "" {
		errs = append(errs, "cluster is required")
	} else if err := ValidateK8sClusterName(c.Cluster); err != nil {
		errs = append(errs, fmt.Sprintf("invalid cluster name: %v", err))
	}

	// Validate node name
	if c.Node == "" {
		errs = append(errs, "node is required")
	} else if err := ValidateK8sNodeName(c.Node); err != nil {
		errs = append(errs, fmt.Sprintf("invalid node name: %v", err))
	}

	// Validate namespace (optional)
	if c.Namespace != "" {
		if err := ValidateK8sNamespace(c.Namespace); err != nil {
			errs = append(errs, fmt.Sprintf("invalid namespace: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid kubernetes context: %s", join(errs))
	}

	return nil
}

// Agent represents the stored agent model.
type Agent struct {
	ID                string                  `json:"id"`
	ProjectID         string                  `json:"project_id"`
	OS                string                  `json:"os"`
	Arch              string                  `json:"arch"`
	Hostname          string                  `json:"hostname"`
	Version           string                  `json:"version"`
	IP                string                  `json:"ip"`
	MachineID         string                  `json:"machine_id"`
	Labels            AgentLabels             `json:"labels"`
	Kind              AgentKind               `json:"kind"`
	GithubContext     *AgentGithubContext     `json:"github_context,omitempty"`
	KubernetesContext *AgentKubernetesContext `json:"kubernetes_context,omitempty"`
	VanillaContext    *AgentVanillaContext    `json:"vanilla_context,omitempty"`
	NetworkPolicy     *MergedNetworkPolicy    `json:"network_policy,omitempty"`
	Active            bool                    `json:"active"`
	LastSeen          time.Time               `json:"last_seen"`
	CreatedAt         time.Time               `json:"created_at"`
	UpdatedAt         time.Time               `json:"updated_at"`
}

// CreateAgent represents the request to create a new agent.
type CreateAgent struct {
	// projectID is populated by decoding the JWT token.
	projectID string
	OS        string      `json:"os"`
	Arch      string      `json:"arch"`
	Hostname  string      `json:"hostname"`
	Version   string      `json:"version"`
	IP        string      `json:"ip"`
	MachineID string      `json:"machine_id"`
	Labels    AgentLabels `json:"labels"`
	Kind      AgentKind   `json:"kind"`

	GithubContext     *AgentGithubContext     `json:"github_context,omitempty"`
	KubernetesContext *AgentKubernetesContext `json:"kubernetes_context,omitempty"`
	VanillaContext    *AgentVanillaContext    `json:"vanilla_context,omitempty"`
}

// SetProjectID sets the project ID for the agent.
func (c *CreateAgent) SetProjectID(projectID string) {
	c.projectID = projectID
}

// ProjectID returns the project ID associated with the agent.
func (c *CreateAgent) ProjectID() string {
	return c.projectID
}

// ErrInvalidAgentType is returned when the agent kind is invalid.
const ErrInvalidAgentType = errs.InvalidArgumentError("invalid agent kind")

// Validate checks if the CreateAgent has all required fields set.
func (c *CreateAgent) Validate() error {
	if !c.Kind.IsValid() {
		return ErrInvalidAgentType
	}

	var errs []string
	if c.OS == "" {
		errs = append(errs, "os is required")
	}

	if c.Arch == "" {
		errs = append(errs, "arch is required")
	}

	if c.Hostname == "" {
		errs = append(errs, "hostname is required")
	}

	if c.Version == "" {
		errs = append(errs, "version is required")
	}

	ip := net.ParseIP(c.IP)
	if ip == nil {
		errs = append(errs, "invalid ip")
	}

	if c.IP == "" {
		errs = append(errs, "ip is required")
	}

	if c.MachineID == "" {
		errs = append(errs, "machine_id is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid agent: %s", join(errs))
	}

	// Validate labels
	if err := c.Labels.Validate(); err != nil {
		return err
	}

	// Validate context based on Kind
	switch c.Kind {
	case AgentKindGithub:
		if c.GithubContext == nil {
			return errors.New("github context is required for github agents")
		}
		return c.GithubContext.Validate()
	case AgentKindKubernetes:
		if c.KubernetesContext == nil {
			return errors.New("kubernetes context is required for kubernetes agents")
		}
		return c.KubernetesContext.Validate()
	case AgentKindVanilla:
		if c.VanillaContext == nil {
			return errors.New("vanilla context is required for vanilla agents")
		}
		return c.VanillaContext.Validate()
	}

	if c.GithubContext == nil && c.KubernetesContext == nil && c.VanillaContext == nil {
		return errors.New("at least one context is required")
	}

	return nil
}

// AgentCreated represents the response after creating an agent.
type AgentCreated struct {
	ID            string               `json:"id"`
	AgentToken    string               `json:"agent_token"`
	NetworkPolicy *MergedNetworkPolicy `json:"network_policy,omitempty"`
}

// UpdateAgent represents the request to update an existing agent.
type UpdateAgent struct {
	OS                *string                 `json:"os,omitempty"`
	Arch              *string                 `json:"arch,omitempty"`
	Hostname          *string                 `json:"hostname,omitempty"`
	Version           *string                 `json:"version,omitempty"`
	IP                *string                 `json:"ip,omitempty"`
	MachineID         *string                 `json:"machine_id,omitempty"`
	Kind              *AgentKind              `json:"kind,omitempty"`
	GithubContext     *AgentGithubContext     `json:"github_context,omitempty"`
	KubernetesContext *AgentKubernetesContext `json:"kubernetes_context,omitempty"`
	VanillaContext    *AgentVanillaContext    `json:"vanilla_context,omitempty"`
}

// Validate checks if the UpdateAgent has all required fields set.
func (a *UpdateAgent) Validate() error { //nolint:gocognit,gocyclo
	if a.OS == nil && a.Arch == nil && a.Hostname == nil &&
		a.Version == nil && a.IP == nil && a.MachineID == nil && a.Kind == nil {
		return errors.New("at least one field is required")
	}

	var errs []string

	if a.OS != nil && *a.OS == "" {
		errs = append(errs, "os valid but empty")
	}

	if a.Arch != nil && *a.Arch == "" {
		errs = append(errs, "arch valid but empty")
	}

	if a.Hostname != nil && *a.Hostname == "" {
		errs = append(errs, "hostname valid but empty")
	}

	if a.Version != nil && *a.Version == "" {
		errs = append(errs, "version valid but empty")
	}

	if a.IP != nil && *a.IP == "" {
		errs = append(errs, "ip valid but empty")
	} else if a.IP != nil {
		ip := net.ParseIP(*a.IP)
		if ip == nil {
			errs = append(errs, "invalid ip format")
		}
	}

	if a.MachineID != nil && *a.MachineID == "" {
		errs = append(errs, "machine_id valid but empty")
	}

	if a.Kind != nil {
		if !a.Kind.IsValid() {
			errs = append(errs, "invalid agent kind")
		}

		switch *a.Kind {
		case AgentKindGithub:
			if a.GithubContext == nil {
				errs = append(errs, "github context is required")
			} else if err := a.GithubContext.Validate(); err != nil {
				errs = append(errs, "invalid github context: "+err.Error())
			}
		case AgentKindKubernetes:
			if a.KubernetesContext == nil {
				errs = append(errs, "kubernetes context is required")
			} else if err := a.KubernetesContext.Validate(); err != nil {
				errs = append(errs, "invalid kubernetes context: "+err.Error())
			}
		case AgentKindVanilla:
			if a.VanillaContext == nil {
				errs = append(errs, "vanilla context is required")
			} else if err := a.VanillaContext.Validate(); err != nil {
				errs = append(errs, "invalid vanilla context: "+err.Error())
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid update agent: %s", join(errs))
	}

	return nil
}

// Helper function to join error messages.
func join(strs []string) string {
	if len(strs) == 0 {
		return ""
	}

	if len(strs) == 1 {
		return strs[0]
	}

	result := strs[0]
	for _, s := range strs[1:] {
		result += "," + s
	}

	return result
}

// ListAgents represents the request to list agents.
type ListAgents struct {
	PageArgs

	Labels    AgentLabels   `json:"labels,omitempty"`
	Filters   *AgentFilters `json:"filters,omitempty"`
	ProjectID string        `json:"project_id,omitempty"` // ProjectID for filtering
}

// Validate checks if the ListAgents has all required fields set.
func (q *ListAgents) Validate() error {
	// Validate filters if provided
	if q.Filters != nil {
		if q.Filters.IP != nil {
			ip := net.ParseIP(*q.Filters.IP)
			if ip == nil {
				return errors.New("invalid ip")
			}
		}
	}

	// Validate labels if provided
	if len(q.Labels) > 0 {
		if err := q.Labels.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// AgentFilters provides strongly typed filtering options for agents.
type AgentFilters struct {
	OS        *string `json:"os,omitempty"`
	Arch      *string `json:"arch,omitempty"`
	Hostname  *string `json:"hostname,omitempty"`
	Version   *string `json:"version,omitempty"`
	IP        *string `json:"ip,omitempty"`
	MachineID *string `json:"machine_id,omitempty"`
	Kind      *string `json:"kind,omitempty"`
}

// Encode encodes the AgentFilters into URL query parameters.
func (f *AgentFilters) Encode() url.Values {
	values := url.Values{}

	if f == nil {
		return values
	}

	if f.OS != nil {
		values.Set("filter.os", *f.OS)
	}

	if f.Arch != nil {
		values.Set("filter.arch", *f.Arch)
	}

	if f.Hostname != nil {
		values.Set("filter.hostname", *f.Hostname)
	}

	if f.Version != nil {
		values.Set("filter.version", *f.Version)
	}

	if f.IP != nil {
		values.Set("filter.ip", *f.IP)
	}

	if f.MachineID != nil {
		values.Set("filter.machine_id", *f.MachineID)
	}

	if f.Kind != nil {
		values.Set("filter.kind", *f.Kind)
	}

	return values
}

// DecodeAgentFilters extracts AgentFilters from URL query parameters.
func DecodeAgentFilters(values url.Values) *AgentFilters {
	filters := &AgentFilters{}

	if os := values.Get("filter.os"); os != "" {
		filters.OS = &os
	}

	if arch := values.Get("filter.arch"); arch != "" {
		filters.Arch = &arch
	}

	if hostname := values.Get("filter.hostname"); hostname != "" {
		filters.Hostname = &hostname
	}

	if version := values.Get("filter.version"); version != "" {
		filters.Version = &version
	}

	if ip := values.Get("filter.ip"); ip != "" {
		filters.IP = &ip
	}

	if machineID := values.Get("filter.machine_id"); machineID != "" {
		filters.MachineID = &machineID
	}

	if kind := values.Get("filter.kind"); kind != "" {
		filters.Kind = &kind
	}

	if filters.IsEmpty() {
		return nil
	}

	return filters
}

// IsEmpty checks if all filters are nil.
func (f AgentFilters) IsEmpty() bool {
	return f.OS == nil && f.Arch == nil && f.Hostname == nil &&
		f.Version == nil && f.IP == nil && f.MachineID == nil && f.Kind == nil
}
