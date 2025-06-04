package types

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/garnet-org/api/types/errs"
)

// PolicyFormat represents the output format for merged network policies.
type PolicyFormat string

const (
	// PolicyFormatJSON returns JSON format (default).
	PolicyFormatJSON PolicyFormat = ""
	// PolicyFormatYAML returns pre-formatted YAML bytes.
	PolicyFormatYAML PolicyFormat = "yaml"
)

// Network policy error constants.
const (
	// ErrInvalidNetworkPolicyScope is returned when the network policy scope is not one of the defined valid options.
	ErrInvalidNetworkPolicyScope = errs.InvalidArgumentError("invalid network policy scope")

	// GitHub context errors
	// ErrInvalidNetworkPolicyRepositoryID is returned when the repository ID is missing or invalid in a repo or workflow scoped policy.
	ErrInvalidNetworkPolicyRepositoryID = errs.InvalidArgumentError("invalid network policy repository id")
	// ErrInvalidNetworkPolicyWorkflowName is returned when the workflow name is missing or invalid for a workflow-scoped policy.
	ErrInvalidNetworkPolicyWorkflowName = errs.InvalidArgumentError("invalid network policy workflow name")

	// Kubernetes context errors
	// ErrInvalidNetworkPolicyClusterName is returned when the cluster name is missing or invalid for a K8s policy.
	ErrInvalidNetworkPolicyClusterName = errs.InvalidArgumentError("invalid network policy cluster name")
	// ErrInvalidNetworkPolicyNodeName is returned when the node name is missing or invalid for a node-scoped policy.
	ErrInvalidNetworkPolicyNodeName = errs.InvalidArgumentError("invalid network policy node name")

	// ErrInvalidNetworkPolicyRuleType is returned when the rule type is not one of the supported types (e.g., CIDR or domain).
	ErrInvalidNetworkPolicyRuleType = errs.InvalidArgumentError("invalid network policy rule type")

	// ErrInvalidNetworkPolicyRuleValue is returned when the rule value (CIDR or domain) is malformed or empty.
	ErrInvalidNetworkPolicyRuleValue = errs.InvalidArgumentError("invalid network policy rule value")

	// ErrInvalidNetworkPolicyCIDRMode is returned when the CIDR mode is not one of the allowed values.
	ErrInvalidNetworkPolicyCIDRMode = errs.InvalidArgumentError("invalid network policy CIDR mode")

	// ErrInvalidNetworkPolicyCIDRPolicy is returned when the CIDR policy is not a valid allow/deny value.
	ErrInvalidNetworkPolicyCIDRPolicy = errs.InvalidArgumentError("invalid network policy CIDR policy")

	// ErrInvalidNetworkPolicyResolveMode is returned when the DNS resolution mode is not valid.
	ErrInvalidNetworkPolicyResolveMode = errs.InvalidArgumentError("invalid network policy resolve mode")

	// ErrInvalidNetworkPolicyResolvePolicy is returned when the resolve policy is not valid.
	ErrInvalidNetworkPolicyResolvePolicy = errs.InvalidArgumentError("invalid network policy resolve policy")

	// ErrInvalidNetworkPolicyID is returned when the provided policy ID is malformed or missing.
	ErrInvalidNetworkPolicyID = errs.InvalidArgumentError("invalid network policy ID")

	// ErrInvalidNetworkPolicyRuleID is returned when the rule ID is invalid or missing.
	ErrInvalidNetworkPolicyRuleID = errs.InvalidArgumentError("invalid network policy rule ID")

	// ErrUnauthorizedNetworkPolicy is returned when a user attempts to modify or view a policy without proper permissions.
	ErrUnauthorizedNetworkPolicy = errs.UnauthorizedError("permission denied")

	// ErrNetworkPolicyNotFound is returned when the specified network policy could not be found.
	ErrNetworkPolicyNotFound = errs.NotFoundError("network policy not found")

	// ErrNetworkPolicyRuleNotFound is returned when a rule with the specified ID could not be found.
	ErrNetworkPolicyRuleNotFound = errs.NotFoundError("network policy rule not found")

	// ErrNetworkPolicyAlreadyExists is returned when attempting to create a policy that already exists.
	ErrNetworkPolicyAlreadyExists = errs.ConflictError("network policy already exists")

	// ErrNetworkPolicyRuleAlreadyExists is returned when a rule already exists in the policy and duplicates are not allowed.
	ErrNetworkPolicyRuleAlreadyExists = errs.ConflictError("network policy rule already exists")
)

// NetworkPolicyScope represents the possible scopes of a network policy.
type NetworkPolicyScope string

const (
	// NetworkPolicyScopeSystemGlobal represents a system-wide network policy that applies across all projects.
	// This scope is managed only by system administrators and cannot be modified by regular users.
	NetworkPolicyScopeSystemGlobal NetworkPolicyScope = "system_global"

	// NetworkPolicyScopeGlobal represents a network policy that applies globally within a project.
	NetworkPolicyScopeGlobal NetworkPolicyScope = "global"

	// NetworkPolicyScopeRepo represents a network policy that applies to a specific repository.
	// This scope is used for GitHub context.
	NetworkPolicyScopeRepo NetworkPolicyScope = "repo"
	// NetworkPolicyScopeWorkflow represents a network policy that applies to a specific workflow.
	// This scope is used for GitHub context.
	NetworkPolicyScopeWorkflow NetworkPolicyScope = "workflow"

	// NetworkPolicyScopeCluster represents a network policy that applies to a specific K8s cluster.
	// This scope is used for Kubernetes context.
	NetworkPolicyScopeCluster NetworkPolicyScope = "cluster"
	// NetworkPolicyScopeNode represents a network policy that applies to a specific K8s node.
	// This scope is used for Kubernetes context.
	NetworkPolicyScopeNode NetworkPolicyScope = "node"
)

// String returns the string representation of the NetworkPolicyScope.
func (s NetworkPolicyScope) String() string {
	return string(s)
}

// IsValid checks if the NetworkPolicyScope is valid.
func (s NetworkPolicyScope) IsValid() bool {
	switch s {
	case NetworkPolicyScopeSystemGlobal, NetworkPolicyScopeGlobal, NetworkPolicyScopeRepo, NetworkPolicyScopeWorkflow,
		NetworkPolicyScopeCluster, NetworkPolicyScopeNode:
		return true
	}
	return false
}

// NetworkPolicyCIDRMode represents the possible modes for CIDR handling.
type NetworkPolicyCIDRMode string

const (
	// NetworkPolicyCIDRModeIPv4 represents a network policy that applies to IPv4 addresses.
	NetworkPolicyCIDRModeIPv4 NetworkPolicyCIDRMode = "ipv4"

	// NetworkPolicyCIDRModeIPv6 represents a network policy that applies to IPv6 addresses.
	NetworkPolicyCIDRModeIPv6 NetworkPolicyCIDRMode = "ipv6"

	// NetworkPolicyCIDRModeBoth represents a network policy that applies to both IPv4 and IPv6 addresses.
	NetworkPolicyCIDRModeBoth NetworkPolicyCIDRMode = "both"
)

// String returns the string representation of the NetworkPolicyCIDRMode.
func (m NetworkPolicyCIDRMode) String() string {
	return string(m)
}

// IsValid checks if the NetworkPolicyCIDRMode is valid.
func (m NetworkPolicyCIDRMode) IsValid() bool {
	switch m {
	case NetworkPolicyCIDRModeIPv4, NetworkPolicyCIDRModeIPv6, NetworkPolicyCIDRModeBoth:
		return true
	}
	return false
}

// NetworkPolicyType represents the possible policy types.
type NetworkPolicyType string

const (
	// NetworkPolicyTypeAllow represents a network policy that allows traffic.
	NetworkPolicyTypeAllow NetworkPolicyType = "allow"

	// NetworkPolicyTypeDeny represents a network policy that denies traffic.
	NetworkPolicyTypeDeny NetworkPolicyType = "deny"
)

// String returns the string representation of the NetworkPolicyType.
func (p NetworkPolicyType) String() string {
	return string(p)
}

// IsValid checks if the NetworkPolicyType is valid.
func (p NetworkPolicyType) IsValid() bool {
	switch p {
	case NetworkPolicyTypeAllow, NetworkPolicyTypeDeny:
		return true
	}
	return false
}

// NetworkPolicyResolveMode represents the possible modes for DNS resolution.
type NetworkPolicyResolveMode string

const (
	// NetworkPolicyResolveModsBypass represents a network policy that bypasses DNS resolution.
	NetworkPolicyResolveModsBypass NetworkPolicyResolveMode = "bypass"

	// NetworkPolicyResolveModeStrict represents a network policy that strictly enforces DNS resolution.
	NetworkPolicyResolveModeStrict NetworkPolicyResolveMode = "strict"

	// NetworkPolicyResolveModePermissive represents a network policy that allows permissive DNS resolution.
	NetworkPolicyResolveModePermissive NetworkPolicyResolveMode = "permissive"
)

// String returns the string representation of the NetworkPolicyResolveMode.
func (m NetworkPolicyResolveMode) String() string {
	return string(m)
}

// IsValid checks if the NetworkPolicyResolveMode is valid.
func (m NetworkPolicyResolveMode) IsValid() bool {
	switch m {
	case NetworkPolicyResolveModsBypass, NetworkPolicyResolveModeStrict, NetworkPolicyResolveModePermissive:
		return true
	}
	return false
}

// NetworkPolicyRuleType represents the type of network policy rule.
type NetworkPolicyRuleType string

const (
	// NetworkPolicyRuleTypeCIDR represents a rule that applies to CIDR ranges.
	NetworkPolicyRuleTypeCIDR NetworkPolicyRuleType = "cidr"

	// NetworkPolicyRuleTypeDomain represents a rule that applies to domain names.
	NetworkPolicyRuleTypeDomain NetworkPolicyRuleType = "domain"
)

// String returns the string representation of the NetworkPolicyRuleType.
func (t NetworkPolicyRuleType) String() string {
	return string(t)
}

// IsValid checks if the NetworkPolicyRuleType is valid.
func (t NetworkPolicyRuleType) IsValid() bool {
	switch t {
	case NetworkPolicyRuleTypeCIDR, NetworkPolicyRuleTypeDomain:
		return true
	}
	return false
}

// NetworkPolicyRule represents a single rule in a network policy.
type NetworkPolicyRule struct {
	ID        string                `json:"id"`
	PolicyID  string                `json:"policy_id"`
	Type      NetworkPolicyRuleType `json:"type"`
	Value     string                `json:"value"`
	Action    NetworkPolicyType     `json:"action"`
	CreatedAt time.Time             `json:"created_at"`
	UpdatedAt time.Time             `json:"updated_at"`
}

// Validate ensures the NetworkPolicyRule is valid.
func (r *NetworkPolicyRule) Validate() error {
	// Validate rule type
	if !r.Type.IsValid() {
		return ErrInvalidNetworkPolicyRuleType
	}

	// Validate action
	if !r.Action.IsValid() {
		return ErrInvalidNetworkPolicyCIDRPolicy
	}

	// Validate rule value based on type
	switch r.Type {
	case NetworkPolicyRuleTypeCIDR:
		_, _, err := net.ParseCIDR(r.Value)
		if err != nil {
			return ErrInvalidNetworkPolicyRuleValue
		}
	case NetworkPolicyRuleTypeDomain:
		if r.Value == "" {
			return ErrInvalidNetworkPolicyRuleValue
		}
		// Could add more sophisticated domain validation here
	}

	return nil
}

// NetworkPolicyConfig represents the configuration options for a network policy.
type NetworkPolicyConfig struct {
	CIDRMode      NetworkPolicyCIDRMode    `json:"cidr_mode"`
	CIDRPolicy    NetworkPolicyType        `json:"cidr_policy"`
	ResolveMode   NetworkPolicyResolveMode `json:"resolve_mode"`
	ResolvePolicy NetworkPolicyType        `json:"resolve_policy"`
}

// Validate ensures the NetworkPolicyConfig is valid.
func (c *NetworkPolicyConfig) Validate() error {
	// Validate CIDR mode
	if !c.CIDRMode.IsValid() {
		return ErrInvalidNetworkPolicyCIDRMode
	}

	// Validate CIDR policy
	if !c.CIDRPolicy.IsValid() {
		return ErrInvalidNetworkPolicyCIDRPolicy
	}

	// Validate resolve mode
	if !c.ResolveMode.IsValid() {
		return ErrInvalidNetworkPolicyResolveMode
	}

	// Validate resolve policy
	if !c.ResolvePolicy.IsValid() {
		return ErrInvalidNetworkPolicyResolvePolicy
	}

	return nil
}

// Scan implements the sql.Scanner interface for NetworkPolicyConfig.
func (c *NetworkPolicyConfig) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, c)
	case string:
		return json.Unmarshal([]byte(v), c)
	default:
		return fmt.Errorf("unsupported type for NetworkPolicyConfig: %T", value)
	}
}

// NetworkPolicy represents the base network policy model.
type NetworkPolicy struct {
	ID        string              `json:"id"`
	ProjectID string              `json:"-"` // Not exposed in API
	Scope     NetworkPolicyScope  `json:"scope"`
	Config    NetworkPolicyConfig `json:"config"`
	Rules     []NetworkPolicyRule `json:"rules"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
	DeletedAt *time.Time          `json:"deleted_at,omitempty"`
}

// SystemGlobalNetworkPolicy represents a network policy with system global scope.
// This policy applies across all projects and can only be managed by system administrators.
type SystemGlobalNetworkPolicy struct {
	NetworkPolicy
	// Note: ProjectID is not set for system global policies (remains empty)
}

// GlobalNetworkPolicy represents a network policy with global scope within a project.
type GlobalNetworkPolicy struct {
	NetworkPolicy
}

// RepoNetworkPolicy represents a network policy with repository scope.
type RepoNetworkPolicy struct {
	NetworkPolicy
	RepositoryID string `json:"repository_id"`
}

// WorkflowNetworkPolicy represents a network policy with workflow scope.
type WorkflowNetworkPolicy struct {
	NetworkPolicy
	RepositoryID string `json:"repository_id"`
	WorkflowName string `json:"workflow_name"`
}

// ClusterNetworkPolicy represents a network policy with Kubernetes cluster scope.
type ClusterNetworkPolicy struct {
	NetworkPolicy
	ClusterName string `json:"cluster_name"`
}

// NodeNetworkPolicy represents a network policy with Kubernetes node scope.
type NodeNetworkPolicy struct {
	NetworkPolicy
	ClusterName string `json:"cluster_name"`
	NodeName    string `json:"node_name"`
}

// MergedNetworkPolicy represents a network policy that combines all applicable policies.
type MergedNetworkPolicy struct {
	Config              NetworkPolicyConfig       `json:"config"`
	Rules               []NetworkPolicyRule       `json:"rules"`
	SystemGlobalPolicy  *SystemGlobalNetworkPolicy `json:"system_global_policy,omitempty"`
	GlobalPolicy        *NetworkPolicy            `json:"global_policy,omitempty"`

	// GitHub context policies
	RepoPolicy          *RepoNetworkPolicy        `json:"repo_policy,omitempty"`
	WorkflowPolicy      *WorkflowNetworkPolicy    `json:"workflow_policy,omitempty"`

	// Kubernetes context policies
	ClusterPolicy       *ClusterNetworkPolicy     `json:"cluster_policy,omitempty"`
	NodePolicy          *NodeNetworkPolicy        `json:"node_policy,omitempty"`
}


// CreateNetworkPolicy represents the request to create a new network policy.
type CreateNetworkPolicy struct {
	Scope        NetworkPolicyScope        `json:"scope"`
	Config       NetworkPolicyConfig       `json:"config"`
	Rules        []CreateNetworkPolicyRule `json:"rules,omitempty"`

	// GitHub context fields
	RepositoryID string                    `json:"repository_id,omitempty"`
	WorkflowName string                    `json:"workflow_name,omitempty"`

	// Kubernetes context fields
	ClusterName  string                    `json:"cluster_name,omitempty"`
	NodeName     string                    `json:"node_name,omitempty"`

	ProjectID    string                    `json:"-"` // Populated by the service layer, not exposed in API
}

// Validate ensures the CreateNetworkPolicy request is valid.
func (c *CreateNetworkPolicy) Validate() error {
	// Check network policy scope
	if !c.Scope.IsValid() {
		return ErrInvalidNetworkPolicyScope
	}

	// Validate required fields based on scope
	switch c.Scope {
	case NetworkPolicyScopeSystemGlobal:
		// System global policy doesn't require any additional fields
	case NetworkPolicyScopeGlobal:
		// Global policy doesn't require any additional fields
	case NetworkPolicyScopeRepo:
		if c.RepositoryID == "" {
			return ErrInvalidNetworkPolicyRepositoryID
		}
	case NetworkPolicyScopeWorkflow:
		if c.RepositoryID == "" {
			return ErrInvalidNetworkPolicyRepositoryID
		}
		if c.WorkflowName == "" {
			return ErrInvalidNetworkPolicyWorkflowName
		}
	case NetworkPolicyScopeCluster:
		if c.ClusterName == "" {
			return ErrInvalidNetworkPolicyClusterName
		}
	case NetworkPolicyScopeNode:
		if c.ClusterName == "" {
			return ErrInvalidNetworkPolicyClusterName
		}
		if c.NodeName == "" {
			return ErrInvalidNetworkPolicyNodeName
		}
	}

	// Validate config
	if err := c.Config.Validate(); err != nil {
		return err
	}

	// Validate rules if provided
	for _, rule := range c.Rules {
		if err := rule.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// NetworkPolicyCreated represents the response when a network policy is successfully created.
type NetworkPolicyCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpdateNetworkPolicy represents the request to update an existing network policy.
type UpdateNetworkPolicy struct {
	Config *NetworkPolicyConfig `json:"config"`
}

// Validate ensures the UpdateNetworkPolicy request is valid.
func (u *UpdateNetworkPolicy) Validate() error {
	// Config is required
	if u.Config == nil {
		return errs.InvalidArgumentError("config is required")
	}

	// Validate config
	if err := u.Config.Validate(); err != nil {
		return err
	}

	return nil
}

// NetworkPolicyUpdated represents the response when a network policy is successfully updated.
type NetworkPolicyUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateNetworkPolicyRule represents the request to create a new network policy rule.
// The PolicyID is populated by the service layer.
type CreateNetworkPolicyRule struct {
	Type   NetworkPolicyRuleType `json:"type"`
	Value  string                `json:"value"`
	Action NetworkPolicyType     `json:"action"`
}

// Validate ensures the CreateNetworkPolicyRule request is valid.
func (c *CreateNetworkPolicyRule) Validate() error {
	// Create a temporary rule to validate the type and value
	rule := NetworkPolicyRule{
		Type:   c.Type,
		Value:  c.Value,
		Action: c.Action,
	}

	return rule.Validate()
}

// NetworkPolicyRuleCreated represents the response when a network policy rule is successfully created.
type NetworkPolicyRuleCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// UpdateNetworkPolicyRule represents the request to update an existing network policy rule.
type UpdateNetworkPolicyRule struct {
	Value  *string            `json:"value,omitempty"`
	Action *NetworkPolicyType `json:"action,omitempty"`
}

// Validate ensures the UpdateNetworkPolicyRule request is valid.
func (u *UpdateNetworkPolicyRule) Validate() error {
	// Check if any fields are specified
	if u.Value == nil && u.Action == nil {
		return errs.InvalidArgumentError("at least one field is required")
	}

	// Validate action if provided
	if u.Action != nil && !u.Action.IsValid() {
		return ErrInvalidNetworkPolicyCIDRPolicy
	}

	// Value validation will need to happen in the service layer since we need the rule type

	return nil
}

// NetworkPolicyRuleUpdated represents the response when a network policy rule is successfully updated.
type NetworkPolicyRuleUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// initialMergedNetworkPolicy creates a new MergedNetworkPolicy with default config values.
// This is a helper function used by the merge policy functions.
func initialMergedNetworkPolicy() *MergedNetworkPolicy {
	return &MergedNetworkPolicy{
		Config: NetworkPolicyConfig{
			CIDRMode:      NetworkPolicyCIDRModeBoth,      // Default values
			CIDRPolicy:    NetworkPolicyTypeAllow,         // Default values
			ResolveMode:   NetworkPolicyResolveModsBypass, // Default values
			ResolvePolicy: NetworkPolicyTypeAllow,         // Default values
		},
		Rules: []NetworkPolicyRule{},
	}
}

// applyPolicy applies a network policy to the merged policy.
// It appends the rules and sets the config, overriding previous values.
func applyPolicy(merged *MergedNetworkPolicy, policy *NetworkPolicy) {
	if policy == nil || policy.ID == "" {
		return // Skip if policy is nil or has no ID
	}

	// Add policy rules
	policyRules := make([]NetworkPolicyRule, len(policy.Rules))
	copy(policyRules, policy.Rules)
	merged.Rules = append(merged.Rules, policyRules...)

	// Config overrides existing config
	merged.Config = policy.Config
}

// GetMergedNetworkPolicy constructs a merged policy from the provided GitHub context policies.
// This is used for agents with GitHub context.
func GetMergedNetworkPolicy(systemGlobal *SystemGlobalNetworkPolicy, global *GlobalNetworkPolicy, repo *RepoNetworkPolicy, workflow *WorkflowNetworkPolicy) *MergedNetworkPolicy {
	// Start with a default config
	merged := initialMergedNetworkPolicy()

	// Store policy references
	if systemGlobal != nil {
		merged.SystemGlobalPolicy = systemGlobal
	}
	if global != nil {
		merged.GlobalPolicy = &global.NetworkPolicy
	}
	if repo != nil {
		merged.RepoPolicy = repo
	}
	if workflow != nil {
		merged.WorkflowPolicy = workflow
	}

	// Apply the configs and rules in order from lowest to highest precedence
	// 1. Start with defaults (already set above)
	// 2. Add system global policy (baseline for all projects)
	// 3. Add project global policy
	// 4. Add repo policy if available
	// 5. Add workflow policy if available

	// Apply system global policy (baseline)
	if systemGlobal != nil {
		applyPolicy(merged, &systemGlobal.NetworkPolicy)
	}

	// Apply project global policy (overrides system global)
	if global != nil {
		applyPolicy(merged, &global.NetworkPolicy)
	}

	// Apply repo policy (overrides project global)
	if repo != nil {
		applyPolicy(merged, &repo.NetworkPolicy)
	}

	// Apply workflow policy (overrides repo and global)
	if workflow != nil {
		applyPolicy(merged, &workflow.NetworkPolicy)
	}

	return merged
}

// GetMergedNetworkPolicyForK8s constructs a merged policy from the provided Kubernetes context policies.
// This is used for agents with Kubernetes context.
func GetMergedNetworkPolicyForK8s(systemGlobal *SystemGlobalNetworkPolicy, global *GlobalNetworkPolicy, cluster *ClusterNetworkPolicy, node *NodeNetworkPolicy) *MergedNetworkPolicy {
	// Start with a default config
	merged := initialMergedNetworkPolicy()

	// Store policy references
	if systemGlobal != nil {
		merged.SystemGlobalPolicy = systemGlobal
	}
	if global != nil {
		merged.GlobalPolicy = &global.NetworkPolicy
	}
	if cluster != nil {
		merged.ClusterPolicy = cluster
	}
	if node != nil {
		merged.NodePolicy = node
	}

	// Apply the configs and rules in order from lowest to highest precedence
	// 1. Start with defaults (already set above)
	// 2. Add system global policy (baseline for all projects)
	// 3. Add project global policy
	// 4. Add cluster policy if available
	// 5. Add node policy if available

	// Apply system global policy (baseline)
	if systemGlobal != nil {
		applyPolicy(merged, &systemGlobal.NetworkPolicy)
	}

	// Apply project global policy (overrides system global)
	if global != nil {
		applyPolicy(merged, &global.NetworkPolicy)
	}

	// Apply cluster policy (overrides project global)
	if cluster != nil {
		applyPolicy(merged, &cluster.NetworkPolicy)
	}

	// Apply node policy (overrides cluster and global)
	if node != nil {
		applyPolicy(merged, &node.NetworkPolicy)
	}

	return merged
}

// GetDefaultNetworkPolicyConfig returns a default network policy configuration.
func GetDefaultNetworkPolicyConfig() NetworkPolicyConfig {
	return NetworkPolicyConfig{
		CIDRMode:      NetworkPolicyCIDRModeBoth,
		CIDRPolicy:    NetworkPolicyTypeAllow,
		ResolveMode:   NetworkPolicyResolveModsBypass,
		ResolvePolicy: NetworkPolicyTypeAllow,
	}
}

// CreateDefaultRepoNetworkPolicy creates a default CreateNetworkPolicy for a repository.
func CreateDefaultRepoNetworkPolicy(repositoryID string) CreateNetworkPolicy {
	return CreateNetworkPolicy{
		Scope:        NetworkPolicyScopeRepo,
		RepositoryID: repositoryID,
		Config:       GetDefaultNetworkPolicyConfig(),
	}
}

// CreateDefaultWorkflowNetworkPolicy creates a default CreateNetworkPolicy for a workflow.
func CreateDefaultWorkflowNetworkPolicy(repositoryID, workflowName string) CreateNetworkPolicy {
	return CreateNetworkPolicy{
		Scope:        NetworkPolicyScopeWorkflow,
		RepositoryID: repositoryID,
		WorkflowName: workflowName,
		Config:       GetDefaultNetworkPolicyConfig(),
	}
}

// CreateDefaultClusterNetworkPolicy creates a default CreateNetworkPolicy for a K8s cluster.
func CreateDefaultClusterNetworkPolicy(clusterName string) CreateNetworkPolicy {
	return CreateNetworkPolicy{
		Scope:       NetworkPolicyScopeCluster,
		ClusterName: clusterName,
		Config:      GetDefaultNetworkPolicyConfig(),
	}
}

// CreateDefaultNodeNetworkPolicy creates a default CreateNetworkPolicy for a K8s node.
func CreateDefaultNodeNetworkPolicy(clusterName, nodeName string) CreateNetworkPolicy {
	return CreateNetworkPolicy{
		Scope:       NetworkPolicyScopeNode,
		ClusterName: clusterName,
		NodeName:    nodeName,
		Config:      GetDefaultNetworkPolicyConfig(),
	}
}
