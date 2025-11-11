// Package types contains all the required clients for marshal/unmarshal requests and responses from/to jibril-server.
package types

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/garnet-org/api/types/errs"
)

// Issue state and priority constants.
const (
	IssueStateAllowed IssueState = "allowed"
	IssueStateBlocked IssueState = "blocked"

	IssuePriorityLow      IssuePriority = "low"
	IssuePriorityMedium   IssuePriority = "medium"
	IssuePriorityHigh     IssuePriority = "high"
	IssuePriorityCritical IssuePriority = "critical"

	IssueClassNetworkExfiltration IssueClass = "network_exfiltration"
	IssueClassCryptoMiner         IssueClass = "crypto_miner"
)

// IssueActionType represents the type of action performed on an issue.
type IssueActionType string

const (
	// IssueActionTypeAllow allows the issue.
	IssueActionTypeAllow IssueActionType = "allow"

	// IssueActionTypeBlock blocks the issue.
	IssueActionTypeBlock IssueActionType = "block"
)

const (
	// ErrInvalidIssueState is returned when the issue state is not one of the valid options.
	ErrInvalidIssueState = errs.InvalidArgumentError("invalid issue state")

	// ErrInvalidIssuePriority is returned when the issue priority is invalid or missing.
	ErrInvalidIssuePriority = errs.InvalidArgumentError("invalid issue priority")

	// ErrInvalidIssueClass is returned when the issue class is not recognized or supported.
	ErrInvalidIssueClass = errs.InvalidArgumentError("invalid issue class")

	// ErrInvalidIssueDescription is returned when the issue description is empty or malformed.
	ErrInvalidIssueDescription = errs.InvalidArgumentError("invalid issue description")

	// ErrInvalidIssueEventIDs is returned when the event IDs provided for the issue are invalid.
	ErrInvalidIssueEventIDs = errs.InvalidArgumentError("invalid issue event IDs")

	// ErrInvalidIssueIgnoreFor is returned when the ignore duration or format is invalid.
	ErrInvalidIssueIgnoreFor = errs.InvalidArgumentError("invalid issue ignore_for")

	// ErrInvalidIssueReason is returned when the issue reason is missing or invalid.
	ErrInvalidIssueReason = errs.InvalidArgumentError("invalid issue reason")

	// ErrInvalidIssueActionType is returned when the action type provided is invalid.
	ErrInvalidIssueActionType = errs.InvalidArgumentError("invalid issue action type")

	// ErrInvalidIssueActionScope is returned when the action scope is not valid or recognized.
	ErrInvalidIssueActionScope = errs.InvalidArgumentError("invalid issue action scope")

	// ErrIssueHasNoNetworkDestination is returned when the issue does not include a network destination.
	ErrIssueHasNoNetworkDestination = errs.InvalidArgumentError("issue has no network destination")

	// ErrInvalidIssueID is returned when the issue ID is missing or not in a valid format.
	ErrInvalidIssueID = errs.InvalidArgumentError("invalid issue ID")

	// ErrInvalidEventID is returned when the event ID provided is invalid or does not exist.
	ErrInvalidEventID = errs.InvalidArgumentError("invalid event ID")

	// ErrUnauthorizedEvents is returned when the user does not have permission to access or modify events.
	ErrUnauthorizedEvents = errs.UnauthorizedError("permission denied")

	// ErrUnauthorizedIssue is returned when the user does not have permission to access or modify the issue.
	ErrUnauthorizedIssue = errs.UnauthorizedError("permission denied")

	// ErrInvalidAgentKind is returned when the agent kind is invalid or unsupported.
	ErrInvalidAgentKind = errs.InvalidArgumentError("invalid agent kind")

	// ErrMissingRepositoryID is returned when the repository ID is not found in the agent context.
	ErrMissingRepositoryID = errs.InvalidArgumentError("missing repository ID in agent context")

	// ErrMissingWorkflow is returned when the workflow is not present in the agent context.
	ErrMissingWorkflow = errs.InvalidArgumentError("missing workflow in agent context")

	// ErrNoAssociatedEvents is returned when an issue does not have any linked events.
	ErrNoAssociatedEvents = errs.InvalidArgumentError("issue has no associated events")

	// ErrMissingGitHubContext is returned when the agent does not have GitHub context available.
	ErrMissingGitHubContext = errs.InvalidArgumentError("agent does not have GitHub context")
)

// IssueState represents the possible states of an issue.
type IssueState string

// String returns the string representation of the IssueState.
func (s IssueState) String() string {
	return string(s)
}

// IsValid checks if the IssueState is valid.
func (s IssueState) IsValid() bool {
	switch s {
	case IssueStateAllowed, IssueStateBlocked:
		return true
	}
	return false
}

// IssuePriority represents the possible priority levels of an issue.
type IssuePriority string

// String returns the string representation of the IssuePriority.
func (p IssuePriority) String() string {
	return string(p)
}

// IsValid checks if the IssuePriority is valid.
func (p IssuePriority) IsValid() bool {
	switch p {
	case IssuePriorityLow, IssuePriorityMedium, IssuePriorityHigh, IssuePriorityCritical:
		return true
	}
	return false
}

// IssueClass represents the possible classes of an issue.
type IssueClass string

// String returns the string representation of the IssueClass.
func (c IssueClass) String() string {
	return string(c)
}

// IsValid checks if the IssueClass is valid.
func (c IssueClass) IsValid() bool {
	switch c {
	case IssueClassNetworkExfiltration, IssueClassCryptoMiner:
		return true
	}
	return false
}

// AllEnabledIssueClasses returns a slice of all enabled issue classes.
func AllEnabledIssueClasses() []IssueClass {
	return []IssueClass{
		IssueClassNetworkExfiltration,
		IssueClassCryptoMiner,
	}
}

// IssueLabels represents a typed map of labels.
type IssueLabels map[string]string

// Validate checks the labels against defined validation rules.
func (l IssueLabels) Validate() error {
	return ValidateLabels(map[string]string(l))
}

// UnmarshalJSON implements custom JSON unmarshaling for IssueLabels.
func (l *IssueLabels) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*l = make(IssueLabels)
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
func (l *IssueLabels) Scan(value interface{}) error {
	if value == nil {
		*l = make(IssueLabels)
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, l)
	case string:
		return json.Unmarshal([]byte(v), l)
	default:
		return fmt.Errorf("unsupported type for IssueLabels: %T", value)
	}
}

// Encode encodes the IssueLabels into URL query parameters.
func (l *IssueLabels) Encode() url.Values {
	values := url.Values{}

	if l == nil {
		return values
	}

	for key, value := range *l {
		values.Set("label."+key, value)
	}

	return values
}

// DecodeIssueLabels extracts IssueLabels from URL query parameters.
func DecodeIssueLabels(values url.Values) IssueLabels {
	labels := IssueLabels{}

	prefix := "label."
	for key, vals := range values {
		if len(vals) > 0 && len(key) > len(prefix) && key[:len(prefix)] == prefix {
			labelKey := key[len(prefix):]
			labels[labelKey] = vals[0]
		}
	}

	return labels
}

// IssueFilters provides strongly typed filtering options for issues.
type IssueFilters struct {
	Class        *IssueClass    `json:"class,omitempty"`
	State        *IssueState    `json:"state,omitempty"`
	Priority     *IssuePriority `json:"priority,omitempty"`
	AgentKind    *AgentKind     `json:"agent_kind,omitempty"`
	RepositoryID *string        `json:"repository_id,omitempty"`
	Repository   *string        `json:"repository,omitempty"`
	WorkflowName *string        `json:"workflow_name,omitempty"`
}

// Validate checks if the IssueFilters has all required fields set.
func (f *IssueFilters) Validate() error {
	if f == nil {
		return nil
	}

	// Validate class if provided
	if f.Class != nil && !f.Class.IsValid() {
		return ErrInvalidIssueClass
	}

	// Validate state if provided
	if f.State != nil && !f.State.IsValid() {
		return ErrInvalidIssueState
	}

	// Validate priority if provided
	if f.Priority != nil && !f.Priority.IsValid() {
		return ErrInvalidIssuePriority
	}

	// Validate agent kind if provided
	if f.AgentKind != nil && !f.AgentKind.IsValid() {
		return ErrInvalidAgentKind
	}

	// Validate repository ID if provided
	if f.RepositoryID != nil && *f.RepositoryID == "" {
		return errs.InvalidArgumentError("repository_id cannot be empty")
	}

	// Validate repository name if provided
	if f.Repository != nil && *f.Repository == "" {
		return errs.InvalidArgumentError("repository cannot be empty")
	}

	// Validate workflow name if provided
	if f.WorkflowName != nil && *f.WorkflowName == "" {
		return errs.InvalidArgumentError("workflow_name cannot be empty")
	}

	return nil
}

// DecodeIssueFilters extracts IssueFilters from URL query parameters.
func DecodeIssueFilters(values url.Values) *IssueFilters {
	filters := &IssueFilters{}

	if classStr := values.Get("filter.class"); classStr != "" {
		class := IssueClass(classStr)
		filters.Class = &class
	}

	if stateStr := values.Get("filter.state"); stateStr != "" {
		state := IssueState(stateStr)
		filters.State = &state
	}

	if priorityStr := values.Get("filter.priority"); priorityStr != "" {
		priority := IssuePriority(priorityStr)
		filters.Priority = &priority
	}

	if agentKindStr := values.Get("filter.agent_kind"); agentKindStr != "" {
		agentKind := AgentKind(agentKindStr)
		filters.AgentKind = &agentKind
	}

	if repoID := values.Get("filter.repository_id"); repoID != "" {
		filters.RepositoryID = &repoID
	}

	if repo := values.Get("filter.repository"); repo != "" {
		filters.Repository = &repo
	}

	if workflow := values.Get("filter.workflow_name"); workflow != "" {
		filters.WorkflowName = &workflow
	}

	if filters.IsEmpty() {
		return nil
	}

	return filters
}

// IsEmpty checks if all filters are nil.
func (f IssueFilters) IsEmpty() bool {
	return f.Class == nil && f.State == nil && f.Priority == nil && f.AgentKind == nil &&
		f.RepositoryID == nil && f.Repository == nil && f.WorkflowName == nil
}

// Issue represents the stored issue model.
type Issue struct {
	ID                  string              `json:"id"`
	ProjectID           string              `json:"-"` // Not exposed in API
	Class               IssueClass          `json:"class"`
	Description         string              `json:"description"`
	State               IssueState          `json:"state"`
	Priority            IssuePriority       `json:"priority"`
	Labels              IssueLabels         `json:"labels"`
	Ignored             bool                `json:"ignored"`
	IgnoredReason       string              `json:"ignored_reason,omitempty"`
	IgnoredBy           string              `json:"ignored_by,omitempty"`
	IgnoredAt           *time.Time          `json:"ignored_at,omitempty"`
	PolicyScope         *NetworkPolicyScope `json:"policy_scope,omitempty"`
	NetworkPolicyID     *string             `json:"network_policy_id,omitempty"`
	NetworkPolicyRuleID *string             `json:"network_policy_rule_id,omitempty"`
	LastActionBy        *string             `json:"last_action_by,omitempty"`
	LastActionAt        *time.Time          `json:"last_action_at,omitempty"`
	Events              []Event             `json:"events"` // No omitempty
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
	DeletedAt           *time.Time          `json:"deleted_at,omitempty"`
}

// ExtractNetworkDestination extracts network destination information from the events linked to an issue.
//
func (i *Issue) ExtractNetworkDestination() (NetworkPolicyRuleType, string, error) {
	if len(i.Events) == 0 {
		return "", "", ErrIssueHasNoNetworkDestination
	}

	// Examine events to extract network destination
	for _, event := range i.Events {
		// For V2 events, check metadata name instead of Kind
		if event.Data.Metadata == nil {
			continue
		}
		
		switch event.Data.Metadata.Name {
		case MetadataNameDropIP:
			// With jibril-ashkaal v0.1.4+, DropIP events can contain both IP and domain names
			// When a domain is blocked, the event has the resolved IP + the domain name(s)
			// Prefer domain if available, otherwise return IP
			if domain := ExtractDomainFromV2Event(event); domain != "" {
				return NetworkPolicyRuleTypeDomain, domain, nil
			}
			// Fallback to IP if no domain names present
			if ip := ExtractIPFromV2Event(event); ip != "" {
				return formatCIDRAddress(ip)
			}

		case MetadataNameDropDomain:
			// DropDomain events are deprecated in jibril-ashkaal v0.1.4+
			// Keep for backward compatibility with older jibril agents
			// Extract domain information from V2 event flows
			if domain := ExtractDomainFromV2Event(event); domain != "" {
				return NetworkPolicyRuleTypeDomain, domain, nil
			}

		case MetadataNameFlow:
			// Flow events no longer generate issues, but included to satisfy exhaustive check
			continue

		case MetadataNameAdultDomainAccess, MetadataNameThreatDomainAccess,
			MetadataNameBadwareDomainAccess, MetadataNameDynDNSDomainAccess,
			MetadataNameFakeDomainAccess, MetadataNameGamblingDomainAccess,
			MetadataNamePiracyDomainAccess, MetadataNamePlaintextComm,
			MetadataNameTrackingDomainAccess, MetadataNameVPNLikeDomainAccess:
			// Extract domain from V2 flow data for various domain access events
			if domain := ExtractDomainFromV2Event(event); domain != "" {
				return NetworkPolicyRuleTypeDomain, domain, nil
			}

		// The following event types don't contain network destination information
		// but are added to satisfy the exhaustive check
		case MetadataNameCapabilitiesModification,
			MetadataNameCodeModificationThroughProcfs, MetadataNameCorePatternAccess,
			MetadataNameCPUFingerprint, MetadataNameCredentialsFilesAccess,
			MetadataNameFilesystemFingerprint, MetadataNameJavaDebugLibLoad,
			MetadataNameJavaInstrumentLibLoad, MetadataNameMachineFingerprint,
			MetadataNameOSFingerprint, MetadataNameOSNetworkFingerprint,
			MetadataNameOSStatusFingerprint, MetadataNamePackageRepoConfigModification,
			MetadataNamePAMConfigModification, MetadataNameSchedDebugAccess,
			MetadataNameShellConfigModification, MetadataNameSSLCertificateAccess,
			MetadataNameSudoersModification, MetadataNameSysrqAccess,
			MetadataNameUnprivilegedBPFConfigAccess, MetadataNameGlobalShlibModification,
			MetadataNameEnvironReadFromProcfs, MetadataNameBinarySelfDeletion,
			MetadataNameCryptoMinerFiles, MetadataNameAuthLogsTamper,
			MetadataNameBinaryExecutedByLoader, MetadataNameCodeOnTheFly,
			MetadataNameDataEncoderExec, MetadataNameDenialOfServiceTools,
			MetadataNameExecFromUnusualDir, MetadataNameFileAttributeChange,
			MetadataNameHiddenELFExec, MetadataNameInterpreterShellSpawn,
			MetadataNameNetFilecopyToolExec, MetadataNameNetMITMToolExec,
			MetadataNameNetScanToolExec, MetadataNameNetSniffToolExec,
			MetadataNameNetSuspiciousToolExec, MetadataNameNetSuspiciousToolShell,
			MetadataNamePasswdUsage, MetadataNameRuncSuspiciousExec,
			MetadataNameWebserverExec, MetadataNameWebserverShellExec,
			MetadataNameCryptoMinerExecution:
			// These events don't provide network destination information for policy rules
			continue
		}
	}

	return "", "", ErrIssueHasNoNetworkDestination
}

// ExtractIPFromV2Event extracts IP address from V2 event's Background.Flows structure.
func ExtractIPFromV2Event(event Event) string {
	if event.Data.Background == nil || event.Data.Background.Flows == nil {
		return ""
	}

	flows := event.Data.Background.Flows
	if len(flows.Protocols) == 0 {
		return ""
	}

	// Look through protocols for IP addresses
	for _, protocol := range flows.Protocols {
		if len(protocol.Pairs) == 0 {
			continue
		}

		for _, pair := range protocol.Pairs {
			// Check remote node for IP address
			if pair.Nodes.Remote.Address != "" {
				return pair.Nodes.Remote.Address
			}
		}
	}

	return ""
}

// ExtractDomainFromV2Event extracts domain name from V2 event's Background.Flows structure.
// With jibril-ashkaal v0.1.4+, ProtocolNode now has both Name (singular) and Names (plural) fields.
// This function checks both fields and returns the first non-empty domain found.
func ExtractDomainFromV2Event(event Event) string {
	if event.Data.Background == nil || event.Data.Background.Flows == nil {
		return ""
	}

	flows := event.Data.Background.Flows
	if len(flows.Protocols) == 0 {
		return ""
	}

	// Look through protocols for domain names
	for _, protocol := range flows.Protocols {
		if len(protocol.Pairs) == 0 {
			continue
		}

		for _, pair := range protocol.Pairs {
			// Check singular Name field first - this is the original requested domain
			// In jibril-ashkaal v0.1.4+, this contains the domain that was actually requested
			if pair.Nodes.Remote.Name != "" && !isIPAddress(pair.Nodes.Remote.Name) {
				return pair.Nodes.Remote.Name
			}

			// Fallback to Names array for backward compatibility
			// Names array contains the DNS resolution chain from resolved IP to original domain:
			// [IP, CNAME_N, ..., CNAME_1, original_domain]
			// We want the last non-IP entry (the original requested domain)
			if len(pair.Nodes.Remote.Names) > 0 {
				// Iterate backwards to find the last non-IP entry
				for i := len(pair.Nodes.Remote.Names) - 1; i >= 0; i-- {
					name := pair.Nodes.Remote.Names[i]
					if name != "" && !isIPAddress(name) {
						return name
					}
				}
			}
		}
	}

	return ""
}


// isIPAddress checks if a string is an IP address (IPv4 or IPv6).
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// formatCIDRAddress ensures an IP address is properly formatted as a CIDR.
func formatCIDRAddress(ipAddress string) (NetworkPolicyRuleType, string, error) {
	// Create a CIDR from the IP address if needed
	if !strings.HasSuffix(ipAddress, "/32") && !strings.Contains(ipAddress, "/") {
		ipAddress += "/32" // Single IP address
	}
	return NetworkPolicyRuleTypeCIDR, ipAddress, nil
}

// CreateIssue represents the request to create a new issue.
type CreateIssue struct {
	Class       IssueClass    `json:"class"`
	Description string        `json:"description"`
	State       IssueState    `json:"state"`
	Priority    IssuePriority `json:"priority"`
	Labels      IssueLabels   `json:"labels"`
	EventIDs    []string      `json:"event_ids"`
}

// Validate ensures the CreateIssue request is valid.
func (c *CreateIssue) Validate() error {
	// Check issue state
	if !c.State.IsValid() {
		return ErrInvalidIssueState
	}

	// Check issue priority
	if !c.Priority.IsValid() {
		return ErrInvalidIssuePriority
	}

	// Check issue class
	if !c.Class.IsValid() {
		return ErrInvalidIssueClass
	}

	if c.Description == "" {
		return ErrInvalidIssueDescription
	}

	if len(c.EventIDs) == 0 {
		return ErrInvalidIssueEventIDs
	}

	// Validate labels
	if err := c.Labels.Validate(); err != nil {
		return err
	}

	return nil
}

// IssueCreated represents the response when an issue is successfully created.
type IssueCreated struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpdateIssue represents the request to update an existing issue.
type UpdateIssue struct {
	Class               *IssueClass         `json:"class,omitempty"`
	Description         *string             `json:"description,omitempty"`
	State               *IssueState         `json:"state,omitempty"`
	Priority            *IssuePriority      `json:"priority,omitempty"`
	Labels              *IssueLabels        `json:"labels,omitempty"`
	Ignored             *bool               `json:"ignored,omitempty"`
	IgnoredReason       *string             `json:"ignored_reason,omitempty"`
	IgnoredBy           *string             `json:"-"`                                // For internal use only, not exposed in API
	Reason              *string             `json:"reason,omitempty"`                 // Reason for state change
	EventIDs            []string            `json:"event_ids,omitempty"`              // Event IDs to add to the issue
	PolicyScope         *NetworkPolicyScope `json:"policy_scope,omitempty"`           // Network policy scope
	NetworkPolicyID     *string             `json:"network_policy_id,omitempty"`      // Network policy ID
	NetworkPolicyRuleID *string             `json:"network_policy_rule_id,omitempty"` // Network policy rule ID
}

// Validate ensures the UpdateIssue request is valid.
func (u *UpdateIssue) Validate() error { //nolint:gocyclo
	// Check if any fields are specified
	if u.Class == nil && u.Description == nil && u.State == nil &&
		u.Priority == nil && u.Labels == nil && u.Ignored == nil &&
		u.IgnoredReason == nil && u.Reason == nil && len(u.EventIDs) == 0 &&
		u.PolicyScope == nil && u.NetworkPolicyID == nil && u.NetworkPolicyRuleID == nil {
		return errs.InvalidArgumentError("at least one field is required")
	}

	// Validate class if provided
	if u.Class != nil && !u.Class.IsValid() {
		return ErrInvalidIssueClass
	}

	// Validate description if provided
	if u.Description != nil && *u.Description == "" {
		return ErrInvalidIssueDescription
	}

	// Validate state if provided
	if u.State != nil && !u.State.IsValid() {
		return ErrInvalidIssueState
	}

	// Validate priority if provided
	if u.Priority != nil && !u.Priority.IsValid() {
		return ErrInvalidIssuePriority
	}

	// If state is being changed, require a reason
	if u.State != nil && (u.Reason == nil || *u.Reason == "") {
		return ErrInvalidIssueReason
	}

	// If ignored is being set to true, require a reason
	if u.Ignored != nil && *u.Ignored && (u.IgnoredReason == nil || *u.IgnoredReason == "") {
		return errs.InvalidArgumentError("ignored_reason is required when ignored is set to true")
	}

	// If EventIDs field is present and empty, prevent removal of all events
	if u.EventIDs != nil && len(u.EventIDs) == 0 {
		return errs.InvalidArgumentError("cannot remove all events from an issue")
	}

	// Validate labels if provided
	if u.Labels != nil {
		if err := u.Labels.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// IssueUpdated represents the response when an issue is successfully updated.
type IssueUpdated struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IssueAction represents an action to be performed on an issue.
type IssueAction struct {
	ActionType       IssueActionType       `json:"action_type"` // allow or block
	Scope            NetworkPolicyScope    `json:"scope"`       // global, repo, or workflow
	Reason           string                `json:"reason"`      // User-provided reason for the action
	UserID           *string               `json:"-"`           // ID of the user who performed the action
	DestinationType  NetworkPolicyRuleType `json:"-"`           // Domain or CIDR
	DestinationValue string                `json:"-"`           // The actual domain or IP CIDR
}

// Validate ensures the IssueAction is valid.
func (a *IssueAction) Validate() error {
	// Check action type
	switch a.ActionType {
	case IssueActionTypeAllow, IssueActionTypeBlock:
		// Valid
	default:
		return ErrInvalidIssueActionType
	}

	// Check scope
	if !a.Scope.IsValid() {
		return ErrInvalidIssueActionScope
	}

	// Reason is required
	if a.Reason == "" {
		return ErrInvalidIssueReason
	}

	return nil
}

// IssueActionPerformed represents the result of performing an action on an issue.
type IssueActionPerformed struct {
	ID                string            `json:"id"`
	State             IssueState        `json:"state"`
	NetworkPolicyID   string            `json:"network_policy_id"`
	NetworkPolicyRule NetworkPolicyRule `json:"network_policy_rule"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// IssueActionHistory represents a record of an action performed on an issue.
type IssueActionHistory struct {
	ID                  string                `json:"id"`
	IssueID             string                `json:"issue_id"`
	ActionType          IssueActionType       `json:"action_type"`
	Scope               NetworkPolicyScope    `json:"scope"`
	Reason              string                `json:"reason"`
	UserID              *string               `json:"user_id,omitempty"`
	NetworkPolicyID     string                `json:"network_policy_id"`
	NetworkPolicyRuleID string                `json:"network_policy_rule_id"`
	DestinationType     NetworkPolicyRuleType `json:"destination_type"`
	DestinationValue    string                `json:"destination_value"`
	CreatedAt           time.Time             `json:"created_at"`
}

// ListIssues represents the request to list issues with filtering and pagination.
type ListIssues struct {
	ProjectID      string        `json:"-"` // Set internally from context
	Labels         IssueLabels   `json:"labels,omitempty"`
	Filters        *IssueFilters `json:"filters,omitempty"`
	PageArgs       PageArgs      `json:"pageArgs"`
	IncludeIgnored bool          `json:"include_ignored,omitempty"` // Whether to include ignored issues, default is false
	Sort           *Sort         `json:"sort,omitempty"`
}

// Validate ensures the ListIssues request is valid.
func (l *ListIssues) Validate() error {
	// Validate filters if provided
	if l.Filters != nil {
		if err := l.Filters.Validate(); err != nil {
			return err
		}
	}

	// Validate labels if provided
	if len(l.Labels) > 0 {
		if err := l.Labels.Validate(); err != nil {
			return err
		}
	}

	// Validate sorting if provided
	if l.Sort != nil {
		if !slices.Contains(allowedSortFields, l.Sort.Field) {
			return fmt.Errorf("invalid sort field: %s, allowed fields are: %v", l.Sort.Field, allowedSortFields)
		}

		if err := l.Sort.Order.Validate(); err != nil {
			return err
		}
	}

	return nil
}

var allowedSortFields = []string{"created_at"}
