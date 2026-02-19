// Package types contains all the required types for v2 events API using ashkaal format.
package types //nolint:revive // Package name is intentionally descriptive

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"time"

	eventkind "github.com/garnet-org/jibril-ashkaal/pkg/kind"
	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
	"github.com/google/uuid"
	"github.com/garnet-org/api/types/errs"
)

const (
	// ErrInvalidEventV2Kind is returned when the v2 event kind is invalid.
	ErrInvalidEventV2Kind = errs.InvalidArgumentError("invalid v2 event kind")

	// ErrIDcannotBeEmptyV2 is returned when the v2 event ID is empty.
	ErrIDcannotBeEmptyV2 = errs.InvalidArgumentError("v2 event id is required")

	// ErrInvalidEventV2ID is returned when the v2 event ID is not a valid UUID.
	ErrInvalidEventV2ID = errs.InvalidArgumentError("v2 event id must be a valid UUID")

	// ErrMetadataNameEmpty is returned when metadata name is empty.
	ErrMetadataNameEmpty = errs.InvalidArgumentError("metadataName cannot be empty")

	// ErrMetadataNameTooLong is returned when metadata name exceeds max length.
	ErrMetadataNameTooLong = errs.InvalidArgumentError("metadataName too long, maximum 64 characters allowed")

	// ErrMetadataNameInvalidChars is returned when metadata name contains invalid characters.
	ErrMetadataNameInvalidChars = errs.InvalidArgumentError("metadataName must contain only ASCII letters, numbers, and underscores")

	// ErrTooManyMetadataNames is returned when too many metadata names are provided.
	ErrTooManyMetadataNames = errs.InvalidArgumentError("too many metadata names, maximum 20 allowed")

	// ErrEventNotFound is returned when the event is not found.
	ErrEventNotFound = errs.NotFoundError("event not found")

	// ErrInvalidEventActionType is returned when the action type provided is invalid.
	ErrInvalidEventActionType = errs.InvalidArgumentError("invalid event action type")

	// ErrInvalidEventActionScope is returned when the action scope is not valid or recognized.
	ErrInvalidEventActionScope = errs.InvalidArgumentError("invalid event action scope")

	// ErrInvalidEventReason is returned when the event reason is missing or invalid.
	ErrInvalidEventReason = errs.InvalidArgumentError("invalid event reason")

	// ErrEventHasNoNetworkDestination is returned when the event does not include a network destination.
	ErrEventHasNoNetworkDestination = errs.InvalidArgumentError("event has no network destination")

	// MaxMetadataNameLength is the maximum allowed length for metadata names.
	MaxMetadataNameLength = 64

	// MaxMetadataNameCount is the maximum number of metadata names in a filter.
	MaxMetadataNameCount = 20

	// MetadataNameDropIP defines metadata name for IP drop events.
	MetadataNameDropIP = "dropip"
	// MetadataNameDropDomain defines metadata name for domain drop events.
	MetadataNameDropDomain = "dropdomain"
	// MetadataNameFlow defines metadata name for flow events.
	MetadataNameFlow = "flow"

	// MetadataNameAdultDomainAccess defines metadata name for adult domain access events.
	MetadataNameAdultDomainAccess = "adult_domain_access"
	// MetadataNameThreatDomainAccess defines metadata name for threat domain access events.
	MetadataNameThreatDomainAccess = "threat_domain_access"
	// MetadataNameBadwareDomainAccess defines metadata name for badware domain access events.
	MetadataNameBadwareDomainAccess = "badware_domain_access"
	// MetadataNameDynDNSDomainAccess defines metadata name for dynamic DNS domain access events.
	MetadataNameDynDNSDomainAccess = "dyndns_domain_access"
	// MetadataNameFakeDomainAccess defines metadata name for fake domain access events.
	MetadataNameFakeDomainAccess = "fake_domain_access"
	// MetadataNameGamblingDomainAccess defines metadata name for gambling domain access events.
	MetadataNameGamblingDomainAccess = "gambling_domain_access"
	// MetadataNamePiracyDomainAccess defines metadata name for piracy domain access events.
	MetadataNamePiracyDomainAccess = "piracy_domain_access"
	// MetadataNamePlaintextComm defines metadata name for plaintext communication events.
	MetadataNamePlaintextComm = "plaintext_communication"
	// MetadataNameTrackingDomainAccess defines metadata name for tracking domain access events.
	MetadataNameTrackingDomainAccess = "tracking_domain_access"
	// MetadataNameVPNLikeDomainAccess defines metadata name for VPN-like domain access events.
	MetadataNameVPNLikeDomainAccess = "vpnlike_domain_access"

	// MetadataNameCapabilitiesModification defines metadata name for capabilities modification events.
	MetadataNameCapabilitiesModification = "capabilities_modification"
	// MetadataNameCodeModificationThroughProcfs defines metadata name for code modification through procfs events.
	MetadataNameCodeModificationThroughProcfs = "code_modification_through_procfs"
	// MetadataNameCorePatternAccess defines metadata name for core pattern access events.
	MetadataNameCorePatternAccess = "core_pattern_access"
	// MetadataNameCPUFingerprint defines metadata name for CPU fingerprint events.
	MetadataNameCPUFingerprint = "cpu_fingerprint"
	// MetadataNameCredentialsFilesAccess defines metadata name for credentials files access events.
	MetadataNameCredentialsFilesAccess = "credentials_files_access"
	// MetadataNameFilesystemFingerprint defines metadata name for filesystem fingerprint events.
	MetadataNameFilesystemFingerprint = "filesystem_fingerprint"
	// MetadataNameJavaDebugLibLoad defines metadata name for Java debug library load events.
	MetadataNameJavaDebugLibLoad = "java_debug_lib_load"
	// MetadataNameJavaInstrumentLibLoad defines metadata name for Java instrument library load events.
	MetadataNameJavaInstrumentLibLoad = "java_instrument_lib_load"
	// MetadataNameMachineFingerprint defines metadata name for machine fingerprint events.
	MetadataNameMachineFingerprint = "machine_fingerprint"
	// MetadataNameOSFingerprint defines metadata name for OS fingerprint events.
	MetadataNameOSFingerprint = "os_fingerprint"
	// MetadataNameOSNetworkFingerprint defines metadata name for OS network fingerprint events.
	MetadataNameOSNetworkFingerprint = "os_network_fingerprint"
	// MetadataNameOSStatusFingerprint defines metadata name for OS status fingerprint events.
	MetadataNameOSStatusFingerprint = "os_status_fingerprint"
	// MetadataNamePackageRepoConfigModification defines metadata name for package repository configuration modification events.
	MetadataNamePackageRepoConfigModification = "package_repo_config_modification"
	// MetadataNamePAMConfigModification defines metadata name for PAM configuration modification events.
	MetadataNamePAMConfigModification = "pam_config_modification"
	// MetadataNameSchedDebugAccess defines metadata name for scheduler debug access events.
	MetadataNameSchedDebugAccess = "sched_debug_access"
	// MetadataNameShellConfigModification defines metadata name for shell configuration modification events.
	MetadataNameShellConfigModification = "shell_config_modification"
	// MetadataNameSSLCertificateAccess defines metadata name for SSL certificate access events.
	MetadataNameSSLCertificateAccess = "ssl_certificate_access"
	// MetadataNameSudoersModification defines metadata name for sudoers modification events.
	MetadataNameSudoersModification = "sudoers_modification"
	// MetadataNameSysrqAccess defines metadata name for sysrq access events.
	MetadataNameSysrqAccess = "sysrq_access"
	// MetadataNameUnprivilegedBPFConfigAccess defines metadata name for unprivileged BPF configuration access events.
	MetadataNameUnprivilegedBPFConfigAccess = "unprivileged_bpf_config_access"
	// MetadataNameGlobalShlibModification defines metadata name for global shared library modification events.
	MetadataNameGlobalShlibModification = "global_shlib_modification"
	// MetadataNameEnvironReadFromProcfs defines metadata name for environment read from procfs events.
	MetadataNameEnvironReadFromProcfs = "environ_read_from_procfs"
	// MetadataNameBinarySelfDeletion defines metadata name for binary self deletion events.
	MetadataNameBinarySelfDeletion = "binary_self_deletion"
	// MetadataNameCryptoMinerFiles defines metadata name for crypto miner files events.
	MetadataNameCryptoMinerFiles = "crypto_miner_files"
	// MetadataNameAuthLogsTamper defines metadata name for authentication logs tamper events.
	MetadataNameAuthLogsTamper = "auth_logs_tamper"
	// MetadataNameBinaryExecutedByLoader defines metadata name for binary executed by loader events.
	MetadataNameBinaryExecutedByLoader = "binary_executed_by_loader"
	// MetadataNameCodeOnTheFly defines metadata name for code on the fly events.
	MetadataNameCodeOnTheFly = "code_on_the_fly"
	// MetadataNameDataEncoderExec defines metadata name for data encoder execution events.
	MetadataNameDataEncoderExec = "data_encoder_exec"
	// MetadataNameDenialOfServiceTools defines metadata name for denial of service tools events.
	MetadataNameDenialOfServiceTools = "denial_of_service_tools"
	// MetadataNameExecFromUnusualDir defines metadata name for execution from unusual directory events.
	MetadataNameExecFromUnusualDir = "exec_from_unusual_dir"
	// MetadataNameFileAttributeChange defines metadata name for file attribute change events.
	MetadataNameFileAttributeChange = "file_attribute_change"
	// MetadataNameHiddenELFExec defines metadata name for hidden ELF execution events.
	MetadataNameHiddenELFExec = "hidden_elf_exec"
	// MetadataNameInterpreterShellSpawn defines metadata name for interpreter shell spawn events.
	MetadataNameInterpreterShellSpawn = "interpreter_shell_spawn"
	// MetadataNameNetFilecopyToolExec defines metadata name for network file copy tool execution events.
	MetadataNameNetFilecopyToolExec = "net_filecopy_tool_exec"
	// MetadataNameNetMITMToolExec defines metadata name for network MITM tool execution events.
	MetadataNameNetMITMToolExec = "net_mitm_tool_exec"
	// MetadataNameNetScanToolExec defines metadata name for network scan tool execution events.
	MetadataNameNetScanToolExec = "net_scan_tool_exec"
	// MetadataNameNetSniffToolExec defines metadata name for network sniff tool execution events.
	MetadataNameNetSniffToolExec = "net_sniff_tool_exec"
	// MetadataNameNetSuspiciousToolExec defines metadata name for network suspicious tool execution events.
	MetadataNameNetSuspiciousToolExec = "net_suspicious_tool_exec"
	// MetadataNameNetSuspiciousToolShell defines metadata name for network suspicious tool shell events.
	MetadataNameNetSuspiciousToolShell = "net_suspicious_tool_shell"
	// MetadataNamePasswdUsage defines metadata name for passwd usage events.
	MetadataNamePasswdUsage = "passwd_usage"
	// MetadataNameRuncSuspiciousExec defines metadata name for runc suspicious execution events.
	MetadataNameRuncSuspiciousExec = "runc_suspicious_exec"
	// MetadataNameWebserverExec defines metadata name for webserver execution events.
	MetadataNameWebserverExec = "webserver_exec"
	// MetadataNameWebserverShellExec defines metadata name for webserver shell execution events.
	MetadataNameWebserverShellExec = "webserver_shell_exec"
	// MetadataNameCryptoMinerExecution defines metadata name for crypto miner execution events.
	MetadataNameCryptoMinerExecution = "crypto_miner_execution"
)

var (
	// metadataNameRegex validates metadata names: ASCII letters, numbers, underscores only.
	metadataNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
)

// CreateOrUpdateEventV2 is used for creating or updating v2 events in ashkaal format.
type CreateOrUpdateEventV2 struct {
	ID string `json:"id"`
	// agentID is populated from JWT token
	agentID string         `json:"-"`
	Kind    eventkind.Kind `json:"kind"`
	Data    ongoing.Base   `json:"data"`
	// CreatedAt time.Time      `json:"createdAt"`
	// UpdatedAt time.Time      `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateEventV2 is valid.
func (e *CreateOrUpdateEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	// Validate that ID is a valid UUID
	if _, err := uuid.Parse(e.ID); err != nil {
		return ErrInvalidEventV2ID
	}

	if !isValidAshkaalKind(e.Kind) {
		return ErrInvalidEventV2Kind
	}

	return nil
}

// isValidAshkaalKind checks if the ashkaal kind.Kind is valid.
func isValidAshkaalKind(k eventkind.Kind) bool {
	switch k {
	case eventkind.KindFlows, eventkind.KindDetections, eventkind.KindInfos, eventkind.KindNetPolicy:
		return true
	case eventkind.KindNone, eventkind.KindEmpty:
		return false
	default:
		return false
	}
}

// EventV2 represents a v2 event with full agent details in ashkaal format.
type EventV2 struct {
	ID        string         `json:"id"`
	AgentID   string         `json:"agent_id"`
	Agent     Agent          `json:"agent"`
	Kind      eventkind.Kind `json:"kind"`
	Data      ongoing.Base   `json:"data"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// Validate checks if the EventV2 is valid.
func (e *EventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if !isValidAshkaalKind(e.Kind) {
		return ErrInvalidEventV2Kind
	}

	return nil
}

// EventV2CreatedOrUpdated represents the response when a v2 event is successfully created or updated.
type EventV2CreatedOrUpdated struct {
	ID        string    `json:"id"`
	Created   bool      `json:"created"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Specific ashkaal event types for different scenarios

// CreateOrUpdateDropIPEventV2 represents a DropIP event in v2 format.
type CreateOrUpdateDropIPEventV2 struct {
	ID        string         `json:"id"`
	agentID   string         `json:"-"`
	Data      ongoing.DropIP `json:"data"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateDropIPEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateDropIPEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateDropIPEventV2 is valid.
func (e *CreateOrUpdateDropIPEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if e.Data.IP == "" {
		return errs.InvalidArgumentError("dropip event must have an IP address")
	}

	return nil
}

// CreateOrUpdateNetworkFlowEventV2 represents a NetworkFlow event in v2 format.
type CreateOrUpdateNetworkFlowEventV2 struct {
	ID        string              `json:"id"`
	agentID   string              `json:"-"`
	Data      ongoing.NetworkFlow `json:"data"`
	CreatedAt time.Time           `json:"createdAt"`
	UpdatedAt time.Time           `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateNetworkFlowEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateNetworkFlowEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateNetworkFlowEventV2 is valid.
func (e *CreateOrUpdateNetworkFlowEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if e.Data.Flow.Proto == "" {
		return errs.InvalidArgumentError("network flow event must have a protocol")
	}

	return nil
}

// CreateOrUpdateExecutionEventV2 represents an Execution event in v2 format.
type CreateOrUpdateExecutionEventV2 struct {
	ID        string            `json:"id"`
	agentID   string            `json:"-"`
	Data      ongoing.Execution `json:"data"`
	CreatedAt time.Time         `json:"createdAt"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateExecutionEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateExecutionEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateExecutionEventV2 is valid.
func (e *CreateOrUpdateExecutionEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if e.Data.Process.Exe == "" && e.Data.Process.Cmd == "" {
		return errs.InvalidArgumentError("execution event must have an executable or command")
	}

	return nil
}

// CreateOrUpdateFileAccessEventV2 represents a FileAccess event in v2 format.
type CreateOrUpdateFileAccessEventV2 struct {
	ID        string             `json:"id"`
	agentID   string             `json:"-"`
	Data      ongoing.FileAccess `json:"data"`
	CreatedAt time.Time          `json:"createdAt"`
	UpdatedAt time.Time          `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateFileAccessEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateFileAccessEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateFileAccessEventV2 is valid.
func (e *CreateOrUpdateFileAccessEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if e.Data.File.Path == "" {
		return errs.InvalidArgumentError("file access event must have a file path")
	}

	return nil
}

// EventV2Wrapper is a wrapper struct for unmarshaling v2 events in different formats.
type EventV2Wrapper struct {
	ID   string         `json:"id"`
	Kind eventkind.Kind `json:"kind"`
	Data any            `json:"data"`
}

// ToCreateOrUpdateEventV2 converts the wrapper to a CreateOrUpdateEventV2.
func (w *EventV2Wrapper) ToCreateOrUpdateEventV2() (*CreateOrUpdateEventV2, error) {
	event := &CreateOrUpdateEventV2{
		ID:   w.ID,
		Kind: w.Kind,
	}

	// Convert data based on kind
	switch w.Kind {
	case eventkind.KindFlows:
		// Try to unmarshal as different flow types
		if dropIP, ok := w.Data.(ongoing.DropIP); ok {
			event.Data = dropIP.Base
		} else if networkFlow, ok := w.Data.(ongoing.NetworkFlow); ok {
			event.Data = networkFlow.Base
		} else if base, ok := w.Data.(ongoing.Base); ok {
			event.Data = base
		} else {
			return nil, errs.InvalidArgumentError("invalid flow event data")
		}
	case eventkind.KindDetections:
		// Try to unmarshal as different detection types
		if execution, ok := w.Data.(ongoing.Execution); ok {
			event.Data = execution.Base
		} else if fileAccess, ok := w.Data.(ongoing.FileAccess); ok {
			event.Data = fileAccess.Base
		} else if base, ok := w.Data.(ongoing.Base); ok {
			event.Data = base
		} else {
			return nil, errs.InvalidArgumentError("invalid detection event data")
		}
	case eventkind.KindInfos:
		if base, ok := w.Data.(ongoing.Base); ok {
			event.Data = base
		} else {
			return nil, errs.InvalidArgumentError("invalid info event data")
		}
	case eventkind.KindNetPolicy:
		if base, ok := w.Data.(ongoing.Base); ok {
			event.Data = base
		} else {
			return nil, errs.InvalidArgumentError("invalid netpolicy event data")
		}
	case eventkind.KindNone, eventkind.KindEmpty:
		return nil, ErrInvalidEventV2Kind
	default:
		return nil, ErrInvalidEventV2Kind
	}

	return event, nil
}

// ListEvents represents the request to list v2 events with pagination and filtering.
type ListEvents struct {
	ProjectID string             `json:"-"` // Set internally from context
	Filters   *ListEventsFilters `json:"filters"`
	PageArgs  PageArgs           `json:"pageArgs"`
	Sort      *Sort              `json:"sort,omitempty"`
}

// Validate checks if the ListEvents is valid.
func (l *ListEvents) Validate() error {
	// Validate filters if provided
	if l.Filters != nil {
		if err := l.Filters.Validate(); err != nil {
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

// ListEventsFilters defines the filters for listing v2 events.
type ListEventsFilters struct {
	// Deprecated: use Kinds instead. Kind is still supported for backward compatibility but will be removed in the future.
	Kind          *eventkind.Kind  `json:"kind"`
	Kinds         []eventkind.Kind `json:"kinds"`
	AgentID       *string          `json:"agentID"`
	MetadataNames []string         `json:"metadataNames"`
	// Kubernetes context filters
	Cluster   *string    `json:"cluster"`
	Namespace *string    `json:"namespace"`
	Node      *string    `json:"node"`
	TimeStart *time.Time `json:"timeStart"`
	TimeEnd   *time.Time `json:"timeEnd"`
}

// Validate checks if the ListEventsFilters are valid.
func (f *ListEventsFilters) Validate() error {
	if f.Kind != nil && *f.Kind == "" {
		return ErrInvalidEventV2Kind
	}

	if f.AgentID != nil && *f.AgentID == "" {
		return errs.InvalidArgumentError("agentID cannot be empty")
	}

	if len(f.MetadataNames) > MaxMetadataNameCount {
		return ErrTooManyMetadataNames
	}

	for _, name := range f.MetadataNames {
		if name == "" {
			return ErrMetadataNameEmpty
		}

		if len(name) > MaxMetadataNameLength {
			return ErrMetadataNameTooLong
		}

		if !metadataNameRegex.MatchString(name) {
			return ErrMetadataNameInvalidChars
		}
	}

	if f.TimeStart != nil && f.TimeEnd != nil && f.TimeStart.After(*f.TimeEnd) {
		return errs.InvalidArgumentError("timeStart cannot be after timeEnd")
	}

	return nil
}

// IsEmpty checks if the filters are empty.
func (f *ListEventsFilters) IsEmpty() bool {
	return f.Kind == nil && len(f.Kinds) == 0 &&
		f.AgentID == nil && len(f.MetadataNames) == 0 &&
		f.Cluster == nil && f.Namespace == nil && f.Node == nil &&
		f.TimeStart == nil && f.TimeEnd == nil
}

// DecodeEventFilters decodes URL query parameters into ListEventsFilters.
func DecodeEventFilters(values url.Values) (*ListEventsFilters, error) {
	filters := &ListEventsFilters{}

	if kindStr := values.Get("filter.kind"); kindStr != "" {
		filters.Kind = new(eventkind.Kind(kindStr))
	}

	if kindStrs := values["filter.kinds"]; len(kindStrs) != 0 {
		for _, kindStr := range kindStrs {
			if kindStr != "" {
				filters.Kinds = append(filters.Kinds, eventkind.Kind(kindStr))
			}
		}
	}

	if agentID := values.Get("filter.agent_id"); agentID != "" {
		filters.AgentID = &agentID
	}

	if metadataNames := values["filter.metadata.name"]; len(metadataNames) != 0 {
		for _, name := range metadataNames {
			if name != "" {
				filters.MetadataNames = append(filters.MetadataNames, name)
			}
		}
	}

	// Kubernetes context filters
	if cluster := values.Get("filter.cluster"); cluster != "" {
		filters.Cluster = &cluster
	}

	if namespace := values.Get("filter.namespace"); namespace != "" {
		filters.Namespace = &namespace
	}

	if node := values.Get("filter.node"); node != "" {
		filters.Node = &node
	}

	if timeStartStr := values.Get("filter.time_start"); timeStartStr != "" {
		timeStart, err := time.Parse(time.RFC3339Nano, timeStartStr)
		if err != nil {
			return nil, fmt.Errorf("invalid time_start format: %w", err)
		}
		filters.TimeStart = &timeStart
	}

	if timeEndStr := values.Get("filter.time_end"); timeEndStr != "" {
		timeEnd, err := time.Parse(time.RFC3339Nano, timeEndStr)
		if err != nil {
			return nil, fmt.Errorf("invalid time_end format: %w", err)
		}
		filters.TimeEnd = &timeEnd
	}

	if filters.IsEmpty() {
		return nil, nil
	}

	return filters, nil
}

// EventActionType represents the type of action performed on an event.
type EventActionType string

const (
	// EventActionTypeBlock blocks the event destination.
	EventActionTypeBlock EventActionType = "block"
)

// String returns the string representation of the EventActionType.
func (t EventActionType) String() string {
	return string(t)
}

// IsValid checks if the EventActionType is valid.
func (t EventActionType) IsValid() bool {
	return t == EventActionTypeBlock
}

// EventAction represents an action to be performed on an event.
type EventAction struct {
	ActionType       EventActionType       `json:"action_type"` // block
	Scope            NetworkPolicyScope    `json:"scope"`       // global, repo, workflow, cluster, or node
	Reason           string                `json:"reason"`      // User-provided reason for the action
	UserID           *string               `json:"-"`           // ID of the user who performed the action
	DestinationType  NetworkPolicyRuleType `json:"-"`           // Domain or CIDR
	DestinationValue string                `json:"-"`           // The actual domain or IP CIDR
}

// Validate ensures the EventAction is valid.
func (a *EventAction) Validate() error {
	// Check action type
	if !a.ActionType.IsValid() {
		return ErrInvalidEventActionType
	}

	// Check scope
	if !a.Scope.IsValid() {
		return ErrInvalidEventActionScope
	}

	// Reason is required
	if a.Reason == "" {
		return ErrInvalidEventReason
	}

	return nil
}

// EventActionPerformed represents the result of performing an action on an event.
type EventActionPerformed struct {
	EventID           string            `json:"event_id"`
	ActionType        EventActionType   `json:"action_type"`
	NetworkPolicyID   string            `json:"network_policy_id"`
	NetworkPolicyRule NetworkPolicyRule `json:"network_policy_rule"`
	CreatedAt         time.Time         `json:"created_at"`
}
